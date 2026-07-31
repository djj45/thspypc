"""Market response compression and bit-plane codecs."""
from __future__ import annotations

import struct


_MAX_NORMALIZED_8901_SIZE = 16 * 1024 * 1024


def normalize_8901_response(body: bytes) -> bytes:
    """解开 8901 响应 ``cmd=0x0a`` 的外层压缩，返回客户端实际分发的帧体。

    算法逐分支移植自 hexin.exe RVA ``0xf74260``。命令字节后的前四字节是
    大端序输出长度，后面是以位控制字驱动、带 64K 三字节哈希字典的压缩流。
    已经是明文帧的输入保持原样返回。

    部分响应（如深市盘后历史帧）的压缩流在输出填满 expected_size 前几字节
    就用完，剩余位置是 0x00 填充——此时 ``read_source_byte`` 越界返回 0，
    与 ``read_bit`` 的边界处理一致，而非抛错。

    Raises:
        ValueError: ``cmd=0x0a`` 帧头非法、声明长度越界或回溯引用无效。
    """
    if not body.startswith(b"\x0a"):
        return body

    payload = body[1:]
    if len(payload) < 9:
        raise ValueError("8901 压缩响应过短")
    expected_size = struct.unpack_from(">I", payload)[0]
    if not 4 <= expected_size <= _MAX_NORMALIZED_8901_SIZE:
        raise ValueError(f"非法 8901 正规化长度: {expected_size}")

    # 原函数为压缩区分配的是整个 payload 长度，却只复制 payload[4:]，
    # 并允许最后一个控制分支预读到分配块的对齐尾部。显式补零可复现其
    # 预期边界语义，同时避免依赖 malloc 返回块里的历史内容。
    source = payload[4:] + b"\0" * 32
    output = bytearray(expected_size + 8)
    output[:4] = source[:4]
    output_pos = 4
    source_pos = 5
    control = source[4]
    bits_left = 8
    dictionary = [0] * 0x10000

    def read_bit() -> bool:
        nonlocal control, bits_left, source_pos
        bit = bool(control & 0x80)
        control = (control << 1) & 0xFF
        bits_left -= 1
        if bits_left == 0:
            if source_pos >= len(source):
                # 原函数在消费完当前控制字节后会预取下一字节，即使当前
                # 匹配分支已经足够填满输出；此时补零只影响不会再使用的预取值。
                control = 0
            else:
                control = source[source_pos]
                source_pos += 1
            bits_left = 8
        return bit

    def read_source_byte() -> int:
        nonlocal source_pos
        if source_pos >= len(source):
            # 末尾零填充区：部分响应（如深市盘后历史帧）的压缩流在 expected_size
            # 之前几字节就用完，剩余位置本就是 0x00 填充。返回 0 让主循环自然填满，
            # 与 read_bit 越界返回 control=0 的边界处理一致。真正损坏的流会在
            # append_reference 处因引用未填充位置而失败。
            return 0
        value = source[source_pos]
        source_pos += 1
        return value

    def history_key() -> int:
        value = (output[output_pos - 3] << 4) ^ output[output_pos - 2]
        return ((value << 7) ^ output[output_pos - 1]) & 0xFFFF

    def append_byte(value: int) -> None:
        nonlocal output_pos
        if output_pos >= len(output):
            raise ValueError("8901 正规化输出越界")
        output[output_pos] = value
        output_pos += 1

    def append_reference(reference_pos: int) -> None:
        if not 0 <= reference_pos < output_pos:
            raise ValueError(f"非法 8901 回溯引用: {reference_pos}")
        append_byte(output[reference_pos])

    while output_pos < expected_size:
        if not read_bit():
            dictionary[history_key()] = output_pos
            append_byte(read_source_byte())
            dictionary[history_key()] = output_pos
            append_byte(read_source_byte())
            continue

        if not read_bit():
            dictionary[history_key()] = output_pos
            append_byte(read_source_byte())

        key = history_key()
        reference = dictionary[key]
        dictionary[key] = output_pos
        append_reference(reference)

        if not read_bit():
            continue
        append_reference(reference + 1)

        fourth_bit = read_bit()
        fifth_bit = read_bit()
        if not fourth_bit:
            if fifth_bit:
                append_reference(reference + 2)
            continue

        append_reference(reference + 2)
        append_reference(reference + 3)
        if not fifth_bit:
            continue

        append_reference(reference + 4)
        sixth_bit = read_bit()
        if not sixth_bit:
            seventh_bit = read_bit()
            eighth_bit = read_bit()
            if seventh_bit:
                append_reference(reference + 5)
                append_reference(reference + 6)
                if eighth_bit:
                    append_reference(reference + 7)
            elif eighth_bit:
                append_reference(reference + 5)
            continue

        for offset in range(5, 9):
            append_reference(reference + offset)
        seventh_bit = read_bit()
        eighth_bit = read_bit()
        if not seventh_bit:
            if eighth_bit:
                append_reference(reference + 9)
            continue

        append_reference(reference + 9)
        append_reference(reference + 10)
        if not eighth_bit:
            continue
        append_reference(reference + 11)

        reference_pos = reference + 12
        while True:
            count = read_source_byte()
            # Native loop (hexin.exe RVA 0xf74260) copies `count` bytes: the
            # x86 body is `dec edx; cmp/jae; copy; test edx; jne`, which lets
            # the edx==0 iteration copy once more.  A `count-1` port loses one
            # byte per long match and silently misaligns record streams that
            # contain long matches (e.g. 4417 historical timelines).
            for _ in range(max(0, count)):
                if output_pos >= expected_size:
                    break
                append_reference(reference_pos)
                reference_pos += 1
            if count != 0xFF or source_pos >= len(source):
                break

    return bytes(output[:expected_size])


def _decode_bitrle_0x13746d0(src: bytes, expect: int) -> bytes:
    """纯 Python 移植 hexin.exe 0x13746d0（hd3.1 BitRLE 解码器）。

    src = BE32 长度头 + 位流；返回 out_len 字节位平面。
    与 Unicorn 模拟真实机器码逐字节对照验证（6 帧 × 1363 字节 + 7526 条全量表
    534346 字节，全部一致）。无 unicorn 依赖。
    """
    if len(src) < 4:
        return b""
    out_len = struct.unpack(">I", src[:4])[0]
    if not (0 < out_len <= 12_000_000):
        return b""
    out = bytearray(out_len)
    out_end = out_len
    src_end = len(src)
    edi = src[4] if len(src) > 4 else 0
    edx = 5
    esi = 8
    optr = 0

    def rb():
        nonlocal edx
        if edx < src_end:
            b = src[edx]
            edx += 1
            return b
        return 0

    def reload():
        nonlocal edi, esi
        edi = rb()
        esi = 8

    def bit():
        nonlocal edi, esi
        ecx = edi & 0x80
        edi = (edi + edi) & 0xFF
        esi -= 1
        if esi == 0:
            reload()
        return ecx

    def emit(b):
        nonlocal optr
        if optr < out_end:
            out[optr] = b & 0xFF
        optr += 1

    while optr < out_end:
        if bit() == 0:
            a = rb()
            b = rb()
            emit(a)
            emit(b)
            continue
        if bit() == 0:
            emit(rb())
        bl = 0xFF if bit() != 0 else 0x00
        emit(bl)
        if optr >= out_end:
            break
        if bit() == 0:
            continue
        emit(bl)
        if optr >= out_end:
            break
        slot_m8 = bit()
        slot_m18 = bit()
        if slot_m8 == 0:
            if slot_m18 != 0:
                emit(bl)
            continue
        emit(bl)
        emit(bl)
        if optr >= out_end:
            break
        if slot_m18 == 0:
            continue
        emit(bl)
        if optr >= out_end:
            break
        slot_pc = bit()
        slot_m8 = bit()
        if slot_pc == 0:
            b9 = bit()
            if slot_m8 == 0:
                if b9 != 0:
                    emit(bl)
            else:
                emit(bl)
                emit(bl)
                if optr >= out_end:
                    break
                if b9 != 0:
                    emit(bl)
            continue
        for _ in range(4):
            emit(bl)
            if optr >= out_end:
                break
        if optr >= out_end:
            break
        b9 = bit()
        if slot_m8 == 0:
            if b9 != 0:
                emit(bl)
            continue
        emit(bl)
        emit(bl)
        if optr >= out_end:
            break
        if b9 == 0:
            continue
        emit(bl)
        if optr >= out_end:
            break
        while True:
            cnt = rb()
            if cnt > 0x7F:
                cnt2 = rb()
                cnt = ((cnt - 0x80) << 8) + cnt2
            if cnt:
                for _ in range(cnt):
                    if optr >= out_end:
                        break
                    emit(bl)
            if cnt != 0x7FFF:
                break
            if edx >= src_end:
                break

    return bytes(out[:out_len])


def _transpose_bitplane_0x1763410(src: bytes, hs: int, dc: int) -> bytes:
    """纯 Python 移植 hexin.exe 0x1763410（位平面转置）。

    把 _decode_bitrle_0x13746d0 输出的 dc*hs 字节位平面转成 dc 条行主序记录
    （每条 hs 字节）。算法（反汇编 + Unicorn 逐位对照）：源位流 LSB-first 读取，
    按列主序：
      for 字节列 c(0..hs-1): for 位 p(0..7): for 记录 r(0..dc-1): 读源位
        源读取序号 m = (c*8 + p)*dc + r → 源字节[m//8] 的第 (m%8) 位（LSB）
      输出字节 (r,c) 的第 p 位（LSB）置为该源位。
    与 Unicorn 对照 6 帧 1363 字节 + 7526 条 534346 字节全部一致。
    """
    out = bytearray(dc * hs)
    if dc == 0 or hs == 0:
        return bytes(out)
    outlen = len(out)
    srclen = len(src)
    for c in range(hs):
        for p in range(8):
            for r in range(dc):
                m = (c * 8 + p) * dc + r
                byte = m >> 3
                if byte < srclen and (src[byte] >> (m & 7)) & 1:
                    if r * hs + c < outlen:
                        out[r * hs + c] |= 1 << p
    return bytes(out)
