"""纯 Python 的 snappy（raw 格式）解压器，服务 9601 推送帧。

2026-09-07 抓包（dxjl_compare_20260907.pcap）确认 9601 pushrealorder
帧已全部改为 snappy 压缩：2813/2813 帧可解压。生产依赖引入
python-snappy/cramjam 会增加装机负担，而帧体只有几百字节，纯解压
实现完全够用，因此这里内置实现、零第三方依赖。

只实现解压（raw 格式：varint 原始长度前导 + literal/copy 元素流），
不做压缩——我们只消费服务器下发的帧。
"""
from __future__ import annotations


def _read_varint(data: bytes, pos: int) -> tuple[int, int]:
    """读 snappy 前导 varint，返回 (值, 新位置)。"""
    value = 0
    shift = 0
    while True:
        if pos >= len(data):
            raise ValueError("snappy 前导 varint 不完整")
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, pos
        shift += 7
        if shift > 32:
            raise ValueError("snappy 前导 varint 过长")


def snappy_decompress(data: bytes) -> bytes:
    """解压 snappy raw 流；长度不符或偏移非法时抛 ValueError。

    元素格式（tag 低 2 位为类型）：

    - literal（00）：长度 = tag>>2（<60 时为「长度-1」，>=60 时其后
      1-4 字节小端给出「长度-1」），随后为等长原文；
    - copy1（01）：长度 = 4+((tag>>2)&7)，偏移 = ((tag>>5)<<8)|下1字节；
    - copy2（10）：长度 = (tag>>2)+1，偏移 = 下 2 字节小端；
    - copy4（11）：长度 = (tag>>2)+1，偏移 = 下 4 字节小端。

    copy 允许offset小于长度（重叠拷贝，等价 RLE），必须逐字节回填。
    """
    expected, pos = _read_varint(data, 0)
    out = bytearray()
    end = len(data)
    while pos < end:
        tag = data[pos]
        pos += 1
        kind = tag & 0x03
        if kind == 0:
            length = tag >> 2
            if length >= 60:
                extra = length - 59  # 1..4 字节小端存「长度-1」
                length = int.from_bytes(data[pos:pos + extra], "little")
                pos += extra
            length += 1
            if pos + length > end:
                raise ValueError("snappy literal 越界")
            out += data[pos:pos + length]
            pos += length
            continue
        if kind == 1:
            length = 4 + ((tag >> 2) & 0x07)
            if pos >= end:
                raise ValueError("snappy copy1 缺偏移字节")
            offset = ((tag >> 5) << 8) | data[pos]
            pos += 1
        elif kind == 2:
            length = (tag >> 2) + 1
            if pos + 2 > end:
                raise ValueError("snappy copy2 缺偏移字节")
            offset = int.from_bytes(data[pos:pos + 2], "little")
            pos += 2
        else:
            length = (tag >> 2) + 1
            if pos + 4 > end:
                raise ValueError("snappy copy4 缺偏移字节")
            offset = int.from_bytes(data[pos:pos + 4], "little")
            pos += 4
        if offset == 0 or offset > len(out):
            raise ValueError(f"snappy copy 偏移非法: {offset}")
        for _ in range(length):
            out.append(out[-offset])
    if len(out) != expected:
        raise ValueError(
            f"snappy 解压长度不符: 前导={expected} 实际={len(out)}"
        )
    return bytes(out)


__all__ = ["snappy_decompress"]
