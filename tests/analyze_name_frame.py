#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""upstockname 名称帧编码逆向分析工具。

目的：为"块状编码"逆向建立自动验证基准——任何解码假设都能立刻用
"解码结果 vs 已知明文"做 100% 比对。

样本对：
  - 密文：captures_live/upstockname_stream35_server.bin（1.6MB，沪A 全量名称）
          含 1 个 [name_16_16] 段，数据区 @675660（前有 MarketCode=16 容器头）
  - 明文：C:/同花顺软件/同花顺/stockname/stockname_16_0.txt（760KB，8 个 [name_16_*] 子段）

编码特征（2026-07-22 系统逆向确认）：
  数据区 = "[name_16_16]\\r\\n" + 17 字节单元 [ctrl][16B] 序列。
  - ctrl=0x00：16B 全 literal（原样直通）。组 0-2 验证 100% 匹配明文。
  - ctrl≠0x00：16B block 含 literal + COPY（复制前字节，RLE）+ MATCH（1 字节
    LZ 引用，如 0xc1→展开 4 字节"A000"，offset≈26）。组 3 完美解码为：
    L L L C L L L L L L M(×4) L L L L L L = 20B 输出（block 消耗 12B）。
  - 残留难点：MATCH 字节的 offset/len 编码 + COPY/MATCH 在 ctrl 8 位里的精确
    位定义未完全确定，导致组 4 起全局对齐失配。需 Ghidra/Unicorn 分析
    hexin.exe 的 name 解码函数（CMarketStockNameMan / ProcessStockName_Step1/2）。
    这是 mac 版作者同样未解的"变体A"（见 D:\\code\\thspy\\PROTOCOL_REVERSE_8901.md）。

  其他市场段（name_96/88/128/216/48_48/64/UNS/UHI）是纯文本 GBK，已由
  thspypc.protocol.decode_name_frame() 完整支持（24K+ 条名称）。

用法：
  py tests/analyze_name_frame.py                    # 默认：解码纯文本段 + verify
  py tests/analyze_name_frame.py --dump-blocks 8    # 打印前 8 个 17 字节组对照
  py tests/analyze_name_frame.py --probe            # 统计 ctrl 分布 / setbit 相关性
  py tests/analyze_name_frame.py --decode-block 3   # 用 oracle 解码组 N 并对照明文
  py tests/analyze_name_frame.py --cipher X --plain Y  # 指定样本
"""
from __future__ import annotations

import argparse
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

DEFAULT_CIPHER = os.path.join(os.path.dirname(__file__), "..", "captures_live",
                              "upstockname_stream35_server.bin")
DEFAULT_PLAIN = r"C:/同花顺软件/同花顺/stockname/stockname_16_0.txt"

# name_16_16 段头 = [name_16_16]\r\n = 14 字节
SEG_HEAD = b"[name_16_16]\r\n"
BLOCK_SIZE = 16        # 数据块大小（字节）
CTRL_SIZE = 1          # 每块前的控制字节
GROUP = BLOCK_SIZE + CTRL_SIZE  # 17


def load_cipher_segments(path: str) -> list[tuple[str, int, bytes]]:
    """加载密文，返回 [(段名, 数据区起点off, 数据区bytes), ...]。

    数据区起点 = 段头 [name_..]\\r\\n 之后。
    数据区结束 = 下一个结构标记（另一个 [name_] 段，或文件末尾的行情帧）。
    """
    raw = open(path, "rb").read()
    out = []
    for m in re.finditer(rb"\[name_([^\]]+)\]", raw):
        name = m.group(1).decode()
        head_end = m.end() + 2  # 跳过 \r\n（假设紧跟）
        # 数据区到下一个 [name_] 或 hd3.1 前
        nxt = raw.find(b"[name_", head_end)
        hd = raw.find(b"hd3.1", head_end)
        ends = [e for e in (nxt, hd) if e > 0]
        data_end = min(ends) if ends else len(raw)
        out.append((name, head_end, raw[head_end:data_end]))
    return out


def load_plain_segments(path: str) -> list[tuple[str, int, int, bytes]]:
    """加载明文，返回 [(段名, 数据起点, 数据终点, 数据bytes), ...]。"""
    raw = open(path, "rb").read()
    matches = list(re.finditer(rb"\[name_([^\]]+)\]\r\n", raw))
    out = []
    for i, m in enumerate(matches):
        name = m.group(1).decode()
        ds = m.end()
        de = matches[i + 1].start() if i + 1 < len(matches) else len(raw)
        out.append((name, ds, de, raw[ds:de]))
    return out


def verify(decoded: bytes, plain: bytes, label: str = "") -> float:
    """比对解码结果与明文，返回匹配率，打印首个失配位置。"""
    n = min(len(decoded), len(plain))
    if n == 0:
        print(f"[{label}] 空数据")
        return 0.0
    match = sum(1 for i in range(n) if decoded[i] == plain[i])
    rate = match / n
    print(f"[{label}] 长度 decoded={len(decoded)} plain={len(plain)} "
          f"比对 {n}B，匹配 {match} ({rate:.2%})")
    # 首个失配
    for i in range(n):
        if decoded[i] != plain[i]:
            ctx_d = decoded[max(0, i - 8):i + 8]
            ctx_p = plain[max(0, i - 8):i + 8]
            print(f"  首失配 @ {i}: decoded[{i}]=0x{decoded[i]:02x} "
                  f"plain[{i}]=0x{plain[i]:02x}")
            print(f"    decoded ctx: {ctx_d.hex(' ')}")
            print(f"    plain  ctx: {ctx_p.hex(' ')}")
            break
    return rate


def dump_blocks(cipher_data: bytes, plain_data: bytes, ngroups: int) -> None:
    """按 17 字节组（1 ctrl + 16 data）打印对照。"""
    print(f"\n=== 前 {ngroups} 个 17 字节组对照（ctrl + 16B密文块 vs 16B明文块）===")
    for g in range(ngroups):
        coff = g * GROUP
        poff = g * BLOCK_SIZE
        if coff + GROUP > len(cipher_data) or poff + BLOCK_SIZE > len(plain_data):
            break
        ctrl = cipher_data[coff]
        cblock = cipher_data[coff + 1:coff + GROUP]
        pblock = plain_data[poff:poff + BLOCK_SIZE]
        match = "✓" if cblock == pblock else "✗"
        print(f"组{g:2}: ctrl=0x{ctrl:02x}({ctrl:08b}) {match}")
        print(f"  密文: {cblock.hex(' ')}")
        print(f"  明文: {pblock.hex(' ')}")
        print(f"  密ASC: {''.join(chr(b) if 32<=b<127 else '.' for b in cblock)}")
        print(f"  明ASC: {''.join(chr(b) if 32<=b<127 else '.' for b in pblock)}")
        if cblock != pblock:
            # 标注差异字节位置
            diffs = [i for i in range(BLOCK_SIZE) if cblock[i] != pblock[i]]
            print(f"  差异位置: {diffs}")


def probe_ctrl(cipher_data: bytes, plain_data: bytes, ngroups: int = 60) -> None:
    """统计 ctrl 字节分布，及 setbit 数与"块差异"的相关性。"""
    print(f"\n=== ctrl 分布 + setbit 相关性探测（前 {ngroups} 组）===")
    ctrls = []
    for g in range(ngroups):
        coff = g * GROUP
        if coff >= len(cipher_data):
            break
        ctrls.append(cipher_data[coff])
    from collections import Counter
    c = Counter(ctrls)
    print(f"ctrl 分布: 0x00={c.get(0, 0)}组, 非零={sum(1 for x in ctrls if x)}组")
    print(f"ctrl 高频值: {c.most_common(10)}")

    # setbit 数 vs 密文块与明文块的字节差异数
    print("\n组  ctrl   setbit  差异数  (setbit=可能省略/标记的字节数?)")
    for g in range(min(ngroups, 20)):
        coff = g * GROUP
        poff = g * BLOCK_SIZE
        if coff + GROUP > len(cipher_data) or poff + BLOCK_SIZE > len(plain_data):
            break
        ctrl = cipher_data[coff]
        cblock = cipher_data[coff + 1:coff + GROUP]
        pblock = plain_data[poff:poff + BLOCK_SIZE]
        setbits = bin(ctrl).count("1")
        ndiff = sum(1 for i in range(BLOCK_SIZE) if cblock[i] != pblock[i])
        print(f"  {g:2} 0x{ctrl:02x}  {setbits:2}     {ndiff:2}")


def decode_block_oracle(cipher_data: bytes, plain_data: bytes, ngroups: int) -> None:
    """用"明文驱动 oracle"逐组解码，验证对齐并打印操作序列。

    这是块状编码逆向的核心工具：对每个 17 字节单元，用明文作为真值，
    判定 block 每个字节是 LITERAL（==明文）/ COPY（复制前字节）/ MATCH
    （历史回引）。能完美对齐的组数即当前编码理解的上限。

    已知：组 0-3（ctrl=0x00,0x00,0x00,0x83）可完美解码到 68B 明文；
    组 4 起因 MATCH 的 offset/len 编码未确定而失配。
    """
    out = bytearray()
    pp = 0  # 明文指针
    print(f"\n=== oracle 解码前 {ngroups} 组（L=literal C=copy前字节 M=match回引）===")
    for g in range(ngroups):
        coff = g * GROUP
        if coff + GROUP > len(cipher_data):
            break
        ctrl = cipher_data[coff]
        block = cipher_data[coff + 1:coff + GROUP]
        bi = 0
        start_pp = pp
        ops = []
        stuck = 0
        while bi < BLOCK_SIZE and pp < len(plain_data) and stuck < 4:
            b = block[bi]
            pv = plain_data[pp]
            if b == pv:
                out.append(b); ops.append(("L", b)); bi += 1; pp += 1; stuck = 0
            elif out and out[-1] == pv:
                out.append(pv); ops.append(("C", pv)); pp += 1; stuck += 1
            else:
                want = plain_data[pp:pp + 16]
                best_l, best_o = 0, 0
                for o in range(1, min(len(out), 2048)):
                    s = len(out) - o; l = 0
                    while l < len(want) and s + l < len(out) and out[s + l] == want[l]:
                        l += 1
                    if l > best_l:
                        best_l, best_o = l, o
                if best_l >= 2:
                    exp = bytes(out[len(out) - best_o + k] for k in range(best_l))
                    ops.append(("M", best_o, best_l, exp))
                    for k in range(best_l):
                        out.append(out[len(out) - best_o + k])
                    pp += best_l; bi += 1; stuck = 0
                else:
                    ops.append(("?", b, pv)); bi += 1; stuck += 1
        produced = pp - start_pp
        # 校验本组输出是否与明文一致
        ok = bytes(out[start_pp:pp]) == plain_data[start_pp:pp]
        non_l = [op for op in ops if op[0] != "L"]
        print(f"组{g} ctrl=0x{ctrl:02x}({ctrl:08b}) 输出{produced}B "
              f"block用{bi}/16 {'✓' if ok else '✗失配'}")
        for op in non_l:
            if op[0] == "M":
                asc = "".join(chr(c) if 32 <= c < 127 else "." for c in op[3])
                print(f"    M off={op[1]} len={op[2]} expand={asc!r}")
            elif op[0] == "C":
                print(f"    C 复制前字节 0x{op[1]:02x}")
            else:
                print(f"    ? 无法对齐 cipher=0x{op[1]:02x} plain=0x{op[2]:02x}")
        if not ok:
            print(f"  ⚠ 组{g} 失配，oracle 对齐到此为止（需逆向 match 编码）")
            break


def main():
    ap = argparse.ArgumentParser(description="upstockname 名称帧编码逆向分析")
    ap.add_argument("--cipher", default=DEFAULT_CIPHER, help="密文样本路径")
    ap.add_argument("--plain", default=DEFAULT_PLAIN, help="明文样本路径")
    ap.add_argument("--dump-blocks", type=int, default=0, metavar="N",
                    help="打印前 N 个 17 字节组对照")
    ap.add_argument("--probe", action="store_true",
                    help="统计 ctrl 分布与 setbit 相关性")
    ap.add_argument("--decode-block", type=int, default=0, metavar="N",
                    help="用 oracle 解码前 N 组并对照明文（验证编码理解）")
    ap.add_argument("--segments", action="store_true",
                    help="列出密文/明文的所有 [name_] 段")
    args = ap.parse_args()

    if not os.path.exists(args.cipher):
        print(f"✗ 密文不存在: {args.cipher}")
        return 1
    if not os.path.exists(args.plain):
        print(f"✗ 明文不存在: {args.plain}")
        return 1

    csegs = load_cipher_segments(args.cipher)
    psegs = load_plain_segments(args.plain)
    print(f"密文: {len(csegs)} 段, 明文: {len(psegs)} 段")

    if args.segments:
        print("\n密文段:")
        for name, off, data in csegs:
            print(f"  [{name}] @{off} 数据 {len(data)}B")
        print("明文段:")
        for name, ds, de, data in psegs:
            print(f"  [{name}] @{ds}..{de} 数据 {len(data)}B")

    # 取首个对齐的段做分析（密文 name_16_16 vs 明文 name_16_16）
    cname, coff, cdata = csegs[0]
    # 明文首个 [name_16_16] 子段
    pname, pds, pde, pdata = psegs[0]
    print(f"\n对照段: 密文[{cname}] {len(cdata)}B vs 明文[{pname}] {len(pdata)}B")
    print(f"比值: {len(cdata)/max(len(pdata),1):.4f}")

    if args.dump_blocks:
        dump_blocks(cdata, pdata, args.dump_blocks)

    if args.probe:
        probe_ctrl(cdata, pdata)

    if args.decode_block:
        decode_block_oracle(cdata, pdata, args.decode_block)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
