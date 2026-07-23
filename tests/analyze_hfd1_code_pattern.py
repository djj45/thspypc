#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
hfd1.0 代码压缩模式精确分析。

只关注名称前固定窗口（30B）的字节模式，从实际数据中归纳编码规律。
"""
from __future__ import annotations

import json
import os
import re
import sys
from collections import defaultdict, Counter

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from thspypc.protocol import decode_ths_float
import struct

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
HFD1_PATH = os.path.join(DATA_DIR, "hfd1_0_response.bin")
ANCHORS_PATH = os.path.join(DATA_DIR, "hfd1_0_name_anchors.json")


def load_data():
    hfd1 = open(HFD1_PATH, "rb").read()
    anchors = json.load(open(ANCHORS_PATH, encoding="utf-8"))
    return hfd1, anchors


def main():
    hfd1, anchors = load_data()
    print(f"加载 {len(anchors)} 个锚点, hfd1.0 = {len(hfd1):,}B")
    
    # 过滤可靠锚点：pre[-1] == code[-1]
    good = [a for a in anchors 
            if bytes.fromhex(a["pre_hex"])[-1] == ord(a["code"][-1])
            and a["code"][0].isdigit()]
    print(f"可靠锚点（末位匹配+数字开头）: {len(good)}/{len(anchors)}")
    
    # 对每个可靠锚点提取"名称前 30B"（含名称前所有字节，含代码+可能的数值区尾部）
    records = []
    for a in sorted(good, key=lambda x: x["name_offset"]):
        off = a["name_offset"]
        window = hfd1[max(0, off - 30):off + 4]  # 30B 前 + 4B 名称开头
        pre = window[:30]
        name_start = window[30:] if len(window) > 30 else b""
        records.append({
            "code": a["code"],
            "name": a["name"],
            "offset": off,
            "pre_30": pre,
            "pre_30_hex": pre.hex(" "),
            "last_byte": pre[-1] if pre else 0,
            "last_match": pre[-1] == ord(a["code"][-1]) if len(pre) > 0 else False,
        })
    
    # ── 1. 分类：名称前 30B 中代码是否完整出现 ──
    print("\n" + "=" * 70)
    print("【分类 1：代码是否以完整 ASCII 出现在名称前 30B 中】")
    print("=" * 70)
    
    full_literal = []
    compressed = []
    for r in records:
        code_bytes = r["code"].encode("ascii")
        if code_bytes in r["pre_30"]:
            full_literal.append(r)
        else:
            compressed.append(r)
    
    print(f"  完整 ASCII 代码: {len(full_literal)}/{len(records)}")
    print(f"  压缩存储: {len(compressed)}/{len(records)}")
    
    # 完整代码的示例
    print(f"\n  完整 ASCII 代码示例:")
    print(f"  {'code':>8s} {'offset':>6s}  pre_30")
    print(f"  {'-'*60}")
    for r in full_literal[:10]:
        pos = r["pre_30"].find(r["code"].encode())
        print(f"  {r['code']:>8s} {r['offset']:>6d}  code@{pos}: {r['pre_30_hex']}")
    
    # ── 2. 压缩代码的 07 模式分析 ──
    print("\n" + "=" * 70)
    print("【分类 2：压缩代码的 07 控制字节模式】")
    print("=" * 70)
    
    # 分析每个压缩代码中 07 的位置
    print(f"\n  {'code':>8s} {'offset':>6s}  {'name':8s}  07模式\tpre_30尾10B")
    print(f"  {'-'*70}")
    
    # 按代码前缀分组
    by_prefix = defaultdict(list)
    for r in compressed:
        by_prefix[r["code"][:3]].append(r)
    
    for prefix in ["600", "601", "603", "688", "000", "002", "300", "870"]:
        group = by_prefix.get(prefix, [])
        if not group:
            continue
        print(f"\n  --- {prefix}xxx ({len(group)}条) ---")
        
        # 找共同模式：名称前最后几字节的规律
        for r in group[:8]:
            pre = r["pre_30"]
            code = r["code"]
            # 找 07 位置
            ctrl_07 = [i for i, b in enumerate(pre) if b == 0x07]
            # 找 ASCII 数字
            digits = [(i, chr(b)) for i, b in enumerate(pre) if 0x30 <= b <= 0x39]
            
            ctrl_info = f"07@{ctrl_07}" if ctrl_07 else "no07"
            tail = pre[-10:].hex(" ") if len(pre) >= 10 else pre.hex(" ")
            print(f"  {code:>8s} {r['offset']:>6d} {r['name']:8s}  {ctrl_info:20s} tail: {tail}")
    
    # ── 3. 完整代码记录的「名称前最后几字节」规律 ──
    print("\n" + "=" * 70)
    print("【分类 3：完整代码记录的末尾模式】")
    print("=" * 70)
    print(f"  {'code':>8s} {'offset':>6s} {'name':8s}  pre尾10B\t\t代码在pre中的位置")
    print(f"  {'-'*70}")
    for r in full_literal[:20]:
        pre = r["pre_30"]
        code_b = r["code"].encode()
        pos = pre.find(code_b)
        tail = pre[-10:].hex(" ")
        # 代码后面跟什么？
        after_code = pre[pos + len(code_b):pos + len(code_b) + 4]
        print(f"  {r['code']:>8s} {r['offset']:>6d} {r['name']:8s}  {tail:30s} code@{pos}, after={after_code.hex(' ')!r}")
    
    # ── 4. 关键发现：07 后的模式 ──
    print("\n" + "=" * 70)
    print("【关键：07 后的字节模式分析】")
    print("=" * 70)
    
    # 收集所有 07 xx yy zz 模式
    patterns = Counter()
    for r in records:
        pre = r["pre_30"]
        for i, b in enumerate(pre):
            if b == 0x07 and i + 3 < len(pre):
                pattern = pre[i:i+4]
                patterns[pattern.hex(" ")] += 1
    
    print(f"\n  07 后 4B 模式频率（前 20）:")
    for pat, cnt in patterns.most_common(20):
        print(f"    {pat}: {cnt}次")
    
    # ── 5. 检查是否 07 表示"代码结束，后面是名称"──
    print("\n" + "=" * 70)
    print("【验证：07 是否表示代码/名称分隔符】")
    print("=" * 70)
    
    # 对每个记录，检查最后一个 07 的位置和名称起始的关系
    sep_candidates = []
    for r in records:
        pre = r["pre_30"]
        last_07 = len(pre) - 1 - pre[::-1].find(0x07) if 0x07 in pre else -1
        code = r["code"]
        if last_07 >= 0:
            after_07 = pre[last_07 + 1:]
            sep_candidates.append((r["code"], r["offset"], last_07, after_07.hex(" ")))
    
    print(f"  含 07 的记录: {len(sep_candidates)}/{len(records)}")
    print(f"  示例（07 紧邻名称前）:")
    for code, off, pos, after in sep_candidates[:15]:
        print(f"    {code} @{off}: 07@-{pos} after_07: {after[:20]}")
    
    # ── 6. 尝试提取代码（从 pre_30 中提取 ASCII 数字 + 末位确认）──
    print("\n" + "=" * 70)
    print("【尝试：从 pre_30 提取代码】")
    print("=" * 70)
    
    success = 0
    fail = 0
    for r in records[:200]:
        pre = r["pre_30"]
        code = r["code"]
        last_digit = code[-1]
        
        # 方法 1：找完整代码
        if code.encode() in pre:
            success += 1
            continue
        
        # 方法 2：从 pre 中提取所有连续数字，拼起来看是否包含 code
        digits = re.findall(rb'(\d+)', pre)
        combined = b"".join(digits).decode()
        
        # 方法 3：找最后一个数字 = last_digit
        last_byte_pos = len(pre) - 1 - pre[::-1].find(ord(last_digit))
        
        print(f"  {code}: pre_digits={combined!r}, last_{last_digit}@[-{len(pre)-last_byte_pos}]")
        fail += 1
    
    print(f"\n  直接匹配: {success}/{len(records[:200])}")
    
    # ── 7. 最终结论：寻找代码前缀压缩规律 ──
    print("\n" + "=" * 70)
    print("【前缀压缩规律：同前缀组的 pre_30 对比】")
    print("=" * 70)
    
    for prefix in ["600"]:
        group = [r for r in full_literal if r["code"].startswith(prefix)]
        if len(group) < 3:
            continue
        print(f"\n  {prefix}xxx 组中代码以完整 ASCII 存储的 {len(group)} 条:")
        for r in group:
            pre = r["pre_30"]
            code_b = r["code"].encode()
            pos = pre.find(code_b)
            before = pre[:pos].hex(" ") if pos > 0 else "(开头)"
            print(f"    {r['code']}: code@{pos}, before={before}")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
