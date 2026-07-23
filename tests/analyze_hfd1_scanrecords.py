#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
用字节模式扫描 hfd1.0 记录边界。

核心发现：每个记录以"末位数字 ASCII + GBK 名称"为特征。
扫描所有"ASCII 数字 + GBK 双字节"的位置，就是记录边界。
"""
from __future__ import annotations

import json
import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from thspypc.protocol import decode_ths_float

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
HFD1_PATH = os.path.join(DATA_DIR, "hfd1_0_response.bin")


def is_gbk_start(b: int) -> bool:
    """GBK 首字节范围。"""
    return 0x81 <= b <= 0xFE


def is_gbk_pair(b1: int, b2: int) -> bool:
    """检查是否为一对有效的 GBK 字节。"""
    return is_gbk_start(b1) and 0x40 <= b2 <= 0xFE


def scan_record_boundaries(raw: bytes) -> list[dict]:
    """扫描所有记录边界。
    
    策略：找"ASCII 数字 + GBK 双字节"模式 → 记录边界。
    然后读 GBK 序列作为名称。
    """
    boundaries = []
    i = 1  # 从 1 开始检查 i-1 是数字
    while i < len(raw) - 5:
        # 检查 raw[i-1] 是 ASCII 数字
        if 0x30 <= raw[i-1] <= 0x39:
            # 检查 raw[i:i+2] 是 GBK 双字节
            if is_gbk_pair(raw[i], raw[i+1]):
                # 找到边界！读取整个 GBK 名称
                name_start = i
                pos = i
                gbk_bytes = bytearray()
                while pos + 1 < len(raw) and is_gbk_pair(raw[pos], raw[pos+1]):
                    gbk_bytes.append(raw[pos])
                    gbk_bytes.append(raw[pos+1])
                    pos += 2
                name = gbk_bytes.decode("gbk", errors="replace")
                name_end = pos
                
                boundaries.append({
                    "last_digit": chr(raw[i-1]),
                    "name_offset": i,
                    "name": name,
                    "name_len": len(gbk_bytes),
                    "name_end": name_end,
                    "last_digit_pos": i - 1,
                })
                
                # 跳到名称结束之后
                i = name_end
                continue
        i += 1
    
    return boundaries


def group_consecutive_records(boundaries: list[dict]) -> list[list[dict]]:
    """将连续的记录分组（同一市场段）。"""
    if not boundaries:
        return []
    
    groups = []
    current = [boundaries[0]]
    for i in range(1, len(boundaries)):
        gap = boundaries[i]["name_offset"] - boundaries[i-1]["name_end"]
        if gap > 100:  # 大间隔 = 新市场段
            groups.append(current)
            current = [boundaries[i]]
        else:
            current.append(boundaries[i])
    groups.append(current)
    return groups


def main():
    raw = open(HFD1_PATH, "rb").read()
    print(f"hfd1.0: {len(raw):,}B")
    
    # 扫描边界
    boundaries = scan_record_boundaries(raw)
    print(f"扫描到 {len(boundaries)} 个记录边界")
    
    # 统计名称长度分布
    name_lens = [b["name_len"] for b in boundaries]
    print(f"名称长度: min={min(name_lens)} max={max(name_lens)} "
          f"avg={sum(name_lens)//len(name_lens)}B")
    
    # 看前 30 条
    print(f"\n前 30 条记录:")
    print(f"  {'offset':>6s} {'name':16s} {'last':4s} {'name_len':4s}")
    for b in boundaries[:30]:
        print(f"  {b['name_offset']:>6d} {b['name']:16s} "
              f"{b['last_digit']:4s} {b['name_len']:4d}")
    
    # 分组
    groups = group_consecutive_records(boundaries)
    print(f"\n市场段: {len(groups)} 组")
    for i, g in enumerate(groups):
        # 计算组内股票的范围
        codes_in_group = []
        for b in g[:5]:
            codes_in_group.append(f"...{b['last_digit']} {b['name']}")
        print(f"  段 {i}: {len(g)} 条, 前: {codes_in_group}")
    
    # 检查 600000 是否被找到
    for b in boundaries:
        if "浦发" in b["name"]:
            print(f"\n✓ 找到: 浦发银行 @{b['name_offset']}, last={b['last_digit']}")
            # 显示上下文
            ctx = raw[max(0, b['name_offset']-10):b['name_offset']+b['name_len']+4]
            print(f"  上下文: {ctx.hex(' ')}")
            print(f"  ASCII: {ctx.decode('ascii', errors='replace')!r}")
            break
    
    # 检查总记录数估计
    total_size = len(raw)
    avg_record = 45  # 估计
    estimated = total_size // avg_record
    print(f"\n估算总记录数: ~{estimated} (~{total_size/avg_record:.0f})")
    
    # 保存边界数据
    out_path = os.path.join(DATA_DIR, "hfd1_0_boundaries.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(boundaries, f, ensure_ascii=False, indent=2)
    print(f"已保存: {out_path}")


if __name__ == "__main__":
    sys.exit(main())
