#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
手动分析 hfd1.0 记录布局：仔细查看相邻记录的原始字节，
确定代码区边界、压缩方式、数值区布局。
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
ANCHORS_PATH = os.path.join(DATA_DIR, "hfd1_0_name_anchors.json")


def load_data():
    hfd1 = open(HFD1_PATH, "rb").read()
    anchors = json.load(open(ANCHORS_PATH, encoding="utf-8"))
    return hfd1, anchors


def find_next_name(hfd1: bytes, start: int, anchors: list[dict]) -> int | None:
    """从 start 开始找下一个名称偏移。"""
    for a in sorted(anchors, key=lambda x: x["name_offset"]):
        if a["name_offset"] > start:
            return a["name_offset"]
    return None


def gbk_decode(b: bytes) -> str:
    try:
        return b.decode("gbk")
    except:
        return b.decode("gbk", errors="replace")


def dump_region(hfd1: bytes, start: int, end: int, label: str = ""):
    """带标注的字节 dump。"""
    data = hfd1[start:end]
    print(f"\n--- {label} [{start}:{end}] ({len(data)}B) ---")
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_part = chunk.hex(" ")
        ascii_part = "".join(chr(b) if 0x20 <= b < 0x7f else "." for b in chunk)
        offset = start + i
        # 标注可识别的 GBK 名称片段
        annotations = []
        # 找 GBK 双字节
        if len(chunk) >= 2:
            for j in range(0, len(chunk)-1):
                if chunk[j] >= 0x81 and chunk[j+1] >= 0x40:
                    pair = chunk[j:j+2]
                    try:
                        ch = pair.decode("gbk")
                        if '\u4e00' <= ch <= '\u9fff':  # CJK 统一汉字
                            annotations.append(f"GBK@{j}:{ch}")
                    except:
                        pass
        ann_str = " | " + "; ".join(annotations[:3]) if annotations else ""
        print(f"  {offset:>6d}: {hex_part:<48s}  {ascii_part}{ann_str}")


def examine_record(hfd1: bytes, anchors: list[dict], code: str):
    """详细查看某个股票的记录布局。"""
    # 找到该股票
    a = next((x for x in anchors if x["code"] == code), None)
    if not a:
        print(f"✗ {code} 不在锚点中")
        return
    
    off = a["name_offset"]
    name_gbk = a["name"].encode("gbk")
    name_end = off + len(name_gbk)
    
    # 找上一个和下一个名称
    sorted_a = sorted(anchors, key=lambda x: x["name_offset"])
    idx = next(i for i, x in enumerate(sorted_a) if x["code"] == code)
    
    prev_name_end = 0
    if idx > 0:
        prev = sorted_a[idx - 1]
        prev_name_end = prev["name_offset"] + len(prev["name"].encode("gbk"))
    
    next_name_start = find_next_name(hfd1, name_end, anchors)
    if next_name_start is None:
        next_name_start = len(hfd1)
    
    # 记录范围：从上一个名称结束到下一个名称开始
    rec_start = prev_name_end
    rec_end = next_name_start - 1
    
    print(f"\n{'='*70}")
    print(f"{code} {a['name']}")
    print(f"  名称 @ {off}, 结束 @ {name_end}")
    print(f"  上一个名称结束 @ {prev_name_end}")
    print(f"  下一个名称开始 @ {next_name_start}")
    print(f"  完整记录 [{rec_start}:{rec_end}] ({rec_end - rec_start + 1}B)")
    
    # 从上一个名称结束后开始 dump
    dump_region(hfd1, prev_name_end, min(prev_name_end + 64, next_name_start),
                f"上一个名称结束 ~ {code} 名称开始")
    
    # 查看名称后行情数据
    num_len = next_name_start - name_end if next_name_start else len(hfd1) - name_end
    if num_len > 0:
        num_data = hfd1[name_end:name_end + min(num_len, 64)]
        print(f"\n  行情区 [{name_end}:{name_end + len(num_data)}] ({len(num_data)}B):")
        # 找 THS float
        for i in range(0, len(num_data) - 3):
            val = struct.unpack("<I", num_data[i:i+4])[0]
            try:
                fv = decode_ths_float(val)
                if 0.01 < abs(fv) < 1000000:
                    print(f"    THS float @{i}: {val:#010x} = {fv}")
            except:
                pass


def find_record_boundary(hfd1: bytes, anchors: list[dict], start_off: int):
    """尝试找到 hfd1.0 的精确记录分隔模式。
    
    策略：找两个相邻的"ASCII 末位数字紧接 GBK 名称"模式。
    有了 1209 个锚点，我们可以精确确定每个记录的范围。
    """
    sorted_a = sorted(anchors, key=lambda x: x["name_offset"])
    
    # 取一段连续记录（间隔正常的）
    print("\n" + "=" * 70)
    print("【连续记录段分析（找记录边界规律）】")
    print("=" * 70)
    
    # 找一段密集且连续的区域
    segment = []
    for i, a in enumerate(sorted_a):
        if len(segment) >= 10:
            break
        if a["code"][0].isdigit() and len(a["code"]) == 6:
            # 确认 pre[-1] 匹配
            pre = bytes.fromhex(a["pre_hex"])
            if pre[-1] == ord(a["code"][-1]):
                segment.append(a)
    
    for i, a in enumerate(segment[:8]):
        off = a["name_offset"]
        name_gbk = a["name"].encode("gbk")
        name_end = off + len(name_gbk)
        
        # 前一个名称结束
        if i > 0:
            prev = segment[i-1]
            prev_name_end = prev["name_offset"] + len(prev["name"].encode("gbk"))
        else:
            prev_name_end = 0
        
        # 名称前 20B
        before = hfd1[max(0, off-20):off]
        # 寻找最后一个 ASCII 数字的位置
        last_digit_pos = -1
        for j in range(len(before)-1, -1, -1):
            if 0x30 <= before[j] <= 0x39:
                last_digit_pos = j
                break
        
        # 代码区 = 从上一个名称结束 或 从最后一个相关字节开始
        code_region_start = prev_name_end if prev_name_end > off - 20 else off - 20
        code_region = hfd1[code_region_start:off]
        
        print(f"\n{i}: {a['code']:>8s} {a['name']:8s} @{off}")
        print(f"   名称前20B: {before.hex(' ')}")
        if last_digit_pos >= 0:
            last_d = chr(before[last_digit_pos])
            print(f"   末位数字'{last_d}'@[-{len(before)-last_digit_pos}]")
        
        # 检查代码是否部分出现在前
        cb = a["code"].encode()
        # 尝试不同长度的后缀匹配
        for suffix_len in range(2, 7):
            suffix = cb[-suffix_len:]
            if suffix in before:
                pos = before.find(suffix)
                print(f"   后缀'{suffix.decode()}'(len={suffix_len})@[-{len(before)-pos}]")
                break
        else:
            # 检查后缀是否分散
            digits_found = bytes([b for b in before if 0x30 <= b <= 0x39])
            print(f"   digits: {digits_found.decode('ascii', errors='replace')!r}")
        
        # 行情区：名称后的 THS float 扫描
        post = hfd1[name_end:min(name_end+40, len(hfd1))]
        ths_vals = []
        for j in range(0, len(post)-3):
            val = struct.unpack("<I", post[j:j+4])[0]
            try:
                fv = decode_ths_float(val)
                ths_vals.append((j, fv, val))
            except:
                pass
        # 只显示合理的行情值
        prices = [(j, fv) for j, fv, _ in ths_vals if 0.01 < abs(fv) < 1000]
        if prices:
            print(f"   THS float(价): {prices[:5]}")
        # 涨幅(高字节a0/a8)
        changes = [(j, fv) for j, fv, val in ths_vals if (val >> 24) in (0xa0, 0xa8)]
        if changes:
            print(f"   THS float(涨幅): {changes[:3]}")
        amounts = [(j, fv) for j, fv, val in ths_vals if abs(fv) > 10000 and abs(fv) < 1e12]
        if amounts:
            print(f"   THS float(金额): {amounts[:3]}")


def main():
    hfd1, anchors = load_data()
    print(f"hfd1.0: {len(hfd1):,}B, 锚点: {len(anchors)}")
    
    # 查看具体股票
    for code in ["1A0001", "600000", "600012", "600048", "601000", "688002"]:
        examine_record(hfd1, anchors, code)
    
    # 分析连续记录段
    find_record_boundary(hfd1, anchors, 0)
    
    # 分析 07 模式的 600012 vs 无 07 的 600048
    print("\n" + "=" * 70)
    print("【07 模式 vs 无 07 模式对比】")
    print("=" * 70)
    
    for code in ["600012", "600048", "600051", "600073"]:
        a = next((x for x in anchors if x["code"] == code), None)
        if not a:
            continue
        off = a["name_offset"]
        pre = hfd1[max(0, off-30):off]
        has_07 = 0x07 in pre
        
        print(f"\n{code} {a['name']} @{off} (07={has_07})")
        print(f"  前30B: {pre.hex(' ')}")
        # 分隔：前 10B | 中 10B | 后 10B
        print(f"        前10: {pre[:10].hex(' ')}")
        print(f"        中10: {pre[10:20].hex(' ') if len(pre) >= 20 else '(short)'}")
        print(f"        尾10: {pre[-10:].hex(' ')}")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
