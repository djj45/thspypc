#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
hfd1.0 数值字段布局分析。

策略：用名称锚点确定记录位置，跳过代码压缩，直接解析名称后的数值区。
目标：定位每个行情字段（价格、涨跌幅、最高、最低、开盘、昨收、金额、成交量等）。
"""
from __future__ import annotations

import json
import os
import struct
import sys
from collections import defaultdict, Counter

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from thspypc.protocol import decode_ths_float

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
HFD1_PATH = os.path.join(DATA_DIR, "hfd1_0_response.bin")
ANCHORS_PATH = os.path.join(DATA_DIR, "hfd1_0_name_anchors.json")
ORACLE_PATH = os.path.join(DATA_DIR, "oracle_code_names.json")


def load_data():
    hfd1 = open(HFD1_PATH, "rb").read()
    anchors = json.load(open(ANCHORS_PATH, encoding="utf-8"))
    oracle = {o["code"]: o for o in json.load(open(ORACLE_PATH, encoding="utf-8"))}
    return hfd1, anchors, oracle


def find_ths_floats(data: bytes, start: int, max_len: int = 100) -> list[dict]:
    """在数据区中找所有 THS float 值。"""
    results = []
    chunk = data[start:start + max_len]
    for i in range(0, len(chunk) - 3):
        val = struct.unpack("<I", chunk[i:i+4])[0]
        try:
            fv = decode_ths_float(val)
            if abs(fv) > 1e-10:  # 非零
                results.append({
                    "offset": start + i,
                    "raw_hex": f"{val:08x}",
                    "value": fv,
                })
        except:
            pass
    return results


def categorize_ths_value(fv: float) -> str:
    """根据值范围分类 THS float 可能的字段类型。"""
    if 0.01 < abs(fv) < 1000:
        return "price"
    elif 1 <= abs(fv) < 10000 and fv == int(fv):
        return "volume"  # 成交量/手
    elif abs(fv) >= 10000:
        return "amount"  # 金额
    elif 0 < abs(fv) < 0.5:
        return "ratio_small"
    elif 0.5 <= abs(fv) < 100:
        return "ratio"  # 涨跌幅/涨速
    return "other"


def analyze_numeric_fields(hfd1: bytes, anchors: list[dict], oracle: dict):
    """分析所有记录的数值区布局。"""
    sorted_a = sorted(anchors, key=lambda x: x["name_offset"])
    
    # 对每条记录，取名称后 60B 分析 THS float 分布
    field_patterns = defaultdict(list)
    
    for i, a in enumerate(sorted_a):
        if not a["code"][0].isdigit() or len(a["code"]) > 8:
            continue
        if bytes.fromhex(a["pre_hex"])[-1] != ord(a["code"][-1]):
            continue
        
        off = a["name_offset"]
        name_gbk = a["name"].encode("gbk")
        name_end = off + len(name_gbk)
        
        # 数值区 = 名称后到下一个记录开始
        if i + 1 < len(sorted_a):
            next_off = sorted_a[i + 1]["name_offset"]
            num_data = hfd1[name_end:next_off]
        else:
            num_data = hfd1[name_end:name_end + 200]
        
        if len(num_data) < 10:
            continue
        
        # 在数值区开头找 THS float 序列
        floats = []
        j = 0
        while j < min(len(num_data) - 3, 60):
            val = struct.unpack("<I", num_data[j:j+4])[0]
            try:
                fv = decode_ths_float(val)
                if abs(fv) > 1e-10 and abs(fv) < 1e12:
                    cat = categorize_ths_value(fv)
                    floats.append((j, fv, cat))
                    j += 4
                else:
                    j += 1
            except:
                j += 1
        
        if floats:
            # 记录前 6 个字段
            key = tuple(f[2] for f in floats[:6])
            field_patterns[key].append(a["code"])
    
    print(f"\n=== 数值区前 6 字段模式分布（采样 {sum(len(v) for v in field_patterns.values())} 条）===")
    for pattern, codes in sorted(field_patterns.items(), key=lambda x: -len(x[1]))[:15]:
        print(f"  {pattern}: {len(codes)} 条 (示例: {codes[:3]})")


def analyze_price_field(hfd1: bytes, anchors: list[dict], oracle: dict):
    """精确定位价格字段的位置。

    策略：价格是第一个合理的 THS float（0.05~200000），
    出现在名称后固定偏移。
    """
    print("\n=== 价格字段定位 ===")
    
    price_offsets = []
    for a in sorted(anchors, key=lambda x: x["name_offset"])[:300]:
        if not a["code"][0].isdigit():
            continue
        pre = bytes.fromhex(a["pre_hex"])
        if pre[-1] != ord(a["code"][-1]):
            continue
        
        off = a["name_offset"]
        name_gbk = a["name"].encode("gbk")
        name_end = off + len(name_gbk)
        
        # 在名称后 40B 内找第一个价格值
        num_data = hfd1[name_end:name_end + 40]
        for j in range(0, len(num_data) - 3):
            val = struct.unpack("<I", num_data[j:j+4])[0]
            try:
                fv = decode_ths_float(val)
                if 1 < abs(fv) < 2000:  # 股票价格范围
                    price_offsets.append((j, fv, a["code"], a["name"]))
                    break
            except:
                pass
    
    if price_offsets:
        print(f"  找到 {len(price_offsets)} 个价格")
        # 偏移分布
        offset_dist = Counter(p[0] for p in price_offsets)
        print(f"  偏移分布: {dict(offset_dist.most_common(10))}")
        # 示例
        for off, fv, code, name in price_offsets[:10]:
            print(f"    {code} {name}: price@{off} = {fv}")


def find_record_markers(hfd1: bytes):
    """查找所有 07 00 记录标记的位置。"""
    markers = []
    pos = 0
    while True:
        idx = hfd1.find(b"\x07\x00", pos)
        if idx < 0:
            break
        markers.append(idx)
        pos = idx + 2
    
    print(f"\n=== 07 00 记录标记统计 ===")
    print(f"  总共 {len(markers)} 个")
    
    # 标记间距分布
    gaps = [markers[i+1] - markers[i] for i in range(len(markers)-1)]
    if gaps:
        from collections import Counter
        gap_dist = Counter(g // 10 * 10 for g in gaps)
        print(f"  间距分布(每10B): {dict(sorted(gap_dist.items()))}")
        print(f"  间距 min={min(gaps)} max={max(gaps)} avg={sum(gaps)//len(gaps)}")
    
    # 检查标记后是否总是紧挨 GBK 名称
    name_count = 0
    for m in markers[:500]:
        # 跳过标记头 07 00 XX YY ZZ (5-6B)
        after_marker = hfd1[m+2:m+10]
        # 检查是否有 GBK 双字节
        has_gbk = False
        for j in range(0, len(after_marker)-1):
            if after_marker[j] >= 0x81 and after_marker[j+1] >= 0x40:
                has_gbk = True
                break
        if has_gbk:
            name_count += 1
    print(f"  标记后含 GBK 名称: {name_count}/{min(500, len(markers))}")


def main():
    hfd1, anchors, oracle = load_data()
    print(f"hfd1.0: {len(hfd1):,}B, 可靠锚点: {sum(1 for a in anchors if a['code'][0].isdigit() and bytes.fromhex(a['pre_hex'])[-1] == ord(a['code'][-1]))}")
    
    # 1. 统计记录标记
    find_record_markers(hfd1)
    
    # 2. 数值字段分析
    analyze_numeric_fields(hfd1, anchors, oracle)
    analyze_price_field(hfd1, anchors, oracle)
    
    # 3. 详细看几条记录的数值区
    print("\n=== 单条数值区详细分析 ===")
    for code in ["600000", "600012", "600048", "688002", "601000"]:
        a = next((x for x in anchors if x["code"] == code), None)
        if not a:
            continue
        off = a["name_offset"]
        name_gbk = a["name"].encode("gbk")
        name_end = off + len(name_gbk)
        
        # 名称后 48B
        post = hfd1[name_end:name_end + 48]
        print(f"\n{code} {a['name']} @{off}")
        print(f"  名称后 48B: {post.hex(' ')}")
        
        # 逐字节检测 THS float
        for j in range(0, min(len(post) - 3, 48)):
            val = struct.unpack("<I", post[j:j+4])[0]
            try:
                fv = decode_ths_float(val)
                if abs(fv) > 1e-10 and abs(fv) < 1e12:
                    cat = categorize_ths_value(fv)
                    print(f"    @{j}: {val:#010x} = {fv:.4f} [{cat}]")
            except:
                pass

    print("\n✓ 分析完成")
    return 0


if __name__ == "__main__":
    sys.exit(main())
