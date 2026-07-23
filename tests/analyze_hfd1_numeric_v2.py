#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
hfd1.0 数值字段精确校准 v2。

策略：
  1. 对每条记录，从名称结束处开始逐字节扫描 THS float
  2. 用"价格在合理范围"作为锚点确定字段序列的起始偏移
  3. 归纳固定偏移规则
  4. 对指数 vs 股票分别建模

参考 mac 版字段顺序：
  [0]=价格, [1]=涨速, [2]=涨跌幅, [3]=最高, [4]=最低, [5]=开盘,
  [6]=总金额, [7]=总手, [8]=昨收
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


def main():
    hfd1 = open(HFD1_PATH, "rb").read()
    anchors = json.load(open(ANCHORS_PATH, encoding="utf-8"))
    
    # 过滤可靠锚点
    good = []
    for a in anchors:
        pre = bytes.fromhex(a["pre_hex"])
        if pre[-1] == ord(a["code"][-1]) and a["code"][0].isdigit():
            good.append(a)
    good.sort(key=lambda a: a["name_offset"])
    
    print(f"可靠锚点: {len(good)}")
    
    # ── 1. 名称后 THS float 偏移统计 ──
    # 对每条记录，记录每个偏移出现的"合理价格"频率
    offset_price_counts = Counter()
    offset_patterns = defaultdict(list)
    
    for a in good[:300]:  # 前 300 条
        off = a["name_offset"]
        name_gbk = a["name"].encode("gbk")
        name_end = off + len(name_gbk)
        
        chunk = hfd1[name_end:name_end + 48]
        
        # 逐 4B 扫描 THS float
        for j in range(0, len(chunk) - 3):
            val = struct.unpack("<I", chunk[j:j+4])[0]
            try:
                fv = decode_ths_float(val)
            except:
                continue
            if abs(fv) < 1e-10:
                continue
            
            # 价格范围：0.5 ~ 2000
            if 0.5 < abs(fv) < 2000:
                offset_price_counts[j] += 1
                offset_patterns[j].append((a["code"], fv))
    
    print(f"\n=== 价格字段偏移统计 ===")
    print(f"每个偏移出现合理价格的频率:")
    for off, cnt in offset_price_counts.most_common(15):
        samples = offset_patterns[off][:3]
        sample_str = "; ".join(f"{c}={v:.2f}" for c, v in samples)
        print(f"  @{off}: {cnt}次  示例: {sample_str}")
    
    # ── 2. 对最可能的偏移，统计后续字段的模式 ──
    best_offset = offset_price_counts.most_common(1)[0][0]
    print(f"\n=== 最佳价格偏移 @{best_offset} 后续字段序列 ===")
    
    # 对每条记录，从 best_offset 开始连续读 THS float
    field_sequences = []
    for a in good[:300]:
        off = a["name_offset"]
        name_gbk = a["name"].encode("gbk")
        name_end = off + len(name_gbk)
        chunk = hfd1[name_end:name_end + 48]
        
        if best_offset + 32 > len(chunk):
            continue
        
        fields = []
        valid = True
        for j in range(best_offset, best_offset + 32, 4):
            if j + 4 > len(chunk):
                break
            val = struct.unpack("<I", chunk[j:j+4])[0]
            try:
                fv = decode_ths_float(val)
            except:
                valid = False
                break
            fields.append(fv)
        
        if valid and len(fields) >= 3:
            field_sequences.append((a["code"], fields))
    
    # 统计序列模式
    print(f"  采样 {len(field_sequences)} 条记录")
    
    # 看前 10 条的序列（字段0=价格, 字段2=涨跌幅）
    print(f"\n  前 10 条的价格+涨幅:")
    for code, fields in field_sequences[:10]:
        price = fields[0] if len(fields) > 0 else 0
        chg = fields[2] if len(fields) > 2 else 0
        high = fields[3] if len(fields) > 3 else 0
        extra = f" high={high:.2f}" if len(fields) > 3 else ""
        print(f"    {code}: price={price:.2f} 涨跌幅={chg:.4f}{extra}")
    
    # ── 3. 指数 vs 股票分类建模 ──
    print(f"\n=== 指数(1A/1B) vs A股(6xx) 对比 ===")
    
    for prefix, label in [("1A", "指数"), ("1B", "指数"), ("600", "A股"), ("603", "A股"), ("688", "A股")]:
        group = [a for a in good if a["code"].startswith(prefix)]
        if not group:
            continue
        
        # 对组内每条找最佳起始偏移
        offsets = []
        for a in group[:20]:
            off = a["name_offset"]
            name_gbk = a["name"].encode("gbk")
            name_end = off + len(name_gbk)
            chunk = hfd1[name_end:name_end + 32]
            for j in range(0, min(16, len(chunk) - 3)):
                val = struct.unpack("<I", chunk[j:j+4])[0]
                try:
                    fv = decode_ths_float(val)
                    if 0.5 < abs(fv) < 2000:
                        offsets.append(j)
                        break
                except:
                    pass
        
        if offsets:
            off_cnt = Counter(offsets)
            print(f"  {prefix}xx ({label}): 价格偏移分布={dict(off_cnt.most_common(5))}")
    
    # ── 4. 调试：看 600048 保利发展的完整数值区域 ──
    print(f"\n=== 单例调试：600048 保利发展 ===")
    a = next((x for x in good if x["code"] == "600048"), None)
    if a:
        off = a["name_offset"]
        name_gbk = a["name"].encode("gbk")
        name_end = off + len(name_gbk)
        chunk = hfd1[name_end:name_end + 32]
        print(f"  名称 @{off}, 结束 @{name_end}")
        print(f"  名称后48B: {chunk.hex(' ')}")
        print(f"  逐4B THS float:")
        for j in range(0, min(len(chunk)-3, 32)):
            val = struct.unpack("<I", chunk[j:j+4])[0]
            try:
                fv = decode_ths_float(val)
                if abs(fv) > 1e-10:
                    cat = "价格" if 0.5 < abs(fv) < 2000 else "涨幅" if 0 < abs(fv) < 50 else "金额" if abs(fv) > 10000 else "其他"
                    print(f"    @{j}: {val:#010x} = {fv:.4f} [{cat}]")
            except:
                pass

    # ── 5. 检查 0x07 解码（mac 版类似 _read_varlen_field） ──
    print(f"\n=== 检查数值区 07 标记（去重/零值标记）===")
    # 在数值区中统计 07 出现的频率和上下文
    for a in good[:5]:
        off = a["name_offset"]
        name_gbk = a["name"].encode("gbk")
        name_end = off + len(name_gbk)
        chunk = hfd1[name_end:name_end + 48]
        print(f"\n  {a['code']} {a['name']} 数值区:")
        # 标记所有 07 位置
        for i, b in enumerate(chunk):
            if b == 0x07:
                ctx = chunk[max(0,i-2):min(len(chunk),i+6)]
                print(f"    07@{i}: ctx={ctx.hex(' ')}")
        # 尝试用 mac 版 _read_varlen_field 逻辑解码
        print(f"  尝试 varlen 解码:")
        pos = 0
        prev_val = None
        field_idx = 0
        while pos < min(len(chunk), 32) and field_idx < 8:
            if pos + 4 > len(chunk):
                break
            b = chunk[pos]
            if b == 0x07 and pos + 3 <= len(chunk) and chunk[pos+1] != 0x00:
                # 07 XX YY de-dup 标记（类似 mac 版 01）
                prev_val = prev_val if prev_val is not None else 0.0
                print(f"    字段{field_idx}: 07标记={chunk[pos:pos+3].hex()}, v={prev_val:.4f}")
                pos += 3
            else:
                val = struct.unpack("<I", chunk[pos:pos+4])[0]
                try:
                    fv = decode_ths_float(val)
                    prev_val = fv
                    cat = "价格" if field_idx == 0 else f"字段{field_idx}"
                    print(f"    字段{field_idx}: {val:#010x} = {fv:.4f}")
                    pos += 4
                except:
                    pos += 1
            field_idx += 1


if __name__ == "__main__":
    sys.exit(main())
