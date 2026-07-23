#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
hfd1.0 代码压缩模式深度分析。

用 1409 个锚点（名称在密文中的位置）研究代码的压缩编码规律。
特别关注 0x07 控制字节的含义。

分析思路：
1. 对每个锚点，截取从"上一个名称结束"到"当前名称开始"的完整记录区间
2. 对比同前缀组的编码模式（如 600xxx 组 vs 603xxx 组）
3. 归纳 0x07 后的字节含义（回退偏移？长度？）
"""
from __future__ import annotations

import json
import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
HFD1_PATH = os.path.join(DATA_DIR, "hfd1_0_response.bin")
ANCHORS_PATH = os.path.join(DATA_DIR, "hfd1_0_name_anchors.json")


def load_data():
    hfd1 = open(HFD1_PATH, "rb").read()
    anchors = json.load(open(ANCHORS_PATH, encoding="utf-8"))
    return hfd1, anchors


def filter_anchors(anchors: list[dict]) -> list[dict]:
    """过滤误匹配（子串匹配、非 A 股代码等），只保留可靠锚点。

    过滤规则：
    - 名称前末位 != 代码末位 ASCII → 疑似误匹配（85% 准确率）
    - 代码以字母开头且非市场指数 → 外盘/期货名称，暂不关注
    - 间距 < 10 → 短名称子串误匹配（如"银行"在"浦发银行"中的二次命中）
    """
    filtered = []
    for a in anchors:
        pre = bytes.fromhex(a["pre_hex"])
        # 规则 1：末位匹配（主要筛选条件）
        if pre[-1] != ord(a["code"][-1]):
            continue
        # 规则 2：过滤非数字开头的代码（保留市场指数 1A/1B）
        code = a["code"]
        if not code[0].isdigit():
            continue
        filtered.append(a)
    return filtered


def get_record_boundaries(anchors: list[dict], hfd1: bytes) -> list[dict]:
    """确定每条记录的精确边界。

    对每个锚点，找到：
    - rec_start: 记录开始（前一条记录的名称结束之后的下一个字节）
    - name_start: 名称开始（已知）
    - name_end: 名称结束（已知 = name_start + len(名称GBK)）
    - rec_end: 记录结束（下一条记录的 name_start - 1）
    
    还标记那些可能是假阳性（间距异常小）的记录。
    """
    sorted_anchors = sorted(anchors, key=lambda a: a["name_offset"])
    
    # 构建 name -> gbk_len 映射
    name_len_map = {}
    for a in sorted_anchors:
        name = a["name"]
        if name not in name_len_map:
            name_len_map[name] = len(name.encode("gbk"))
    
    records = []
    for i, a in enumerate(sorted_anchors):
        name_gbk_len = name_len_map.get(a["name"], len(a["name"].encode("gbk")))
        name_start = a["name_offset"]
        name_end = name_start + name_gbk_len
        
        if i == 0:
            # 第一条记录从 hfd1.0 头之后开始
            hdr_end = hfd1.find(b"hfd1.0") + 6 + 16
            rec_start = hdr_end
        else:
            prev = sorted_anchors[i - 1]
            prev_name_len = name_len_map.get(prev["name"], len(prev["name"].encode("gbk")))
            prev_name_end = prev["name_offset"] + prev_name_len
            # 上一个名称结束到当前名称开始之间 = 上一个的数值区 + 当前的代码区
            rec_start = prev_name_end
        
        if i + 1 < len(sorted_anchors):
            next_name_start = sorted_anchors[i + 1]["name_offset"]
            rec_end = next_name_start - 1
        else:
            rec_end = len(hfd1) - 1
        
        records.append({
            "code": a["code"],
            "name": a["name"],
            "name_start": name_start,
            "name_end": name_end,
            "rec_start": rec_start,
            "rec_end": rec_end,
            "code_region": hfd1[rec_start:name_start],  # 从记录开始到名称 = 代码区
            "name_data": hfd1[name_start:name_end],
            "num_region": hfd1[name_end:rec_end + 1] if rec_end >= name_end else b"",
            "gap_prev": name_start - rec_start,  # 代码区大小
        })
    
    return records


def analyze_code_07_pattern(records: list[dict]) -> None:
    """分析 0x07 控制字节模式。"""
    print("\n" + "=" * 70)
    print("【0x07 控制字节分析】")
    print("=" * 70)
    
    # 按代码前缀分组
    by_prefix = defaultdict(list)
    for r in records:
        by_prefix[r["code"][:3]].append(r)
    
    for prefix in ["600", "601", "603", "688", "000", "002", "300", "870", "920"]:
        group = by_prefix.get(prefix, [])
        if not group:
            continue
        print(f"\n--- {prefix}xxx 组 ({len(group)} 条) ---")
        
        # 分析 0x07 位置
        for r in group[:8]:
            cr = r["code_region"]
            code = r["code"]
            # 找 cr 中的 0x07
            ctrl_positions = [i for i, b in enumerate(cr) if b == 0x07]
            # 找 cr 中的 ASCII 数字
            digits_in_cr = bytes([b for b in cr if 0x30 <= b <= 0x39])
            
            # 显示
            cr_preview = cr.hex(" ") if len(cr) <= 40 else cr[:40].hex(" ") + "..."
            print(f"  {code} ({r['name']}) code_region({len(cr)}B): {cr_preview}")
            if ctrl_positions:
                print(f"    0x07 @ {ctrl_positions}")
            if digits_in_cr:
                digits_str = digits_in_cr.decode("ascii")
                print(f"    ASCII digits: {digits_str!r}")
            # 检查代码是否部分出现在 code_region 中
            for start in range(len(code)):
                for end in range(start + 1, len(code) + 1):
                    sub = code[start:end]
                    if sub.encode() in cr:
                        pass  # 匹配太多，精简输出
            # 显示 07 后的上下文
            for pos in ctrl_positions:
                ctx = cr[pos:pos + 8]
                print(f"    07@{pos} context: {ctx.hex(' ')}")
                # 最后几个字节 = 末位数字?
                print(f"    07@{pos} after_07: {ctx[1:].hex(' ')}")


def analyze_backreference(records: list[dict]) -> None:
    """分析代码前缀的回退复制（back-reference）模式。

    核心假设：
    - 0x07 之后跟的是"回退偏移+长度"编码
    - 或者 0x07 之前的某个标记指定了复制源
    """
    print("\n" + "=" * 70)
    print("【回退复制（Back-reference）分析】")
    print("=" * 70)
    
    # 对每个前缀组，比较 code_region 的相似性
    by_prefix = defaultdict(list)
    for r in records:
        by_prefix[r["code"][:3]].append(r)
    
    for prefix in ["600", "603", "688"]:
        group = by_prefix.get(prefix, [])
        if len(group) < 3:
            continue
        print(f"\n--- {prefix}xxx 组 ({len(group)} 条) ---")
        
        # 找每个记录的代码区中与真实代码匹配的部分
        for r in group[:10]:
            cr = r["code_region"]
            code = r["code"]
            # 在 cr 中找连续的数字子串匹配
            matches = []
            i = 0
            while i < len(cr):
                if 0x30 <= cr[i] <= 0x39:
                    j = i
                    while j < len(cr) and 0x30 <= cr[j] <= 0x39:
                        j += 1
                    digit_str = cr[i:j].decode("ascii")
                    # 检查是否匹配 code 的某个子串
                    if digit_str in code and len(digit_str) >= 2:
                        matches.append((i, digit_str, code.index(digit_str)))
                    i = j
                else:
                    i += 1
            
            # 显示匹配结果
            if matches:
                print(f"  {code}: 数字子串={[(m[0], m[1], f'@code[{m[2]}:{m[2]+len(m[1])}]') for m in matches]}")
            else:
                print(f"  {code}: 代码区中无 ≥2 位数字子串")
                # 显示完整代码区
                print(f"    cr({len(cr)}B): {cr.hex(' ')[:80]}")
                # 检查每个字节是否为可打印 ASCII
                ascii_part = "".join(chr(b) if 0x20 <= b < 0x80 else "." for b in cr)
                print(f"    ascii: {ascii_part[:40]}")


def analyze_last_digit_position(records: list[dict]) -> None:
    """分析代码末位数字在 code_region 中的位置。"""
    print("\n" + "=" * 70)
    print("【代码末位数字定位分析】")
    print("=" * 70)
    
    # 对于每条记录，末位数字应该出现在 code_region 末尾
    for r in records[:20]:
        cr = r["code_region"]
        code = r["code"]
        last_digit = code[-1]
        last_digit_byte = ord(last_digit)
        
        # 末位在 cr 中的位置
        if last_digit_byte in cr:
            pos = cr.rfind(last_digit_byte)
            dist_from_end = len(cr) - pos - 1
            print(f"  {code}: 末位'{last_digit}'@{pos}(距尾{dist_from_end}), "
                  f"cr尾: {cr[-5:].hex(' ')}")
        else:
            print(f"  {code}: 末位'{last_digit}'不在代码区!")


def analyze_record_layout(records: list[dict]) -> None:
    """分析记录整体布局。"""
    print("\n" + "=" * 70)
    print("【记录布局分析】")
    print("=" * 70)
    
    # 统计数值区大小
    num_sizes = [len(r["num_region"]) for r in records]
    if num_sizes:
        print(f"  数值区大小: min={min(num_sizes)} max={max(num_sizes)} "
              f"avg={sum(num_sizes)//len(num_sizes)}")
        # 分桶
        from collections import Counter
        buckets = Counter(s // 10 * 10 for s in num_sizes)
        print(f"  分布(每10B): {dict(sorted(buckets.items()))}")
    
    # 代码区大小
    code_sizes = [len(r["code_region"]) for r in records]
    if code_sizes:
        print(f"  代码区大小: min={min(code_sizes)} max={max(code_sizes)} "
              f"avg={sum(code_sizes)//len(code_sizes)}")


def main():
    hfd1, anchors = load_data()
    print(f"加载 {len(anchors)} 个原始锚点")
    
    # 过滤
    anchors = filter_anchors(anchors)
    print(f"过滤后 {len(anchors)} 个可靠锚点")
    
    # 获取记录边界
    records = get_record_boundaries(anchors, hfd1)
    print(f"构建 {len(records)} 条记录区间")
    
    # 各角度分析
    analyze_record_layout(records)
    analyze_code_07_pattern(records)
    analyze_backreference(records)
    analyze_last_digit_position(records)
    
    # 详细输出前 20 条
    print("\n" + "=" * 70)
    print("【前 20 条记录详情】")
    print("=" * 70)
    for r in records[:20]:
        cr = r["code_region"]
        cr_show = cr.hex(" ") if len(cr) <= 30 else cr[:30].hex(" ") + "..."
        nr_show = r["num_region"][:20].hex(" ") if r["num_region"] else "(空)"
        print(f"\n{r['code']:>8s} {r['name']}")
        print(f"  代码区({len(cr)}B): {cr_show}")
        print(f"  名称({len(r['name_data'])}B): {r['name_data'].hex(' ')} = {r['name']}")
        print(f"  数值区({len(r['num_region'])}B): {nr_show}...")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
