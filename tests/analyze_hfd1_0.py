#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
hfd1.0 格式离线分析工具（基于 collect_snapshot_oracle.py 采集的对照数据）。

用明文锚点（list_queries 拿的 code+name）对照密文，逆向 hfd1.0 的位压缩格式。

已确认的结构特征（2026-07-23 初步分析）：
  - 记录变长（名称间距 5~290B，含行情字段，非定长）
  - 名称前的最后 1 字节 = 代码末位数字 ASCII（20/21 验证）
  - 名称前有压缩的代码前缀（如 "60000" + 控制字节 0x07）
  - 名称 GBK 字节在密文中明文出现（可作锚点）
  - 名称后跟变长的行情二进制数据（0xff 填充 + THS float）

与 mac 版 id=200 格式的关系（2026-07-23 确认）：
  hfd1.0 与 thspy 的 `_parse_one_record_200`（id=200 基础数据响应，protocol.py:1236）
  共享同一套 LZ 压缩原理：
    - 代码含 LZ 压缩标记（0x01/0x07 等控制字节打断 ASCII 代码）
    - 名称 GBK 变长（mac 版用 UTF-8，PC 版用 GBK）
    - 数值区变长（去重标记 01 XX YY）
  但布局不同：hfd1.0 无 mac 版的 fe0100 锚点和 05800000 尾标记，
  控制字节也不同（hfd1.0 用 0x07，mac 用 0x01）。
  → 复用 mac 版 _read_varlen_field 的去重标记思路，但需重新定位字段边界。

用法：
    py tests/analyze_hfd1_0.py                  # 汇总分析
    py tests/analyze_hfd1_0.py --record 600000  # 单条记录详细 dump
    py tests/analyze_hfd1_0.py --verbose        # 所有锚点详情
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
HFD1_PATH = os.path.join(DATA_DIR, "hfd1_0_response.bin")
ORACLE_PATH = os.path.join(DATA_DIR, "oracle_code_names.json")
ANCHORS_PATH = os.path.join(DATA_DIR, "hfd1_0_name_anchors.json")


def load_data():
    with open(HFD1_PATH, "rb") as f:
        hfd1 = f.read()
    with open(ORACLE_PATH, encoding="utf-8") as f:
        oracle = json.load(f)
    with open(ANCHORS_PATH, encoding="utf-8") as f:
        anchors = json.load(f)
    return hfd1, oracle, anchors


def analyze_header(hfd1: bytes) -> None:
    """分析 hfd1.0 头部。"""
    pos = hfd1.find(b"hfd1.0")
    print(f"=== hfd1.0 头部分析 ===")
    print(f"hfd1.0 标记 @ {pos}, 总数据 {len(hfd1):,}B")
    base = pos + 6
    print(f"头部 16B: {hfd1[base:base+16].hex(' ')}")
    # 头部含 ServerCost 文本
    sc = hfd1.find(b"ServerCost")
    if sc >= 0:
        print(f"ServerCost 文本 @ {sc}: {hfd1[sc:sc+20].decode('gbk',errors='replace')!r}")


def analyze_anchors(hfd1: bytes, oracle: list, anchors: list, verbose: bool) -> None:
    """分析锚点：代码压缩模式 + 记录长度。"""
    print(f"\n=== 锚点分析（{len(anchors)}/{len(oracle)} 命中）===")

    # 1. 验证：pre[-1] = 代码末位 ASCII
    hit = sum(1 for a in anchors
              if bytes.fromhex(a["pre_hex"])[-1] == ord(a["code"][-1]))
    print(f"· 名称前最后 1 字节 == 代码末位 ASCII: {hit}/{len(anchors)}")

    # 2. 记录长度分布
    anchors.sort(key=lambda a: a["name_offset"])
    gaps = []
    for i in range(len(anchors) - 1):
        n1 = len(bytes.fromhex(next(
            o["name_gbk_hex"] for o in oracle if o["code"] == anchors[i]["code"])))
        gap = anchors[i + 1]["name_offset"] - anchors[i]["name_offset"]
        gaps.append(gap)
    if gaps:
        print(f"· 相邻记录名称间距: min={min(gaps)} max={max(gaps)} avg={sum(gaps)//len(gaps)}")

    # 3. 代码压缩前缀分析
    print(f"\n· 代码压缩模式（名称前的字节 vs 真实代码）:")
    print(f"  {'code':8s} pre末6B          末位匹配  ASCII前缀")
    print("  " + "-" * 56)
    for a in anchors[:20] if not verbose else anchors:
        pre = bytes.fromhex(a["pre_hex"])
        code = a["code"]
        last_match = "✓" if pre[-1] == ord(code[-1]) else "✗"
        # 找 code 在 pre 里的最长 ASCII 前缀
        found = ""
        for L in range(5, 0, -1):
            if code[:L].encode() in pre:
                found = code[:L]
                break
        print(f"  {code:8s} {pre[-6:].hex():16s} {last_match:8s} {found!r}")


def dump_record(hfd1: bytes, oracle: list, anchors: list, code: str) -> None:
    """单条记录详细 dump。"""
    a = next((x for x in anchors if x["code"] == code), None)
    if a is None:
        print(f"✗ {code} 不在锚点中")
        return
    item = next(o for o in oracle if o["code"] == code)
    name_gbk = bytes.fromhex(item["name_gbk_hex"])
    off = a["name_offset"]
    print(f"=== {code} {item['name']} ===")
    print(f"名称 @ offset {off}, GBK {len(name_gbk)}B")
    # 名称前 30B（记录头 + 压缩代码）
    pre = hfd1[max(0, off - 30):off]
    print(f"\n名称前 30B（记录头+代码）: {pre.hex(' ')}")
    print(f"  ASCII 可读: {pre.decode('ascii', errors='replace')!r}")
    # 名称本身
    print(f"\n名称 {len(name_gbk)}B: {name_gbk.hex(' ')} = {item['name']}")
    # 名称后 40B（行情数据）
    post = hfd1[off + len(name_gbk):off + len(name_gbk) + 40]
    print(f"\n名称后 40B（行情数据）: {post.hex(' ')}")


def main():
    verbose = "--verbose" in sys.argv
    record_code = None
    for i, a in enumerate(sys.argv):
        if a == "--record" and i + 1 < len(sys.argv):
            record_code = sys.argv[i + 1]

    if not os.path.exists(HFD1_PATH):
        print(f"✗ 缺少采集数据，请先运行: py tests/collect_snapshot_oracle.py")
        return 1

    hfd1, oracle, anchors = load_data()
    analyze_header(hfd1)
    if record_code:
        dump_record(hfd1, oracle, anchors, record_code)
    else:
        analyze_anchors(hfd1, oracle, anchors, verbose)
    return 0


if __name__ == "__main__":
    sys.exit(main())
