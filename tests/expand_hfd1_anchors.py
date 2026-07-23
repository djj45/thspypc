#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
扩采 hfd1.0 锚点 v2 —— 用 hexin 本地缓存全量名称匹配，无需网络查询。

已有 hfd1_0_response.bin（326KB, ~7000+ 条全市场记录）。
直接在同花顺本地 ~60K 名称中找出现在 hfd1.0 里的股票，用 GBK 名称字节
在密文中定位锚点。速度极快，无网络依赖。
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from thspypc import THSClient

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
HFD1_PATH = os.path.join(DATA_DIR, "hfd1_0_response.bin")
ANCHORS_PATH = os.path.join(DATA_DIR, "hfd1_0_name_anchors.json")
ORACLE_PATH = os.path.join(DATA_DIR, "oracle_code_names.json")


def load_hexin_all_names() -> dict[str, str]:
    """加载同花顺全部本地名称缓存，返回 {code: name}。"""
    base = r"C:\同花顺软件\同花顺\stockname"
    if not os.path.isdir(base):
        # 备选路径
        alt = r"c:\同花顺软件\同花顺\stockname"
        if os.path.isdir(alt):
            base = alt
        else:
            print(f"✗ 找不到 stockname 目录: {base}")
            return {}
    all_names: dict[str, str] = {}
    for fn in sorted(os.listdir(base)):
        if fn.startswith("stockname_") and fn.endswith("_0.txt"):
            fp = os.path.join(base, fn)
            try:
                data = open(fp, "rb").read()
                # 跳过 BOM
                if data[:3] == b"\xef\xbb\xbf":
                    data = data[3:]
                text = data.decode("gbk", errors="replace")
                for line in text.splitlines():
                    line = line.strip()
                    if not line or "=" not in line:
                        continue
                    code, rest = line.split("=", 1)
                    name = rest.split("|")[0].strip()
                    if code and name:
                        all_names[code] = name
            except Exception as e:
                print(f"  跳过 {fn}: {e}")
    return all_names


def name_to_gbk(name: str) -> bytes:
    """名称 → GBK 字节。"""
    try:
        return name.encode("gbk")
    except UnicodeEncodeError:
        return name.encode("gbk", errors="replace")


def find_all_anchors(hfd1: bytes, all_names: dict[str, str]) -> tuple[list[dict], list[dict]]:
    """在 hfd1.0 密文中搜索所有名称的 GBK 位置。

    Returns:
        (anchors, oracle) — 锚点列表和对应的 oracle 条目
    """
    anchors = []
    oracle = []
    seen_codes = set()
    skipped_short = 0
    skipped_common = 0

    # 过滤：只找代码以数字/字母开头的正常股票
    for code, name in sorted(all_names.items()):
        if code in seen_codes:
            continue
        # 过滤非股票代码
        if not code[:1].isalnum():
            continue
        # 短名称（1个中文字=2GBK字节）可能误匹配太多
        name_gbk = name_to_gbk(name)
        if len(name_gbk) < 4:
            skipped_short += 1
            continue

        idx = hfd1.find(name_gbk)
        if idx >= 0:
            # 前 15B 上下文
            pre = hfd1[max(0, idx - 15):idx]
            post = hfd1[idx:idx + len(name_gbk) + 8]
            anchors.append({
                "code": code,
                "name": name,
                "name_offset": idx,
                "pre_hex": pre.hex(),
                "post_hex": post.hex(),
                "pre_text": pre.decode("ascii", errors="replace"),
            })
            oracle.append({
                "code": code,
                "name": name,
                "name_gbk_hex": name_gbk.hex(),
            })
            seen_codes.add(code)

    print(f"  跳过短名称(<2字): {skipped_short}")
    return anchors, oracle


def analyze_code_compression(anchors: list[dict]) -> None:
    """分析代码压缩模式。"""
    print(f"\n{'='*70}")
    print("【代码压缩模式分析】")
    print(f"{'='*70}")

    # 1. pre[-1] 验证
    hit = sum(1 for a in anchors
              if bytes.fromhex(a["pre_hex"])[-1] == ord(a["code"][-1]))
    print(f"\n■ 名称前末位 == 代码末位 ASCII: {hit}/{len(anchors)} ({hit*100//max(len(anchors),1)}%)")

    # 2. 记录间距
    gaps = []
    for i in range(len(anchors) - 1):
        gap = anchors[i + 1]["name_offset"] - anchors[i]["name_offset"]
        gaps.append(gap)
    if gaps:
        sorted_gaps = sorted(gaps)
        print(f"■ 记录间距: min={min(gaps)} max={max(gaps)} "
              f"avg={sum(gaps)//len(gaps)} median={sorted_gaps[len(gaps)//2]}")

    # 3. 代码前缀分布
    prefixes = {}
    for a in anchors:
        p = a["code"][:3]
        prefixes[p] = prefixes.get(p, 0) + 1
    print(f"■ 代码前缀分布: {dict(sorted(prefixes.items()))}")

    # 4. 控制字节分析（pre 中 < 0x20 的字节）
    ctrl_stats: dict[int, int] = {}
    for a in anchors:
        pre = bytes.fromhex(a["pre_hex"])
        for b in pre:
            if b < 0x20:
                ctrl_stats[b] = ctrl_stats.get(b, 0) + 1
    print(f"■ 控制字节频率: {dict(sorted(ctrl_stats.items(), key=lambda x:-x[1])[:15])}")

    # 5. 详细表格（前 40 条 + 代码前缀完整样本）
    print(f"\n{'='*70}")
    print("详细锚点对照（按 offset 排序）")
    print(f"{'='*70}")
    print(f"{'offset':>6} {'code':>8} {'名称':8s} {'pre[-1]':>6} {'match':4s}  pre_hex")
    print("-" * 90)
    for a in sorted(anchors, key=lambda x: x["name_offset"])[:40]:
        pre = bytes.fromhex(a["pre_hex"])
        last = pre[-1]
        m = "✓" if last == ord(a["code"][-1]) else "✗"
        print(f"{a['name_offset']:>6} {a['code']:>8} {a['name']:8s} "
              f"{hex(last):>6} {m:4s} {pre.hex()[:50]}")


def main():
    if not os.path.exists(HFD1_PATH):
        print(f"✗ 缺少 {HFD1_PATH}")
        return 1

    print("=" * 60)
    print("hfd1.0 锚点扩采 v2（本地缓存匹配，零网络依赖）")
    print("=" * 60)

    # 1. 加载 hfd1.0 密文
    hfd1 = open(HFD1_PATH, "rb").read()
    print(f"\n[1/3] 加载 hfd1.0 密文: {len(hfd1):,}B @ {hfd1.find(b'hfd1.0')}")

    # 2. 加载全部名称
    print(f"\n[2/3] 加载 hexin 本地缓存名称...")
    all_names = load_hexin_all_names()
    print(f"  加载 {len(all_names)} 条名称")

    # 3. 匹配锚点
    print(f"\n[3/3] 在 hfd1.0 密文中搜索名称...")
    anchors, oracle = find_all_anchors(hfd1, all_names)
    print(f"  命中 {len(anchors)} 个锚点 / {len(all_names)} 总名称 "
          f"({len(anchors)*100//max(len(all_names),1)}%)")

    # 去重&排序
    seen_offsets = set()
    anchors_dedup = []
    for a in sorted(anchors, key=lambda x: x["name_offset"]):
        if a["name_offset"] not in seen_offsets:
            seen_offsets.add(a["name_offset"])
            anchors_dedup.append(a)
    anchors = anchors_dedup
    print(f"  去重后: {len(anchors)} 个唯一锚点")

    # 4. 存盘
    with open(ANCHORS_PATH, "w", encoding="utf-8") as f:
        json.dump(anchors, f, ensure_ascii=False, indent=2)
    with open(ORACLE_PATH, "w", encoding="utf-8") as f:
        json.dump(oracle, f, ensure_ascii=False, indent=2)
    print(f"\n  已存盘:")
    print(f"    {ORACLE_PATH}  ({len(oracle)} 条 oracle)")
    print(f"    {ANCHORS_PATH} ({len(anchors)} 个锚点)")

    # 5. 分析
    analyze_code_compression(anchors)

    return 0


if __name__ == "__main__":
    sys.exit(main())
