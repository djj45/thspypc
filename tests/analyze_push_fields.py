#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
推送帧数值字段逆向分析工具（v2，基于完整帧）。

用法：
  py tests/analyze_push_fields.py                    # 分析 data/matched.csv（需 push_frame_hex 列）
  py tests/analyze_push_fields.py --verbose          # 逐条详细输出
  py tests/analyze_push_fields.py --offset-stats     # 统计涨幅/金额字段相对异动字节的偏移

核心思路（2026-07-22 确认）：
  1. 推送帧 = hq1.0 头(88B) + 记录区
  2. 记录区 = marker(0x11/0x21) + 6位ASCII代码 + 多条异动子记录
  3. 一个帧可含多个代码，每个代码含多条异动
  4. 数值字段（涨幅等）用标准 THS float 编码（LE32，a0/a8 高字节标记）
  5. 异动字节（d6/d7/66/67/bc...）在记录区可定位，用作锚点

前置条件：matched.csv 必须含 push_frame_hex 列（完整帧 hex）。
用 collect_push_samples.py（已修复）采集的 matched.csv 自动带此列。

⚠️ 时间窗口：推送帧的数值是瞬时值，必须和 hist 在同一时刻才能匹配。
   matched.csv 的 time_diff_s 越小越可靠（建议 < 3s）。
"""
import argparse
import csv
import json
import os
import struct
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from thspypc.protocol import decode_ths_float

DATA_DIR = r"D:\code\ths_takehome\thspypc\data"

# 异动字节 → 名称（来自 SUMMARY 30 种映射）
ANOMALY_NAMES = {
    0xbc: "特大主动买", 0xbd: "特大被动买", 0xbe: "特大主动卖", 0xbf: "特大被动卖",
    0xd6: "大笔买入", 0xd7: "大笔卖出", 0x66: "特大挂买", 0x67: "特大挂卖",
    0xa2: "拖拉机挂买", 0xa3: "拖拉机挂卖", 0xa4: "远价位垫单", 0xa5: "远价位压单",
    0x6c: "撤特大买", 0x6d: "撤涨停买", 0x6e: "撤特大卖", 0x6f: "撤跌停卖",
    0xd1: "区间放量涨", 0xd2: "区间放量跌", 0xdc: "急速拉升", 0xdd: "猛烈打压",
    0xd8: "涨停封板", 0xda: "跌停封板", 0xd9: "打开涨停板", 0xdb: "打开跌停板",
    0xe0: "逼近涨停", 0xe1: "逼近跌停", 0xe2: "涨停大减", 0xe3: "跌停大减",
    0xe4: "强势封涨停", 0xee: "强势封跌停",
}

# 有金额字段的异动类型（SUMMARY 标注"有"金额）
HAS_AMOUNT = {0xbc, 0xbd, 0xbe, 0xbf, 0xd6, 0xd7, 0x66, 0x67, 0xa2, 0xa3,
              0xa4, 0xa5, 0x6c, 0x6d, 0x6e, 0x6f, 0xe2, 0xe3, 0xe4, 0xee}


def encode_ths_float(val: float) -> int | None:
    """将浮点数编码为 THS LE32（decode_ths_float 的逆函数，修复浮点精度）。"""
    sign = 1 if val >= 0 else -1
    av = abs(val)
    for divide in (False, True):
        for exp in range(8):
            factor = [1.0, 10.0, 100.0, 1000.0, 10000.0, 100000.0, 1000000.0, 10000000.0][exp]
            mant = av * factor if divide else av / factor
            mant_r = round(mant)
            if abs(mant - mant_r) < 0.01 and 0 <= mant_r < 0x08000000:
                le32 = ((1 << 31) if divide else 0) | (exp << 28) | \
                       ((1 << 27) if sign < 0 else 0) | mant_r
                if abs(decode_ths_float(le32) - val) < 0.01:
                    return le32
    return None


def find_anomaly_bytes(raw: bytes, code: str, type_byte: int) -> list[int]:
    """在代码 type_byte 出现的位置列表（相对 raw 起点的 offset）。"""
    code_b = code.encode("ascii")
    cp = raw.find(code_b)
    positions = []
    while cp >= 0:
        # 在代码后 500 字节内找 type_byte
        for i in range(cp, min(cp + 500, len(raw))):
            if raw[i] == type_byte:
                positions.append(i)
        cp = raw.find(code_b, cp + 1)
    return positions


def analyze_sample(row: dict, verbose: bool = False) -> dict:
    """分析一条 matched 样本：在完整帧里定位异动字节，验证涨幅/金额。"""
    code = row["code"]
    type_byte = int(row["hist_code_byte"], 16)
    amt = float(row["hist_amount"]) if row["hist_amount"] else 0.0
    chg = float(row["hist_change"]) if row["hist_change"] else 0.0
    frame_hex = row.get("push_frame_hex", "")

    result = {
        "code": code, "type_byte": type_byte, "amount": amt, "change": chg,
        "time_diff": float(row.get("time_diff_s", 999)),
        "has_frame": bool(frame_hex),
        "anomaly_positions": [],
        "amount_found": False, "change_found": False,
        "amount_offset": None, "change_offset": None,
    }

    if not frame_hex:
        return result

    raw = bytes.fromhex(frame_hex)

    # 定位异动字节
    anom_positions = find_anomaly_bytes(raw, code, type_byte)
    result["anomaly_positions"] = anom_positions

    # 在完整帧里搜索金额（THS float）
    amt_enc = encode_ths_float(amt)
    if amt_enc:
        amt_bytes = struct.pack("<I", amt_enc)
        pos = raw.find(amt_bytes)
        if pos >= 0:
            result["amount_found"] = True
            result["amount_offset"] = pos

    # 在完整帧里搜索涨幅（THS float）
    chg_enc = encode_ths_float(chg)
    if chg_enc:
        chg_bytes = struct.pack("<I", chg_enc)
        pos = raw.find(chg_bytes)
        if pos >= 0:
            result["change_found"] = True
            result["change_offset"] = pos

    if verbose:
        type_name = ANOMALY_NAMES.get(type_byte, f"未知0x{type_byte:02x}")
        print(f"\n=== {code} {type_name} amt={amt:.0f} chg={chg} "
              f"Δt={result['time_diff']:.1f}s ===")
        print(f"  异动字节 @raw positions: {anom_positions}")
        if result["amount_found"]:
            print(f"  金额 THS bytes @raw[{result['amount_offset']}]")
        else:
            print(f"  金额 未找到（可能时间错位或非 THS float）")
        if result["change_found"]:
            print(f"  涨幅 THS bytes @raw[{result['change_offset']}]")
            # 显示涨幅相对最近异动字节的偏移
            if anom_positions:
                nearest = min(anom_positions, key=lambda p: abs(p - result["change_offset"]))
                print(f"    相对异动字节@{nearest} 的偏移: {result['change_offset'] - nearest}")
        else:
            print(f"  涨幅 未找到（可能时间错位）")

    return result


def offset_stats(samples: list[dict]) -> None:
    """统计涨幅/金额字段相对异动字节的偏移分布。"""
    print("\n" + "=" * 60)
    print("字段偏移统计（相对异动字节）")
    print("=" * 60)

    # 只用时间差小（可靠）的样本
    reliable = [s for s in samples if s["has_frame"] and s["time_diff"] < 5]
    print(f"可靠样本（Δt<5s 且有完整帧）: {len(reliable)}")

    # 涨幅命中样本：统计涨幅字节相对异动字节的偏移
    chg_hits = [s for s in reliable if s["change_found"] and s["anomaly_positions"]]
    print(f"\n涨幅命中: {len(chg_hits)}")
    if chg_hits:
        offsets = []
        for s in chg_hits:
            nearest_anom = min(s["anomaly_positions"],
                               key=lambda p: abs(p - s["change_offset"]))
            offsets.append(s["change_offset"] - nearest_anom)
        c = Counter(offsets)
        print("  涨幅相对异动字节偏移分布（offset: count）:")
        for off, cnt in c.most_common(10):
            print(f"    +{off}: {cnt}")

    # 金额命中样本
    amt_hits = [s for s in reliable if s["amount_found"] and s["anomaly_positions"]]
    print(f"\n金额命中: {len(amt_hits)}")
    if amt_hits:
        offsets = []
        for s in amt_hits:
            nearest_anom = min(s["anomaly_positions"],
                               key=lambda p: abs(p - s["amount_offset"]))
            offsets.append(s["amount_offset"] - nearest_anom)
        c = Counter(offsets)
        print("  金额相对异动字节偏移分布（offset: count）:")
        for off, cnt in c.most_common(10):
            print(f"    +{off}: {cnt}")


def main():
    ap = argparse.ArgumentParser(description="推送帧数值字段逆向分析（v2，基于完整帧）")
    ap.add_argument("--verbose", "-v", action="store_true", help="逐条详细输出")
    ap.add_argument("--offset-stats", action="store_true",
                    help="统计涨幅/金额字段相对异动字节的偏移分布")
    ap.add_argument("--max-diff", type=float, default=999,
                    help="只分析 time_diff_s < 此值的样本（默认全部）")
    ap.add_argument("--input", default=None,
                    help="matched CSV 路径（默认 data/matched.csv）")
    args = ap.parse_args()

    matched_path = args.input or os.path.join(DATA_DIR, "matched.csv")
    if not os.path.exists(matched_path):
        print(f"✗ 未找到 {matched_path}，请先用 collect_push_samples.py 采集")
        return 1

    rows = []
    with open(matched_path, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            rows.append(row)

    has_frame_col = "push_frame_hex" in (rows[0].keys() if rows else [])
    if not has_frame_col:
        print("⚠️ matched.csv 无 push_frame_hex 列（旧格式）。")
        print("   请用修复后的 collect_push_samples.py 重新采集。")

    print(f"样本总数: {len(rows)}")
    print(f"含完整帧: {sum(1 for r in rows if r.get('push_frame_hex'))}")

    samples = []
    for row in rows:
        if float(row.get("time_diff_s", 999)) >= args.max_diff:
            continue
        s = analyze_sample(row, verbose=args.verbose)
        samples.append(s)

    # 汇总
    print("\n" + "=" * 60)
    print("分析汇总")
    print("=" * 60)
    with_frame = [s for s in samples if s["has_frame"]]
    amt_with = [s for s in with_frame if s["amount"] > 0]
    print(f"分析样本: {len(samples)}（含完整帧 {len(with_frame)}）")
    print(f"金额命中率: {sum(1 for s in amt_with if s['amount_found'])}/{len(amt_with)}"
          f" ({100 * sum(1 for s in amt_with if s['amount_found']) / max(len(amt_with),1):.0f}%)")
    print(f"涨幅命中率: {sum(1 for s in with_frame if s['change_found'])}/{len(with_frame)}"
          f" ({100 * sum(1 for s in with_frame if s['change_found']) / max(len(with_frame),1):.0f}%)")
    print(f"异动字节定位率: {sum(1 for s in with_frame if s['anomaly_positions'])}/{len(with_frame)}"
          f" ({100 * sum(1 for s in with_frame if s['anomaly_positions']) / max(len(with_frame),1):.0f}%)")

    if args.offset_stats or args.verbose:
        offset_stats(samples)

    # 输出按异动类型分组的命中率（定位哪种类型的字段最可靠）
    print("\n按异动类型分组（含完整帧样本）:")
    by_type = defaultdict(lambda: {"total": 0, "amt_found": 0, "chg_found": 0})
    for s in with_frame:
        name = ANOMALY_NAMES.get(s["type_byte"], f"0x{s['type_byte']:02x}")
        by_type[name]["total"] += 1
        if s["amount_found"] and s["amount"] > 0:
            by_type[name]["amt_found"] += 1
        if s["change_found"]:
            by_type[name]["chg_found"] += 1
    for name, stats in sorted(by_type.items(), key=lambda x: -x[1]["total"]):
        print(f"  {name:12}: {stats['total']:3d} 样本, "
              f"金额 {stats['amt_found']}/{stats['total']}, "
              f"涨幅 {stats['chg_found']}/{stats['total']}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
