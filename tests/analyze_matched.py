#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
离线逆向分析：用 matched.csv 的对照样本，破解 pushrealorder 推送帧的数值编码。

前置条件：先盘中跑 collect_push_samples.py 生成 matched.csv（需代码+时间窗口匹配）。
本脚本离线、可重复运行，不需要账号/网络。

思路：
  matched.csv 每行有：历史已知值（金额/涨幅/异动类型）+ 推送 raw_bytes（hex）。
  历史接口已验证字段映射：金额=字段17(LE32 定点数), 涨幅=字段18, 异动字节=字段61。
  推送 raw_bytes 里这些值用未知编码。本脚本用"滑动窗口 + 多解码假设"暴力搜索：
  对每个已知数值 V，在 raw_bytes 里找哪个字节区间 [i:j] 的解码值 D 满足
  V == D 或 V == D × 某固定缩放因子（因子对所有样本一致）。

  若某 (offset, width, encoding, scale) 对所有样本都成立 → 找到字段映射。

解码假设（每种都试 LE/BE）：
  - u8/u16/u24/u32 整数
  - varint（protobuf 风格）
  - THS 定点数（decode_ths_float）

用法：
  py tests/analyze_matched.py            # 读 data/matched.csv
  py tests/analyze_matched.py --verbose  # 打印每个候选字段的详细对照
"""
from __future__ import annotations

import csv
import os
import struct
import sys
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
DATA_DIR = r"D:\code\ths_takehome\thspypc\data"

from thspypc.protocol import decode_ths_float


# ── 解码原语 ──


def read_varint(data: bytes, off: int) -> tuple[int, int]:
    """protobuf 风格 varint，返回 (value, end_offset)。越界返回 (0, off)。"""
    val = 0
    shift = 0
    while off < len(data):
        b = data[off]
        off += 1
        val |= (b & 0x7F) << shift
        if not (b & 0x80):
            return val, off
        shift += 7
        if shift > 63:
            break
    return val, off


def decode_candidates(data: bytes, off: int) -> dict[str, float]:
    """对 data[off] 起的所有可能解码方式，返回 {label: value}。"""
    out: dict[str, float] = {}
    n = len(data)
    # varint
    v, end = read_varint(data, off)
    out["varint"] = float(v)
    # 整数 LE/BE，宽度 1~4
    for w in (1, 2, 3, 4):
        if off + w <= n:
            chunk = data[off:off + w]
            out[f"u{w*8}_le"] = float(int.from_bytes(chunk, "little"))
            out[f"u{w*8}_be"] = float(int.from_bytes(chunk, "big"))
    # THS 定点数（4字节 LE32）
    if off + 4 <= n:
        le32 = struct.unpack("<I", data[off:off + 4])[0]
        out["ths_float"] = decode_ths_float(le32)
    return out


def find_field_mapping(samples: list[dict], known_key: str) -> list[dict]:
    """对一个已知数值字段（如 hist_amount），在 raw_bytes 里搜索一致的映射。

    返回候选列表，每项 {offset, encoding, scale, samples_matched}，
    按 samples_matched 降序、scale 方差升序排序。
    """
    # 收集 (raw_bytes, known_value) 对
    pairs = []
    for s in samples:
        val = s.get(known_key)
        raw_hex = s.get("push_raw_bytes", "")
        if val is None or val == "" or not raw_hex:
            continue
        try:
            val_f = float(val)
        except (ValueError, TypeError):
            continue
        if val_f == 0:
            continue  # 0 值无法定位（任何全0字节都匹配）
        pairs.append((bytes.fromhex(raw_hex), val_f))
    if not pairs:
        return []

    # 对第一个样本的所有 (offset, encoding) 候选，检查是否对所有样本一致
    first_raw, _ = pairs[0]
    candidates = []
    max_off = min(len(first_raw), 44)  # raw_bytes 通常 ≤48 字节
    for off in range(max_off):
        decs = decode_candidates(first_raw, off)
        for enc, v0 in decs.items():
            if v0 == 0:
                continue
            _, known0 = pairs[0]
            scale0 = known0 / v0
            if not (1e-6 < abs(scale0) < 1e12):
                continue
            # 验证所有样本
            matched = 0
            scales = []
            for raw, known in pairs:
                decs2 = decode_candidates(raw, off)
                v = decs2.get(enc)
                if v is None or v == 0:
                    continue
                s = known / v
                # scale 允许 ±10% 浮动（异动时间差导致金额微小变化）
                if abs(s - scale0) / abs(scale0) < 0.1:
                    matched += 1
                    scales.append(s)
            if matched >= max(2, len(pairs) // 3):  # 至少 1/3 样本匹配
                avg_scale = sum(scales) / len(scales)
                var = sum((s - avg_scale) ** 2 for s in scales) / len(scales)
                candidates.append({
                    "offset": off, "encoding": enc,
                    "scale": avg_scale, "scale_std": var ** 0.5,
                    "matched": matched, "total": len(pairs),
                })
    # 排序：匹配数降序，标准差升序
    candidates.sort(key=lambda c: (-c["matched"], c["scale_std"]))
    return candidates


def main():
    verbose = "--verbose" in sys.argv
    matched_path = os.path.join(DATA_DIR, "matched.csv")
    if not os.path.exists(matched_path):
        print(f"未找到 {matched_path}，先盘中跑 collect_push_samples.py")
        return 1

    with open(matched_path, encoding="utf-8") as f:
        samples = list(csv.DictReader(f))
    print(f"载入 {len(samples)} 条匹配样本\n")
    if not samples:
        print("matched.csv 为空。必须盘中（9:30-15:00）跑 collect_push_samples.py。")
        return 1

    # 按异动类型分组（不同类型字段布局可能不同）
    by_type: dict[str, list[dict]] = defaultdict(list)
    for s in samples:
        by_type[s.get("hist_type", "")].append(s)

    print("=" * 60)
    print("数值字段逆向分析（按异动类型分组）")
    print("=" * 60)
    for atype, group in sorted(by_type.items(), key=lambda kv: -len(kv[1])):
        print(f"\n【{atype}】{len(group)} 条样本")
        for known_key, label in (("hist_amount", "金额"),
                                  ("hist_change", "涨幅")):
            cands = find_field_mapping(group, known_key)
            if not cands:
                print(f"  {label}: 无一致映射候选（样本不足或编码未覆盖）")
                continue
            print(f"  {label}: 找到 {len(cands)} 个候选（前3）:")
            for c in cands[:3]:
                pct = c["matched"] / c["total"] * 100
                print(f"    offset={c['offset']:>2} enc={c['encoding']:<12} "
                      f"scale={c['scale']:.4f} ±{c['scale_std']:.4f} "
                      f"匹配 {c['matched']}/{c['total']} ({pct:.0f}%)")

    if verbose:
        print("\n" + "=" * 60)
        print("逐样本详细对照（第一条样本的 raw_bytes 解码）")
        print("=" * 60)
        s = samples[0]
        raw = bytes.fromhex(s["push_raw_bytes"])
        print(f"代码 {s['code']} 类型 {s['hist_type']}")
        print(f"历史: 金额={s['hist_amount']} 涨幅={s['hist_change']} "
              f"编码={s['hist_code_byte']}")
        print(f"raw_bytes ({len(raw)} 字节): {s['push_raw_bytes']}")
        print(f"{'off':>3} {'hex':<12} {'解码':<40}")
        for off in range(min(len(raw), 48)):
            hexs = " ".join(f"{b:02x}" for b in raw[off:off+4])
            decs = decode_candidates(raw, off)
            parts = [f"{k}={v:.4g}" for k, v in decs.items()]
            print(f"{off:>3} {hexs:<12} {', '.join(parts)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
