#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
离线逆向分析 v2：用 matched.csv 的对照样本，破解 pushrealorder 推送帧的数值编码。

v2 改进：
  1. 正确解析 Format B/A 记录壳，提取纯 payload + extra
  2. 按 4-byte payload 前缀分组，组内字段布局一致
  3. 扩展编码假设：LEB128 全读取、zigzag、THS 定点变体、0xa0/0xa8 子记录
  4. 对每个前缀组，滑窗搜索 + 跨样本一致性验证

用法：
  py tests/analyze_matched.py              # 基础分析
  py tests/analyze_matched.py --verbose    # 打印每个候选字段的详细对照
  py tests/analyze_matched.py --group 01270901  # 只分析特定前缀组
"""
from __future__ import annotations

import csv
import os
import struct
import sys
from collections import defaultdict
from typing import Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
DATA_DIR = r"D:\code\ths_takehome\thspypc\data"

from thspypc.protocol import decode_ths_float


# ═══════════════════════════════════════════════════════════
# 记录解析：Format B / A → (payload, extra)
# ═══════════════════════════════════════════════════════════

def extract_parts(raw_hex: str) -> tuple[bytes, bytes]:
    """从 raw_bytes 提取纯 payload 和 extra bytes。
    Returns (payload, extra). payload 从格式壳后开始（不含 code 前缀字节）。
    """
    raw = bytes.fromhex(raw_hex)
    if not raw:
        return b"", b""
    if raw[0] == 0x2d:                     # Format B: marker + length + code + payload
        dlen = raw[1]
        data = raw[2:2 + dlen]
        extra = raw[2 + dlen:]
        # 检查是否有市场前缀字节（codes start with '0'-'9', 0x30-0x39）
        if len(data) >= 7 and data[0] not in range(0x30, 0x3A):
            return data[7:], extra         # 有前缀: prefix(1) + code(6)
        else:
            return data[6:], extra         # 无前缀: code(6)
    elif raw[0] == 0x21:                   # Format A: marker + code(6) + payload
        return raw[7:], b""
    return b"", b""


# ═══════════════════════════════════════════════════════════
# 解码原语（扩展版）
# ═══════════════════════════════════════════════════════════

def read_leb128(data: bytes, off: int) -> tuple[int, int]:
    """读取无符号 LEB128 varint，返回 (value, end_offset)。"""
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


def read_leb128_signed(data: bytes, off: int) -> tuple[int, int]:
    """读取有符号 LEB128 varint。"""
    val = 0
    shift = 0
    last_off = off
    while off < len(data):
        b = data[off]
        last_off = off
        off += 1
        val |= (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            # 符号扩展
            if b & 0x40:
                val |= -(1 << shift)
            return val, off
        if shift > 63:
            break
    return val, last_off + 1


def read_zigzag_leb128(data: bytes, off: int) -> tuple[int, int]:
    """读取 zigzag + LEB128 编码的有符号整数。"""
    uval, end = read_leb128(data, off)
    # zigzag decode: (uval >> 1) ^ -(uval & 1)
    sval = (uval >> 1) ^ (-(uval & 1))
    return sval, end


def decode_candidates(data: bytes, off: int) -> dict[str, float]:
    """对 data[off] 起的所有可能解码方式，返回 {label: value}。
    扩展了更多编码假设。
    """
    out: dict[str, float] = {}
    n = len(data)

    # ── LEB128 变体 ──
    for label, fn in [("leb128", read_leb128),
                       ("leb128s", read_leb128_signed),
                       ("zigzag", read_zigzag_leb128)]:
        v, end = fn(data, off)
        out[label] = float(v)

    # ── 整数 LE/BE，宽度 1~4 ──
    for w in (1, 2, 3, 4):
        if off + w <= n:
            chunk = data[off:off + w]
            out[f"u{w*8}_le"] = float(int.from_bytes(chunk, "little"))
            out[f"u{w*8}_be"] = float(int.from_bytes(chunk, "big"))
            # 有符号
            out[f"s{w*8}_le"] = float(int.from_bytes(chunk, "little", signed=True))
            out[f"s{w*8}_be"] = float(int.from_bytes(chunk, "big", signed=True))

    # ── THS 定点数（4字节 LE32）──
    if off + 4 <= n:
        le32 = struct.unpack("<I", data[off:off + 4])[0]
        out["ths_float"] = decode_ths_float(le32)

    # ── THS 定点数 3字节变体 ──
    if off + 3 <= n:
        le24 = int.from_bytes(data[off:off + 3], "little")
        # 尝试用 THS 解码（假定 bit23=div, bit22-20=exp, bit19=sign, bit18-0=mantissa）
        div = (le24 >> 23) & 1
        exp = (le24 >> 20) & 7
        sign = -1.0 if (le24 & 0x080000) else 1.0
        mantissa = le24 & 0x07FFFF
        _FLOAT_TABLE = [1.0, 10.0, 100.0, 1000.0, 10000.0, 100000.0, 1000000.0, 10000000.0]
        factor = _FLOAT_TABLE[exp]
        out["ths24"] = sign * (mantissa / factor if div else mantissa * factor)

    # ── 金额常见缩放 ──
    if off + 3 <= n:
        v24 = int.from_bytes(data[off:off + 3], "little")
        out["amt_div256"] = float(v24 * 256)       # 金额÷256 存储
        out["amt_div100"] = float(v24 * 100)        # 金额÷100（元→分）
        out["amt_mul1000"] = float(v24 * 1000)      # 金额×1000
    if off + 4 <= n:
        v32 = int.from_bytes(data[off:off + 4], "little")
        out["amt32_div256"] = float(v32 * 256)

    return out


# ═══════════════════════════════════════════════════════════
# 0xa0 / 0xa8 子记录解析
# ═══════════════════════════════════════════════════════════

def extract_a0_a8_values(data: bytes) -> list[tuple[int, int, bytes]]:
    """扫描 data 中所有 0xa0 / 0xa8 标签及其后续数据。
    返回 [(tag, offset_of_data, data_bytes), ...]
    0xa0 后跟 2 字节数据，0xa8 后跟 3 字节数据（推测）。
    """
    results = []
    i = 0
    while i < len(data):
        if data[i] in (0xa0, 0xa8):
            tag = data[i]
            tag_off = i
            i += 1
            if tag == 0xa0:
                if i + 2 <= len(data):
                    results.append((tag, tag_off, data[i:i + 2]))
                    i += 2
                else:
                    break
            elif tag == 0xa8:
                if i + 3 <= len(data):
                    results.append((tag, tag_off, data[i:i + 3]))
                    i += 3
                else:
                    break
        else:
            i += 1
    return results


# ═══════════════════════════════════════════════════════════
# 核心搜索：在一个前缀组内找字段映射
# ═══════════════════════════════════════════════════════════

def find_field_in_group(
    group: list[dict],
    known_key: str,        # "amt" or "chg"
    search_in: str = "all",  # "payload", "extra", "a0_values", "all"
) -> list[dict]:
    """在一个前缀组内搜索数值字段的 offset + encoding。

    返回候选列表，按匹配率降序。
    """
    # 收集 (data_to_search, known_value) 对
    pairs = []
    for s in group:
        val = s.get(known_key, 0)
        if val == 0:
            continue
        try:
            val_f = float(val)
        except (ValueError, TypeError):
            continue
        payload = s.get("payload", b"")
        extra = s.get("extra", b"")

        if search_in == "payload":
            data = payload
        elif search_in == "extra":
            data = extra
        elif search_in == "combined":
            data = payload + extra
        elif search_in == "a0_values":
            data = b"".join(v for _, _, v in extract_a0_a8_values(payload + extra))
        else:
            data = payload + extra  # "all" defaults to combined

        if len(data) < 2:
            continue
        pairs.append((data, val_f, s.get("code", "")))

    if len(pairs) < 3:
        return []

    # 对 data[0] 的所有 (offset, encoding) 候选，检查是否对所有样本一致
    first_data, first_known, _ = pairs[0]
    candidates = []
    max_off = len(first_data)
    for off in range(max_off):
        decs = decode_candidates(first_data, off)
        for enc, v0 in decs.items():
            if v0 == 0:
                continue
            scale0 = first_known / v0
            if not (1e-6 < abs(scale0) < 1e12):
                continue
            # 验证所有样本
            matched = 0
            scales = []
            for data, known, code in pairs:
                if off >= len(data):
                    continue
                decs2 = decode_candidates(data, off)
                v = decs2.get(enc)
                if v is None or v == 0:
                    continue
                s = known / v
                # 放宽容忍度到 20%（推送和历史的金额可能有微小时间差）
                if abs(s - scale0) / max(abs(scale0), 1) < 0.2:
                    matched += 1
                    scales.append(s)
            if matched >= max(2, len(pairs) // 3):
                avg_scale = sum(scales) / len(scales)
                var = sum((s - avg_scale) ** 2 for s in scales) / len(scales) if scales else 0
                candidates.append({
                    "offset": off,
                    "encoding": enc,
                    "scale": avg_scale,
                    "scale_std": var ** 0.5,
                    "matched": matched,
                    "total": len(pairs),
                    "search_in": search_in,
                })
    candidates.sort(key=lambda c: (-c["matched"], c["scale_std"]))
    return candidates


def find_field_across_all(
    samples: list[dict],
    known_key: str,
    search_in: str = "all",
) -> list[dict]:
    """不在组分，直接在所有样本的 combined data 中搜索。"""
    pairs = []
    for s in samples:
        val = s.get(known_key, 0)
        if val == 0:
            continue
        try:
            val_f = float(val)
        except (ValueError, TypeError):
            continue
        payload = s.get("payload", b"")
        extra = s.get("extra", b"")

        if search_in == "payload":
            data = payload
        elif search_in == "extra":
            data = extra
        elif search_in == "combined":
            data = payload + extra
        elif search_in == "a0_values":
            data = b"".join(v for _, _, v in extract_a0_a8_values(payload + extra))
        else:
            data = payload + extra

        if len(data) < 2:
            continue
        pairs.append((data, val_f))

    if len(pairs) < 3:
        return []

    first_data, first_known = pairs[0]
    candidates = []
    max_off = min(len(first_data), 80)
    for off in range(max_off):
        decs = decode_candidates(first_data, off)
        for enc, v0 in decs.items():
            if v0 == 0:
                continue
            scale0 = first_known / v0
            if not (1e-6 < abs(scale0) < 1e12):
                continue
            matched = 0
            scales = []
            for data, known in pairs:
                if off >= len(data):
                    continue
                decs2 = decode_candidates(data, off)
                v = decs2.get(enc)
                if v is None or v == 0:
                    continue
                s = known / v
                if abs(s - scale0) / max(abs(scale0), 1) < 0.2:
                    matched += 1
                    scales.append(s)
            if matched >= max(2, len(pairs) // 3):
                avg_scale = sum(scales) / len(scales)
                var = sum((s - avg_scale) ** 2 for s in scales) / len(scales) if scales else 0
                candidates.append({
                    "offset": off,
                    "encoding": enc,
                    "scale": avg_scale,
                    "scale_std": var ** 0.5,
                    "matched": matched,
                    "total": len(pairs),
                    "search_in": search_in,
                })
    candidates.sort(key=lambda c: (-c["matched"], c["scale_std"]))
    return candidates


# ═══════════════════════════════════════════════════════════
# 主流程
# ═══════════════════════════════════════════════════════════

def main():
    verbose = "--verbose" in sys.argv
    group_filter = None
    for a in sys.argv[1:]:
        if a.startswith("--group="):
            group_filter = a.split("=", 1)[1]

    matched_path = os.path.join(DATA_DIR, "matched.csv")
    if not os.path.exists(matched_path):
        print(f"未找到 {matched_path}，先盘中跑 collect_push_samples.py")
        return 1

    with open(matched_path, encoding="utf-8") as f:
        raw_samples = list(csv.DictReader(f))
    print(f"载入 {len(raw_samples)} 条匹配样本\n")

    # ── 解析每条的 payload + extra ──
    for s in raw_samples:
        payload, extra = extract_parts(s.get("push_raw_bytes", ""))
        s["payload"] = payload
        s["extra"] = extra
        s["amt"] = float(s.get("hist_amount", 0) or 0)
        s["chg"] = float(s.get("hist_change", 0) or 0)
        s["prefix"] = payload[:4] if len(payload) >= 4 else b""

    # 过滤非零样本
    samples_amt = [s for s in raw_samples if s["amt"] != 0]
    samples_chg = [s for s in raw_samples if s["chg"] != 0]

    # ── 按前缀分组 ──
    def group_by_prefix(samples_list):
        groups = defaultdict(list)
        for s in samples_list:
            prefix = s["prefix"]
            if prefix:
                groups[prefix].append(s)
        return groups

    amt_groups = group_by_prefix(samples_amt)
    chg_groups = group_by_prefix(samples_chg)

    # ── 对每个前缀组搜索字段 ──
    print("=" * 70)
    print("金额字段搜索（按前缀分组 + 跨组全量）")
    print("=" * 70)

    all_amt_candidates = []

    # 先搜索最大的几个组
    sorted_groups = sorted(amt_groups.items(), key=lambda x: -len(x[1]))
    for prefix, group in sorted_groups:
        if group_filter and prefix.hex() != group_filter:
            continue
        if len(group) < 3:
            continue
        print(f"\n── 前缀组 {prefix.hex()} ({len(group)} 样本) ──")
        for search_in in ["payload", "extra", "combined", "a0_values"]:
            cands = find_field_in_group(group, "amt", search_in=search_in)
            if cands:
                best = cands[0]
                if best["matched"] >= max(3, len(group) // 3):
                    print(f"  [{search_in}] offset={best['offset']:>3} enc={best['encoding']:<14} "
                          f"scale={best['scale']:.4f} ±{best['scale_std']:.4f} "
                          f"匹配 {best['matched']}/{best['total']}")
                    all_amt_candidates.append(best)
                    if verbose and len(cands) > 1:
                        for c in cands[1:3]:
                            print(f"         offset={c['offset']:>3} enc={c['encoding']:<14} "
                                  f"scale={c['scale']:.4f} ±{c['scale_std']:.4f} "
                                  f"匹配 {c['matched']}/{c['total']}")

    # 跨全量搜索
    print(f"\n── 全量跨组搜索 ({len(samples_amt)} 样本) ──")
    for search_in in ["payload", "extra", "combined", "a0_values"]:
        cands = find_field_across_all(samples_amt, "amt", search_in=search_in)
        if cands:
            for c in cands[:5]:
                if c["matched"] >= 10:
                    print(f"  [{search_in}] offset={c['offset']:>3} enc={c['encoding']:<14} "
                          f"scale={c['scale']:.4f} ±{c['scale_std']:.4f} "
                          f"匹配 {c['matched']}/{c['total']}")

    # ── 涨幅字段 ──
    print("\n" + "=" * 70)
    print("涨幅字段搜索（按前缀分组 + 跨组全量）")
    print("=" * 70)

    sorted_chg_groups = sorted(chg_groups.items(), key=lambda x: -len(x[1]))
    for prefix, group in sorted_chg_groups:
        if group_filter and prefix.hex() != group_filter:
            continue
        if len(group) < 3:
            continue
        has_nonzero = sum(1 for s in group if s["chg"] != 0)
        if has_nonzero < 3:
            continue
        print(f"\n── 前缀组 {prefix.hex()} ({len(group)} 样本, {has_nonzero} 非零涨幅) ──")
        for search_in in ["payload", "extra", "combined", "a0_values"]:
            cands = find_field_in_group(group, "chg", search_in=search_in)
            if cands:
                best = cands[0]
                if best["matched"] >= max(3, has_nonzero // 3):
                    print(f"  [{search_in}] offset={best['offset']:>3} enc={best['encoding']:<14} "
                          f"scale={best['scale']:.4f} ±{best['scale_std']:.4f} "
                          f"匹配 {best['matched']}/{best['total']}")
                    if verbose and len(cands) > 1:
                        for c in cands[1:3]:
                            print(f"         offset={c['offset']:>3} enc={c['encoding']:<14} "
                                  f"scale={c['scale']:.4f} ±{c['scale_std']:.4f} "
                                  f"匹配 {c['matched']}/{c['total']}")

    # 跨全量
    print(f"\n── 全量跨组搜索 ({len(samples_chg)} 样本) ──")
    for search_in in ["payload", "extra", "combined", "a0_values"]:
        cands = find_field_across_all(samples_chg, "chg", search_in=search_in)
        if cands:
            for c in cands[:5]:
                if c["matched"] >= 10:
                    print(f"  [{search_in}] offset={c['offset']:>3} enc={c['encoding']:<14} "
                          f"scale={c['scale']:.4f} ±{c['scale_std']:.4f} "
                          f"匹配 {c['matched']}/{c['total']}")

    # ── verbose 模式：详细打印样本 ──
    if verbose:
        print("\n" + "=" * 70)
        print("样本详情（前 10 条）")
        print("=" * 70)
        for s in raw_samples[:10]:
            payload = s["payload"]
            extra = s["extra"]
            print(f"\n{s['code']} {s['hist_type']} amt={s['amt']:.0f} chg={s['chg']}")
            print(f"  payload ({len(payload)}B): {payload.hex()}")
            if extra:
                print(f"  extra   ({len(extra)}B): {extra.hex()}")

            # 显示 a0/a8 子记录
            combined = payload + extra
            a0a8 = extract_a0_a8_values(combined)
            if a0a8:
                for tag, off, val in a0a8:
                    le = int.from_bytes(val, "little")
                    be = int.from_bytes(val, "big")
                    ths_val = None
                    if len(val) == 4:
                        le32 = struct.unpack("<I", val)[0]
                        ths_val = decode_ths_float(le32)
                    print(f"  {'a0' if tag==0xa0 else 'a8'}@{off}: {val.hex()} "
                          f"LE={le} BE={be}" +
                          (f" THS={ths_val:.4f}" if ths_val is not None else ""))

            # 显示每个 offset 的解码
            print(f"  {'off':>3} {'hex':<14} {'解码 (payload+extra)'}")
            data = payload + extra
            for off in range(min(len(data), 40)):
                hexs = " ".join(f"{b:02x}" for b in data[off:off + 4])
                decs = decode_candidates(data, off)
                parts = [f"{k}={v:.4g}" for k, v in decs.items()]
                print(f"  {off:>3} {hexs:<14} {', '.join(parts)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
