#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""破解 0xc4 表的 fmt=0x79/0x7B 浮点编码。

方法：
1. 解码 16 个 0xc4 帧 → (code, 各 raw 字段, dt10/dt6 自算涨幅)
2. 从后端拉真值：sort_by=592890(主力 dt250)、199112(涨幅 dt200 参照)、
   592888(DDE dt248)、265260(封单 dt44)
3. 对每个候选字段 × 真值源，枚举位切分（符号/指数/尾数边界 × 乘除）
   找一致映射。
"""
from __future__ import annotations

import json
import struct
import sys
import urllib.request
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, ValueError):
    pass

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from thspypc.codecs.hd import (  # noqa: E402
    _decode_bitrle_0x13746d0,
    _transpose_bitplane_0x1763410,
    _parse_hd_field_table,
)

C4_DIR = ROOT / "captures_live" / "c4"
API = "http://127.0.0.1:8765"


def decode_frame(frame: bytes) -> list[dict]:
    pos = frame.find(b"hd3.1\x00")
    base = pos + 6
    dc = struct.unpack("<I", frame[base : base + 4])[0] & 0xFFFFFF
    hs = struct.unpack("<H", frame[base + 6 : base + 8])[0]
    fc = struct.unpack("<H", frame[base + 8 : base + 10])[0]
    fields = _parse_hd_field_table(frame, base + 10, fc)
    payload = frame[base + 10 + fc * 4 :]
    bitplane = _decode_bitrle_0x13746d0(payload[0x40:], dc * hs)
    recs = _transpose_bitplane_0x1763410(bitplane, hs, dc)
    rows = []
    for i in range(dc):
        row = recs[i * hs : (i + 1) * hs]
        rec = {}
        off = 0
        for dt, fmt, width in fields:
            chunk = row[off : off + width]
            off += width
            key = f"dt{dt}" if dt != 5 else "code"
            if dt == 5:
                rec["code"] = chunk[1:7].split(b"\x00")[0].decode()
            elif fmt == 0x70 and width == 4:
                from thspypc.codecs.numeric import decode_ths_float

                rec[key] = decode_ths_float(struct.unpack("<I", chunk)[0])
            else:
                base_key = key
                n = 2
                while base_key in rec:  # 重复 dt 字段（如两个 dt200）
                    base_key = f"dt{dt}#{n}"
                    n += 1
                rec[base_key] = struct.unpack("<I", chunk)[0] if width == 4 else chunk
        rows.append(rec)
    return rows


def fetch(path: str):
    with urllib.request.urlopen(API + path, timeout=60) as resp:
        return json.load(resp)


def main() -> None:
    all_rows: dict[str, dict] = {}
    frames = sorted(C4_DIR.glob("*.bin"))
    for path in frames:
        for row in decode_frame(path.read_bytes()):
            code = row.get("code")
            if code and len(code) == 6:
                if code in all_rows:
                    # 同一代码跨帧一致性检查
                    for k, v in row.items():
                        if k.startswith("dt2") or k.startswith("dt1"):
                            old = all_rows[code].get(k)
                            if old != v:
                                print(f"  !! {code} {k} 跨帧不一致: {old} vs {v}")
                all_rows[code] = row
    print(f"解码 {len(frames)} 帧 → {len(all_rows)} 个唯一代码")

    codes = list(all_rows)
    print("样例:", codes[:10])

    # 真值：主力 dt250 / DDE dt248 / 涨幅（自算 + dt200 参照）
    truth = {}
    for name, sort_by in (("dt250", 592890), ("dde", 592888), ("seal", 265260)):
        rows = fetch(
            f"/api/stock_list_ranked?sort_by={sort_by}&count=5400&sort_dir=D&with_values=1"
        )
        m = {r["code"]: r for r in rows}
        for c in codes:
            truth.setdefault(c, {})[name] = m.get(c, {}).get(
                "value", m.get(c, {}).get("dt250")
            )
        print(f"真值 {name}(sort_by={sort_by}): 命中 {sum(1 for c in codes if truth[c][name] is not None)}/{len(codes)}")

    # 输出 (raw, truth) 对
    fields_raw = ["dt200", "dt200#2", "dt202", "dt126", "dt250", "dt248", "dt131"]
    print("\n(raw, truth) 样本（每字段前 8 个有真值的）:")
    pairs = {}
    for f in fields_raw:
        lst = []
        for c in codes:
            raw = all_rows[c].get(f)
            t250 = truth[c]["dt250"]
            t248 = truth[c]["dde"]
            pct = None
            if all_rows[c].get("dt10") and all_rows[c].get("dt6"):
                pct = (all_rows[c]["dt10"] - all_rows[c]["dt6"]) / all_rows[c]["dt6"] * 100
            if isinstance(raw, int):
                lst.append((c, raw, t250, t248, pct))
        pairs[f] = lst
        sample = ", ".join(
            f"{c}:raw=0x{r:08x},250={a},248={b},pct={p and round(p,2)}"
            for c, r, a, b, p in lst[:8]
        )
        print(f"  {f}: {sample}")

    Path(ROOT / "captures_live" / "c4_pairs.json").write_text(
        json.dumps(
            {
                code: {
                    "raw": {f: all_rows[code].get(f) for f in fields_raw},
                    "dt10": all_rows[code].get("dt10"),
                    "dt6": all_rows[code].get("dt6"),
                    "truth": truth[code],
                }
                for code in codes
            },
            ensure_ascii=False,
            indent=1,
        ),
        encoding="utf-8",
    )
    print("\n已写 captures_live/c4_pairs.json")


if __name__ == "__main__":
    main()
