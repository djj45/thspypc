#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""0xc4 负载结构精确分析：头字段定位 + 尝试 BitRLE 解码。

观察（tests/inspect_c4_frames.py）：
- 负载[0:0x26]=0，[0x26:] 有小结构，[0x3c] LE32 ≈ 负载长-63
- 数据区充满 0f/f0/3f 位模式 → 疑似位平面 RLE（BitRLE）
"""
from __future__ import annotations

import struct
import sys
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
    _parse_hd_records,
)

C4_DIR = ROOT / "captures_live" / "c4"


def parse_header(frame: bytes):
    pos = frame.find(b"hd3.1\x00")
    base = pos + 6
    dc = struct.unpack("<I", frame[base : base + 4])[0]
    variant = struct.unpack("<H", frame[base + 4 : base + 6])[0]
    hs = struct.unpack("<H", frame[base + 6 : base + 8])[0]
    fc = struct.unpack("<H", frame[base + 8 : base + 10])[0]
    fields = _parse_hd_field_table(frame, base + 10, fc)
    payload_off = base + 10 + fc * 4
    return dc, variant, hs, fc, fields, frame[payload_off:]


def try_decode(payload: bytes, dc_rows: int, hs: int, data_off: int, tag: str):
    expected = dc_rows * hs
    data = payload[data_off:]
    try:
        bitplane = _decode_bitrle_0x13746d0(data, expected)
    except Exception as exc:  # noqa: BLE001
        print(f"    [{tag}] 解码异常: {type(exc).__name__}: {exc}")
        return None
    if bitplane is None:
        print(f"    [{tag}] 返回 None")
        return None
    print(f"    [{tag}] 解码成功! bitplane={len(bitplane)}B (期望 {expected})")
    return bitplane


def main() -> None:
    for path in sorted(C4_DIR.glob("*.bin"))[:4]:
        frame = path.read_bytes()
        dc, variant, hs, fc, fields, payload = parse_header(frame)
        rows = dc & 0xFFFFFF
        print(f"== {path.name}: rows={rows} hs={hs} 负载={len(payload)}B")

        # 精确 dump 0x20-0x46
        seg = payload[0x20:0x46]
        print(f"    [0x20:0x46] = {seg.hex(' ')}")
        for off in (0x26, 0x2c, 0x30, 0x3c):
            le16 = struct.unpack("<H", payload[off : off + 2])[0]
            le32 = struct.unpack("<I", payload[off : off + 4])[0]
            print(f"    @{off:#04x}: LE16={le16:<6} LE32={le32}")

        size_at_3c = struct.unpack("<I", payload[0x3C : 0x40])[0]
        for cand in (0x40, 0x3F, 0x41, 0x42):
            rem = len(payload) - cand
            print(f"    data@{cand:#04x}: 剩余={rem} (size@0x3c={size_at_3c}, 差={size_at_3c - rem})")

        # 尝试从 0x40 直接 BitRLE（解码器可能自带大小）
        bitplane = try_decode(payload, rows, hs, 0x40, "off=0x40")
        if bitplane is None:
            continue
        records = _transpose_bitplane_0x1763410(bitplane, hs, rows)
        print(f"    转置完成: {len(records)}B")
        parsed = _parse_hd_records(records, fields, hs, rows)
        print(f"    解析行数: {len(parsed)}")
        for row in parsed[:3]:
            trimmed = {k: v for k, v in row.items() if v not in ("", 0, b"", None, 0.0)}
            print(f"      {trimmed}")
        return  # 第一个成功即停，人工核对


if __name__ == "__main__":
    main()
