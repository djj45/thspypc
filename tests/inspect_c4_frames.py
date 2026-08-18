#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""0xc4 帧结构检视：头部、负载布局、与 dc×hs 的关系。"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, ValueError):
    pass

ROOT = Path(__file__).resolve().parents[1]
C4_DIR = ROOT / "captures_live" / "c4"


def parse(frame: bytes) -> dict:
    pos = frame.find(b"hd3.1\x00")
    base = pos + 6
    dc = struct.unpack("<I", frame[base : base + 4])[0]
    variant = struct.unpack("<H", frame[base + 4 : base + 6])[0]
    hs = struct.unpack("<H", frame[base + 6 : base + 8])[0]
    fc = struct.unpack("<H", frame[base + 8 : base + 10])[0]
    fields = []
    for i in range(fc):
        p = base + 10 + i * 4
        dt, fmt, width = struct.unpack("<HBB", frame[p : p + 4])
        fields.append((dt, fmt, width))
    payload = frame[base + 10 + fc * 4 :]
    return {
        "dc": dc, "variant": variant, "hs": hs, "fc": fc,
        "fields": fields, "payload": payload, "prefix": frame[:pos],
    }


def hexdump(data: bytes, limit: int = 240) -> str:
    lines = []
    for off in range(0, min(len(data), limit), 16):
        chunk = data[off : off + 16]
        hexs = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"    {off:06x}  {hexs:<48}  {asc}")
    return "\n".join(lines)


def main() -> None:
    frames = sorted(C4_DIR.glob("*.bin"))
    print(f"0xc4 帧数: {len(frames)}\n")
    for path in frames:
        frame = path.read_bytes()
        h = parse(frame)
        payload = h["payload"]
        dc_rows = h["dc"] & 0x00FFFFFF
        flag = h["dc"] >> 24
        expected_plain = dc_rows * h["hs"]
        print(f"== {path.name} 帧长={len(frame)}")
        print(
            f"   dc=0x{h['dc']:08x}(行数={dc_rows}, 高8位=0x{flag:02x})"
            f" variant=0x{h['variant']:04x} hs={h['hs']} fc={h['fc']}"
        )
        print(
            f"   负载长={len(payload)}  dc×hs={expected_plain}"
            f"  比例={len(payload) / expected_plain:.3f}"
            if expected_plain
            else "   dc=0"
        )
        # 负载前 4 字节（BitRLE 路径在这里放明文长度）
        head4 = struct.unpack(">I", payload[:4])[0] if len(payload) >= 4 else 0
        head4le = struct.unpack("<I", payload[:4])[0] if len(payload) >= 4 else 0
        print(f"   负载头4B: BE=0x{head4:08x}({head4}) LE=0x{head4le:08x}({head4le})")
        prefix = h["prefix"]
        if prefix:
            print(f"   hd3.1 前缀({len(prefix)}B): {prefix[:120]!r}")
        print(hexdump(payload))
        print()


if __name__ == "__main__":
    main()
