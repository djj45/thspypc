#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""hd3.1 变体分析：从抓包提取响应帧，按 variant 归类，dump 0xc4 帧供逆向。

hd3.1 头（与 codecs/hd.py 对齐）：
    "hd3.1\\0" + dc(LE32) + variant(LE16) + hs(LE16) + fc(LE16)
    + 字段表(fc × 4B: dt LE16 + fmt + width) + [变体负载]

已知变体：BitRLE(标准批量)、0xc4(未知编码，fc=30, hs=139)、
0x4a(分时伴随/时间轴)。本脚本把每个 hd3.1 帧的头信息打表，
并把 0xc4 帧完整落盘到 captures_live/c4/。

用法：
    py tests/analyze_hd3_variants.py [pcapng]
"""
from __future__ import annotations

import re
import struct
import subprocess
import sys
from collections import Counter
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, ValueError):
    pass

ROOT = Path(__file__).resolve().parents[1]
CAPTURE_DIR = ROOT / "captures_live"
PORT = 8901
FRAME_MAGIC = b"\xfd\xfd\xfd\xfd"

WIRESHARK = Path(
    r"D:\software\Wireshark_4.6.7_Portable\Wireshark\WiresharkPortable64"
    r"\App\Wireshark\tshark.exe"
)


def _run_tool(args: list[str], timeout: int = 240):
    result = subprocess.run(args, capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(
            f"命令失败 ({result.returncode}): {' '.join(args[:3])}\n"
            + (result.stderr or result.stdout).decode("utf-8", "replace")[:500]
        )
    return result


def _streams(tshark: Path, pcap: Path) -> list[str]:
    result = _run_tool(
        [str(tshark), "-r", str(pcap), "-T", "fields", "-e", "tcp.stream"],
        timeout=240,
    )
    return sorted({s for s in result.stdout.decode("ascii").split() if s})


def _follow(tshark: Path, pcap: Path, stream: str) -> bytes:
    result = _run_tool(
        [
            str(tshark), "-r", str(pcap), "-q",
            "-z", f"follow,tcp,raw,{stream}",
        ],
        timeout=120,
    )
    text = result.stdout.decode("ascii", "replace")
    hex_lines = re.findall(r"^\t?[0-9a-fA-F]+\r?$", text, re.M)
    return bytes.fromhex("".join(hex_lines)) if hex_lines else b""


def _split_fdf_frames(blob: bytes):
    frames = []
    offset = blob.find(FRAME_MAGIC)
    while offset != -1:
        try:
            body_len = int(blob[offset + 4 : offset + 12], 16)
        except ValueError:
            offset = blob.find(FRAME_MAGIC, offset + 1)
            continue
        if not 0 < body_len < 8 * 1024 * 1024:
            offset = blob.find(FRAME_MAGIC, offset + 1)
            continue
        start = offset + 12
        end = start + body_len
        if end > len(blob):
            offset = blob.find(FRAME_MAGIC, offset + 1)
            continue
        frames.append(blob[start:end])
        offset = blob.find(FRAME_MAGIC, end)
    return frames


def parse_hd3_header(frame: bytes) -> dict | None:
    pos = frame.find(b"hd3.1\x00")
    if pos < 0:
        return None
    base = pos + 6
    if len(frame) < base + 10:
        return None
    dc = struct.unpack("<I", frame[base : base + 4])[0]
    variant = struct.unpack("<H", frame[base + 4 : base + 6])[0]
    hs = struct.unpack("<H", frame[base + 6 : base + 8])[0]
    fc = struct.unpack("<H", frame[base + 8 : base + 10])[0]
    fields = []
    for i in range(fc):
        p = base + 10 + i * 4
        if p + 4 > len(frame):
            break
        dt, fmt, width = struct.unpack("<HBB", frame[p : p + 4])
        fields.append((dt, fmt, width))
    payload_off = base + 10 + fc * 4
    return {
        "dc": dc,
        "variant": variant,
        "hs": hs,
        "fc": fc,
        "fields": fields,
        "payload": frame[payload_off:],
        "frame_len": len(frame),
    }


def main() -> int:
    pcap = (
        Path(sys.argv[1])
        if len(sys.argv) > 1
        else CAPTURE_DIR / "stocklist_page_20260818_185944.pcapng"
    )
    tshark = WIRESHARK
    if not tshark.is_file():
        print(f"tshark 不存在: {tshark}")
        return 1

    out_dir = CAPTURE_DIR / "c4"
    out_dir.mkdir(exist_ok=True)

    stats: Counter[str] = Counter()
    field_sets: dict[str, Counter] = {}
    c4_count = 0
    for stream in _streams(tshark, pcap):
        blob = _follow(tshark, pcap, stream)
        if len(blob) < 200:
            continue
        for idx, frame in enumerate(_split_fdf_frames(blob)):
            if len(frame) < 100:
                continue
            header = parse_hd3_header(frame)
            if header is None:
                if b"hd1.0" in frame:
                    stats["hd1.0"] += 1
                continue
            v = f"0x{header['variant']:02x}"
            stats[v] += 1
            sig = ",".join(f"dt{dt}(f{fmt}w{width})" for dt, fmt, width in header["fields"])
            field_sets.setdefault(v, Counter())[sig] += 1
            if v == "0xc4":
                out = out_dir / f"c4_s{stream}_{idx}_{len(frame)}B.bin"
                out.write_bytes(frame)
                c4_count += 1

    print("[hd 变体统计]")
    for v, n in stats.most_common():
        print(f"  {v:<8} x{n}")
    print("\n[各变体字段表签名（前 3 个）]")
    for v, sigs in field_sets.items():
        print(f"  {v}:")
        for sig, n in sigs.most_common(3):
            print(f"    x{n}  {sig}")
    print(f"\n0xc4 帧 dumped: {c4_count} → {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
