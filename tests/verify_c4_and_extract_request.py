#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""① dt248(fmt 0x7B, ths_float) 全量对照 dde API 硬核验；
② 提取 pcap 中 0xc4 响应前的客户端请求帧原文。"""
from __future__ import annotations

import json
import re
import struct
import subprocess
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
from thspypc.codecs.numeric import decode_ths_float  # noqa: E402

C4_DIR = ROOT / "captures_live" / "c4"
PCAP = ROOT / "captures_live" / "stocklist_page_20260818_185944.pcapng"
TSHARK = Path(
    r"D:\software\Wireshark_4.6.7_Portable\Wireshark\WiresharkPortable64"
    r"\App\Wireshark\tshark.exe"
)
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
        seen = {}
        for dt, fmt, width in fields:
            chunk = row[off : off + width]
            off += width
            if dt == 5 and width >= 7:
                rec["code"] = chunk[1:7].split(b"\x00")[0].decode()
            elif width == 4 and fmt in (0x70, 0x79, 0x7B):
                seen[dt] = seen.get(dt, 0) + 1
                key = f"dt{dt}" if seen[dt] == 1 else f"dt{dt}#{seen[dt]}"
                rec[key] = decode_ths_float(struct.unpack("<I", chunk)[0])
        rows.append(rec)
    return rows


def main() -> None:
    # ① dt248 对照 dde API
    all_rows: dict[str, dict] = {}
    for path in sorted(C4_DIR.glob("*.bin")):
        for row in decode_frame(path.read_bytes()):
            if row.get("code") and len(row["code"]) == 6:
                all_rows[row["code"]] = row
    with urllib.request.urlopen(
        API + "/api/dde_rank?count=5400&sort_dir=D", timeout=120
    ) as resp:
        dde = {r["code"]: r["value"] for r in json.load(resp) if r.get("value") is not None}
    hits = misses = 0
    samples = []
    for code, row in all_rows.items():
        if code not in dde or "dt248" not in row:
            continue
        ours = row["dt248"]  # 亿 口径
        theirs = dde[code]   # 亿 口径
        if abs(ours - theirs) <= max(0.02, abs(theirs) * 0.01):
            hits += 1
        else:
            misses += 1
            if len(samples) < 6:
                samples.append((code, ours, theirs))
    total = hits + misses
    print(f"[dt248 vs dde API] 匹配 {hits}/{total}（容差 1% 或 0.02 亿）")
    for code, ours, theirs in samples:
        print(f"  不匹配: {code} ours={ours:.4f} api={theirs:.4f}")

    # ② 提取 0xc4 响应对应流上的客户端请求
    result = subprocess.run(
        [str(TSHARK), "-r", str(PCAP), "-Y",
         "tcp.port==8901 and tcp.dstport==8901 and tcp.payload",
         "-T", "fields", "-e", "tcp.stream"],
        capture_output=True, timeout=240,
    )
    streams = sorted({s for s in result.stdout.decode("ascii").split() if s})
    req_result = subprocess.run(
        [str(TSHARK), "-r", str(PCAP), "-Y",
         "tcp.port==8901 and tcp.dstport==8901 and tcp.payload",
         "-T", "fields", "-E", "separator=\t",
         "-e", "tcp.stream", "-e", "tcp.payload"],
        capture_output=True, timeout=240,
    )
    shown = 0
    print("\n[0xc4 所在流的客户端请求（stream=0，截取前 3 个含 DataType 的）]")
    for line in req_result.stdout.decode("ascii", "replace").splitlines():
        parts = line.split("\t")
        if len(parts) < 2 or parts[0] != "0" or not parts[1]:
            continue
        try:
            payload = bytes.fromhex(parts[1].replace(":", ""))
        except ValueError:
            continue
        text = payload.decode("gbk", errors="replace")
        if "DataType=" not in text or ("592890" not in text and "592888" not in text):
            continue
        compact = re.sub(r"\s+", " ", text)[:400]
        print(f"  {compact}")
        shown += 1
        if shown >= 3:
            break


if __name__ == "__main__":
    main()
