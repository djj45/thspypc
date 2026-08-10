#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""打印两账号 pcap 板块通道关键帧的完整文本。

探针：不入库（tests/_*.py 约定）。
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TSHARK = r"D:\software\Wireshark_4.6.7_Portable\Wireshark\WiresharkPortable64\App\Wireshark\tshark.exe"
MAGIC = b"\xfd\xfd\xfd\xfd"


def _run(args):
    r = subprocess.run(args, capture_output=True, timeout=240)
    return r.stdout.decode("utf-8", errors="replace")


def extract(pcap_name: str, sid: int) -> list[bytes]:
    pcap = ROOT / "captures_live" / pcap_name
    hexp = "".join(
        _run([TSHARK, "-r", str(pcap), "-Y",
              f"tcp.stream=={sid} and tcp.dstport==8901",
              "-T", "fields", "-e", "tcp.payload"]).split()
    )
    data = bytes.fromhex(hexp) if hexp else b""
    frames = []
    for sub in data.split(MAGIC):
        if len(sub) >= 8:
            try:
                blen = int(sub[:8], 16)
            except ValueError:
                blen = 0
            frames.append(sub[8:8 + blen])
    return frames


def main():
    for pcap, sid, idx in (
        ("system_blocks_20260801_132302.pcap", 2, 56),
        ("system_blocks_20260801_132439.pcap", 2, 65),
    ):
        frames = extract(pcap, sid)
        fb = frames[idx]
        txt = fb.decode("gbk", errors="replace")
        print(f"===== {pcap} frame[{idx}] {len(fb)}B =====")
        print(" head:", fb[:23].hex(" "))
        print(" text:", repr(txt[:800]))
    for pcap, sid, idx in (
        ("system_blocks_20260801_132302.pcap", 2, 17),
        ("system_blocks_20260801_132439.pcap", 2, 31),
    ):
        frames = extract(pcap, sid)
        fb = frames[idx]
        txt = fb.decode("gbk", errors="replace")
        print(f"\n===== {pcap} frame[{idx}] MKT_INIT {len(fb)}B =====")
        print(" head:", fb[:23].hex(" "))
        print(" text head:", repr(txt[:260]))
        print(" text tail:", repr(txt[-120:]))
    for pcap, sid, idx in (
        ("system_blocks_20260801_132302.pcap", 2, 62),
        ("system_blocks_20260801_132439.pcap", 2, 84),
    ):
        frames = extract(pcap, sid)
        fb = frames[idx]
        txt = fb.decode("gbk", errors="replace")
        print(f"\n===== {pcap} frame[{idx}] StockNameVer {len(fb)}B =====")
        print(" head:", fb[:23].hex(" "))
        print(" text head:", repr(txt[:300]))
        print(" text tail:", repr(txt[-160:]))


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    main()
