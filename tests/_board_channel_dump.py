#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""Dump 板块专用通道（sid=2）引导期请求帧的完整字节（hex + 文本）。

探针：不入库（tests/_*.py 约定）。
"""
from __future__ import annotations

import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PCAP = os.path.join(ROOT, "captures_live", "system_blocks_20260801_132302.pcap")
OUT = os.path.join(ROOT, "captures_live", "_board_boot_frames_dump.txt")
TSHARK = r"D:\software\Wireshark_4.6.7_Portable\Wireshark\WiresharkPortable64\App\Wireshark\tshark.exe"
MAGIC = b"\xfd\xfd\xfd\xfd"


def _run(args):
    r = subprocess.run(args, capture_output=True, timeout=180)
    return r.stdout.decode("utf-8", errors="replace")


def main():
    lines = []
    for direction, filt in (
        ("C->S", "tcp.stream==2 and tcp.dstport==8901"),
        ("S->C", "tcp.stream==2 and tcp.srcport==8901"),
    ):
        hexp = "".join(
            _run([TSHARK, "-r", PCAP, "-Y", filt,
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
        lines.append(f"===== stream 2 {direction}: {len(frames)} frames =====")
        for i, fb in enumerate(frames):
            if direction == "C->S" and i > 70:
                break
            if direction == "S->C" and i > 30:
                break
            txt = fb.decode("gbk", errors="replace")
            m = re.search(r"method=(\w+)", txt)
            method = m.group(1) if m else ""
            p = re.search(r"pageid=(\d+)", txt)
            mk = re.search(r"market=(\w+)", txt)
            lines.append(
                f"\n[{i:2d}] {direction} {len(fb)}B method={method} "
                f"pageid={p.group(1) if p else '-'} market={mk.group(1) if mk else '-'}"
            )
            lines.append("  hex: " + fb.hex(" "))
            clean = txt.replace("\r", "\\r").replace("\n", "\\n")
            lines.append("  text: " + clean[:600])
    with open(OUT, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"written {OUT}")


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    main()
