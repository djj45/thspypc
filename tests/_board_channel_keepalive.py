#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""统计板块通道（sid=2）全程的帧类型分布：心跳/keepalive/qureal 轮询。

探针：不入库（tests/_*.py 约定）。
"""
from __future__ import annotations

import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TSHARK = r"D:\软件\Wireshark-4.4.7-x64-with-Npcap-1.50-Portable\Wireshark\App\Wireshark\tshark.exe"
MAGIC = b"\xfd\xfd\xfd\xfd"


def _run(args):
    r = subprocess.run(args, capture_output=True, timeout=180)
    return r.stdout.decode("utf-8", errors="replace")


def analyze(pcap_name, sid):
    pcap = os.path.join(ROOT, "captures_live", pcap_name)
    for direction, filt in (
        ("C->S", f"tcp.stream=={sid} and tcp.dstport==8901"),
        ("S->C", f"tcp.stream=={sid} and tcp.srcport==8901"),
    ):
        hexp = "".join(
            _run([TSHARK, "-r", pcap, "-Y", filt,
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
        counts = {}
        examples = {}
        for i, fb in enumerate(frames):
            txt = fb.decode("gbk", errors="replace")
            kind = "other"
            if "tsi0=" in txt:
                kind = "heartbeat"
            elif "instid=65536" in txt and "qureal" in txt:
                kind = "qureal-poll"
            elif "method=subreal" in txt:
                kind = "subreal"
            elif "pageid=" in txt and "method=" not in txt:
                kind = "pageid-register"
            elif "method=init" in txt or "qustocklink" in txt:
                kind = "qureal-init"
            elif "MarketCode" in txt or "StockNameVer" in txt:
                kind = "mkt/stockname"
            elif "CodeList=" in txt or "DataType=" in txt:
                kind = "query"
            counts[kind] = counts.get(kind, 0) + 1
            examples.setdefault(kind, i)
        print(f"{pcap_name} stream {sid} {direction}: {len(frames)} frames")
        for kind, n in sorted(counts.items(), key=lambda x: -x[1]):
            print(f"  {kind:16s} {n:4d}  (first at {examples[kind]})")


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    analyze("system_blocks_20260801_132302.pcap", 2)
    analyze("system_blocks_20260801_132439.pcap", 2)
