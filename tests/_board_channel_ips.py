#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""打印 pcap 各 TCP 流的 IP 端点 + 登录用户，判断 MAIN/板块通道是否同 IP。

探针：不入库（tests/_*.py 约定）。
"""
from __future__ import annotations

import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TSHARK = r"D:\软件\Wireshark-4.4.7-x64-with-Npcap-1.50-Portable\Wireshark\App\Wireshark\tshark.exe"


def _run(args):
    r = subprocess.run(args, capture_output=True, timeout=180)
    return r.stdout.decode("utf-8", errors="replace")


for pcap_name in ("system_blocks_20260801_132302.pcap", "system_blocks_20260801_132439.pcap"):
    pcap = os.path.join(ROOT, "captures_live", pcap_name)
    print(f"===== {pcap_name} =====")
    out = _run([
        TSHARK, "-r", pcap, "-Y", "tcp.port==8901",
        "-T", "fields", "-e", "tcp.stream", "-e", "ip.src",
        "-e", "ip.dst", "-e", "tcp.srcport", "-e", "tcp.dstport",
    ])
    seen = {}
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) < 5:
            continue
        sid, src, dst, sport, dport = parts[:5]
        try:
            sid = int(sid)
        except ValueError:
            continue
        if dport == "8901":
            pair = (src, dst)
        else:
            pair = (dst, src)
        seen.setdefault(sid, pair)
    for sid in sorted(seen):
        print(f"  stream {sid}: client {seen[sid][0]} <-> server {seen[sid][1]}")


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    _run = _run
