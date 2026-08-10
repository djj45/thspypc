#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""打印 pcap 各 8901 TCP 流的 SYN/首个数据帧时间与端点。

探针：不入库（tests/_*.py 约定）。
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TSHARK = r"D:\software\Wireshark_4.6.7_Portable\Wireshark\WiresharkPortable64\App\Wireshark\tshark.exe"


def _run(args):
    r = subprocess.run(args, capture_output=True, timeout=180)
    return r.stdout.decode("utf-8", errors="replace")


def main():
    for pcap_name in (
        "system_blocks_20260801_132302.pcap",
        "system_blocks_20260801_132439.pcap",
        "realtime_push_20260724_131453.pcap",
    ):
        pcap = ROOT / "captures_live" / pcap_name
        out = _run([
            TSHARK, "-r", str(pcap), "-Y", "tcp.port==8901",
            "-T", "fields", "-e", "tcp.stream", "-e", "frame.time_relative",
            "-e", "tcp.flags.syn", "-e", "ip.src", "-e", "tcp.srcport",
            "-e", "tcp.dstport", "-e", "tcp.len",
        ])
        first_syn = {}
        first_data = {}
        endpoints = {}
        print("  sample:", repr(out.splitlines()[0]) if out.splitlines() else "(空)" if not out.strip() else out.splitlines()[0])
        debug = 0
        for line in out.splitlines():
            parts = line.split("\t")
            if len(parts) < 7:
                continue
            sid, t, flags, src, sport, dport, tlen = parts[:7]
            try:
                sid = int(sid)
                t = float(t)
            except ValueError:
                continue
            debug += 1
            if debug <= 3:
                print(f"    debug sid={sid} flags={flags!r} tlen={tlen!r}")
            if flags in ("1", "True"):
                first_syn.setdefault(sid, t)
            if tlen not in ("0", ""):
                first_data.setdefault(sid, t)
            if dport == "8901":
                endpoints.setdefault(sid, (src, sport))
            else:
                endpoints.setdefault(sid, (src, sport))
        print(f"===== {pcap_name} =====")
        for sid in sorted(first_syn):
            syn = first_syn[sid]
            data = first_data.get(sid)
            gap = f"{data - syn:.3f}" if data is not None else "-"
            print(f"  stream {sid}: SYN t={syn:8.3f} 首数据 t={data}  "
                  f"(SYN→首数据 {gap}s)  src={endpoints.get(sid)}")


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    main()
