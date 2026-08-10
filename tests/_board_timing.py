#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""统计 pcap 板块通道（sid=2）帧的时间戳，看服务器响应延迟。

探针：不入库（tests/_*.py 约定）。
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TSHARK = r"D:\software\Wireshark_4.6.7_Portable\Wireshark\WiresharkPortable64\App\Wireshark\tshark.exe"
MAGIC = b"\xfd\xfd\xfd\xfd"


def _run(args):
    r = subprocess.run(args, capture_output=True, timeout=240)
    return r.stdout.decode("utf-8", errors="replace")


def analyze(pcap_name: str, sid: int):
    pcap = ROOT / "captures_live" / pcap_name
    rows = []
    out = _run([
        TSHARK, "-r", str(pcap), "-Y", f"tcp.stream=={sid}",
        "-T", "fields", "-e", "frame.time_relative",
        "-e", "tcp.dstport", "-e", "tcp.payload",
    ])
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        t, dport, hexp = parts
        try:
            t = float(t)
        except ValueError:
            continue
        hexp = "".join(hexp.split())
        if not hexp:
            continue
        data = bytes.fromhex(hexp)
        to_server = dport == "8901"
        for sub in data.split(MAGIC):
            if len(sub) < 8:
                continue
            try:
                blen = int(sub[:8], 16)
            except ValueError:
                continue
            fb = sub[8:8 + blen]
            rows.append((t, to_server, fb))
    rows.sort()
    print(f"===== {pcap_name} stream {sid}: {len(rows)} frames =====")
    t0 = rows[0][0]
    labels = {
        "login": "login",
        "subreal": "subreal",
        "pageid": "pageid-reg",
        "MarketCode": "mkt-init",
        "qustocklink": "qureal-init",
        "DataType=[5]": "[5],[55]",
        "StockNameVer": "stockname",
        "CodeList=48(": "board-query",
        "instid=65536": "qureal-poll",
        "hd3.1": "hd3.1-resp",
        "rettype=ini": "init-reply",
        "Reply=login": "login-reply",
        "markettime=48": "hd1.0-resp",
        "errorcode": "error",
    }
    prev = None
    for i, (t, to_server, fb) in enumerate(rows[:80]):
        txt = fb.decode("gbk", errors="replace")
        label = "?"
        for needle, name in labels.items():
            if needle in txt:
                label = name
                break
        gap = f"{t - prev:.3f}" if prev is not None else "-"
        arrow = "C->S" if to_server else "S->C"
        print(f"  [{i:3d}] t={t-t0:8.3f} +{gap:>8} {arrow} {len(fb):6d}B {label}")
        prev = t


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    analyze("system_blocks_20260801_132302.pcap", 2)
