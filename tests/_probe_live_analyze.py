#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""分析 _probe_live.pcap：探针连接的 TCP 细节 + 帧序列 + FIN 时机。

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
    r = subprocess.run(args, capture_output=True, timeout=120)
    return r.stdout.decode("utf-8", errors="replace")


def main():
    pcap = ROOT / "captures_live" / "_probe_live.pcap"
    out = _run([
        TSHARK, "-r", str(pcap),
        "-T", "fields", "-e", "frame.number", "-e", "frame.time_relative",
        "-e", "ip.src", "-e", "ip.dst", "-e", "tcp.srcport",
        "-e", "tcp.dstport", "-e", "tcp.len", "-e", "tcp.flags.str",
        "-e", "tcp.payload",
    ])
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) < 9:
            continue
        num, t, src, dst, sport, dport, tlen, flags, payload = parts[:9]
        try:
            t = float(t)
        except ValueError:
            continue
        detail = ""
        if payload:
            data = bytes.fromhex("".join(payload.split()))
            frames = data.split(MAGIC)
            if len(frames) > 1:
                detail = f" magic={len(frames)-1}"
            fb = None
            for sub in frames:
                if len(sub) >= 8:
                    try:
                        blen = int(sub[:8], 16)
                    except ValueError:
                        continue
                    fb = sub[8:8 + blen]
                    if fb:
                        break
            if fb:
                txt = fb.decode("gbk", errors="replace")
                if "Ask=login" in txt:
                    detail += " LOGIN"
                elif "subreal" in txt:
                    detail += " subreal"
                elif "Reply=login" in txt:
                    detail += " login-reply"
                elif "pageid=" in txt:
                    detail += " pageid"
                elif "MarketCode" in txt:
                    detail += " MKT_INIT"
                else:
                    detail += f" {len(fb)}B"
        print(f"{num:>4} t={t:7.3f} {src}->{dst} {sport}->{dport} "
              f"len={tlen} flags={flags}{detail}")


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    main()
