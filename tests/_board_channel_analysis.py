#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""分析系统板块专用通道（sid=2）的建连引导序列，逐帧 dump 请求/响应。

探针：不入库（tests/_*.py 约定）。
"""
from __future__ import annotations

import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TSHARK = r"D:\software\Wireshark_4.6.7_Portable\Wireshark\WiresharkPortable64\App\Wireshark\tshark.exe"
MAGIC = b"\xfd\xfd\xfd\xfd"


def _run(args):
    r = subprocess.run(args, capture_output=True, timeout=180)
    return r.stdout.decode("utf-8", errors="replace")


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--pcap", default="system_blocks_20260801_132302.pcap")
    parser.add_argument("--stream", type=int, default=2)
    args = parser.parse_args()
    pcap = os.path.join(ROOT, "captures_live", args.pcap)
    streams = sorted(
        {int(s) for s in _run(
            [TSHARK, "-r", pcap, "-Y", "tcp.port==8901",
             "-T", "fields", "-e", "tcp.stream"]
        ).split() if s}
    )
    print("streams:", streams)
    for sid in streams:
        if args.stream is not None and sid != args.stream:
            continue
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
            print(f"\n===== stream {sid} {direction}: {len(frames)} frames =====")
            for i, fb in enumerate(frames):
                if direction == "C->S" and i > 70:
                    break
                if direction == "S->C" and i > 24:
                    break
                txt = fb.decode("gbk", errors="replace")
                head = fb[:23].hex(" ")
                summary = ""
                if "method=subreal" in txt:
                    m = re.search(r"market=(\w+)", txt)
                    p = re.search(r"pageid=(\d+)", txt)
                    summary = (
                        f"SUBREAL market={m.group(1) if m else '?'} "
                        f"pageid={p.group(1) if p else '?'}"
                    )
                elif "MarketCode" in txt and "StockLinkVer" in txt:
                    summary = "MKT_INIT(StockLinkVer)"
                elif "MarketCode" in txt and "StockNameVer" in txt:
                    summary = "STOCKNAME(MarketCode+StockNameVer)"
                elif "[5],[55]" in txt or "DataType=[5]" in txt:
                    summary = "DATATYPE classification table"
                elif "pageid=" in txt:
                    m = re.search(r"pageid=(\d+)", txt)
                    dt = re.search(r"DateTime=(\d+\([^)]*\))", txt)
                    code = re.search(r"CodeList=(\d+)\(([^)]*)\)", txt)
                    summary = (
                        f"QUERY pageid={m.group(1) if m else '?'} "
                        f"DateTime={dt.group(1) if dt else '-'} "
                        f"codes={code.group(2)[:40] if code else '-'}"
                    )
                elif b"hd3.1" in fb:
                    summary = f"hd3.1 response {len(fb)}B"
                elif "S-OS" in txt or "S-Version" in txt:
                    summary = f"INIT/SERVER config {len(fb)}B"
                elif txt.strip():
                    summary = (
                        f"TEXT {len(fb)}B: "
                        f"{txt[:90].replace(chr(10), '|')!r}"
                    )
                else:
                    summary = f"BINARY {len(fb)}B"
                print(f"  [{i:2d}] len={len(fb):6d} {head[:42]}  {summary}")


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    main()
