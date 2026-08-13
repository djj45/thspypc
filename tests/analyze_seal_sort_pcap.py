# -*- coding: utf-8 -*-
"""Analyze a seal_sort pcap: reassemble streams and dump SortBy requests."""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from collections import defaultdict

TSHARK = r"D:\software\Wireshark_4.6.7_Portable\Wireshark\WiresharkPortable64\App\Wireshark\tshark.exe"

TOKENS = ["Sort", "SortBy", "SortType", "CodeList", "265260", "68758", "199112", "DataType", "SortCount", "SortBegin", "pageid"]


def run_tshark(pcap, y_filter, fields):
    cmd = [TSHARK, "-r", pcap, "-Y", y_filter, "-T", "fields"]
    for f in fields:
        cmd += ["-e", f]
    cmd += ["-E", "separator=\t"]
    r = subprocess.run(cmd, capture_output=True, timeout=180)
    return r.stdout.decode("utf-8", errors="replace")


def token_counts(pcap):
    print("=== token occurrences (per TCP segment) ===")
    for tok in TOKENS:
        out = run_tshark(pcap, 'tcp.payload contains "' + tok + '"', ["frame.number"])
        n = len([l for l in out.splitlines() if l.strip()])
        print(f"  {tok:10s}: {n}")


def reassemble_streams(pcap):
    """Per-stream client->server reassembly of tcp payloads (hex)."""
    out = run_tshark(
        pcap,
        "tcp.dstport == 8901",
        ["tcp.stream", "ip.dst", "tcp.payload"],
    )
    streams = defaultdict(list)
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        stream, dst, hx = parts[0], parts[1], parts[2]
        if not hx:
            continue
        try:
            data = bytes.fromhex(hx.replace(":", ""))
        except ValueError:
            continue
        streams[(stream, dst)].append(data)
    return {k: b"".join(v) for k, v in streams.items()}


def extract_kv(text):
    kv = {}
    keys = ["CodeList", "DataType", "SortType", "SortBy", "SortDir",
            "SortBegin", "SortCount", "FuncPeriod", "DateTime", "pageid"]
    for k in keys:
        idx = text.find(k + "=")
        if idx >= 0:
            val = text[idx + len(k) + 1:]
            end = val.find("\r")
            if end < 0:
                end = val.find("\n")
            kv[k] = val[:end] if end >= 0 else val[:60]
    return kv


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    args = ap.parse_args()
    pcap = args.pcap
    token_counts(pcap)

    streams = reassemble_streams(pcap)
    print(f"\n=== reassembled streams: {len(streams)} ===")
    reqs = []
    for (stream, dst), data in streams.items():
        text = data.decode("gbk", errors="replace")
        idx = 0
        while True:
            idx = text.find("SortBy=", idx)
            if idx < 0:
                break
            # capture a window around the SortBy= occurrence
            start = max(0, text.rfind("\xfd\xfd\xfd\xfd", 0, idx))
            window = text[idx:idx + 400]
            kv = extract_kv(window)
            if kv.get("SortBy"):
                reqs.append((stream, dst, kv, window))
            idx += 1
    print(f"\n=== SortBy requests found: {len(reqs)} ===")
    for stream, dst, kv, window in reqs:
        sb = kv.get("SortBy", "?")
        print(f"\n--- stream={stream} dst={dst} SortBy={sb} ---")
        for k in ["CodeList", "DataType", "SortType", "SortBy", "SortDir", "SortBegin", "SortCount", "pageid"]:
            if k in kv:
                print(f"   {k:12s} = {kv[k]}")


if __name__ == "__main__":
    main()
