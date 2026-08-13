# -*- coding: utf-8 -*-
"""Dump the full client->server request flow of a seal_sort pcap in time order."""
from __future__ import annotations

import subprocess
import sys
from collections import defaultdict

TSHARK = r"D:\software\Wireshark_4.6.7_Portable\Wireshark\WiresharkPortable64\App\Wireshark\tshark.exe"
MAGIC = b"\xfd\xfd\xfd\xfd"


def run_tshark(pcap, y_filter, fields):
    cmd = [TSHARK, "-r", pcap, "-Y", y_filter, "-T", "fields"]
    for f in fields:
        cmd += ["-e", f]
    cmd += ["-E", "separator=\t"]
    r = subprocess.run(cmd, capture_output=True, timeout=180)
    return r.stdout.decode("utf-8", errors="replace")


def extract_kv(text):
    kv = {}
    for k in ["CodeList", "DataType", "SortType", "SortBy", "SortDir",
              "SortBegin", "SortCount", "pageid", "market", "method",
              "instid", "StockNameVer", "prototype"]:
        idx = text.find(k + "=")
        if idx >= 0:
            val = text[idx + len(k) + 1:]
            end = val.find("\r")
            if end < 0:
                end = val.find("\n")
            kv[k] = val[:end] if end >= 0 else val[:50]
    return kv


def main():
    pcap = sys.argv[1]
    out = run_tshark(pcap, "tcp.dstport == 8901", ["frame.number", "frame.time_relative", "ip.dst", "tcp.stream", "tcp.payload"])
    # group by stream, keep frame order
    stream_frames = defaultdict(list)
    for line in out.splitlines():
        p = line.split("\t")
        if len(p) < 5:
            continue
        fr, t, dst, stream, hx = p[0], p[1], p[2], p[3], p[4]
        if not hx:
            continue
        try:
            data = bytes.fromhex(hx.replace(":", ""))
        except ValueError:
            continue
        stream_frames[(stream, dst)].append((float(t) if t else 0.0, data))

    # reassemble per stream and split into frames
    events = []
    for (stream, dst), frames in stream_frames.items():
        buf = b""
        for t, data in frames:
            buf += data
            # try to split complete frames
            while True:
                i = buf.find(MAGIC)
                if i < 0:
                    break
                # need at least 8 bytes header after magic
                if len(buf) < i + 12:
                    break
                length = int(buf[i+4:i+12], 16)
                total = 12 + length
                if len(buf) < i + total:
                    break
                body = buf[i+12:i+total]
                buf = buf[i+total:]
                text = body.decode("gbk", errors="replace")
                if "SortBy=" in text or "CodeList=" in text or "method=" in text:
                    events.append((t, stream, dst, body, text))

    events.sort(key=lambda e: e[0])
    print(f"total request frames: {len(events)}\n")
    for t, stream, dst, body, text in events:
        kv = extract_kv(text)
        cl = kv.get("CodeList", "")
        sb = kv.get("SortBy", "")
        pg = kv.get("pageid", "")
        meth = kv.get("method", "")
        cl_head = cl[:70] + ("..." if len(cl) > 70 else "")
        # count codes in CodeList
        ncode = cl.count(",")
        print(f"t={t:7.2f}s s{stream} {dst} pg={pg:>6} sb={sb:>7} method={meth:>12} codes~{ncode:>3} CodeList={cl_head}")


if __name__ == "__main__":
    main()
