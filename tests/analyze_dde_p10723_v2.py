#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""DDE p10723 深度分析 v2：完整文本帧 + 响应原始字节 dump。

用法: py tests/analyze_dde_p10723_v2.py
输出: tests/_dde_v2_level2.txt, tests/_dde_v2_normal.txt
"""
from __future__ import annotations

import re
import struct
import sys
from collections import defaultdict
from pathlib import Path

import dpkt

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, ValueError):
    pass

from thspypc.codecs.compression import normalize_8901_response  # noqa: E402

MAGIC = b"\xfd\xfd\xfd\xfd"
PCAP_L2 = ROOT / "captures_live" / "kanpan_20260808_114753.pcap"
PCAP_NORMAL = ROOT / "captures_live" / "kanpan_20260808_114923.pcap"


def split_frames(data: bytes):
    frames = []
    i = 0
    while i + 12 <= len(data):
        if data[i : i + 4] == MAGIC:
            try:
                ln = int(data[i + 4 : i + 12], 16)
            except ValueError:
                i += 1
                continue
            body = data[i + 12 : i + 12 + ln]
            if len(body) < ln:
                break
            frames.append((body, i))
            i += 12 + ln
        else:
            i += 1
    return frames


def reassemble(pcap_path: Path):
    streams = defaultdict(list)
    with open(pcap_path, "rb") as f:
        head = f.read(4)
        f.seek(0)
        if head == b"\x0a\x0d\x0d\x0a":
            pcap = dpkt.pcapng.Reader(f)
        else:
            pcap = dpkt.pcap.Reader(f)
        for ts, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except Exception:
                continue
            ip = eth.data
            if not isinstance(ip, dpkt.ip.IP):
                continue
            tcp = ip.data
            if not isinstance(tcp, dpkt.tcp.TCP):
                continue
            if not (tcp.sport in (8901, 9601) or tcp.dport in (8901, 9601)):
                continue
            if len(tcp.data) == 0:
                continue
            client = tcp.sport in (8901, 9601)
            key = (tcp.sport, tcp.dport, ip.src, ip.dst) if not client else (
                tcp.dport, tcp.sport, ip.dst, ip.src)
            streams[key].append((ts, "S" if client else "C", tcp.data))
    out = {}
    for key, segs in streams.items():
        out[key] = list(sorted(segs, key=lambda x: x[0]))
    return out


def route_of(body: bytes):
    if len(body) >= 13 and body[0] == 0x09:
        return int.from_bytes(body[11:13], "little")
    if len(body) >= 12 and body[:4] == b"\x00\x16\x00\x00":
        return int.from_bytes(body[10:12], "little")
    return -1


def summarize_resp(body: bytes):
    n = normalize_8901_response(body)
    s = f"len={len(body)} norm={len(n)}"
    for marker in (b"hd1.0", b"hd3.1", b"hd8d1.0"):
        pos = n.find(marker)
        if pos >= 0:
            base = pos + 6
            if len(n) >= base + 10:
                dc32 = struct.unpack_from("<I", n, base)[0]
                dc16 = struct.unpack_from("<H", n, base)[0]
                flag = struct.unpack_from("<H", n, base + 4)[0]
                hs = struct.unpack_from("<H", n, base + 6)[0]
                fc = struct.unpack_from("<H", n, base + 8)[0]
                fields = []
                for i in range(min(fc, 40)):
                    e = n[base + 10 + i * 4 : base + 14 + i * 4]
                    if len(e) < 4:
                        break
                    fields.append((e[0], e[1], e[3]))
                s += (f" {marker.decode()}@off{pos} dc32=0x{dc32:x} dc16={dc16}"
                      f" flag=0x{flag:04x} hs={hs} fc={fc}"
                      f" fields={fields}")
                # 文本字段（SortTotal 等）
                t = n.decode("gbk", errors="replace")
                m = re.search(r"SortTotal=(\d+)", t)
                if m:
                    s += f" SortTotal={m.group(1)}"
                m = re.search(r"SortDataCount=(\d+)", t)
                if m:
                    s += f" SortDataCount={m.group(1)}"
            return s
    if n[:1] == b"\x09":
        t = n.decode("gbk", errors="replace")
        return s + " text09: " + t[:300].replace("\r", "\\r").replace("\n", "\\n")
    return s + " hd_none"


def analyze(path: Path, tag: str, out):
    streams = reassemble(path)
    for key in sorted(streams, key=lambda k: streams[k][0][0]):
        (sp, dp, src, dst) = key
        segs = streams[key]
        if dp != 8901:
            continue
        t0 = segs[0][0]
        reqs, resps = [], []
        for ts, d, seg in segs:
            if d == "C":
                for b, _ in split_frames(seg):
                    reqs.append((ts, b))
            else:
                for b, _ in split_frames(seg):
                    resps.append((ts, b))
        out.write(f"\n### stream {src}:{sp}->{dst} req={len(reqs)} resp={len(resps)}\n")
        # 全时序打印：p10723 请求（含文本协议）+ 跟随响应
        timeline = []
        for ts, b in reqs:
            t = b.decode("gbk", errors="replace")
            r = route_of(b)
            if "pageid=10723" in t or (r == 0x3437):
                timeline.append((ts, "REQ", b))
        for ts, b in resps:
            timeline.append((ts, "RESP", b))
        timeline.sort(key=lambda x: x[0])
        pending = []
        last_req = 0.0
        for ts, kind, b in timeline:
            if kind == "REQ":
                pending = [(ts, b)]
                last_req = ts
                t = b.decode("gbk", errors="replace")
                r = route_of(b)
                # 提取关键文本
                parts = []
                for pat, name in [
                    (r"CodeList=([^\r\n]*)", "CL"),
                    (r"DataType=([^\r\n]*)", "DT"),
                    (r"DateTime=([^\r\n]*)", "DTIME"),
                    (r"SortBy=(\d+)", "SB"),
                    (r"SortBegin=(\d+)", "SBE"),
                    (r"SortCount=(\d+)", "SC"),
                    (r"SortDir=(\w+)", "SD"),
                    (r"SortType=(\w+)", "ST"),
                    (r"FuncPeriod=([\w\-]*)", "FP"),
                    (r"rettype=(\w+)", "RET"),
                    (r"method=(\w+)", "M"),
                    (r"instid=(\d+)", "IID"),
                    (r"dataclass=([\w\-,]*)", "DC"),
                ]:
                    m = re.search(pat, t)
                    if m and m.group(1):
                        parts.append(f"{name}={m.group(1)[:120]}")
                out.write(f"[t={ts-t0:7.2f}s] REQ r=0x{r:04x} {' '.join(parts)}\n")
            else:
                if ts - last_req > 3.0:
                    continue
                s = summarize_resp(b)
                out.write(f"[t={ts-t0:7.2f}s] RESP {s}\n")


def main():
    with open(ROOT / "tests" / "_dde_v2_level2.txt", "w", encoding="utf-8") as f:
        f.write("LEVEL2\n")
        analyze(PCAP_L2, "LEVEL2", f)
    with open(ROOT / "tests" / "_dde_v2_normal.txt", "w", encoding="utf-8") as f:
        f.write("NORMAL\n")
        analyze(PCAP_NORMAL, "NORMAL", f)
    print("done")


if __name__ == "__main__":
    main()
