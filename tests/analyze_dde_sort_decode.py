#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""用现有 parse_stock_list_response 解析 DDE sort/主力资金响应，验证代码解码。"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

import dpkt

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, ValueError):
    pass

from thspypc.protocol import parse_stock_list_response  # noqa: E402
from thspypc.codecs.compression import normalize_8901_response  # noqa: E402

MAGIC = b"\xfd\xfd\xfd\xfd"
PCAP_L2 = ROOT / "captures_live" / "kanpan_20260808_114753.pcap"


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
    streams = {}
    with open(pcap_path, "rb") as f:
        head = f.read(4)
        f.seek(0)
        pcap = dpkt.pcapng.Reader(f) if head == b"\x0a\x0d\x0d\x0a" else dpkt.pcap.Reader(f)
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
            streams.setdefault(key, []).append((ts, "S" if client else "C", tcp.data))
    out = {}
    for key, segs in streams.items():
        out[key] = list(sorted(segs, key=lambda x: x[0]))
    return out


def main():
    streams = reassemble(PCAP_L2)
    for key in sorted(streams, key=lambda k: streams[k][0][0]):
        (sp, dp, src, dst) = key
        if dp != 8901:
            continue
        for ts, d, seg in streams[key]:
            if d != "S":
                continue
            for b, _ in split_frames(seg):
                n = normalize_8901_response(b)
                if b"hd3.1" not in n:
                    continue
                for marker in (b"hd3.1",):
                    pos = n.find(marker)
                    base = pos + 6
                    if len(n) < base + 10:
                        continue
                    cnt = struct.unpack_from("<H", n, base)[0]
                    v2 = struct.unpack_from("<H", n, base + 2)[0]
                    hs = struct.unpack_from("<H", n, base + 6)[0]
                    fc = struct.unpack_from("<H", n, base + 8)[0]
                    if v2 != 0x0100 or cnt == 0:
                        continue
                    try:
                        r = parse_stock_list_response(n)
                        stocks = r["stocks"]
                        extra = ""
                        if stocks:
                            extra = " | first codes: " + ",".join(
                                s["code"] for s in stocks[:8])
                        print(f"stream {src} {ts:.2f}: cnt={cnt} v2=0x{v2:04x} hs={hs} fc={fc}"
                              f" SortTotal={r['sort_total']} SortBegin={r['sort_begin']}"
                              f" SortCount={r['sort_count']} SortDataCount={r['sort_data_count']}"
                              f" stocks={len(stocks)}{extra}")
                    except Exception as exc:
                        print(f"stream {src} parse err: {exc}")


if __name__ == "__main__":
    main()
