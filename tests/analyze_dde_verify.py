#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""DDE 验证：排序响应代码的市场字节 + 名称表响应 + 主力字段数值。

输出 tests/_dde_verify.txt
"""
from __future__ import annotations

import re
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

from thspypc.codecs.compression import (  # noqa: E402
    _decode_bitrle_0x13746d0,
    _transpose_bitplane_0x1763410,
    normalize_8901_response,
)
from thspypc.protocol import parse_stock_list_response  # noqa: E402

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


def find_hd(n: bytes):
    for marker in (b"hd1.0", b"hd3.1", b"hd8d1.0"):
        pos = n.find(marker)
        if pos >= 0:
            return marker, pos
    return None, -1


def decode_rows(n: bytes, marker: bytes, pos: int, want: int = 6):
    base = pos + 6
    cnt = struct.unpack_from("<H", n, base)[0]
    v2 = struct.unpack_from("<H", n, base + 2)[0]
    flag = struct.unpack_from("<H", n, base + 4)[0]
    hs = struct.unpack_from("<H", n, base + 6)[0]
    fc = struct.unpack_from("<H", n, base + 8)[0]
    fields = []
    for i in range(fc):
        e = n[base + 10 + i * 4 : base + 14 + i * 4]
        if len(e) < 4:
            break
        fields.append((e[0], e[1], e[3]))
    payload = n[base + 10 + fc * 4 + 8 :]
    rows = _transpose_bitplane_0x1763410(_decode_bitrle_0x13746d0(payload, cnt * hs), hs, cnt)
    out = []
    for i in range(min(want, cnt)):
        row = rows[i * hs : (i + 1) * hs]
        d = {}
        off = 0
        for dt, fmt, w in fields:
            c = row[off : off + w]
            off += w
            if dt == 5:
                d["mkt"] = c[0]
                d["code"] = c[1:7].split(b"\x00")[0].decode("ascii", "replace")
            elif fmt == 0x7b:
                d[f"dt{dt}"] = int.from_bytes(c, "little", signed=False)
            elif fmt in (0x70, 0x64) and w == 4:
                from thspypc.codecs.numeric import decode_ths_float
                d[f"dt{dt}"] = decode_ths_float(int.from_bytes(c, "little"))
            else:
                d[f"dt{dt}_h"] = c.hex()
        out.append(d)
    return cnt, v2, flag, hs, fc, fields, out


def main():
    out_path = ROOT / "tests" / "_dde_verify.txt"
    with open(out_path, "w", encoding="utf-8") as f:
        for path, tag in ((PCAP_L2, "LEVEL2"), (PCAP_NORMAL, "NORMAL")):
            f.write(f"\n===== {tag} =====\n")
            streams = reassemble(path)
            for key in sorted(streams, key=lambda k: streams[k][0][0]):
                (sp, dp, src, dst) = key
                if dp != 8901:
                    continue
                for ts, d, seg in streams[key]:
                    if d != "S":
                        continue
                    for b, _ in split_frames(seg):
                        n = normalize_8901_response(b)
                        marker, pos = find_hd(n)
                        if marker is None:
                            continue
                        t = n.decode("gbk", errors="replace")
                        m = re.search(r"SortTotal=(\d+)", t)
                        sort_total = m.group(1) if m else ""
                        try:
                            cnt, v2, flag, hs, fc, fields, rows = decode_rows(n, marker, pos)
                        except Exception as exc:
                            continue
                        if cnt > 5 or sort_total:
                            f.write(f"{src} t={ts:.2f} {marker.decode()} cnt={cnt} v2=0x{v2:04x}"
                                    f" flag=0x{flag:04x} hs={hs} fc={fc} SortTotal={sort_total}\n")
                            for r in rows:
                                f.write(f"    {r}\n")
                            if rows:
                                f.write("    ...\n")


if __name__ == "__main__":
    main()
