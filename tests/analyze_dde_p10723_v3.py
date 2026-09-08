#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""DDE p10723 协议全景：请求模式聚合 + 响应指纹聚合 + 请求→响应关联。

输出 tests/_dde_map_level2.txt / _dde_map_normal.txt
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


def resp_fp(body: bytes):
    n = normalize_8901_response(body)
    for marker in (b"hd1.0", b"hd3.1", b"hd8d1.0"):
        pos = n.find(marker)
        if pos >= 0:
            base = pos + 6
            if len(n) < base + 10:
                return ("hd?", 0, 0, 0, 0, [], len(n))
            cnt = struct.unpack_from("<H", n, base)[0]
            v2 = struct.unpack_from("<H", n, base + 2)[0]
            hs = struct.unpack_from("<H", n, base + 6)[0]
            fc = struct.unpack_from("<H", n, base + 8)[0]
            fields = []
            for i in range(min(fc, 60)):
                e = n[base + 10 + i * 4 : base + 14 + i * 4]
                if len(e) < 4:
                    break
                fields.append((e[0], e[1], e[3]))
            return (marker.decode(), cnt, v2, hs, fc, fields, len(n))
    return ("none", 0, 0, 0, 0, [], len(n))


def analyze(path: Path, tag: str, out):
    streams = reassemble(path)
    for key in sorted(streams, key=lambda k: streams[k][0][0]):
        (sp, dp, src, dst) = key
        segs = streams[key]
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
        # 请求模式聚合
        req_groups = defaultdict(list)
        for ts, b in reqs:
            r = route_of(b)
            t = b.decode("gbk", errors="replace")
            m_cl = re.search(r"CodeList=([^\r\n]*)", t)
            m_dt = re.search(r"DataType=([^\r\n]*)", t)
            m_dtt = re.search(r"DateTime=([^\r\n]*)", t)
            m_sb = re.search(r"SortBy=(\d+)", t)
            m_sd = re.search(r"SortDir=(\w+)", t)
            m_sc = re.search(r"SortCount=(\d+)", t)
            m_sbe = re.search(r"SortBegin=(\d+)", t)
            m_ret = re.search(r"rettype=(\w+)", t)
            m_m = re.search(r"method=(\w+)", t)
            cl = (m_cl.group(1) if m_cl else "").split(";")
            ncode = 0
            codes = []
            for part in cl:
                mm = re.match(r"(\d+)\(([^)]*)\)", part)
                if mm:
                    ncode += len(mm.group(2).split(",")) - 1 if mm.group(2) else 0
            dt = (m_dt.group(1).strip() if m_dt else "").rstrip(",")
            dtt = (m_dtt.group(1).strip() if m_dtt else "")
            key_pat = (r, dt[:60], dtt[:24], m_sb.group(1) if m_sb else "",
                       m_sd.group(1) if m_sd else "", m_sc.group(1) if m_sc else "",
                       m_sbe.group(1) if m_sbe else "", m_ret.group(1) if m_ret else "",
                       m_m.group(1) if m_m else "")
            req_groups[key_pat].append((ts, ncode, t))
        out.write("  [请求模式聚合]\n")
        for (r, dt, dtt, sb, sd, sc, sbe, ret, m), items in sorted(req_groups.items()):
            codes = [n for _, n, _ in items]
            n = len(items)
            ex = items[-1][2]
            cl_m = re.search(r"CodeList=([^\r\n]*)", ex)
            sample_cl = (cl_m.group(1)[:90] if cl_m else "?")
            out.write(f"  r=0x{r:04x} n={n:3d} codes={codes[0] if codes else 0}..{codes[-1] if codes else 0}"
                      f" DT={dt} DateTime={dtt} SB={sb} SD={sd} SC={sc} SBE={sbe} ret={ret} M={m}\n")
            if sb:
                out.write(f"      ex CL={sample_cl}\n")
        # 响应指纹聚合
        fp_groups = defaultdict(list)
        for ts, b in resps:
            m, cnt, v2, hs, fc, fields, ln = resp_fp(b)
            fp_groups[(m, cnt, v2, hs, fc, tuple(fields), ln)].append((ts, b))
        out.write("  [响应指纹聚合]\n")
        for (marker, cnt, v2, hs, fc, fields, ln), items in sorted(
                fp_groups.items(), key=lambda kv: -len(kv[1])):
            out.write(f"  x{len(items):3d} {marker} cnt={cnt} v2=0x{v2:04x} hs={hs} fc={fc} fields={fields[:12]}... len={ln}\n")
            if marker != "none" and cnt > 5:
                # 解码前2条
                n = normalize_8901_response(items[0][1])
                pos = n.find(marker.encode())
                base = pos + 6
                flds = fields
                body = n[base + 10 + len(flds) * 4 :]
                from thspypc.codecs.compression import _decode_bitrle_0x13746d0, _transpose_bitplane_0x1763410
                try:
                    expected = cnt * hs
                    bp = _decode_bitrle_0x13746d0(body, expected)
                    rows = _transpose_bitplane_0x1763410(bp, hs, cnt)
                    for i in range(min(2, cnt)):
                        row = rows[i * hs : (i + 1) * hs]
                        vals = {}
                        off = 0
                        for dt, fmt, w in flds:
                            c = row[off : off + w]
                            off += w
                            if dt == 5:
                                vals["code"] = c[1:7].split(b"\x00")[0].decode("ascii", "replace")
                            elif fmt == 0x7b:
                                vals[f"dt{dt}"] = int.from_bytes(c, "little")
                            elif fmt in (0x70, 0x64) and w == 4:
                                from thspypc.codecs.numeric import decode_ths_float
                                vals[f"dt{dt}"] = decode_ths_float(int.from_bytes(c, "little"))
                            else:
                                vals[f"dt{dt}"] = c.hex()
                        out.write(f"      row{i}: {vals}\n")
                except Exception as exc:
                    out.write(f"      bitrle err {exc}\n")


def main():
    for path, tag, outp in ((PCAP_L2, "LEVEL2", "_dde_map_level2.txt"),
                            (PCAP_NORMAL, "NORMAL", "_dde_map_normal.txt")):
        with open(ROOT / "tests" / outp, "w", encoding="utf-8") as f:
            f.write(f"{tag}\n")
            analyze(path, tag, f)
    print("done")


if __name__ == "__main__":
    main()
