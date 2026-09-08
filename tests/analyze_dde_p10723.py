#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""分析 DDE/看盘 pageid=10723 协议（Level2 + 普通账号双 pcap 对照）。

输出：
  1. 每流时间线：p10723 请求（route/CodeList/DataType/DateTime/文本）→ 响应指纹
  2. 请求模式分组：同 (route, DataType, period) 的请求序列，观察翻页/排序
  3. 响应 hd 表指纹：(marker, dc, flag, hs, fc, 字段表)
  4. 大列表响应（dc~5300）字段解码抽样
用法：
  py tests/analyze_dde_p10723.py
"""
from __future__ import annotations

import struct
import sys
from collections import Counter, defaultdict
from pathlib import Path

import dpkt

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, ValueError):
    pass

from thspypc.codecs.compression import normalize_8901_response  # noqa: E402
from thspypc.codecs.numeric import decode_ths_float  # noqa: E402

MAGIC = b"\xfd\xfd\xfd\xfd"
PCAP_L2 = ROOT / "captures_live" / "kanpan_20260808_114753.pcap"
PCAP_NORMAL = ROOT / "captures_live" / "kanpan_20260808_114923.pcap"


def split_frames(data: bytes):
    """按 FD FD FD FD + 8hex 长度 切帧，返回 (body, offset) 列表（容忍粘包/跨段由调用方保证）"""
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
    """重组 TCP 流：key=(dst_port, src, sport, dst) → 有序 (ts, direction, segment)"""
    import socket as _socket

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
            client = tcp.sport in (8901, 9601)  # server->client
            key = (tcp.sport, tcp.dport, ip.src, ip.dst) if not client else (
                tcp.dport, tcp.sport, ip.dst, ip.src)
            streams[key].append((ts, "S" if client else "C", tcp.data))
    out = {}
    for key, segs in streams.items():
        out[key] = list(sorted(segs, key=lambda x: x[0]))
    return out


def parse_subframes(body: bytes):
    """8901 请求/响应体解析：返回 [(sub_body, offset)]。单子帧 0x09 开头，双子帧 00 16 00 00 头"""
    out = []
    if body[:1] == b"\x09":
        out.append((body, 0))
        return out
    if body[:4] == b"\x00\x16\x00\x00":
        # 双子帧：总头 22B？按现有识别器 route 在 [10:12]
        out.append((body, 0))
        return out
    # 尝试按文本 \x00 分隔多子帧（dump 里看到 09 ... 00 09 ... 模式）
    return out


def extract_route(body: bytes):
    cand = []
    if len(body) >= 13 and body[0] == 0x09:
        cand.append(int.from_bytes(body[11:13], "little"))
    if len(body) >= 12 and body[:4] == b"\x00\x16\x00\x00":
        cand.append(int.from_bytes(body[10:12], "little"))
    return cand[0] if cand else 0


def req_text(body: bytes) -> str:
    t = body.decode("gbk", errors="replace")
    return t


def hd_fingerprint(body: bytes):
    """对响应体找 hd 标记，返回指纹 dict"""
    n = normalize_8901_response(body)
    res = {"norm_len": len(n), "marker": None}
    for marker in (b"hd1.0", b"hd3.1", b"hd8d1.0"):
        pos = n.find(marker)
        if pos >= 0:
            base = pos + 6
            if len(n) < base + 10:
                continue
            dc = struct.unpack("<I", n[base : base + 4])[0]
            flag = struct.unpack("<H", n[base + 4 : base + 6])[0]
            hs = struct.unpack("<H", n[base + 6 : base + 8])[0]
            fc = struct.unpack("<H", n[base + 8 : base + 10])[0]
            fields = []
            for i in range(fc):
                e = n[base + 10 + i * 4 : base + 14 + i * 4]
                if len(e) < 4:
                    break
                fields.append((e[0], e[1], e[3]))
            res = {
                "norm_len": len(n),
                "marker": marker.decode(),
                "dc": dc, "flag": hex(flag), "hs": hs, "fc": fc,
                "fields": fields,
                "body": n,
                "base": base,
            }
            break
    return res


def decode_hd(body: bytes, fp: dict, max_records: int = 8):
    """行主序解码 fp['fields'] 前 max_records 条"""
    if not fp.get("body"):
        return []
    n = fp["body"]
    base = fp["base"]
    fields = fp["fields"]
    hs = fp["hs"]
    dc = fp["dc"]
    recs = n[base + 10 + len(fields) * 4 :]
    out = []
    for r in range(min(dc, max_records)):
        row = recs[r * hs : (r + 1) * hs]
        if len(row) < hs:
            break
        d = {}
        off = 0
        for dt, fmt, w in fields:
            chunk = row[off : off + w]
            off += w
            if len(chunk) < w:
                break
            if dt == 5:
                code = chunk[1:7].split(b"\x00")[0].decode("ascii", "replace")
                d["code"] = code
            elif fmt in (0x70, 0x64) and w == 4:
                d[f"dt{dt}"] = decode_ths_float(struct.unpack("<I", chunk)[0])
            else:
                d[f"dt{dt}_h"] = chunk.hex()
        out.append(d)
    return out


def analyze_pcap(path: Path, tag: str):
    print("=" * 100)
    print(f"## {tag}: {path.name}")
    print("=" * 100)
    streams = reassemble(path)
    total_req = 0
    total_resp = 0
    for key in sorted(streams, key=lambda k: streams[k][0][0]):
        (sp, dp, src, dst) = key
        segs = streams[key]
        t0 = segs[0][0]
        if dp != 8901:
            continue
        # 按 direction 组包（段可能粘包/拆包）
        buf_c = b""
        buf_s = b""
        reqs = []
        resps = []
        for ts, d, seg in segs:
            if d == "C":
                buf_c += seg
                for b, _ in split_frames(buf_c):
                    reqs.append((ts, b))
                buf_c = b""
                # 残留：split_frames 可能留下未消费前缀
            else:
                buf_s += seg
                for b, _ in split_frames(buf_s):
                    resps.append((ts, b))
                buf_s = b""
        if not reqs and not resps:
            continue
        total_req += len(reqs)
        total_resp += len(resps)
        p10723 = []
        for ts, b in reqs:
            t = req_text(b)
            if "pageid=10723" in t:
                p10723.append(("req", ts, b, t))
        # 响应侧：按 hd 指纹匹配 p10723 对应的（无 pageid 文本，近似：跟随在 p10723 请求后）
        print(f"\n### stream {src}:{sp}->{dst}:{dp}  req={len(reqs)} resp={len(resps)}  p10723_req={len(p10723)}")
        # 合并成时序
        timeline = []
        for ts, b in reqs:
            t = req_text(b)
            if "pageid=10723" in t:
                timeline.append((ts, "REQ", b, t))
        for ts, b in resps:
            fp = hd_fingerprint(b)
            if fp["marker"]:
                timeline.append((ts, "RESP", b, f"{fp['marker']} dc={fp['dc']} flag={fp['flag']} hs={fp['hs']} fc={fp['fc']} fields={[ (f[0],hex(f[1]),f[2]) for f in fp['fields']]}"))
        timeline.sort(key=lambda x: x[0])
        # 只打印 p10723 请求及其后 3s 内的响应
        last_req_ts = None
        for ts, kind, b, desc in timeline:
            if kind == "REQ":
                route = extract_route(b)
                t = desc
                m_codelist = __import__("re").search(r"CodeList=([^\r\n;]*(?:\([^)]*\))?;?)", t)
                m_dt = __import__("re").search(r"DataType=([^\r\n]+)", t)
                m_dtt = __import__("re").search(r"DateTime=([^\r\n]+)", t)
                m_sort = __import__("re").search(r"SortBy=(\d+)[^\r\n]*\r\n", t)
                m_sb = __import__("re").search(r"SortBegin=(\d+)", t)
                m_sc = __import__("re").search(r"SortCount=(\d+)", t)
                m_sd = __import__("re").search(r"SortDir=(\w+)", t)
                m_funcp = __import__("re").search(r"FuncPeriod=(\w+)", t)
                m_ret = __import__("re").search(r"rettype=(\w+)", t)
                m_sub = __import__("re").search(r"SUB(\d)=\d+:\d+", t)
                print(f"  [t={ts-t0:.2f}s] REQ route=0x{route:04x} CodeList={m_codelist.group(1) if m_codelist else '?'} DataType={m_dt.group(1).strip() if m_dt else '?'} DateTime={m_dtt.group(1).strip() if m_dtt else '?'} SortBy={m_sort.group(1) if m_sort else '?'} SB={m_sb.group(1) if m_sb else '?'} SC={m_sc.group(1) if m_sc else '?'} SD={m_sd.group(1) if m_sd else '?'} FuncPeriod={m_funcp.group(1) if m_funcp else '?'} ret={m_ret.group(1) if m_ret else '?'}")
                if m_sort:
                    print(f"      sort: {m_sort.group(0).strip()}")
                last_req_ts = ts
            else:
                if last_req_ts is not None and ts - last_req_ts < 3.0:
                    print(f"  [t={ts-t0:.2f}s] RESP {desc}")
                    fp = hd_fingerprint(b)
                    if fp["dc"] and fp["dc"] > 1000:
                        recs = decode_hd(b, fp, 3)
                        for r in recs:
                            print(f"      sample: {r}")
        t0 = segs[0][0]


def main():
    for p, tag in ((PCAP_L2, "LEVEL2"), (PCAP_NORMAL, "NORMAL")):
        analyze_pcap(p, tag)


if __name__ == "__main__":
    main()
