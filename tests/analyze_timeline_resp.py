#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""离线分析历史分时响应帧结构（一次性 dump 清楚，避免反复猜字节切分）。

用法: py tests/analyze_timeline_resp.py [pcap]
不传 pcap 用默认 timeline_20260724_090145.pcap
"""
import os, sys, re, struct
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.dirname(__file__))
import capture_timeline as c
from thspypc.protocol import decode_ths_float


def main(pcap):
    streams = c._tshark_streams(pcap, 8901)
    # 找含历史分时(DateTime=8192 arg1≠0)请求的 stream
    target_sids = set()
    for sid, cb, sb in streams:
        for fb in c._split_frames(cb):
            try: txt = fb.decode("gbk", "replace")
            except: continue
            m = re.search(r"DateTime=8192\((\d+)-", txt)
            if m and int(m.group(1)) != 0:
                target_sids.add(sid)
    print(f"含历史分时的 stream: {target_sids}\n")

    for sid, cb, sb in streams:
        if sid not in target_sids:
            continue
        sframes = c._split_frames(sb)
        print(f"=== stream {sid}: {len(sframes)} 个响应帧 ===")
        for i, sf in enumerate(sframes):
            if len(sf) < 20:
                continue
            tag = None
            if b"hd1.0" in sf:
                tag = "hd1.0"
            elif b"hd3.1" in sf:
                tag = "hd3.1"
            elif b"CodeListSize" in sf or b"MarketTime" in sf:
                print(f"  帧{i}: 文本帧 {len(sf)}B: {sf[:80].decode('gbk','replace')[:80]}")
                continue
            else:
                # 看前16字节
                print(f"  帧{i}: 未知 {len(sf)}B 前16: {sf[:16].hex(' ')}")
                continue
            if tag:
                p = sf.find(tag.encode())
                base = p + len(tag) + 1  # 跳过 tag\0
                print(f"\n  帧{i}: {tag} {len(sf)}B  tag@{p}")
                print(f"    base 后 32 字节: {sf[base:base+32].hex(' ')}")
                # 系统性尝试 3 种字段表切法
                for layout, d_off, h_off, f_off in [
                    ("dc4B hs2B fc2B", 0, 4, 6),
                    ("dc2B pad2B hs2B fc2B", 0, 4, 6),
                    ("dc4B +2B hs2B fc2B", 0, 6, 8),
                ]:
                    try:
                        dc4 = struct.unpack("<I", sf[base+d_off:base+d_off+4])[0]
                        dc2 = struct.unpack("<H", sf[base:base+2])[0]
                        hs = struct.unpack("<H", sf[base+h_off:base+h_off+2])[0]
                        fc = struct.unpack("<H", sf[base+f_off:base+f_off+2])[0]
                        print(f"    [{layout}] dc4={dc4:#010x} dc2={dc2} hs={hs} fc={fc}")
                        if 1 <= fc <= 40 and 10 <= hs <= 300:
                            ftoff = base + f_off + 2
                            ft = sf[ftoff:ftoff+fc*4]
                            if len(ft) >= fc*4:
                                widths = [ft[j*4+3] for j in range(fc)]
                                total = sum(widths)
                                dts = [ft[j*4] for j in range(fc)]
                                print(f"      → 字段表 dt={dts[:12]}... widths总={total}")
                                if total == hs:
                                    print(f"      *** width和==hs! dc2={dc2} hs={hs} fc={fc}")
                    except Exception as e:
                        print(f"    [{layout}] err {e}")
        print()


if __name__ == "__main__":
    pcap = sys.argv[1] if len(sys.argv) > 1 else \
        "captures_live/timeline_20260724_090145.pcap"
    main(pcap)
