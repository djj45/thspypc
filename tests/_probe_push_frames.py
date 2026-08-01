#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""离线深挖 realtime_push 抓包里服务端推送帧的真实结构（写文件，避免终端编码问题）。

用法: py tests/_probe_push_frames.py [pcap]
"""
import os, sys, re, struct
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.dirname(__file__))
import capture_timeline as c
from thspypc.protocol import parse_kline_hd3_response, decode_ths_float, TIMELINE_DATATYPE

PCAP = sys.argv[1] if len(sys.argv) > 1 else \
    "captures_live/realtime_push_20260724_104540.pcap"

out = []
def p(*a):
    out.append(" ".join(str(x) for x in a))

streams = c._tshark_streams(PCAP, 8901)
# 拿每帧时间（服务端方向）
import subprocess
def srv_frame_times(port):
    r = subprocess.run(
        [c.TSHARK, "-r", PCAP, "-Y", f"tcp.srcport=={port} and tcp.len>0",
         "-T", "fields", "-e", "frame.time_relative", "-e", "tcp.stream",
         "-e", "tcp.len", "-e", "tcp.payload"],
        capture_output=True, timeout=120)
    by_stream = {}
    for ln in r.stdout.decode().splitlines():
        parts = ln.split("\t")
        if len(parts) < 4:
            continue
        t, sid, ln2, hexp = parts
        try:
            t = float(t); sid = int(sid)
        except ValueError:
            continue
        by_stream.setdefault(sid, []).append((t, hexp))
    return by_stream

srv_times = srv_frame_times(8901)

for sid, cb, sb in streams:
    sframes = c._split_frames(sb)
    if not sframes:
        continue
    # 计算每帧大致时间（用该 stream 的服务端包时间）
    times = srv_times.get(sid, [])
    p(f"\n{'='*70}")
    p(f"stream {sid}: {len(sframes)} 个服务端帧, {len(sb)}B 总")
    p(f"{'='*70}")
    # 用包 payload 重组来对齐时间
    # 简化：按 MAGIC 把重组流切成帧，对应到包序列
    # 这里用近似：第 i 个帧的时间 ≈ 第 i 个有 MAGIC 的包时间
    frame_idx = 0
    for i, f in enumerate(sframes):
        tag = "hd3.1" if b"hd3.1\x00" in f else ("hd1.0" if b"hd1.0" in f else "")
        head_hex = f[:48].hex(" ")
        # 文本帧？
        is_text = False
        try:
            txt_preview = f[:60].decode("gbk", "replace")
            if any(k in txt_preview for k in ["pageid", "method", "market=", "CodeList",
                                              "instid", "datetime", "DataType"]):
                is_text = True
        except Exception:
            txt_preview = ""
        # 时间近似：第 i 个包
        t_approx = times[i][0] if i < len(times) else -1
        line = f"帧{i:3d} t~{t_approx:7.1f}s {len(f):6d}B"
        if tag:
            line += f" [{tag}]"
        if is_text:
            # 文本帧：打印关键字段
            one = txt_preview.replace("\n", "\\n")[:100]
            line += f" 文本: {one!r}"
        elif tag:
            line += f" 头48: {head_hex}"
            # 尝试解析
            try:
                recs = parse_kline_hd3_response(f)
            except Exception as e:
                line += f" 解析异常:{e}"
                recs = None
            if recs:
                line += f" -> {len(recs)}点"
                # 现价
                prices = [r.get("dt10") for r in recs if r.get("dt10") is not None]
                if prices:
                    line += f" 现价[{prices[0]}..{prices[-1]}]n={len(prices)}"
                t0 = recs[0].get("time"); tN = recs[-1].get("time")
                if t0:
                    line += f" [{t0.strftime('%H:%M:%S')}->{tN.strftime('%H:%M:%S')}]"
        p(line)

outpath = "captures_live/_probe_out.txt"
open(outpath, "w", encoding="utf-8").write("\n".join(out))
print(f"写入 {outpath} ({len(out)} 行)")
