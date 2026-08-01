#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""hexin 8901 连接拓扑：冷启动建了多少条连接？各干什么？

thspypc 只建 1 条登录连接，实测推送不来。
看 hexin 冷启动建多少条 8901 连接，每条的用途（login？心跳？查询？推送？）。
"""
import os, sys, re, subprocess
sys.path.insert(0, os.path.dirname(__file__))
import capture_timeline as c

out = []
def p(*a):
    out.append(" ".join(str(x) for x in a))

# market_open 是冷启动抓包，能看到所有连接建立
PCAP = "captures_live/market_open.pcap"
p("="*70)
p(f"【{PCAP}】所有 8901 stream 拓扑分析")
p("="*70)

# 所有 8901 stream + SYN 时间
r = subprocess.run(
    [c.TSHARK, "-r", PCAP, "-Y", "tcp.port==8901 and tcp.flags.syn==1 and tcp.flags.ack==0",
     "-T", "fields", "-e", "tcp.stream", "-e", "frame.time_relative",
     "-e", "ip.src", "-e", "ip.dst"],
    capture_output=True, timeout=120)
syn_info = {}  # sid -> (t, src, dst)
for ln in r.stdout.decode().splitlines():
    parts = ln.split("\t")
    if len(parts) < 4:
        continue
    sid, t, src, dst = parts
    try:
        sid = int(sid); t = float(t)
    except ValueError:
        continue
    syn_info[sid] = (t, src, dst)

p(f"8901 共 {len(syn_info)} 条连接（SYN）")
p()

# 每条 stream：SYN时间 + 是否login + 是否心跳 + 是否查询 + 服务端字节数
streams = c._tshark_streams(PCAP, 8901)
p(f"{'sid':>4} {'SYN时间':>8} {'login':>6} {'心跳':>5} {'查询':>5} {'srv字节':>9} {'cli字节':>9} 用途")
p("-"*80)
for sid, cb, sb in sorted(streams, key=lambda x: syn_info.get(x[0], (999,))[0]):
    syn_t = syn_info.get(sid, (-1, "", ""))[0]
    has_login = has_hb = has_query = False
    for fb in c._split_frames(cb):
        try:
            txt = fb.decode("gbk", "replace")
        except Exception:
            txt = ""
        if "Ask=login" in txt:
            has_login = True
        if b"\x12\x00\x03\x00" in fb[:12] and b"tsi0=" in fb:
            has_hb = True
        if "CodeList=" in txt or "method=" in txt:
            has_query = True
    # 判断用途
    if has_login:
        use = "★登录主连接"
    elif has_query and len(sb) > 10000:
        use = "查询+响应"
    elif has_hb and len(cb) < 500:
        use = "?推送/心跳连接(无login)"
    else:
        use = "?"
    p(f"{sid:>4} {syn_t:>7.1f}s {'Y' if has_login else '-':>6} "
      f"{'Y' if has_hb else '-':>5} {'Y' if has_query else '-':>5} "
      f"{len(sb):>9,} {len(cb):>9,} {use}")

# 重点：登录连接 vs 非登录连接
p("")
p("="*70)
p("【关键】非登录连接（无 Ask=login）上的客户端首帧")
p("="*70)
for sid, cb, sb in sorted(streams, key=lambda x: syn_info.get(x[0], (999,))[0]):
    has_login = any(b"Ask=login" in fb for fb in c._split_frames(cb))
    if has_login:
        continue
    syn_t = syn_info.get(sid, (-1,))[0]
    p(f"\n--- stream {sid} (SYN@{syn_t:.1f}s, srv {len(sb):,}B) ---")
    # 前3个非心跳客户端帧
    nshown = 0
    for fb in c._split_frames(cb):
        try:
            txt = fb.decode("gbk", "replace")
        except Exception:
            continue
        if b"\x12\x00\x03\x00" in fb[:12] and b"tsi0=" in fb:
            continue
        method = re.search(r"method=(\w+)", txt)
        code = re.search(r"CodeList=\d+\(([^)]*)\)", txt)
        p(f"  首2字节: {fb[:2].hex()} | method={method.group(1) if method else '-'} "
          f"code={code.group(1)[:20] if code else '-'}")
        p(f"    {txt[:90].replace(chr(10),'|')[:90]!r}")
        nshown += 1
        if nshown >= 3:
            break

open("captures_live/_topology.txt", "w", encoding="utf-8").write("\n".join(out))
print(f"写入 captures_live/_topology.txt ({len(out)} 行)")
