#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""分析 ABCBA 五次切换分时图的请求序列（收盘包，干净无实时推送干扰）。

目标：
1. 每次切票（A/B/C/B/A）发了哪些请求？按时间分组
2. subreal×5 是否每次切票都重发？（=前置必需？）
3. pageid=4214 的「带DataType触发请求」每次切票的完整字节（找最小必需集）
4. 区分「订阅类请求」vs「查询类请求」

A=000977 B=605090 C=002008（从抓包代码推断）
"""
import os, sys, re, subprocess
sys.path.insert(0, os.path.dirname(__file__))
import capture_timeline as c

PCAP = "captures_live/realtime_push_20260724_113732.pcap"
out = []
def p(*a):
    out.append(" ".join(str(x) for x in a))

r = subprocess.run(
    [c.TSHARK, "-r", PCAP, "-Y", "tcp.dstport==8901 and tcp.len>0",
     "-T", "fields", "-e", "frame.time_relative", "-e", "tcp.stream",
     "-e", "tcp.payload"], capture_output=True, timeout=120)

# 收集所有客户端请求（按时间）
reqs = []
for ln in r.stdout.decode().splitlines():
    parts = ln.split("\t")
    if len(parts) < 3:
        continue
    t, sid, hexp = parts
    try:
        t = float(t); sid = int(sid)
    except ValueError:
        continue
    hexp = "".join(hexp.split())
    if not hexp:
        continue
    raw = bytes.fromhex(hexp)
    for sub in raw.split(b"\xfd\xfd\xfd\xfd"):
        if len(sub) < 8:
            continue
        fb = sub[8:]
        try:
            txt = fb.decode("gbk", "replace")
        except Exception:
            txt = ""
        # 跳过心跳
        if b"\x12\x00\x03\x00" in fb[:12] and b"tsi0=" in fb:
            continue
        reqs.append((t, sid, fb, txt))

p(f"共 {len(reqs)} 个非心跳客户端请求")
p("")

# === A. 按时间窗口分组（静默期分隔出每次切票）===
p("="*70)
p("【A】请求时间线（找切票爆发点，静默期分隔）")
p("="*70)
# 列出所有请求的时间 + 关键标识
prev_t = None
for t, sid, fb, txt in reqs:
    method = re.search(r"method=(\w+)", txt)
    pageid = re.search(r"pageid=(\d+)", txt)
    code = re.search(r"CodeList=\d+\(([^)]*)\)", txt) or re.search(r"codelist=([^\n]*)", txt)
    dt = re.search(r"DateTime=(\d+\([^)]*\))", txt)
    datatype = re.search(r"DataType=([^\r\n]*)", txt)
    # 标记爆发点（与前一个间隔>3s）
    gap_mark = ""
    if prev_t is not None and t - prev_t > 3.0:
        gap_mark = f"  <<< 间隔 {t-prev_t:.1f}s（切票爆发点）"
    tag = f"{method.group(1) if method else '-'}/{pageid.group(1) if pageid else '-'}"
    code_s = code.group(1)[:18] if code else "-"
    dt_s = dt.group(1)[:14] if dt else "-"
    dty_s = datatype.group(1)[:20] if datatype else "-"
    p(f"  {t:6.1f}s s{sid} [{tag:<16}] code={code_s:<18} DT={dt_s:<15} DT2={dty_s}{gap_mark}")
    prev_t = t

outpath = "captures_live/_abcba_seq.txt"
open(outpath, "w", encoding="utf-8").write("\n".join(out))
print(f"写入 {outpath} ({len(out)} 行)")
