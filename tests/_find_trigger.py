#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""精确定位触发 71B 推送的真正请求（带 DataType/DateTime 的 4214）。

之前实测只发简陋的 'CodeList+pageid=4214' 没收到推送。
抓包里 96.9s stream2 紫光切分时图的 4214 请求带了完整 DataType + DateTime。
本脚本：dump 所有带 DataType 的 4214 请求完整字节，找触发推送的最小集。
"""
import os, sys, re, subprocess
sys.path.insert(0, os.path.dirname(__file__))
import capture_timeline as c

PCAP = "captures_live/realtime_push_20260724_104540.pcap"
out = []
def p(*a):
    out.append(" ".join(str(x) for x in a))

# 按时间顺序 dump 所有 4214 请求（含完整 hex + 解读）
r = subprocess.run(
    [c.TSHARK, "-r", PCAP, "-Y", "tcp.dstport==8901 and tcp.len>0",
     "-T", "fields", "-e", "frame.time_relative", "-e", "tcp.stream",
     "-e", "tcp.payload"], capture_output=True, timeout=120)

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
        if "pageid=4214" not in txt:
            continue
        reqs.append((t, sid, fb, txt))

p(f"共 {len(reqs)} 个 pageid=4214 请求")
p("="*70)
p("【所有 4214 请求完整内容（按时间）】")
p("="*70)
for i, (t, sid, fb, txt) in enumerate(reqs):
    code = re.search(r"CodeList=\d+\(([^)]*)\)", txt)
    dt = re.search(r"DateTime=(\d+\([^)]*\))", txt)
    datatype = re.search(r"DataType=([^\r\n]*)", txt)
    lacktime = re.search(r"LackTime=([^\r\n]*)", txt)
    p(f"\n--- #{i} t={t:.1f}s stream{sid} ({len(fb)}B) ---")
    p(f"  CodeList: {code.group(1)[:40] if code else '(无)'}")
    p(f"  DataType: {datatype.group(1)[:60] if datatype else '(无)'}")
    p(f"  DateTime: {dt.group(1) if dt else '(无)'}")
    p(f"  LackTime: {lacktime.group(1) if lacktime else '(无)'}")
    # 头部
    if len(fb) >= 23:
        p(f"  头23字节: {fb[:23].hex(' ')}")
        p(f"    byte7-10(子帧): {fb[7:11].hex()}  byte11-12: {fb[11:13].hex()}")

# 关键：哪个请求之后开始出现 71B 推送？
# stream2 推送从 95.8s 开始（_trigger_analysis 显示）
# 找 95.8s 之前最近的 4214/4417 请求序列
p("")
p("="*70)
p("【关键：紫光(stream2)推送开始(95.8s)前的请求序列】")
p("="*70)
for t, sid, fb, txt in reqs:
    if sid != 2 or t > 97.5:
        continue
    code = re.search(r"CodeList=\d+\(([^)]*)\)", txt)
    dt = re.search(r"DateTime=(\d+\([^)]*\))", txt)
    datatype = re.search(r"DataType=([^\r\n]*)", txt)
    p(f"  t={t:.1f}s stream{sid}: code={code.group(1)[:25] if code else '-'} "
      f"DT={dt.group(1) if dt else '-'} DataType={datatype.group(1)[:40] if datatype else '-'}")

# 也看 stream2 的 4417 请求（分时图）
p("")
p("--- stream2 的 4417 请求 ---")
r2 = subprocess.run(
    [c.TSHARK, "-r", PCAP, "-Y", "tcp.dstport==8901 and tcp.len>0",
     "-T", "fields", "-e", "frame.time_relative", "-e", "tcp.stream",
     "-e", "tcp.payload"], capture_output=True, timeout=120)
for ln in r2.stdout.decode().splitlines():
    parts = ln.split("\t")
    if len(parts) < 3:
        continue
    t, sid, hexp = parts
    try:
        t = float(t); sid = int(sid)
    except ValueError:
        continue
    if sid != 2 or t > 97.5:
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
        if "pageid=4417" not in txt and "pageid=4214" not in txt:
            continue
        code = re.search(r"CodeList=\d+\(([^)]*)\)", txt)
        dt = re.search(r"DateTime=(\d+\([^)]*\))", txt)
        datatype = re.search(r"DataType=([^\r\n]*)", txt)
        pg = re.search(r"pageid=(\d+)", txt)
        p(f"  t={t:.1f}s stream{sid} pg={pg.group(1) if pg else '?'}: "
          f"code={code.group(1)[:20] if code else '-'} "
          f"DT={dt.group(1) if dt else '-'} DataType={datatype.group(1)[:35] if datatype else '-'}")

outpath = "captures_live/_4214_full.txt"
open(outpath, "w", encoding="utf-8").write("\n".join(out))
print(f"写入 {outpath} ({len(out)} 行)")
