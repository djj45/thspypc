#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""提取 subreal×5 前置请求的完整字节 + 确认最小必需订阅集。

从 ABCBA 五次切换中提取 subreal 前置序列，搞清楚：
1. subreal×5 的完整字节格式（字节级复刻用）
2. pageid 是 4417 还是 4214？（第一次切A是4417，后面是4214）
3. 5 个 subreal 之后的「最小必需集」（哪些不发也能触发推送？）
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

# 找第一次切票(t=17.7s)的完整请求序列
first_burst = []
for ln in r.stdout.decode().splitlines():
    parts = ln.split("\t")
    if len(parts) < 3:
        continue
    t, sid, hexp = parts
    try:
        t = float(t); sid = int(sid)
    except ValueError:
        continue
    if not (17.5 < t < 18.5):
        continue
    hexp = "".join(hexp.split())
    if not hexp:
        continue
    raw = bytes.fromhex(hexp)
    for sub in raw.split(b"\xfd\xfd\xfd\xfd"):
        if len(sub) < 8:
            continue
        fb = sub[8:]
        first_burst.append((t, sid, fb))

p("="*70)
p("【第一次切票 A=000977 (t=17.5-18.5s) 完整请求序列】")
p("="*70)
seen_subreal = []
seen_others = []
for i, (t, sid, fb) in enumerate(sorted(first_burst)):
    try:
        txt = fb.decode("gbk", "replace")
    except Exception:
        txt = ""
    if b"\x12\x00\x03\x00" in fb[:12] and b"tsi0=" in fb:
        continue  # 心跳
    method = re.search(r"method=(\w+)", txt)
    pageid = re.search(r"pageid=(\d+)", txt)
    code = re.search(r"CodeList=\d+\(([^)]*)\)", txt) or re.search(r"codelist=([^\n]*)", txt)
    dt = re.search(r"DateTime=(\d+\([^)]*\))", txt)
    datatype = re.search(r"DataType=([^\r\n]*)", txt)
    market = re.search(r"market=(\w+)", txt)
    period = re.search(r"period=(\d+)", txt)

    if method and method.group(1) == "subreal":
        seen_subreal.append((t, sid, fb, txt, method, pageid, market, period))
    else:
        seen_others.append((t, sid, fb, txt, pageid, code, dt, datatype))

p(f"\n--- subreal 前置请求 ({len(seen_subreal)} 个) ---")
for j, (t, sid, fb, txt, method, pageid, market, period) in enumerate(seen_subreal[:8]):
    p(f"\n[subreal #{j}] t={t:.1f}s stream{sid} ({len(fb)}B)")
    p(f"  完整文本: {txt[:200].replace(chr(10), '|')[:200]!r}")
    p(f"  method={method.group(1)} pageid={pageid.group(1) if pageid else '-'} "
      f"market={market.group(1) if market else '-'} period={period.group(1) if period else '-'}")
    p(f"  头23字节: {fb[:23].hex(' ')}")

p(f"\n--- 后续非subreal请求 ({len(seen_others)} 个，前12个) ---")
for j, (t, sid, fb, txt, pageid, code, dt, datatype) in enumerate(seen_others[:12]):
    p(f"\n[req #{j}] t={t:.1f}s stream{sid} ({len(fb)}B)")
    p(f"  pageid={pageid.group(1) if pageid else '-'} "
      f"code={code.group(1)[:20] if code else '-'} "
      f"DT={dt.group(1)[:14] if dt else '-'} "
      f"DataType={datatype.group(1)[:30] if datatype else '-'}")

# === 关键：对比5次切票的 subreal 序列，看是否完全一致 ===
p("")
p("="*70)
p("【对比5次切票的 subreal×5 序列（验证每次是否一致）】")
p("="*70)
# 找5次爆发点
bursts = {}
burst_starts = [17.5, 32.5, 46.5, 59.5, 69.0]
all_reqs = []
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
        all_reqs.append((t, sid, fb))

for bs, blabel in zip(burst_starts, "ABCBA"):
    subreals = []
    for t, sid, fb in all_reqs:
        if not (bs < t < bs + 1.5):
            continue
        try:
            txt = fb.decode("gbk", "replace")
        except Exception:
            continue
        if "method=subreal" in txt:
            market = re.search(r"market=(\w+)", txt)
            pageid = re.search(r"pageid=(\d+)", txt)
            subreals.append((market.group(1) if market else "?",
                            pageid.group(1) if pageid else "?"))
    p(f"  {blabel} (t>{bs}s): subreal {[m+'/'+p for m,p in subreals]}")

outpath = "captures_live/_subreal_extract.txt"
open(outpath, "w", encoding="utf-8").write("\n".join(out))
print(f"写入 {outpath} ({len(out)} 行)")
