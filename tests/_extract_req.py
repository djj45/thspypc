#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""提取 pageid=4214/4417 订阅请求的完整原始字节（供 protocol.py 字节级复刻）。

只提取「打开分时图瞬间」爆发的请求序列，按时间排序，完整 hex dump。
"""
import os, sys, re, subprocess
sys.path.insert(0, os.path.dirname(__file__))
import capture_timeline as c

PCAP = "captures_live/realtime_push_20260724_104540.pcap"
out = []
def p(*a):
    out.append(" ".join(str(x) for x in a))

r = subprocess.run(
    [c.TSHARK, "-r", PCAP, "-Y",
     "tcp.dstport==8901 and tcp.len>0",
     "-T", "fields", "-e", "frame.time_relative", "-e", "tcp.stream",
     "-e", "tcp.payload"], capture_output=True, timeout=120)

# 收集 stream1 (603118) 和 stream2 (000938) 的 4214/4417 请求
targets = []
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
        fb = sub[8:]  # body（去掉 magic + hexlen）
        try:
            txt = fb.decode("gbk", "replace")
        except Exception:
            txt = ""
        if "pageid=4214" not in txt and "pageid=4417" not in txt:
            continue
        # 只看含具体股票代码的
        if "603118" not in txt and "000938" not in txt:
            continue
        targets.append((t, sid, fb, txt))

p(f"共 {len(targets)} 个 4214/4417 含股票代码请求")
p("="*70)
p("【关键订阅请求完整字节 dump】（按时间，含完整 body hex + 解读）")
p("="*70)
seen = set()
for t, sid, fb, txt in targets:
    # 提取关键特征去重
    pageid = re.search(r"pageid=(\d+)", txt)
    code = re.search(r"CodeList=\d+\(([^)]*)\)", txt)
    dt = re.search(r"DateTime=(\d+\([^)]*\))", txt)
    datatype = re.search(r"DataType=([^\r\n]*)", txt)
    key = (sid, pageid.group(1) if pageid else "",
           code.group(1)[:20] if code else "",
           dt.group(1) if dt else "",
           datatype.group(1)[:30] if datatype else "")
    if key in seen:
        continue
    seen.add(key)
    p(f"\n--- t={t:.1f}s stream{sid} ---")
    p(f"  pageid={pageid.group(1) if pageid else '?'}")
    p(f"  code={code.group(1)[:40] if code else '?'}")
    p(f"  DateTime={dt.group(1) if dt else '(无)'}")
    p(f"  DataType={datatype.group(1)[:50] if datatype else '(无)'}")
    p(f"  body完整hex({len(fb)}B):")
    # 分行打印 hex，每行16字节
    for i in range(0, len(fb), 16):
        chunk = fb[i:i+16]
        hexs = chunk.hex(' ')
        asciis = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        p(f"    {i:04x}: {hexs:<48} {asciis}")
    # 关键：识别头部结构
    if len(fb) >= 23:
        p(f"  头部分析:")
        p(f"    byte0: 0x{fb[0]:02x} (cmd)")
        p(f"    byte1-4: {fb[1:5].hex()} (长度/标志)")
        p(f"    byte5-6: {fb[5:7].hex()} (seq)")
        p(f"    byte7-10: {fb[7:11].hex()} (子帧类型/路由)")
        p(f"    byte11-18: {fb[11:19].hex()}")
        p(f"    byte19-22: {fb[19:23].hex()} (文本长度?)")

outpath = "captures_live/_req_bytes.txt"
open(outpath, "w", encoding="utf-8").write("\n".join(out))
print(f"写入 {outpath} ({len(out)} 行)")
