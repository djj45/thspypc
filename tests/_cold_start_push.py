#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""market_open.pcap 冷启动：login → 首个 71B 推送 之间的完整初始化序列。

这是开启推送通道的钥匙。thspypc 只发 init，缺了中间步骤。
"""
import os, sys, re, subprocess
sys.path.insert(0, os.path.dirname(__file__))
import capture_timeline as c

PCAP = "captures_live/market_open.pcap"
out = []
def p(*a):
    out.append(" ".join(str(x) for x in a))

r = subprocess.run(
    [c.TSHARK, "-r", PCAP, "-Y", "tcp.port==8901 and tcp.len>0",
     "-T", "fields", "-e", "frame.time_relative", "-e", "tcp.stream",
     "-e", "tcp.srcport", "-e", "tcp.payload"],
    capture_output=True, timeout=120)

all_pkts = []
for ln in r.stdout.decode().splitlines():
    parts = ln.split("\t")
    if len(parts) < 4:
        continue
    t, sid, src, hexp = parts
    try:
        t = float(t); sid = int(sid)
    except ValueError:
        continue
    hexp = "".join(hexp.split())
    if not hexp:
        continue
    all_pkts.append((t, sid, src, bytes.fromhex(hexp)))

# 找首个 71B 推送
first_push_t = None
first_push_sid = None
for t, sid, src, raw in all_pkts:
    if src != "8901":
        continue
    for sub in raw.split(b"\xfd\xfd\xfd\xfd"):
        if len(sub) < 8:
            continue
        fb = sub[8:]
        if len(fb) in (71,72) and fb[0]==0x09 and len(fb)>=35 and all(0x30<=b<=0x39 for b in fb[29:35]):
            first_push_t = t
            first_push_sid = sid
            break
    if first_push_t:
        break

if first_push_t is None:
    p("✗ market_open.pcap 无 71B 推送（可能非盘中抓的）")
else:
    p(f"★ 首个 71B 推送: t={first_push_t:.2f}s stream{first_push_sid}")
    p("")
    p("="*70)
    p(f"【login → 首个推送 ({first_push_t:.2f}s) 之间所有客户端请求】")
    p("="*70)
    for t, sid, src, raw in all_pkts:
        if src == "8901" or t > first_push_t:
            continue
        for sub in raw.split(b"\xfd\xfd\xfd\xfd"):
            if len(sub) < 8:
                continue
            fb = sub[8:]
            try:
                txt = fb.decode("gbk", "replace")
            except Exception:
                continue
            is_hb = b"\x12\x00\x03\x00" in fb[:12] and b"tsi0=" in fb
            if is_hb:
                continue
            method = re.search(r"method=(\w+)", txt)
            code = re.search(r"CodeList=\d+\(([^)]*)\)", txt)
            ask = "Ask=login" in txt
            kind = "LOGIN" if ask else (method.group(1) if method else "?")
            p(f"  t={t:5.2f}s s{sid} [{kind:<10}] code={code.group(1)[:15] if code else '-'}")
            if kind in ("LOGIN","?") or method:
                short = txt[:70].replace("\n","|")
                p(f"      {short[:70]!r}")

open("captures_live/_cold_start_push.txt", "w", encoding="utf-8").write("\n".join(out))
print(f"写入 captures_live/_cold_start_push.txt ({len(out)} 行)")
print(f"首个推送: t={first_push_t}s stream{first_push_sid}" if first_push_t else "无推送")
