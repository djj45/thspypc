#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""冷启动包详解：login时间 → 71B推送时间 → 中间初始化序列。

这是解开推送通道之谜的关键包（冷启动+静默+点分时）。
"""
import os, sys, re, subprocess
sys.path.insert(0, os.path.dirname(__file__))
import capture_timeline as c

PCAP = "captures_live/realtime_push_20260724_131453.pcap"
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

# 找 login 时间 + 首个 71B 推送
login_t = None
first_push_t = None
first_push_sid = None
push_sids = {}
for t, sid, src, raw in all_pkts:
    for sub in raw.split(b"\xfd\xfd\xfd\xfd"):
        if len(sub) < 8:
            continue
        fb = sub[8:]
        if src != "8901" and b"Ask=login" in fb and login_t is None:
            login_t = t
        if src == "8901" and len(fb) in (71,72) and fb[0]==0x09 \
           and len(fb)>=35 and all(0x30<=b<=0x39 for b in fb[29:35]):
            push_sids.setdefault(sid, []).append(t)
            if first_push_t is None:
                first_push_t = t
                first_push_sid = sid

p(f"login 时间: t={login_t}s")
p(f"首个 71B 推送: t={first_push_t}s stream{first_push_sid}" if first_push_t else "✗ 无 71B 推送")
p(f"含 71B 推送的 stream: {sorted(push_sids.keys())}")
for sid, times in sorted(push_sids.items()):
    p(f"  stream{sid}: {len(times)}帧, {times[0]:.1f}s-{times[-1]:.1f}s")
p("")

if first_push_t:
    p("="*70)
    p(f"【login({login_t:.2f}s) → 首推送({first_push_t:.2f}s) 之间的客户端请求】")
    p("="*70)
    for t, sid, src, raw in all_pkts:
        if src == "8901" or t > first_push_t + 0.1:
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
            if kind != "?":
                p(f"      {txt[:70].replace(chr(10),'|')[:70]!r}")

open("captures_live/_coldstart_detail.txt", "w", encoding="utf-8").write("\n".join(out))
print(f"写入 captures_live/_coldstart_detail.txt ({len(out)} 行)")
