#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""找 71B 推送前的最后一个客户端请求（推送的真正触发动作）。

realtime_push_104540.pcap 里 stream1 的首个 71B 推送在 t≈0s。
但该 stream 客户端只发心跳（无查询请求）。
所以推送触发可能在【别的 stream】或【登录初始化阶段】。

本脚本：
1. 全局找第一个 71B 推送的精确时间
2. 该时间点之前所有 stream 的所有客户端请求（跨 stream）
3. 看推送开始前最后发的是什么请求
"""
import os, sys, re, subprocess
sys.path.insert(0, os.path.dirname(__file__))
import capture_timeline as c

PCAP = "captures_live/realtime_push_20260724_104540.pcap"
out = []
def p(*a):
    out.append(" ".join(str(x) for x in a))

# 全局所有包（带 stream + 方向 + 时间）
r = subprocess.run(
    [c.TSHARK, "-r", PCAP, "-Y", "tcp.port==8901 and tcp.len>0",
     "-T", "fields", "-e", "frame.time_relative", "-e", "tcp.stream",
     "-e", "tcp.srcport", "-e", "tcp.payload"],
    capture_output=True, timeout=120)

# 收集所有 71B 推送帧的时间（服务端方向）
first_push_t = None
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
    raw = bytes.fromhex(hexp)
    all_pkts.append((t, sid, src, raw))

# 找第一个 71B 推送
for t, sid, src, raw in all_pkts:
    if src != "8901":
        continue
    for sub in raw.split(b"\xfd\xfd\xfd\xfd"):
        if len(sub) < 8:
            continue
        fb = sub[8:]
        if len(fb) == 71 and fb[0] == 0x09 and all(0x30<=b<=0x39 for b in fb[29:35]):
            first_push_t = t
            p(f"★ 首个 71B 推送: t={t:.2f}s stream{sid}")
            break
    if first_push_t:
        break

p("")
p("="*70)
p(f"【首个 71B 推送 (t={first_push_t:.2f}s) 之前的所有客户端请求（跨 stream）】")
p("="*70)
prev_t = None
for t, sid, src, raw in all_pkts:
    if src == "8901" or t > first_push_t + 0.5:
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
        method = re.search(r"method=(\w+)", txt)
        code = re.search(r"CodeList=\d+\(([^)]*)\)", txt)
        gap = ""
        if prev_t and t - prev_t > 2:
            gap = f"  <<<(间隔{t-prev_t:.1f}s)"
        if is_hb:
            kind = "心跳"
        elif method:
            kind = method.group(1)
        elif "Ask=login" in txt:
            kind = "LOGIN"
        else:
            kind = "?"
        # 只打非心跳的，或心跳但距上个间隔大
        if kind != "心跳" or gap:
            p(f"  t={t:6.2f}s s{sid} [{kind:<10}] code={code.group(1)[:18] if code else '-'}{gap}")
            if kind not in ("心跳",) and kind != "?":
                p(f"      {txt[:75].replace(chr(10),'|')[:75]!r}")
        prev_t = t

p("")
p("="*70)
p("【关键】首个推送所在 stream 的客户端请求（只发心跳吗？）")
p("="*70)
push_sid = None
for t, sid, src, raw in all_pkts:
    if src != "8901":
        continue
    for sub in raw.split(b"\xfd\xfd\xfd\xfd"):
        if len(sub) < 8:
            continue
        fb = sub[8:]
        if len(fb) == 71 and fb[0] == 0x09 and all(0x30<=b<=0x39 for b in fb[29:35]):
            push_sid = sid
            break
    if push_sid:
        break

if push_sid:
    p(f"推送在 stream{push_sid}，该 stream 所有客户端请求:")
    for t, sid, src, raw in all_pkts:
        if sid != push_sid or src == "8901":
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
            method = re.search(r"method=(\w+)", txt)
            code = re.search(r"CodeList=\d+\(([^)]*)\)", txt)
            kind = "心跳" if is_hb else (method.group(1) if method else ("LOGIN" if "Ask=login" in txt else "?"))
            if kind != "心跳":
                p(f"  t={t:6.2f}s [{kind:<10}] code={code.group(1)[:20] if code else '-'}")
                p(f"      {txt[:75].replace(chr(10),'|')[:75]!r}")

open("captures_live/_before_push.txt", "w", encoding="utf-8").write("\n".join(out))
print(f"写入 captures_live/_before_push.txt ({len(out)} 行)")
