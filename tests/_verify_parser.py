#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""验证 parse_snapshot_push 解析器：用抓包真实 71B 帧跑一遍。"""
import os, sys, struct, subprocess
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.dirname(__file__))
import capture_timeline as c
from thspypc.protocol import parse_snapshot_push, is_snapshot_push, build_snapshot_subscribe

PCAP = "captures_live/realtime_push_20260724_104540.pcap"

# 收集 71B 帧
r = subprocess.run(
    [c.TSHARK, "-r", PCAP, "-Y", "tcp.srcport==8901 and tcp.len>0",
     "-T", "fields", "-e", "frame.time_relative", "-e", "tcp.payload"],
    capture_output=True, timeout=120)
frames = []
for ln in r.stdout.decode().splitlines():
    parts = ln.split("\t")
    if len(parts) < 2:
        continue
    t, hexp = parts
    try:
        t = float(t)
    except ValueError:
        continue
    hexp = "".join(hexp.split())
    if not hexp:
        continue
    raw = bytes.fromhex(hexp)
    for sub in raw.split(b"\xfd\xfd\xfd\xfd"):
        if len(sub) >= 8:
            fb = sub[8:]
            if len(fb) in (71, 72) and fb[0] == 0x09:
                frames.append((t, fb))

print(f"收集 {len(frames)} 个 71/72B 帧")
print()

# 测试解析器
ok = fail = 0
by_code = {}
for t, fb in frames[:200]:
    if not is_snapshot_push(fb):
        fail += 1
        continue
    rec = parse_snapshot_push(fb)
    if rec is None:
        fail += 1
        continue
    rec["t"] = t
    by_code.setdefault(rec["code"], []).append(rec)
    ok += 1

print(f"解析成功 {ok} / 失败 {fail}")
print()

# 打印 603118 的现价序列（验证跳动）
for code in sorted(by_code):
    recs = by_code[code]
    print(f"=== {code} ({recs[0]['market']}) 现价序列（前15个）===")
    for r in recs[:15]:
        print(f"  t={r['t']:6.1f}s  现价={r['price']:.3f}  量={r['volume']}  seq={r['tick_seq']:#x}")
    if recs:
        prices = [r["price"] for r in recs]
        print(f"  现价范围: {min(prices):.3f} - {max(prices):.3f} ({len(recs)} 帧)")
    print()

# 验证订阅请求构造
print("=== build_snapshot_subscribe 字节级验证 ===")
req = build_snapshot_subscribe("603118", market=17)
# 抓包真值（去掉 fdfdfdfd + hexlen 后的 body）
expected_body_head = bytes.fromhex("09 00 16 00 00 00 00 12 00 02 00 fc 03".replace(" ", ""))
req_body = req[12:]  # 去 magic(4) + hexlen(8)
print(f"构造请求 body 前13字节: {req_body[:13].hex(' ')}")
print(f"抓包真值 body 前13字节: {expected_body_head.hex(' ')}")
print(f"匹配: {req_body[:13] == expected_body_head}")
print(f"请求含 CodeList=17(603118,): {b'CodeList=17(603118,)' in req}")
print(f"请求含 pageid=4214: {b'pageid=4214' in req}")
