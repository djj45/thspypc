#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""提取 __manual stream1 login→首推送 的完整原始请求字节序列，供精确重放。

从 cold-start 包提取 stream1（__manual）t=0 到 t=5.3s（首次321B指数推送前）
所有客户端发出的【完整 fdfdfdfd 帧】（含 login），逐帧保存为 hex + 分类。
"""
import os, sys, subprocess
sys.path.insert(0, os.path.dirname(__file__))
import capture_timeline as c

PCAP = "captures_live/realtime_push_20260724_131453.pcap"
TSHARK = c.TSHARK
# 提取 stream1 客户端方向 t=0 到 5.3s
r = subprocess.run(
    [TSHARK, "-r", PCAP, "-Y",
     "tcp.stream==1 and tcp.dstport==8901 and tcp.len>0 and frame.time_relative<5.3",
     "-T", "fields", "-e", "frame.time_relative", "-e", "tcp.payload"],
    capture_output=True, timeout=120)

frames = []  # (t, raw_payload_bytes)
for ln in r.stdout.decode().splitlines():
    parts = ln.split("\t")
    if len(parts) < 2:
        continue
    try:
        t = float(parts[0])
    except ValueError:
        continue
    hexp = "".join(parts[1].split())
    if not hexp:
        continue
    frames.append((t, bytes.fromhex(hexp)))

# 每个 tcp.payload 可能含多个 fdfdfdfd 帧，拆分
out = []
def p(*a):
    out.append(" ".join(str(x) for x in a))

p("="*70)
p(f"__manual stream1 t=0..5.3s: {len(frames)} 个 tcp payload，拆 fdfdfdfd 帧")
p("="*70)
n = 0
import re
for t, raw in frames:
    # payload 可能以 fdfdfdfd 开头，含多帧
    # 用 split 但保留分隔
    chunks = raw.split(b"\xfd\xfd\xfd\xfd")
    for chunk in chunks:
        if len(chunk) < 8:
            continue
        # chunk = 8 字节 ascii hex 长度 + body
        try:
            bodylen = int(chunk[:8], 16)
        except Exception:
            continue
        body = chunk[8:8+bodylen]
        if len(body) < 5:
            continue
        n += 1
        try:
            txt = body.decode("gbk", "replace")
        except Exception:
            txt = ""
        is_login = "Ask=login" in txt
        is_hb = b"\x12\x00\x03\x00" in body[:12] and b"tsi0=" in body
        method = re.search(r"method=(\w+)", txt)
        pg = re.search(r"pageid=(\d+)", txt)
        code = re.search(r"CodeList=(\d+\([^)]*\))", txt) or re.search(r"codelist=([^|]*)", txt)
        kind = "LOGIN" if is_login else ("HB" if is_hb else (method.group(1) if method else "RAW"))
        pg_s = pg.group(1) if pg else "-"
        code_s = code.group(1)[:24] if code else "-"
        p(f"\n--- 帧#{n} t={t:.2f}s [{kind}] pg={pg_s} code={code_s} body={len(body)}B ---")
        p(f"  hex前32: {body[:32].hex(' ')}")
        if not is_hb:
            p(f"  txt: {txt[:110].replace(chr(10),'|').replace(chr(13),'')!r}")

p(f"\n共 {n} 帧（含心跳）")
open("captures_live/_warmup_frames.txt", "w", encoding="utf-8").write("\n".join(out))
print(f"写入 captures_live/_warmup_frames.txt ({n} 帧)")
