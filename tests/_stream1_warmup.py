#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""stream1 从 login 到分时请求之间的完整请求序列（含 seq 递增）。

thspypc 缺的可能不是单个请求，而是连接预热序列。
看 hexin stream1 login 后到 30s 之间所有请求 + seq。
"""
import os, sys, re, subprocess, struct
sys.path.insert(0, os.path.dirname(__file__))
import capture_timeline as c

PCAP = "captures_live/realtime_push_20260724_131453.pcap"
out = []
def p(*a):
    out.append(" ".join(str(x) for x in a))

r = subprocess.run(
    [c.TSHARK, "-r", PCAP, "-Y", "tcp.stream==1 and tcp.dstport==8901 and tcp.len>0",
     "-T", "fields", "-e", "frame.time_relative", "-e", "tcp.payload"],
    capture_output=True, timeout=120)

p("="*70)
p("stream1 客户端请求完整序列（login → 分时请求，含 seq）")
p("="*70)
n = 0
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
        if len(sub) < 8:
            continue
        fb = sub[8:]
        try:
            txt = fb.decode("gbk", "replace")
        except Exception:
            txt = ""
        is_hb = b"\x12\x00\x03\x00" in fb[:12] and b"tsi0=" in fb
        method = re.search(r"method=(\w+)", txt)
        code = re.search(r"CodeList=\d+\(([^)]*)\)", txt)
        pg = re.search(r"pageid=(\d+)", txt)
        ask = "Ask=login" in txt
        # seq 在 byte5-6（对 0x09 开头的二进制头帧）
        seq = ""
        if fb[0] == 0x09 and len(fb) >= 7 and not is_hb:
            seq = "0x%04x" % struct.unpack("<H", fb[5:7])[0]
        kind = "LOGIN" if ask else ("HB" if is_hb else (method.group(1) if method else "?"))
        if is_hb:
            continue  # 跳过心跳，只看实质请求
        pg_s = pg.group(1) if pg else "-"
        code_s = code.group(1)[:20] if code else "-"
        p(f"  t={t:6.2f}s seq={seq:<8} [{kind:<8}] pg={pg_s:<6} code={code_s}")
        n += 1

p(f"\n共 {n} 个实质请求（不含心跳）")

open("captures_live/_stream1_warmup.txt", "w", encoding="utf-8").write("\n".join(out))
print(f"写入 captures_live/_stream1_warmup.txt ({len(out)} 行)")
