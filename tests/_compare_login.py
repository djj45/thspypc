#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""对比 hexin login 帧 vs thspypc login 帧，找推送权限差异。

71B 推送连接的 login 在抓包前完成（market_open SYN=-1s），
但 market_open.pcap 抓到了 login 帧（stream0 等含 Ask=login）。
对比 hexin login body 与 thspypc build_login_body_pc 的输出。
"""
import os, sys, re, subprocess
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.dirname(__file__))
import capture_timeline as c
from thspypc.protocol import build_login_body_pc, build_passport64

out = []
def p(*a):
    out.append(" ".join(str(x) for x in a))

PCAP = "captures_live/market_open.pcap"
# 提取 hexin 的 login 帧 body
r = subprocess.run(
    [c.TSHARK, "-r", PCAP, "-Y", "tcp.dstport==8901 and tcp.len>0",
     "-T", "fields", "-e", "tcp.stream", "-e", "tcp.payload"],
    capture_output=True, timeout=120)
hexin_login = None
hexin_login_sid = None
for ln in r.stdout.decode().splitlines():
    parts = ln.split("\t")
    if len(parts) < 2:
        continue
    sid, hexp = parts
    hexp = "".join(hexp.split())
    if not hexp:
        continue
    raw = bytes.fromhex(hexp)
    for sub in raw.split(b"\xfd\xfd\xfd\xfd"):
        if len(sub) < 8:
            continue
        fb = sub[8:]
        if b"Ask=login" in fb:
            hexin_login = fb
            hexin_login_sid = sid
            break
    if hexin_login:
        break

p("="*70)
p(f"【hexin login 帧】(stream {hexin_login_sid}, {len(hexin_login)}B)")
p("="*70)
# 解析 hexin login 的字段
txt = hexin_login.decode("gbk", "replace")
p(f"完整文本（|分隔）:")
for line in txt.split("\n"):
    p(f"  {line!r}")
p()
p(f"前80字节 hex: {hexin_login[:80].hex(' ')}")

# thspypc 的 login body（需要 passport，用一个示例）
p("")
p("="*70)
p("【thspypc build_login_body_pc 输出对比】")
p("="*70)
# 构造一个示例 passport（不需要真实，看结构差异）
try:
    # 用抓包里的 passport 字段
    body_ths = build_login_body_pc(
        username="test", passport64=build_passport64({}),
        imei="0"*32, mac64="0"*22,
    )
    p(f"thspypc login body ({len(body_ths)}B):")
    txt_ths = body_ths.decode("gbk", "replace")
    for line in txt_ths.split("\n"):
        p(f"  {line!r}")
    p()
    p(f"前80字节 hex: {body_ths[:80].hex(' ')}")
except Exception as e:
    p(f"构造失败: {e}")

# 关键字段对比
p("")
p("="*70)
p("【关键字段对比】")
p("="*70)
# 找 hexin login 里的特殊字段
hexin_fields = {}
for line in txt.replace("\x09", "\n").split("\n"):
    if "=" in line:
        k, _, v = line.partition("=")
        hexin_fields[k.strip()] = v.strip()[:40]

p("hexin login 含的字段:")
for k in sorted(hexin_fields):
    p(f"  {k} = {hexin_fields[k]!r}")

# 特别找：C-SupportPush / SupportPush / push 相关
p("")
p("推送相关字段（含 push/Push/PUSH）:")
for k, v in hexin_fields.items():
    if "push" in k.lower() or "push" in v.lower():
        p(f"  ★ {k} = {v!r}")

open("captures_live/_login_compare.txt", "w", encoding="utf-8").write("\n".join(out))
print(f"写入 captures_live/_login_compare.txt ({len(out)} 行)")
