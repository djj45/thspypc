#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""破解订阅触发：找触发 71B/72B 持续推送的客户端请求。

71B/72B 推送从 t=0s 就开始（stream1），说明订阅在抓包前/开头就建立了。
本脚本：
1. 看 stream1 的冷启动请求序列（login + 前几个请求）
2. 对比 market_open.pcap 的冷启动（看哪些请求是共有的订阅触发项）
3. 重点：找 method=qureal / 含具体股票代码的订阅请求
"""
import os, sys, re, subprocess
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.dirname(__file__))
import capture_timeline as c

out = []
def p(*a):
    out.append(" ".join(str(x) for x in a))

# === A. realtime_push stream1 的冷启动请求序列 ===
p("="*70)
p("【A】realtime_push.pcap stream1 冷启动请求序列（71B推送源头）")
p("="*70)
PCAP1 = "captures_live/realtime_push_20260724_104540.pcap"
for target_sid in [1]:
    r = subprocess.run(
        [c.TSHARK, "-r", PCAP1, "-Y",
         f"tcp.stream=={target_sid} and tcp.dstport==8901 and tcp.len>0",
         "-T", "fields", "-e", "frame.time_relative", "-e", "tcp.payload"],
        capture_output=True, timeout=60)
    count = 0
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
            is_hb = b"\x12\x00\x03\x00" in fb[:12]
            method = re.search(r"method=(\w+)", txt)
            pageid = re.search(r"pageid=(\d+)", txt)
            code = re.search(r"CodeList=(\d+)\(([^)]*)\)", txt) or \
                   re.search(r"codelist=([^\n]*)", txt)
            Ask = "Ask=login" in txt
            if is_hb:
                continue  # 跳过心跳
            if not (method or pageid or Ask or "CodeList" in txt):
                continue
            tag = "LOGIN" if Ask else (f"{method.group(1)}/{pageid.group(1)}"
                                       if method and pageid
                                       else (method.group(1) if method else
                                             (pageid.group(1) if pageid else "?")))
            code_s = ""
            if code:
                if code.group(0).startswith("CodeList"):
                    code_s = f"mk{code.group(1)}({code.group(2)[:30]})"
                else:
                    code_s = f"cl={code.group(1)[:30]}"
            # 对 login 打印前150字符
            if Ask:
                p(f"  {t:6.1f}s [{tag}] {code_s}")
                p(f"          login头: {txt[:180].replace(chr(10),'|')[:180]}")
            else:
                # 打印完整文本（去掉不可打印）
                oneline = txt[:200].replace("\n", "|").replace("\r", "")
                p(f"  {t:6.1f}s [{tag}] {code_s}")
                p(f"          {oneline}")
            count += 1
            if count > 40:
                p("  ... 截断")
                break
        if count > 40:
            break

# === B. 看 stream1 的前几个请求到底订阅了什么（重点 qureal）===
p("")
p("="*70)
p("【B】所有 stream 里的 qureal/含股票代码订阅请求（全 pcap）")
p("="*70)
for PCAP, label in [(PCAP1, "realtime_push")]:
    p(f"\n--- {label} ---")
    streams = c._tshark_streams(PCAP, 8901)
    seen = set()
    for sid, cb, sb in streams:
        for fb in c._split_frames(cb):
            try:
                txt = fb.decode("gbk", "replace")
            except Exception:
                continue
            if "method=qureal" not in txt and "Ask=login" not in txt:
                continue
            key = txt[:120]
            if key in seen:
                continue
            seen.add(key)
            p(f"  stream{sid}: {key.replace(chr(10),'|')[:160]}")

outpath = "captures_live/_subscribe_analysis.txt"
open(outpath, "w", encoding="utf-8").write("\n".join(out))
print(f"写入 {outpath} ({len(out)} 行)")
