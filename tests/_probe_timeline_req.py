#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""确认 71B 推送的触发源 + 打开分时图瞬间的请求序列。

关键疑点：71B 推送从 t=0s 就有（stream1），但 stream1 订阅请求在 t=68.6s。
说明订阅在别的 stream。本脚本：
1. 找所有 stream 里最早出现 603118/000938 代码的请求（订阅源）
2. 重点看 pageid=4214 的请求（出现时间 + 是否含股票代码）
3. 确认 71B 推送的 stream 与订阅 stream 是否同一 TCP 连接
"""
import os, sys, re, subprocess
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.dirname(__file__))
import capture_timeline as c

PCAP = "captures_live/realtime_push_20260724_104540.pcap"
out = []
def p(*a):
    out.append(" ".join(str(x) for x in a))

# === A. 每个 stream 的时间范围 + 客户端首个非心跳请求 ===
p("="*70)
p("【A】每个 8901 stream 的时间范围 + 首个非心跳请求")
p("="*70)
streams = c._tshark_streams(PCAP, 8901)
# 拿每个 stream 的包时间
r = subprocess.run(
    [c.TSHARK, "-r", PCAP, "-Y", "tcp.port==8901 and tcp.len>0",
     "-T", "fields", "-e", "tcp.stream", "-e", "frame.time_relative",
     "-e", "tcp.srcport", "-e", "tcp.len", "-e", "tcp.payload"],
    capture_output=True, timeout=120)
stream_info = {}  # sid -> [t_first, t_last, cli_first_req_text]
for ln in r.stdout.decode().splitlines():
    parts = ln.split("\t")
    if len(parts) < 5:
        continue
    sid, t, src, ln2, hexp = parts
    try:
        sid = int(sid); t = float(t)
    except ValueError:
        continue
    info = stream_info.setdefault(sid, {"t0": t, "t1": t, "first_req": None})
    info["t1"] = max(info["t1"], t)
    if src != "8901":  # 客户端请求
        hexp = "".join(hexp.split())
        if hexp and info["first_req"] is None:
            raw = bytes.fromhex(hexp)
            for sub in raw.split(b"\xfd\xfd\xfd\xfd"):
                if len(sub) >= 8:
                    fb = sub[8:]
                    if b"\x12\x00\x03\x00" in fb[:12]:
                        continue  # 心跳
                    try:
                        txt = fb.decode("gbk", "replace")
                    except Exception:
                        txt = ""
                    if txt.strip():
                        info["first_req"] = txt[:100].replace("\n", "|")
                        break

for sid in sorted(stream_info):
    info = stream_info[sid]
    dur = info["t1"] - info["t0"]
    req = info["first_req"] or "(无/纯心跳)"
    p(f"  stream{sid:2d}: {info['t0']:6.1f}s-{info['t1']:6.1f}s ({dur:5.1f}s) 首req: {req[:90]}")

# === B. 找含 603118/000938 的所有请求（按时间）===
p("")
p("="*70)
p("【B】所有含具体股票代码的请求（按时间，找订阅触发点）")
p("="*70)
for ln in r.stdout.decode().splitlines():
    parts = ln.split("\t")
    if len(parts) < 5:
        continue
    sid, t, src, ln2, hexp = parts
    if src == "8901":
        continue
    try:
        sid = int(sid); t = float(t)
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
        # 找 ASCII 代码
        codes = re.findall(rb"[036]\d{5}", fb)
        if not codes:
            continue
        code_set = {c.decode() for c in codes}
        # 过滤掉纯数字碰巧的
        if not any(c in ("603118", "000938") for c in code_set):
            continue
        try:
            txt = fb.decode("gbk", "replace")
        except Exception:
            txt = ""
        pageid = re.search(r"pageid=(\d+)", txt)
        dt = re.search(r"DateTime=(\d+\([^)]*\))", txt)
        datatype = re.search(r"DataType=([^\r\n|]*)", txt)
        pg = pageid.group(1) if pageid else "-"
        dt_s = dt.group(1) if dt else "-"
        dty = datatype.group(1)[:25] if datatype else "-"
        p(f"  {t:6.1f}s stream{sid} pg={pg} DT={dt_s:<16} DT2={dty:<26} codes={sorted(code_set)[:4]}")

# === C. 确认 71B 推送 stream + 时间 ===
p("")
p("="*70)
p("【C】71B 推送的 stream 分布 + 首末时间（确认持续推送）")
p("="*70)
push_by_stream = {}  # sid -> [count, t0, t1]
for ln in r.stdout.decode().splitlines():
    parts = ln.split("\t")
    if len(parts) < 5:
        continue
    sid, t, src, ln2, hexp = parts
    if src != "8901":
        continue
    try:
        sid = int(sid); t = float(t)
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
        if len(fb) in (71, 72) and fb[:1] == b"\x09":
            info = push_by_stream.setdefault(sid, [0, t, t])
            info[0] += 1
            info[1] = min(info[1], t)
            info[2] = max(info[2], t)

for sid, (cnt, t0, t1) in sorted(push_by_stream.items(), key=lambda x: -x[1][0]):
    p(f"  stream{sid}: {cnt} 个 71/72B 帧, {t0:.1f}s-{t1:.1f}s ({t1-t0:.0f}s)")

outpath = "captures_live/_trigger_analysis.txt"
open(outpath, "w", encoding="utf-8").write("\n".join(out))
print(f"写入 {outpath} ({len(out)} 行)")
