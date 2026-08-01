#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""聚焦分析 stream2（紫光000938分时流）的请求-响应配对 + 无标记小帧内容。

搞清楚：
1. 客户端发了什么请求 → 服务端回了哪些 hd3.1 增量帧（配对关系）
2. 持续不断的 321B/488B 无标记小帧是什么（盘口？五档？快照？）
3. 推送是轮询触发还是服务端主动推（看请求和响应的时间间隔）
"""
import os, sys, re, struct, subprocess
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.dirname(__file__))
import capture_timeline as c
from thspypc.protocol import parse_kline_hd3_response, decode_ths_float

PCAP = "captures_live/realtime_push_20260724_104540.pcap"
PORT = 8901
TARGET_STREAM = 2

out = []
def p(*a):
    out.append(" ".join(str(x) for x in a))

# 拿 stream2 的包级时间+payload+方向
r = subprocess.run(
    [c.TSHARK, "-r", PCAP, "-Y", f"tcp.stream=={TARGET_STREAM} and tcp.len>0",
     "-T", "fields", "-e", "frame.time_relative", "-e", "tcp.srcport",
     "-e", "tcp.payload"], capture_output=True, timeout=120)
pkts = []
for ln in r.stdout.decode().splitlines():
    parts = ln.split("\t")
    if len(parts) < 3:
        continue
    t, src, hexp = parts
    try:
        t = float(t)
    except ValueError:
        continue
    hexp = "".join(hexp.split())
    pkts.append((t, src, bytes.fromhex(hexp) if hexp else b""))

# 按包重组出帧序列，带时间+方向
def split_frames_timed(payload_bytes, t, is_srv):
    """从一段 payload 切出 MAGIC 帧，返回 [(t, is_srv, body)]"""
    frames = []
    parts = payload_bytes.split(b"\xfd\xfd\xfd\xfd")
    for sub in parts:
        if len(sub) >= 8:
            frames.append((t, is_srv, sub[8:]))  # 去8字节hex长度头
        elif len(sub) > 0 and not is_srv:
            # 残片
            pass
    return frames

# 重组：把同方向连续包拼起来再切帧（因为一个帧可能跨包）
# 简化：按包逐个切，记录时间
all_frames = []  # [(t, is_srv, body)]
cli_buf = b""
srv_buf = b""
last_dir = None
for t, src, payload in pkts:
    is_srv = (src == str(PORT))
    # 简单策略：每个包独立切帧
    for ft, fsrv, fb in split_frames_timed(payload, t, is_srv):
        all_frames.append((ft, fsrv, fb))

p(f"stream{TARGET_STREAM}: {len(all_frames)} 个带时间帧 "
  f"(客户端请求 {sum(1 for _,s,_ in all_frames if not s)} / "
  f"服务端响应 {sum(1 for _,s,_ in all_frames if s)})")
p(f"时间范围: {all_frames[0][0]:.1f}s - {all_frames[-1][0]:.1f}s")
p("")

# === A. 所有客户端请求（看发什么）===
p("="*70)
p("【A】stream2 所有客户端请求（按时间，看发什么触发推送）")
p("="*70)
req_count = 0
for t, is_srv, fb in all_frames:
    if is_srv:
        continue
    try:
        txt = fb.decode("gbk", "replace")
    except Exception:
        txt = ""
    # 提取关键字段
    pageid = re.search(r"pageid=(\d+)", txt)
    method = re.search(r"method=(\w+)", txt)
    code = re.search(r"CodeList=\d+\(([^)]*)\)", txt) or re.search(r"codelist=([^\n]*)", txt)
    dt = re.search(r"DateTime=(\d+\([^)]*\))", txt) or re.search(r"datetime=(\d+\([^)]*\))", txt)
    dtype = re.search(r"DataType=([^\r\n]*)", txt)
    # 心跳判定
    is_hb = b"\x12\x00\x03\x00" in fb[:12]
    if is_hb:
        kind = "心跳"
    elif pageid or method or dt:
        kind = f"{method.group(1) if method else '-'}/{pageid.group(1) if pageid else '-'}"
    else:
        kind = "?"
    code_s = code.group(1)[:25] if code else "-"
    dt_s = dt.group(1) if dt else "-"
    dtype_s = datatype.group(1)[:30] if (datatype := re.search(r"DataType=([^\r\n]*)", txt)) else "-"
    p(f"  {t:7.1f}s [{kind:<16}] code={code_s:<26} DT={dt_s:<14} DT2={datatype_s if (datatype_s:=dtype_s) else '-'}")
    req_count += 1
    if req_count > 60:
        p("  ... (截断)")
        break

# === B. 服务端响应：hd3.1 增量帧 + 时间 ===
p("")
p("="*70)
p("【B】stream2 服务端 hd3.1 帧（分时增量推送，带时间+点数+现价）")
p("="*70)
hd_count = 0
for t, is_srv, fb in all_frames:
    if not is_srv:
        continue
    if b"hd3.1\x00" not in fb and b"hd1.0" not in fb:
        continue
    tag = "hd3.1" if b"hd3.1\x00" in fb else "hd1.0"
    # 解析 MarketTime
    mt = re.search(rb"MarketTime=(\d+)\((\d+)\)", fb)
    mt_s = f"mk{mt.group(1).decode()}({mt.group(2).decode()})" if mt else "-"
    try:
        recs = parse_kline_hd3_response(fb)
    except Exception:
        recs = []
    if recs:
        prices = [r.get("dt10") for r in recs if r.get("dt10") is not None]
        t0 = recs[0].get("time"); tN = recs[-1].get("time")
        ts0 = t0.strftime("%H:%M:%S") if t0 else "?"
        tsN = tN.strftime("%H:%M:%S") if tN else "?"
        pr = f" 现价[{prices[0]}..{prices[-1]}]" if prices else ""
        p(f"  {t:7.1f}s [{tag}] {len(fb)}B {mt_s} -> {len(recs)}点 [{ts0}->{tsN}]{pr}")
    else:
        # hd1.0 文本帧
        if b"ServerCost" in fb or b"hd1.0" in fb:
            txt = fb[:50].decode("gbk", "replace")
            p(f"  {t:7.1f}s [{tag}] {len(fb)}B {mt_s} 文本")
        else:
            p(f"  {t:7.1f}s [{tag}] {len(fb)}B {mt_s} 解析空")
    hd_count += 1
    if hd_count > 40:
        p("  ... (截断)")
        break

# === C. 无标记小帧（321B/488B 等）内容探测 ===
p("")
p("="*70)
p("【C】stream2 无标记小帧内容探测（321B/488B 持续帧是什么）")
p("="*70)
# 按大小分组统计
from collections import Counter
size_cnt = Counter(len(fb) for t, is_srv, fb in all_frames if is_srv)
p("服务端帧大小分布 TOP10:")
for sz, cnt in size_cnt.most_common(10):
    p(f"  {sz}B: {cnt} 次")

# 取一个 321B 和 488B 的样本看内容
p("")
p("── 321B 样本（前3个）──")
shown = 0
for t, is_srv, fb in all_frames:
    if not is_srv or len(fb) != 321:
        continue
    p(f"  {t:7.1f}s 前64hex: {fb[:64].hex(' ')}")
    # 尝试 gbk 解码看有没有可读文本
    try:
        txt = fb.decode("gbk", "replace")
        printable = "".join(ch if 32 <= ord(ch) < 127 else "." for ch in txt[:80])
        p(f"          ascii: {printable}")
    except Exception:
        pass
    # 看头部 cmd/subtype
    if len(fb) > 11:
        p(f"          头12: {fb[:12].hex(' ')}  cmd={fb[0]:#x} subtype={fb[7:11].hex()}")
    shown += 1
    if shown >= 3:
        break

p("")
p("── 488B 样本（前3个）──")
shown = 0
for t, is_srv, fb in all_frames:
    if not is_srv or len(fb) != 488:
        continue
    p(f"  {t:7.1f}s 前64hex: {fb[:64].hex(' ')}")
    try:
        txt = fb.decode("gbk", "replace")
        printable = "".join(ch if 32 <= ord(ch) < 127 else "." for ch in txt[:80])
        p(f"          ascii: {printable}")
    except Exception:
        pass
    if len(fb) > 11:
        p(f"          头12: {fb[:12].hex(' ')}  cmd={fb[0]:#x} subtype={fb[7:11].hex()}")
    shown += 1
    if shown >= 3:
        break

# === D. 请求-响应时间间隔（判断轮询 vs 主动推）===
p("")
p("="*70)
p("【D】请求-响应时间间隔（判断是轮询还是主动推送）")
p("="*70)
# 找 hd3.1 增量帧前最近的客户端请求
cli_times = [t for t, s, _ in all_frames if not s]
hd_times = []
for t, is_srv, fb in all_frames:
    if is_srv and (b"hd3.1\x00" in fb):
        try:
            recs = parse_kline_hd3_response(fb)
            if recs and any(r.get("dt10") is not None for r in recs):
                hd_times.append(t)
        except Exception:
            pass
p(f"含现价的 hd3.1 增量帧时间: {[f'{x:.1f}' for x in hd_times[:15]]}")
p(f"客户端请求总数(含心跳): {len(cli_times)}, 平均间隔: "
  f"{(cli_times[-1]-cli_times[0])/max(len(cli_times)-1,1):.2f}s" if cli_times else "")

outpath = "captures_live/_stream2_analysis.txt"
open(outpath, "w", encoding="utf-8").write("\n".join(out))
print(f"写入 {outpath} ({len(out)} 行)")
