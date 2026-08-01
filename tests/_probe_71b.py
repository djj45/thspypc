#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""解码 71B/72B 持续小帧（疑似个股实时快照推送 = 分时白线数据源）。

321B 帧已确认是指数快照（含 '399001' GBK 文本 + 二进制 OHLC）。
71B/72B 帧结构未知，但出现 816 次（每~3s 一个），贯穿整个抓包。
若是单股快照，里面应该有：代码/现价/量/额/买卖盘。
"""
import os, sys, re, struct, subprocess
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.dirname(__file__))
import capture_timeline as c
from thspypc.protocol import decode_ths_float

PCAP = "captures_live/realtime_push_20260724_104540.pcap"
PORT = 8901

out = []
def p(*a):
    out.append(" ".join(str(x) for x in a))

# 收集所有 stream 的服务端帧（带时间）
r = subprocess.run(
    [c.TSHARK, "-r", PCAP, "-Y", f"tcp.srcport=={PORT} and tcp.len>0",
     "-T", "fields", "-e", "frame.time_relative", "-e", "tcp.stream",
     "-e", "tcp.payload"], capture_output=True, timeout=120)
all_frames = []  # [(t, stream, body)]
for ln in r.stdout.decode().splitlines():
    parts = ln.split("\t")
    if len(parts) < 3:
        continue
    t, sid, hexp = parts
    try:
        t = float(t); sid = int(sid)
    except ValueError:
        continue
    hexp = "".join(hexp.split())
    if not hexp:
        continue
    raw = bytes.fromhex(hexp)
    for sub in raw.split(b"\xfd\xfd\xfd\xfd"):
        if len(sub) >= 8:
            all_frames.append((t, sid, sub[8:]))

# 取 71B 和 72B 样本
p("="*70)
p("【71B/72B 小帧解码】（贯穿全程的持续推送）")
p("="*70)
samples_71 = [(t, s, fb) for t, s, fb in all_frames if len(fb) == 71][:8]
samples_72 = [(t, s, fb) for t, s, fb in all_frames if len(fb) == 72][:8]

p(f"\n── 71B 样本 ({len(samples_71)}个) ──")
for i, (t, s, fb) in enumerate(samples_71):
    p(f"\n[样本{i}] t={t:.1f}s stream{s}")
    p(f"  全hex: {fb.hex(' ')}")
    # cmd 字节
    p(f"  byte0(cmd)={fb[0]:#04x}  byte1-4={fb[1:5].hex()}")
    # 尝试找 ASCII 代码（6位数字）
    ascii_run = re.findall(rb"[036]\d{5}", fb)
    p(f"  ASCII代码候选: {[x.decode() for x in ascii_run]}")
    # 尝试各种 THS float 解码（每4字节滑动）
    p(f"  4字节滑动 THS float (合理价位 1-1000):")
    found = []
    for off in range(0, len(fb)-3, 1):
        u32 = struct.unpack("<I", fb[off:off+4])[0]
        val = decode_ths_float(u32)
        if 0.5 < val < 5000:
            found.append((off, val, u32))
    # 去重相近的
    seen_val = set()
    for off, val, u32 in found:
        rk = round(val, 2)
        if rk in seen_val:
            continue
        seen_val.add(rk)
        p(f"    off={off:2d}: val={val:.4f} (u32={u32:#010x})")

p(f"\n── 72B 样本 ({len(samples_72)}个) ──")
for i, (t, s, fb) in enumerate(samples_72):
    p(f"\n[样本{i}] t={t:.1f}s stream{s}")
    p(f"  全hex: {fb.hex(' ')}")
    p(f"  byte0(cmd)={fb[0]:#04x}  byte1-4={fb[1:5].hex()}")
    ascii_run = re.findall(rb"[036]\d{5}", fb)
    p(f"  ASCII代码候选: {[x.decode() for x in ascii_run]}")
    found = []
    for off in range(0, len(fb)-3, 1):
        u32 = struct.unpack("<I", fb[off:off+4])[0]
        val = decode_ths_float(u32)
        if 0.5 < val < 5000:
            found.append((off, val, u32))
    seen_val = set()
    for off, val, u32 in found:
        rk = round(val, 2)
        if rk in seen_val:
            continue
        seen_val.add(rk)
        p(f"    off={off:2d}: val={val:.4f} (u32={u32:#010x})")

# 对比：321B 指数帧里现价怎么编码（已知 399001 深证成指）
p("")
p("="*70)
p("【对照：321B 指数帧解码】（已知含 '399001'，看现价编码方式）")
p("="*70)
idx_samples = [(t, s, fb) for t, s, fb in all_frames if len(fb) == 321][:2]
for i, (t, s, fb) in enumerate(idx_samples):
    p(f"\n[指数样本{i}] t={t:.1f}s stream{s}")
    code_pos = fb.find(b"399001")
    p(f"  '399001' 位置: byte{code_pos}")
    p(f"  代码前后 hex: ...{fb[max(0,code_pos-8):code_pos+14].hex(' ')}...")
    # 指数现价一般几千~几万点，找大数值
    found = []
    for off in range(0, len(fb)-3, 1):
        u32 = struct.unpack("<I", fb[off:off+4])[0]
        val = decode_ths_float(u32)
        if 500 < val < 50000:  # 指数点位范围
            found.append((off, val))
    p(f"  THS float 指数级数值(500-50000): {[(o,f'{v:.2f}') for o,v in found[:10]]}")

outpath = "captures_live/_71b_decode.txt"
open(outpath, "w", encoding="utf-8").write("\n".join(out))
print(f"写入 {outpath} ({len(out)} 行)")
