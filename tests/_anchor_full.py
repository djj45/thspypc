#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""完整锚定 71B/72B 快照帧字段表（已确认 off58-59 LE16=现价×1000）。

已知：
- off0=0x09 cmd, off5 变化(序号?), off12 变化(时间戳高位?)
- off25=市场标志, off29-34=ASCII代码
- off50-51 变化(累计额?), off54 变化, off58-59=现价(LE16÷1000)
- off61 固定 0xb0, off62-63 变化, off66-68 变化(额?)
- 72B 比 71B 多1字节

本脚本：
1. 71B vs 72B 逐字节对照，找多出的字节位置
2. 用 LE16÷1000 假设验证更多字段(开盘/最高/最低/昨收)
3. 确认 off54 变化字段(可能均价/涨跌)
4. 输出最终字段表
"""
import os, sys, re, struct, subprocess
from collections import defaultdict
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.dirname(__file__))
import capture_timeline as c
from thspypc.protocol import decode_ths_float

PCAP = "captures_live/realtime_push_20260724_104540.pcap"
out = []
def p(*a):
    out.append(" ".join(str(x) for x in a))

r = subprocess.run(
    [c.TSHARK, "-r", PCAP, "-Y", "tcp.srcport==8901 and tcp.len>0",
     "-T", "fields", "-e", "frame.time_relative", "-e", "tcp.stream",
     "-e", "tcp.payload"], capture_output=True, timeout=120)
frames_by_code = defaultdict(list)
for ln in r.stdout.decode().splitlines():
    parts = ln.split("\t")
    if len(parts) < 3:
        continue
    t, sid, hexp = parts
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
        if len(fb) in (71, 72) and fb[:1] == b"\x09":
            codes = re.findall(rb"[036]\d{5}", fb)
            code = codes[0].decode() if codes else "?"
            frames_by_code[code].append((t, len(fb), fb))

# === A. 71B vs 72B 逐字节对照 ===
p("="*70)
p("【A】71B vs 72B 结构差异（找多出的字节）")
p("="*70)
for code in ["603118"]:
    f71 = [fb for t, l, fb in frames_by_code.get(code, []) if l == 71][:5]
    f72 = [fb for t, l, fb in frames_by_code.get(code, []) if l == 72][:5]
    if not f71 or not f72:
        continue
    p(f"\n{code} 71B 样本0: {f71[0].hex(' ')}")
    p(f"{code} 72B 样本0: {f72[0].hex(' ')}")
    # 找第一个不同的位置
    min_len = min(71, 72)
    diff_pos = []
    for i in range(min_len):
        if f71[0][i] != f72[0][i]:
            diff_pos.append(i)
    p(f"前71字节差异位置: {diff_pos}")
    # 72B 多的是最后1字节？还是中间插入？
    if len(f72[0]) > 71:
        p(f"72B 末字节: 0x{f72[0][-1]:02x}, 71B 末字节: 0x{f71[0][-1]:02x}")
    # 对齐检查：71B[0:35] 是否 == 72B[0:35]
    same_prefix = f71[0][:35] == f72[0][:35]
    p(f"前35字节相同: {same_prefix}")
    # 找 72B 中 off58 区域
    for i, fb in enumerate(f72[:3]):
        # 现价在 off58? 72B 可能偏移了
        for off in [57, 58, 59]:
            if off+1 < len(fb):
                le16 = struct.unpack("<H", fb[off:off+2])[0]
                if 14000 < le16 < 20000:  # 603118 价位 14-20
                    p(f"  72B样本{i}: off{off}-off{off+1} LE16={le16} → {le16/1000:.3f} (现价候选)")

# === B. 现价 LE16÷1000 全面验证 + 找其他价格字段 ===
p("")
p("="*70)
p("【B】603118 所有可能的 LE16÷1000 价格字段（价位14-20元）")
p("="*70)
frames_603 = [(t, fb) for t, l, fb in frames_by_code.get("603118", []) if l == 71][:20]
if frames_603:
    # 对每个2字节对齐位置，看是否落在合理价位
    price_fields = {}
    for off in range(0, 70):
        vals = []
        for t, fb in frames_603:
            if off + 2 <= len(fb):
                le16 = struct.unpack("<H", fb[off:off+2])[0]
                vals.append(le16)
        # 看这些值是否都在 14000-20000 (14-20元)
        in_range = sum(1 for v in vals if 10000 < v < 25000)
        if in_range >= len(vals) * 0.7 and len(vals) > 5:
            price_fields[off] = vals
    p(f"\n落在价位区间(10-25元)的2字节位置: {sorted(price_fields.keys())}")
    for off in sorted(price_fields.keys()):
        vals = price_fields[off][:8]
        decoded = [f"{v/1000:.2f}" for v in vals]
        p(f"  off{off}: LE16值 {vals} → 价格 {decoded}")

# === C. off54 区域 + 其他变化字段解码 ===
p("")
p("="*70)
p("【C】所有变化字段的多种解码尝试")
p("="*70)
if frames_603:
    var_pos = [5, 12, 39, 50, 51, 54, 58, 59, 62, 63, 66, 67, 68]
    p(f"\n变化位置: {var_pos}")
    p(f"\n逐帧变化字节值:")
    p(f"{'t':>4} {'p5':>4} {'p12':>4} {'p39':>4} {'p50-51':>12} {'p54':>4} {'p58-59':>10} {'p62-63':>10} {'p66-68':>16}")
    for t, fb in frames_603[:15]:
        p(f"{t:>4.1f} 0x{fb[5]:02x} 0x{fb[12]:02x} 0x{fb[39]:02x} "
          f"{fb[50:52].hex():>12} 0x{fb[54]:02x} "
          f"{struct.unpack('<H',fb[58:60])[0]:>8}(÷1k={struct.unpack('<H',fb[58:60])[0]/1000:.2f}) "
          f"{struct.unpack('<H',fb[62:64])[0]:>8} "
          f"{fb[66:69].hex():>16}")

# === D. 000938 验证现价 off58-59 ===
p("")
p("="*70)
p("【D】000938(紫光) off58-59 验证（现价应~42元）")
p("="*70)
frames_938 = [(t, fb) for t, l, fb in frames_by_code.get("000938", []) if l == 71][:15]
for t, fb in frames_938[:10]:
    le16 = struct.unpack("<H", fb[58:60])[0]
    p(f"  t={t:.1f}s off58-59 LE16={le16} → {le16/1000:.3f}")

outpath = "captures_live/_fields_full.txt"
open(outpath, "w", encoding="utf-8").write("\n".join(out))
print(f"写入 {outpath} ({len(out)} 行)")
