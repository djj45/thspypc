#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""精确锚定 71B/72B 逐 tick 快照帧的字段布局（多样本对照，不靠猜）。

策略：
1. 收集同一只股票(603118)连续多个 71B 帧，按字节对齐叠加
2. 找「变化字节」vs「固定字节」——现价/量/额会变，代码/市场/标志固定
3. 对变化字节尝试 THS float / LE32 / LE16 解码，对照已知现价(16.xx)
4. 用两只不同股票(603118 vs 000938)交叉验证代码字段偏移
5. 用 321B 指数帧(已知现价~1万点)验证 THS float 编码正确性

目标：给出每个字段的【偏移+长度+类型+含义】，可直接写解析器。
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

# 收集所有 71/72B 帧，按 stream+代码分组
r = subprocess.run(
    [c.TSHARK, "-r", PCAP, "-Y", "tcp.srcport==8901 and tcp.len>0",
     "-T", "fields", "-e", "frame.time_relative", "-e", "tcp.stream",
     "-e", "tcp.payload"], capture_output=True, timeout=120)
frames_by_code = defaultdict(list)  # code -> [(t, len, body)]
all_push = []
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
            # 提取 ASCII 代码
            codes = re.findall(rb"[036]\d{5}", fb)
            code = codes[0].decode() if codes else "?"
            frames_by_code[code].append((t, len(fb), fb))
            all_push.append((t, code, len(fb), fb))

p(f"共 {len(all_push)} 个 71/72B 推送帧")
p(f"涉及代码: {sorted(frames_by_code.keys())}")
for code, lst in sorted(frames_by_code.items()):
    p(f"  {code}: {len(lst)} 帧, 大小分布 {sorted(set(l for _,l,_ in lst))}")
p("")

# === A. 603118 多帧对齐，找变化字节 ===
p("="*70)
p("【A】603118 连续 71B 帧字节级对照（找变化字节=数据，固定=结构）")
p("="*70)
frames_603 = [fb for t, l, fb in frames_by_code.get("603118", []) if l == 71][:15]
if len(frames_603) < 3:
    p("603118 71B 样本不足")
else:
    # 按字节位置统计：该位置所有帧的值集合
    p(f"\n603118 71B 帧，{len(frames_603)} 个样本，逐字节变化性分析：")
    p(f"{'pos':>3} {'示例值(hex)':>12} {'变化?':>6}  解读")
    p("-"*70)
    fixed_regions = []
    var_regions = []
    for pos in range(71):
        vals = set(f[pos] for f in frames_603)
        sample = frames_603[0][pos]
        is_var = len(vals) > 1
        # 尝试解读
        note = ""
        # 检查是否 ASCII 数字
        if 0x30 <= sample <= 0x39:
            note = f"ASCII '{chr(sample)}'"
        elif sample == 0x09:
            note = "cmd=0x09"
        mark = "***变" if is_var else "固定"
        p(f"{pos:>3}   0x{sample:02x}({sample:>3}) {mark:>6}  {note}")
        if is_var:
            var_regions.append(pos)
        else:
            fixed_regions.append(pos)
    p(f"\n变化字节位置: {var_regions}")
    p(f"固定字节位置数: {len(fixed_regions)}/71")

# === B. 现价字段精确定位（off=47 区域 b0 XX XX）===
p("")
p("="*70)
p("【B】现价字段精确定位（off=47 区域，对照 THS float）")
p("="*70)
if frames_603:
    p(f"\n603118 的 off=44~53 区域（10字节），逐帧解码：")
    p(f"{'帧':>3} {'时间':>6}  {'hex(off44-53)':>32}  off47 THS  off51 THS")
    for i, (t, l, fb) in enumerate(frames_by_code.get("603118", [])[:15]):
        if l != 71:
            continue
        seg = fb[44:54]
        v47 = decode_ths_float(struct.unpack("<I", fb[47:51])[0])
        v51 = decode_ths_float(struct.unpack("<I", fb[51:55])[0]) if len(fb) >= 55 else 0
        p(f"{i:>3} {t:>6.1f}s  {seg.hex(' '):>32}  {v47:>9.4f}  {v51:>9.4f}")

# === C. 两只股票交叉验证代码字段 ===
p("")
p("="*70)
p("【C】代码字段交叉验证（603118 vs 000938）")
p("="*70)
for code in ["603118", "000938"]:
    lst = [fb for t, l, fb in frames_by_code.get(code, []) if l == 71][:3]
    if not lst:
        continue
    p(f"\n{code}:")
    for i, fb in enumerate(lst):
        # 找代码在帧里的位置
        code_bytes = code.encode()
        pos = fb.find(code_bytes)
        p(f"  样本{i}: 代码位置 byte{pos}, 前后: {fb[max(0,pos-3):pos+9].hex(' ')}")

# === D. 用 321B 指数帧验证 THS float 编码（指数现价~1万点）===
p("")
p("="*70)
p("【D】321B 指数帧 THS float 验证（深证成指现价应~1万点）")
p("="*70)
idx_frames = [(t, fb) for t, code, l, fb in all_push if l == 321]
# 321B 在 all_push 里没有（只收了71/72），单独收
r2 = subprocess.run(
    [c.TSHARK, "-r", PCAP, "-Y", "tcp.srcport==8901 and tcp.len>0",
     "-T", "fields", "-e", "frame.time_relative", "-e", "tcp.stream",
     "-e", "tcp.payload"], capture_output=True, timeout=120)
idx_samples = []
for ln in r2.stdout.decode().splitlines():
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
        if len(fb) == 321 and b"399001" in fb:
            idx_samples.append((t, fb))
            break
p(f"含 399001 的 321B 帧样本数: {len(idx_samples)}")
for i, (t, fb) in enumerate(idx_samples[:3]):
    code_pos = fb.find(b"399001")
    p(f"\n[指数样本{i}] t={t:.1f}s, 399001@byte{code_pos}")
    p(f"  代码区 hex: {fb[code_pos-4:code_pos+10].hex(' ')}")
    # 深证成指当日约 10000-12000 点，找这个范围的 THS float
    candidates = []
    for off in range(code_pos, min(len(fb)-3, code_pos+80)):
        u32 = struct.unpack("<I", fb[off:off+4])[0]
        val = decode_ths_float(u32)
        if 8000 < val < 15000:
            candidates.append((off, val, off-code_pos))
    p(f"  代码后 THS float(8000-15000, 疑似指数点位): "
      f"{[(o,f'{v:.2f}',f'+{r}') for o,v,r in candidates[:8]]}")

outpath = "captures_live/_anchor_71b.txt"
open(outpath, "w", encoding="utf-8").write("\n".join(out))
print(f"写入 {outpath} ({len(out)} 行)")
