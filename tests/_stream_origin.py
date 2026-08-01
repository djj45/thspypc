#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""关键：71B 推送所在 stream 是怎么建立的？登录连接还是独立连接？

之前一直假设「主连接发请求即触发推送」，但实测零响应。
重新查 market_open.pcap（盘中包，有 71B 推送）：
1. 71B 推送在哪些 stream？这些 stream 的 SYN 握手时间 vs 登录时间
2. 这些 stream 上有没有 login 帧？还是无登录的「裸推送连接」？
3. stream 上的第一个客户端帧是什么？（login？subreal？还是别的）
"""
import os, sys, re, subprocess
sys.path.insert(0, os.path.dirname(__file__))
import capture_timeline as c

out = []
def p(*a):
    out.append(" ".join(str(x) for x in a))

# 用市场开盘包（盘中，有 71B 推送）
for PCAP, label in [
    ("captures_live/market_open.pcap", "market_open(盘中)"),
    ("captures_live/realtime_push_20260724_104540.pcap", "realtime_push_104540(盘中)"),
]:
    p("="*70)
    p(f"【{label}】71B 推送 stream 的来源分析")
    p("="*70)

    # 找含 71B 推送的 stream
    r = subprocess.run(
        [c.TSHARK, "-r", PCAP, "-Y", "tcp.srcport==8901 and tcp.len>0",
         "-T", "fields", "-e", "tcp.stream", "-e", "tcp.payload"],
        capture_output=True, timeout=120)
    push_streams = set()
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
            if len(fb) in (71, 72) and fb[:1] == b"\x09" and len(fb) >= 35 \
               and all(0x30 <= b <= 0x39 for b in fb[29:35]):
                push_streams.add(int(sid))
                break

    p(f"含 71B 推送的 stream: {sorted(push_streams)}")

    # 对每个推送 stream：看 SYN 时间 + 第一个客户端帧
    for sid in sorted(push_streams)[:4]:
        p(f"\n--- stream {sid} ---")
        # SYN/SYN-ACK 时间（连接建立）
        r2 = subprocess.run(
            [c.TSHARK, "-r", PCAP, "-Y",
             f"tcp.stream=={sid} and tcp.flags.syn==1",
             "-T", "fields", "-e", "frame.time_relative",
             "-e", "tcp.flags"],
            capture_output=True, timeout=60)
        syn_times = [ln.split("\t")[0] for ln in r2.stdout.decode().splitlines() if ln]
        p(f"  SYN 握手时间: {syn_times}")

        # 第一个客户端数据帧（tcp.dstport==8901）
        r3 = subprocess.run(
            [c.TSHARK, "-r", PCAP, "-Y",
             f"tcp.stream=={sid} and tcp.dstport==8901 and tcp.len>0",
             "-T", "fields", "-e", "frame.time_relative", "-e", "tcp.payload"],
            capture_output=True, timeout=60)
        first_cli = []
        for ln in r3.stdout.decode().splitlines():
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
                is_login = "Ask=login" in txt
                is_hb = b"\x12\x00\x03\x00" in fb[:12] and b"tsi0=" in fb
                method = re.search(r"method=(\w+)", txt)
                if is_hb:
                    kind = "心跳"
                elif is_login:
                    kind = "★LOGIN"
                elif method:
                    kind = f"{method.group(1)}"
                else:
                    kind = "?"
                first_cli.append((t, kind, txt[:80].replace("\n","|")))
                break  # 每包首个帧
            if len(first_cli) >= 5:
                break

        p(f"  前5个客户端帧:")
        for t, kind, txt in first_cli[:5]:
            p(f"    {t:6.1f}s [{kind:<8}] {txt[:70]!r}")

        # 有没有 login 帧？
        has_login = any(k == "★LOGIN" for _, k, _ in first_cli)
        p(f"  含 login 帧: {has_login}")

    p("")

open("captures_live/_stream_origin.txt", "w", encoding="utf-8").write("\n".join(out))
print(f"写入 captures_live/_stream_origin.txt ({len(out)} 行)")
