#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
抓 hexin 短线精灵推送（9601 pushrealorder）+ 启动序列（8901 subreal）。

⚠ 必须盘中运行（周一~周五 9:30-15:00），否则没有异动推送。

用法：
    py tests/capture_hexin_start.py                # 默认 300s（5 分钟）
    py tests/capture_hexin_start.py --duration 600 # 抓 10 分钟

操作步骤（严格按顺序）：
    1. 先彻底退出同花顺（任务管理器确认 hexin.exe 没了）
    2. 运行本脚本（选网卡后开始抓包）
    3. 看到「开始抓包」后，立即启动同花顺并登录
    4. 登录后切到「短线精灵」页面，滚动几下（触发推送接收）
    5. 保持同花顺在前台、短线精灵页面可见（不要最小化，否则可能停推）
    6. 等待自动结束，脚本会分析推送帧统计

产物：captures_live/hexin_full.pcap + 推送帧统计报告
"""
import argparse
import os
import re
import subprocess
import sys
from collections import Counter, defaultdict

WS = r"D:\软件\Wireshark-4.4.7-x64-with-Npcap-1.50-Portable\Wireshark\App\Wireshark"
DUMPCAP = os.path.join(WS, "dumpcap.exe")
TSHARK = os.path.join(WS, "tshark.exe")
PCAP_DIR = os.path.join(os.path.dirname(__file__), "..", "captures_live")
PCAP = os.path.join(PCAP_DIR, "hexin_full.pcap")

MAGIC = b"\xfd\xfd\xfd\xfd"  # 9601 帧分隔符（同 8901；见 protocol.py FRAME_MAGIC）


def list_interfaces():
    r = subprocess.run([TSHARK, "-D"], capture_output=True,
                       encoding="gbk", errors="replace", timeout=15)
    ifaces = {}
    for ln in (r.stdout or "").splitlines():
        m = re.match(r"(\d+)\.\s+(\S+)\s+\((.+?)\)", ln)
        if m:
            ifaces[m.group(1)] = (m.group(2), m.group(3))
    return ifaces


def pick_interface():
    ifaces = list_interfaces()
    if not ifaces:
        print("✗ 未检测到网卡")
        sys.exit(1)
    print("网卡列表:")
    for num, (dev, desc) in ifaces.items():
        mark = " ← 推荐" if desc.strip() == "WLAN" else ""
        print(f"  {num}. {desc}{mark}")
    default = next((n for n, (_, d) in ifaces.items() if d.strip() == "WLAN"), "4")
    choice = input(f"\n选择网卡编号 [{default}]: ").strip() or default
    if choice not in ifaces:
        print("无效编号，用默认 4")
        choice = "4"
    return choice


def capture(iface, duration):
    os.makedirs(PCAP_DIR, exist_ok=True)
    print(f"\n{'='*60}")
    print(f"开始抓包 {duration}s（8901 + 9601，网卡 {iface}）")
    print(f"{'='*60}")
    print(">>> 现在立即：")
    print("    1. 启动同花顺并登录")
    print("    2. 登录后切到「短线精灵」页面，滚动几下")
    print("    3. 保持短线精灵页面可见（别最小化！）")
    print("-" * 60)
    try:
        subprocess.run(
            [DUMPCAP, "-i", iface, "-f", "tcp port 8901 or tcp port 9601",
             "-w", PCAP, "-a", f"duration:{duration}"],
            timeout=duration + 15,
        )
    except KeyboardInterrupt:
        print("\n抓包提前结束（已保存）")
    except subprocess.TimeoutExpired:
        print("\n抓包超时")
    size = os.path.getsize(PCAP) if os.path.exists(PCAP) else 0
    print(f"\n抓包完成：{PCAP} ({size:,} bytes)")


def _tshark(y_filter, fields):
    cmd = [TSHARK, "-r", PCAP, "-Y", y_filter, "-T", "fields"]
    for f in fields:
        cmd += ["-e", f]
    r = subprocess.run(cmd, capture_output=True, timeout=180)
    return r.stdout.decode("utf-8", errors="replace")


def _split_frames(payload):
    """9601 帧也用 fdfdfdfd magic + 8字节hex长度。"""
    frames = []
    for sub in payload.split(MAGIC):
        if len(sub) >= 8:
            frames.append(sub[8:])
    return frames


def analyze():
    if not os.path.exists(PCAP):
        print(f"✗ pcap 不存在: {PCAP}")
        return

    print(f"\n{'='*60}")
    print("【1】连接概览（8901 + 9601）")
    print(f"{'='*60}")
    out = _tshark("tcp.port==8901 or tcp.port==9601",
                  ["tcp.stream", "ip.src", "tcp.srcport", "ip.dst", "tcp.dstport"])
    streams = {}
    for ln in out.splitlines():
        p = ln.split("\t")
        if len(p) >= 5:
            sid = p[0]
            if sid not in streams:
                streams[sid] = p
    port_n = Counter()
    for sid, p in streams.items():
        dp = p[4] if len(p) > 4 else "?"
        port_n[dp] += 1
    print(f"  共 {len(streams)} 条 TCP 流：8901={port_n.get('8901',0)} 9601={port_n.get('9601',0)}")

    # 【2】推送帧统计（核心）
    print(f"\n{'='*60}")
    print("【2】pushrealorder 推送帧统计（★核心）")
    print(f"{'='*60}")
    # 9601 服务器下行的所有 payload
    out = _tshark("tcp.srcport==9601 and tcp.payload",
                  ["frame.number", "frame.time_relative", "tcp.len", "tcp.payload"])
    push_frames = []
    all_push_bytes = 0
    push_codes = Counter()
    push_sizes = []
    push_times = []
    for ln in out.splitlines():
        p = ln.split("\t")
        if len(p) < 4:
            continue
        fr, t, ln_len, hx = p
        try:
            payload = bytes.fromhex(hx.replace(":", ""))
        except ValueError:
            continue
        for body in _split_frames(payload):
            if b"pushrealorder" not in body:
                continue
            push_frames.append((fr, float(t or 0), int(ln_len or 0), body))
            all_push_bytes += len(body)
            push_sizes.append(len(body))
            push_times.append(float(t or 0))
            # 提取异动代码（格式 A: 0x21+6BASCII；格式 B: 0x2d+len+代码）
            for m in re.finditer(rb"[\x21\x2d]([036]\d{5})", body):
                push_codes[m.group(1).decode("ascii", errors="replace")] += 1

    if not push_frames:
        print("  ✗ 未抓到 pushrealorder 推送帧")
        print("    可能原因：① 非交易日/非盘中（必须 9:30-15:00）")
        print("              ② 同花顺没切到短线精灵页面")
        print("              ③ 同花顺被最小化（停推）")
        print("              ④ 选错网卡")
    else:
        print(f"\n  ★ 抓到 {len(push_frames)} 个 pushrealorder 帧（{all_push_bytes:,} 字节）")
        if push_sizes:
            print(f"  帧大小：min={min(push_sizes)} avg={sum(push_sizes)//len(push_sizes)} "
                  f"max={max(push_sizes)}")
        if push_times:
            t0, t1 = min(push_times), max(push_times)
            print(f"  时间跨度：{t0:.1f}s ~ {t1:.1f}s（{t1-t0:.1f}s）")
            if t1 - t0 > 0:
                rate = len(push_frames) / (t1 - t0) * 60
                print(f"  推送频率：≈ {rate:.0f} 帧/分钟")
        if push_codes:
            print(f"\n  异动代码统计（去重前 {sum(push_codes.values())}，唯一 {len(push_codes)}）：")
            print(f"  出现最多的 15 个代码：")
            for code, n in push_codes.most_common(15):
                print(f"    {code}: {n} 次")

    # 【3】9601 客户端请求（subrealorder 订阅 + qurealorder 历史）
    print(f"\n{'='*60}")
    print("【3】9601 客户端请求（订阅 + 历史查询）")
    print(f"{'='*60}")
    out = _tshark("tcp.dstport==9601 and tcp.payload", ["tcp.payload"])
    methods = Counter()
    for ln in out.splitlines():
        hx = ln.strip().replace(":", "")
        if not hx:
            continue
        try:
            payload = bytes.fromhex(hx)
        except ValueError:
            continue
        for body in _split_frames(payload):
            for m in re.finditer(rb"method=(\w+)", body):
                methods[m.group(1).decode("ascii", errors="replace")] += 1
    if methods:
        for m, n in sorted(methods.items(), key=lambda x: -x[1]):
            print(f"  method={m}: {n} 次")
    else:
        print("  ✗ 未抓到 9601 客户端请求")

    # 【4】8901 subreal 订阅（启动序列）
    print(f"\n{'='*60}")
    print("【4】8901 subreal 订阅序列")
    print(f"{'='*60}")
    out = _tshark('tcp.dstport==8901 and tcp.payload contains "method=subreal"',
                  ["tcp.payload"])
    sub_markets = Counter()
    for ln in out.splitlines():
        hx = ln.strip().replace(":", "")
        if not hx:
            continue
        try:
            payload = bytes.fromhex(hx)
        except ValueError:
            continue
        for body in _split_frames(payload):
            for m in re.finditer(rb"market=(\w+)", body):
                if b"subreal" in body:
                    sub_markets[m.group(1).decode("ascii", errors="replace")] += 1
    if sub_markets:
        for mk, n in sorted(sub_markets.items(), key=lambda x: -x[1]):
            print(f"  subreal market={mk}: {n} 次")
    else:
        print("  ✗ 未抓到 subreal 订阅（可能同花顺没重启，走了缓存）")

    print(f"\npcap 已保存：{PCAP}")
    print(f"用 Wireshark 打开可 Follow TCP Stream 看具体推送内容")


def main():
    ap = argparse.ArgumentParser(description="抓短线精灵推送（9601 pushrealorder）")
    ap.add_argument("--duration", type=int, default=300,
                    help="抓包时长（秒），默认 300（5 分钟）")
    ap.add_argument("--iface", default=None,
                    help="网卡编号（默认交互选择或 4=WLAN）")
    args = ap.parse_args()
    iface = args.iface or pick_interface()
    capture(iface, args.duration)
    analyze()


if __name__ == "__main__":
    main()
