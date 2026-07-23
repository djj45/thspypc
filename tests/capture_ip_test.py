#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
抓同花顺「获取/测试 IP」功能的流量，看它怎么选服务器 IP。

用途：thspypc 当前对所有 IP 一视同仁（并发连前 7 个），经常选到慢 IP。
      同花顺有主动测速选 IP 的功能，本脚本抓它点按钮时的流量，看：
      - 它请求什么接口拿 IP 列表（HTTP? 8901?）
      - 怎么测速/排序
      - 最终选哪些 IP

操作步骤（严格按顺序）：
    1. 启动同花顺，停在登录界面（别登录）
    2. 运行本脚本（选网卡后开始抓包）
    3. 看到「开始抓包」后，点「获取/测试 IP」按钮
    4. 等它测完显示结果（通常几秒~十几秒）
    5. 等待自动结束，脚本会分析

用法：
    py tests/capture_ip_test.py                # 默认 30s
    py tests/capture_ip_test.py --duration 45
    py tests/capture_ip_test.py --pcap xxx.pcap  # 分析已有 pcap
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
PCAP = os.path.join(PCAP_DIR, "ip_test.pcap")


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
    return choice if choice in ifaces else "4"


def capture(iface, duration):
    os.makedirs(PCAP_DIR, exist_ok=True)
    print(f"\n{'='*60}")
    print(f"抓包 {duration}s（全端口，网卡 {iface}）")
    print(f"{'='*60}")
    print(">>> 现在立即：")
    print("    1. 在同花顺登录界面，点「获取/测试 IP」按钮")
    print("    2. 等它测完显示结果")
    print("-" * 60)
    # 抓全端口（IP 测试可能走 HTTP 80/443，也可能走别的端口）
    try:
        subprocess.run(
            [DUMPCAP, "-i", iface, "-f", "tcp or udp",
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


def _tshark_follow(stream_id):
    cmd = [TSHARK, "-r", PCAP, "-z", f"follow,tcp,ascii,{stream_id}"]
    r = subprocess.run(cmd, capture_output=True, timeout=180)
    return r.stdout.decode("utf-8", errors="replace")


def analyze():
    if not os.path.exists(PCAP):
        print(f"✗ pcap 不存在: {PCAP}")
        return
    print(f"\n{'#'*60}")
    print(f"# 分析 IP 测试功能流量")
    print(f"{'#'*60}")

    # 【1】HTTP 请求（IP 列表接口最可能是 HTTP）
    print(f"\n{'='*60}")
    print("【1】HTTP 请求（找 IP 列表接口）")
    print(f"{'='*60}")
    out = _tshark("http.request", ["tcp.stream", "http.host", "http.request.uri"])
    http_streams = []
    for ln in out.splitlines():
        p = ln.split("\t")
        if len(p) >= 3 and p[2]:
            host = p[1]
            uri = p[2]
            sid = p[0]
            http_streams.append((sid, host, uri))
            print(f"  stream {sid}: {host}{uri[:80]}")
    if not http_streams:
        print("  ✗ 无 HTTP 请求（可能 IP 测试不走 HTTP，看【2】）")

    # 【2】连接的所有目标 IP + 端口（看测速模式）
    print(f"\n{'='*60}")
    print("【2】所有目标 IP:端口（测速连接）")
    print(f"{'='*60}")
    out = _tshark("tcp.flags.syn==1 and tcp.flags.ack==0", ["ip.dst", "tcp.dstport"])
    conn = Counter()
    for ln in out.splitlines():
        p = ln.split("\t")
        if len(p) >= 2:
            conn[(p[0], p[1])] += 1
    # 按端口分组
    by_port = defaultdict(list)
    for (ip, port), n in conn.items():
        by_port[port].append((ip, n))
    for port in sorted(by_port.keys()):
        ips = by_port[port]
        print(f"\n  端口 {port}: {len(ips)} 个 IP")
        for ip, n in sorted(ips)[:15]:
            print(f"    {ip} ({n} 次连接)")
        if len(ips) > 15:
            print(f"    ... 共 {len(ips)} 个")

    # 【3】8901 连接（如果 IP 测试走 8901 login 测速）
    print(f"\n{'='*60}")
    print("【3】8901 连接（login 测速？）")
    print(f"{'='*60}")
    out = _tshark("tcp.dstport==8901 and tcp.flags.syn==1", ["ip.dst"])
    ips_8901 = []
    for ln in out.splitlines():
        ip = ln.strip()
        if ip and ip not in ips_8901:
            ips_8901.append(ip)
    if ips_8901:
        print(f"  连了 {len(ips_8901)} 个 8901 IP:")
        for ip in ips_8901:
            print(f"    {ip}")
    else:
        print("  无 8901 连接")

    # 【4】分析 HTTP 响应（找 IP 列表 JSON/XML）
    print(f"\n{'='*60}")
    print("【4】HTTP 响应内容（找 IP 列表数据）")
    print(f"{'='*60}")
    for sid, host, uri in http_streams:
        if any(kw in uri.lower() for kw in ["ip", "server", "list", "host", "hq", "dns", "test", "speed"]):
            print(f"\n  ★ 疑似 IP 接口: {host}{uri[:80]}")
            content = _tshark_follow(sid)
            # 找响应部分（含 IP 模式的文本）
            # 显示含 IP 地址的行
            for line in content.split("\n"):
                if re.search(r"\d+\.\d+\.\d+\.\d+", line):
                    print(f"    {line.strip()[:120]}")

    print(f"\npcap 已保存：{PCAP}")


def main():
    global PCAP
    ap = argparse.ArgumentParser()
    ap.add_argument("--duration", type=int, default=30)
    ap.add_argument("--iface", default=None)
    ap.add_argument("--pcap", default=None)
    args = ap.parse_args()

    if args.pcap:
        PCAP = args.pcap
        analyze()
    else:
        iface = args.iface or pick_interface()
        capture(iface, args.duration)
        analyze()


if __name__ == "__main__":
    main()
