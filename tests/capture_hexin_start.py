#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
抓 hexin 启动序列：8901 + 9601 全流量，重点看 subreal 订阅和 pushrealorder 推送。

用法：
    1. 先运行本脚本（开始抓包）
    2. 打开同花顺客户端并登录（能看到行情/短线精灵）
    3. 切到短线精灵页面、滚动几下（触发改动推送）
    4. 等 90 秒自动结束（或 Ctrl+C 提前停）

产物：captures_live/hexin_full.pcap + 逐流分析报告
"""
import os
import subprocess
import sys
import time

WS = r"D:\software\Wireshark_4.6.7_Portable\Wireshark\WiresharkPortable64\App\Wireshark"
DUMPCAP = os.path.join(WS, "dumpcap.exe")
TSHARK = os.path.join(WS, "tshark.exe")
PCAP_DIR = os.path.join(os.path.dirname(__file__), "..", "captures_live")
PCAP = os.path.join(PCAP_DIR, "hexin_full.pcap")
DURATION = 90  # 秒


def capture():
    os.makedirs(PCAP_DIR, exist_ok=True)
    print(f"开始抓包 {DURATION}s（8901 + 9601，WLAN 接口）...")
    print(f"现在请：1) 打开同花顺 2) 登录 3) 切到短线精灵页面 4) 等待自动结束")
    print("-" * 60)
    # WLAN=4（之前确认有流量），抓 8901+9601
    subprocess.run(
        [DUMPCAP, "-i", "4", "-f", "tcp port 8901 or tcp port 9601",
         "-w", PCAP, "-a", f"duration:{DURATION}"],
        timeout=DURATION + 15,
    )
    print(f"\n抓包完成：{PCAP} ({os.path.getsize(PCAP)} bytes)")


def analyze():
    """逐流分析：找 subreal（客户端发）和 pushrealorder（服务端推）。"""
    print("\n" + "=" * 60)
    print("分析抓包结果")
    print("=" * 60)

    # 列出所有 8901/9601 流
    r = subprocess.run(
        [TSHARK, "-r", PCAP, "-Y", "tcp.port==8901 or tcp.port==9601",
         "-T", "fields", "-e", "tcp.stream", "-e", "ip.src", "-e", "tcp.srcport",
         "-e", "ip.dst", "-e", "tcp.dstport"],
        capture_output=True, text=True, timeout=60,
    )
    streams = {}
    for ln in r.stdout.strip().splitlines():
        parts = ln.split("\t")
        if len(parts) >= 5:
            sid = parts[0]
            if sid not in streams:
                streams[sid] = parts

    print(f"共 {len(streams)} 条 TCP 流")
    port_counts = {"8901": 0, "9601": 0}
    for sid, p in streams.items():
        dst_port = p[4] if len(p) > 4 else ""
        if dst_port in port_counts:
            port_counts[dst_port] += 1
    print(f"  8901 连接: {port_counts['8901']} 条")
    print(f"  9601 连接: {port_counts['9601']} 条")

    # 逐流提取客户端/服务端数据，找 subreal 和 pushrealorder
    subreal_streams = []
    push_streams = []
    for sid in sorted(streams.keys(), key=int):
        r = subprocess.run(
            [TSHARK, "-r", PCAP, "-qz", f"follow,tcp,raw,{sid}"],
            capture_output=True, text=True, timeout=30,
        )
        client = b""
        server = b""
        for ln in r.stdout.splitlines():
            if len(ln) < 10:
                continue
            if not all(c in "0123456789abcdef \t" for c in ln.lower()):
                continue
            if ln.startswith("\t"):
                h = ln[1:].strip()
                if h:
                    server += bytes.fromhex(h)
            else:
                h = ln.strip()
                if h:
                    client += bytes.fromhex(h)

        c_subreal = b"method=subreal" in client
        c_push = b"pushrealorder" in client
        s_push = b"pushrealorder" in server
        c_login = b"Ask=login" in client or b"Reply=login" in server

        dst_port = streams[sid][4] if len(streams[sid]) > 4 else "?"
        labels = []
        if c_login: labels.append("LOGIN")
        if c_subreal: labels.append("SUBREAL-REQ")
        if s_push: labels.append("PUSH-RECV!")
        if c_push: labels.append("push-req?")

        if labels:
            print(f"\n流 {sid} (→:{dst_port}) client={len(client)}B server={len(server)}B [{', '.join(labels)}]")
            if c_subreal:
                # 提取 subreal 帧的完整内容
                idx = client.find(b"method=subreal")
                if idx >= 0:
                    # 往前找帧起始（magic 或 0x09）
                    start = max(0, idx - 30)
                    snippet = client[start:idx + 80]
                    print(f"  subreal 帧片段: {snippet.hex(' ')}")
                    print(f"  subreal 文本: {snippet.decode('gbk', 'replace')[:100]}")
                subreal_streams.append(sid)
            if s_push:
                # 统计推送帧数量
                push_count = server.count(b"pushrealorder")
                print(f"  收到 {push_count} 个 pushrealorder 帧！")
                push_streams.append(sid)

    print("\n" + "=" * 60)
    print("结论：")
    if subreal_streams:
        print(f"  ✓ 找到 {len(subreal_streams)} 条发过 subreal 的流: {subreal_streams}")
    else:
        print(f"  ✗ 未找到 subreal 订阅帧（hexin 可能没发，或抓包窗口太短）")
    if push_streams:
        print(f"  ✓ 找到 {len(push_streams)} 条收到推送的流: {push_streams}")
    else:
        print(f"  ✗ 未找到 pushrealorder 推送帧")
    print(f"\npcap 已保存: {PCAP}")


def main():
    try:
        capture()
    except KeyboardInterrupt:
        print("\n抓包被中断（已保存部分数据）")
    except subprocess.TimeoutExpired:
        print("\n抓包超时")
    analyze()


if __name__ == "__main__":
    main()
