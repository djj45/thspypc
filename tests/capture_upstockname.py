#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
抓 hexin 启动时的 upstockname 全量名称响应。

操作步骤：
  1. 确认 C:\\同花顺软件\\同花顺\\stockname\\ 已清空
  2. 彻底退出同花顺（任务管理器确认 hexin.exe 没了）
  3. 运行本脚本（选网卡后开始抓包）
  4. 启动同花顺并登录
  5. 等待 30 秒（脚本自动结束），期间 hexin 会拉全量名称
  6. 脚本自动分析 pcap，提取 upstockname 帧 → captures_live/upstockname_full_*.bin

用法：
  py tests/capture_upstockname.py                  # 默认 30s
  py tests/capture_upstockname.py --duration 60    # 60 秒
  py tests/capture_upstockname.py --pcap xxx.pcap  # 分析已有 pcap
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import struct
import sys
import time
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

# Wireshark portable 路径
WS = r"D:\软件\Wireshark-4.4.7-x64-with-Npcap-1.50-Portable\Wireshark\App\Wireshark"
DUMPCAP = os.path.join(WS, "dumpcap.exe")
CAPTURE_DIR = os.path.join(os.path.dirname(__file__), "..", "captures_live")
os.makedirs(CAPTURE_DIR, exist_ok=True)


def list_interfaces() -> list[tuple[int, str]]:
    """列出可用网卡。返回 [(index, name), ...]"""
    try:
        out = subprocess.check_output(
            [DUMPCAP, "-D"], stderr=subprocess.STDOUT,
        )
        # dumpcap 输出可能是 gbk，尝试多种编码
        for enc in ["utf-8", "gbk", "cp936", "latin-1"]:
            try:
                text = out.decode(enc)
                break
            except UnicodeDecodeError:
                continue
        else:
            text = out.decode("utf-8", errors="replace")
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"✗ dumpcap 不可用: {e}")
        sys.exit(1)
    ifaces = []
    for line in text.strip().splitlines():
        m = re.match(r"^(\d+)\.\s*(.+)", line)
        if m:
            idx = int(m.group(1))
            name = m.group(2).strip()
            ifaces.append((idx, name))
    return ifaces


def capture(iface_idx: int, duration: int, pcap_path: str):
    """用 dumpcap 抓包。iface_idx 是 dumpcap -D 列出的编号（从 1 开始）。"""
    cmd = [
        DUMPCAP, "-i", str(iface_idx),
        "-a", f"duration:{duration}",
        "-w", pcap_path,
        "-q",
    ]
    print(f"抓包 {duration}s → {pcap_path}")
    print(f"命令: {' '.join(cmd)}")
    subprocess.run(cmd, check=True)
    size = os.path.getsize(pcap_path) if os.path.exists(pcap_path) else 0
    print(f"✓ 抓包完成 ({size} bytes)")


def analyze_pcap(pcap_path: str):
    """分析 pcap，提取 upstockname 帧。"""
    import subprocess
    # 用 tshark 过滤 8901 端口包含 upstockname 的 TCP 流
    tshark = os.path.join(WS, "tshark.exe")
    if not os.path.exists(tshark):
        print("⚠ tshark 不可用，跳过分析")
        return

    print("\n分析 pcap...")

    # Step 1: 找包含 "upstockname" 的 TCP 流
    cmd = [
        tshark, "-r", pcap_path,
        "-Y", 'tcp.payload and frame contains "upstockname"',
        "-T", "fields", "-e", "tcp.stream",
    ]
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL)
        out_text = out.decode("utf-8", errors="replace")
    except subprocess.CalledProcessError:
        print("未找到 upstockname 请求")
        return

    streams = set(out_text.strip().splitlines())
    print(f"找到 {len(streams)} 个 upstockname TCP 流: {streams}")

    # Step 2: 导出每个流的全部 payload
    for stream_id in sorted(streams):
        if not stream_id:
            continue
        # 导出该 TCP 流的服务端→客户端方向数据
        cmd_export = [
            tshark, "-r", pcap_path,
            "-Y", f"tcp.stream eq {stream_id}",
            "-T", "fields", "-e", "tcp.payload",
        ]
        try:
            out = subprocess.check_output(cmd_export, stderr=subprocess.DEVNULL)
            out_text = out.decode("utf-8", errors="replace")
        except subprocess.CalledProcessError:
            continue

        payloads_hex = [line.strip() for line in out_text.splitlines() if line.strip()]
        print(f"  流 {stream_id}: {len(payloads_hex)} 个 TCP segment")

        # 解码 hex payload，找名称帧
        name_frames = []
        for ph in payloads_hex:
            try:
                data = bytes.fromhex(ph)
            except ValueError:
                continue
            if len(data) < 100:
                continue
            # 名称帧特征：含 MarketCode= 或 [name_ 或 ConfigVer=
            if b"MarketCode" in data or b"[name_" in data or b"StockNameVer" in data:
                name_frames.append(data)
                print(f"    名称帧 {len(data)}B")

        # 保存
        for i, nf in enumerate(name_frames):
            fname = f"upstockname_full_stream{stream_id}_{i}.bin"
            fpath = os.path.join(CAPTURE_DIR, fname)
            with open(fpath, "wb") as f:
                f.write(nf)
            print(f"    保存: {fpath} ({len(nf)}B)")

            # 预览
            print(f"    预览: ", end="")
            for b in nf[:160]:
                if 32 <= b < 127:
                    print(chr(b), end="")
                elif b == 0x0a:
                    print("\\n", end="")
                else:
                    print(".", end="")
            print()


def main():
    parser = argparse.ArgumentParser(description="抓 hexin 启动时 upstockname 全量名称")
    parser.add_argument("--duration", type=int, default=30,
                        help="抓包时长（秒），默认 30")
    parser.add_argument("--pcap", default=None,
                        help="分析已有 pcap（跳过抓包）")
    parser.add_argument("--iface", type=int, default=None,
                        help="网卡编号（跳过交互选择）")
    args = parser.parse_args()

    if args.pcap:
        # 只分析模式
        if not os.path.exists(args.pcap):
            print(f"pcap 不存在: {args.pcap}")
            return 1
        analyze_pcap(args.pcap)
        return 0

    # 抓包模式
    ifaces = list_interfaces()
    if not ifaces:
        print("未找到可用网卡")
        return 1

    if args.iface is not None:
        idx = args.iface
        if not any(idx == i for i, _ in ifaces):
            print(f"网卡编号 {idx} 不存在")
            return 1
    else:
        print("可用网卡:")
        for idx, name in ifaces:
            print(f"  {idx}. {name}")
        print()
        choice = input(f"选择网卡编号 ({ifaces[0][0]}-{ifaces[-1][0]}): ").strip()
        try:
            idx = int(choice)
            if not any(idx == i for i, _ in ifaces):
                raise ValueError
        except ValueError:
            print("无效选择")
            return 1

    timestamp = time.strftime("%Y%m%d_%H%M%S")
    pcap_path = os.path.join(CAPTURE_DIR, f"upstockname_capture_{timestamp}.pcap")

    print(f"\n⚠ 请先确认:")
    print(f"  1. C:\\同花顺软件\\同花顺\\stockname\\ 已清空")
    print(f"  2. 同花顺已彻底退出")
    print(f"\n按 Enter 开始抓包，然后立即启动同花顺...")
    input()

    # 抓包
    try:
        capture(idx, args.duration, pcap_path)
    except subprocess.CalledProcessError as e:
        print(f"✗ 抓包失败: {e}")
        return 1

    # 分析
    analyze_pcap(pcap_path)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
