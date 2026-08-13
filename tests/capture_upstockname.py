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

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, ValueError):
    pass

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

# Wireshark portable path (override with THS_WIRESHARK_DIR)
WS = os.environ.get(
    "THS_WIRESHARK_DIR",
    r"D:\software\Wireshark_4.6.7_Portable\Wireshark\WiresharkPortable64\App\Wireshark",
)
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
        "-f", "tcp port 8901",
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
    """分析 pcap，重组每条 TCP 流、解码 0x0a 名称帧，报告名称数量与服务器 IP。

    输出两类信息：
      · 请求(→)：StockNameVer / upstockname 名称触发帧的 MarketCode + pageid
      · 响应(←)：0x0a LZ 压缩名称帧解码后的名称总数（沪 6x / 深 0/3x 各多少）
    并保存重组后的完整 0x0a 帧体到 captures_live/upstockname_full_*.bin。
    """
    import subprocess
    from thspypc.features.stock_name_protocol import decode_name_frame

    tshark = os.path.join(WS, "tshark.exe")
    if not os.path.exists(tshark):
        print("⚠ tshark 不可用，跳过分析")
        return

    print("\n分析 pcap...")

    # Step 1: 找名称同步相关 TCP 流
    filter_expr = (
        'tcp.payload and '
        '(frame contains "upstockname" or '
        'frame contains "StockNameVer" or '
        'frame contains "[name_")'
    )
    cmd = [tshark, "-r", pcap_path, "-Y", filter_expr,
           "-T", "fields", "-e", "tcp.stream"]
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL)
        out_text = out.decode("utf-8", errors="replace")
    except subprocess.CalledProcessError:
        print("未找到名称同步请求/响应")
        return
    streams = sorted({s for s in out_text.strip().splitlines() if s})
    print(f"找到 {len(streams)} 个名称同步 TCP 流: {streams}")

    MAGIC = b"\xfd\xfd\xfd\xfd"

    def reassemble(stream, srcport):
        y = f"tcp.stream eq {stream} and tcp.payload"
        if srcport is not None:
            y += f" and tcp.srcport=={srcport}"
        cmd = [tshark, "-r", pcap_path, "-Y", y,
               "-T", "fields", "-e", "tcp.payload"]
        try:
            out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError:
            return b""
        return b"".join(
            bytes.fromhex(h.replace(":", ""))
            for h in out.decode("utf-8", "replace").splitlines() if h.strip()
        )

    def frames_in(seg):
        frames = []
        i = 0
        while True:
            j = seg.find(MAGIC, i)
            if j < 0:
                break
            ln = seg[j + 4:j + 12]
            if not re.fullmatch(rb"[0-9A-Fa-f]{8}", ln):
                i = j + 4
                continue
            blen = int(ln, 16)
            frames.append((j, blen, seg[j + 12:j + 12 + blen]))
            i = j + 12 + blen
        return frames

    for stream_id in streams:
        # 服务器 IP：取该流 srcport==8901 的第一条 ip.src
        cmd = [tshark, "-r", pcap_path, "-Y",
               f"tcp.stream eq {stream_id} and tcp.srcport==8901",
               "-T", "fields", "-e", "ip.src"]
        try:
            peer = subprocess.check_output(cmd, stderr=subprocess.DEVNULL)
            peer_lines = peer.decode("utf-8", "replace").strip().splitlines()
            server_ip = peer_lines[0].strip() if peer_lines and peer_lines[0].strip() else "?"
        except (subprocess.CalledProcessError, IndexError):
            server_ip = "?"

        c2s = reassemble(stream_id, None)
        s2c = reassemble(stream_id, 8901)

        print(f"\n  流 {stream_id}  服务器 IP={server_ip}")

        # 请求：client→server 帧里找 StockNameVer / upstockname
        for _j, _blen, body in frames_in(c2s):
            text = body.decode("gbk", errors="replace")
            if "StockNameVer" not in text and "upstockname" not in text:
                continue
            m_mc = re.search(r"MarketCode=([^\r\n\0]+)", text)
            m_mk = re.search(r"(?m)^market=(\S+)", text)
            m_pid = re.search(r"pageid=(\d+)", text)
            market = m_mc.group(1) if m_mc else (m_mk.group(1) if m_mk else "-")
            pageid = m_pid.group(1) if m_pid else "-"
            print(f"    请求(→) MarketCode={market} pageid={pageid}")
            break

        # 响应：server→client 里解码 0x0a 名称帧
        saved = False
        for j, blen, body in frames_in(s2c):
            result = decode_name_frame(body)
            if not result["names"]:
                continue
            saved = True
            sh = sum(1 for k in result["names"] if k.startswith("6"))
            sz = sum(1 for k in result["names"]
                     if k.startswith(("0", "3")))
            print(f"    响应(←) 名称帧 {blen}B → {len(result['names'])} 名称"
                  f"（沪6x={sh} 深0/3x={sz}）")
            segs = sorted({s[0] for s in result["segments"]})
            print(f"        段: {segs}")
            if result["skipped"]:
                print(f"        跳过(块编码历史段): {result['skipped']}")
            fname = f"upstockname_full_stream{stream_id}_{j}.bin"
            with open(os.path.join(CAPTURE_DIR, fname), "wb") as f:
                f.write(body)
        if not saved:
            print("    未找到 0x0a 名称响应帧")

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