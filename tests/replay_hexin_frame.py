#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
实验 A：重放 hexin 完整 login 帧（head128 + check + Passport64 全用 hexin 原样）。

从 pcap 提取 hexin 的完整 login 帧，不经过 thspypc 任何加工，直接 sendall 给服务器。
- 结果 =0：hexin 帧可用 → 问题在 thspypc 重放时改坏了某个字节
- 结果 =-6：hexin 的 session 已过期 → 问题在 thspypc signature→head128 转换

用法：
    py tests/replay_hexin_frame.py --host 8.134.146.31
"""
import argparse
import os
import socket
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.dirname(__file__))

from thspypc.protocol import MARKET_HOSTS, MARKET_PORT, FRAME_MAGIC, parse_login_response
from compare_login_frame_bytes import extract_hexin_login_bodies
import re

WS = r"D:\软件\Wireshark-4.4.7-x64-with-Npcap-1.50-Portable\Wireshark\App\Wireshark"
TSHARK = os.path.join(WS, "tshark.exe")
PCAP = os.path.join(os.path.dirname(__file__), "..", "captures_live", "login_compare.pcap")


def _tshark(y_filter, fields):
    cmd = [TSHARK, "-r", PCAP, "-Y", y_filter, "-T", "fields"]
    for f in fields:
        cmd += ["-e", f]
    r = subprocess.run(cmd, capture_output=True, timeout=180)
    return r.stdout.decode("utf-8", errors="replace")


def extract_hexin_raw_login_frame():
    """从 pcap 提取 hexin 的完整原始 login 帧（含 fdfdfdfd magic + len + body）。"""
    out = _tshark("tcp.dstport==8901 and tcp.payload", ["tcp.payload"])
    for ln in out.splitlines():
        hx = ln.strip().replace(":", "")
        if not hx:
            continue
        try:
            payload = bytes.fromhex(hx)
        except ValueError:
            continue
        # payload 可能是完整帧（magic + len + body）
        if FRAME_MAGIC in payload and b"Ask=login" in payload:
            return payload
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="8.134.146.31")
    args = ap.parse_args()

    raw_frame = extract_hexin_raw_login_frame()
    if not raw_frame:
        print("✗ 未提取到 hexin 完整 login 帧")
        return 1
    print(f"hexin 完整 login 帧: {len(raw_frame)} 字节")
    print(f"  前 32 字节: {raw_frame[:32].hex(' ')}")
    print(f"  check 字节 @ offset 17 (magic4+len8+body[13]): 0x{raw_frame[4+8+13]:02x}")

    # 原样发送（hexin 的帧已经含 magic + len，但可能没 trailing \n）
    frame_to_send = raw_frame if raw_frame.endswith(b"\n") else raw_frame + b"\n"
    print(f"\n重放到 {args.host}:{MARKET_PORT}（不加任何 thspypc 加工）...")

    try:
        sock = socket.create_connection((args.host, MARKET_PORT), timeout=15)
    except Exception as e:
        print(f"✗ 连接失败: {e}")
        return 1
    sock.settimeout(8)
    try:
        sock.sendall(frame_to_send)
    except Exception as e:
        print(f"✗ 发送失败: {e}")
        sock.close()
        return 1

    chunks = []
    total = 0
    t0 = time.time()
    while time.time() - t0 < 8:
        try:
            data = sock.recv(4096)
        except socket.timeout:
            print(f"  [读超时，已收 {total} 字节]")
            break
        except OSError as e:
            print(f"  [socket 错误: {e}]")
            break
        if not data:
            print(f"  [对端 FIN，已收 {total} 字节]")
            break
        chunks.append(data)
        total += len(data)
    sock.close()
    raw = b"".join(chunks)

    if not raw:
        print("\n✗ 0 字节（连接建立后直接关闭）")
        return 1

    result = parse_login_response(raw)
    vc = result.get("VerifyCode", "?")
    print(f"\n响应 {len(raw)} 字节, VerifyCode={vc}")
    if vc == "0":
        print("✅ hexin 帧重放成功！→ thspypc 重放时改坏了某个字节，需对比定位")
    elif vc == "-1":
        print(f"❌ VerifyCode=-1, PromptText={result.get('PromptText','?')}")
        print("   → hexin 的 session 已过期（HTTP 鉴权 session 有时效）")
        print("   → 必须用 thspypc 自己的 auth，问题在 signature→head128 转换")
        # 打印完整响应
        print(f"   完整响应: {raw.decode('gbk', errors='replace')[:300]}")
    else:
        print(f"   响应: {raw.decode('gbk', errors='replace')[:300]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
