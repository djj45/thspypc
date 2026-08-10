#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
诊断脚本：抓同花顺 login 帧 → 提取新鲜 Passport64 → 立刻用它查行情。

用法：先打开同花顺客户端并登录（能看到行情），再运行本脚本。
     uv run python tests/diag_fresh_passport.py

抓 8901 端口 30 秒，提取 login 帧里的 Passport64，然后：
  1. 用该 Passport64 构造 login 帧登录 8901
  2. 发 list_quotes 请求
  3. 打印响应

这样能区分「passport 时效问题」vs「请求格式/会话问题」。
"""
from __future__ import annotations

import base64
import os
import socket
import struct
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

WS = r"D:\software\Wireshark_4.6.7_Portable\Wireshark\WiresharkPortable64\App\Wireshark"
DUMPCAP = os.path.join(WS, "dumpcap.exe")
TSHARK = os.path.join(WS, "tshark.exe")

from thspypc import (
    MARKET_HOSTS, MARKET_PORT, encode_frame, read_frame,
    build_login_body_pc, generate_mac64, parse_login_response,
    build_list_quote_query, parse_hd1_response, parse_hd3_response,
)


def capture_and_extract_passport(duration: int = 30) -> str | None:
    """抓 8901 流量，提取 hexin login 帧里的 Passport64。"""
    pcap = os.path.join(os.path.dirname(__file__), "..", "captures_live", "diag_login.pcap")
    os.makedirs(os.path.dirname(pcap), exist_ok=True)
    print(f"抓包 {duration}s (8901 端口)...")
    # WLAN=4, 以太网=8（之前确认 WLAN 有流量）
    import subprocess
    subprocess.run([DUMPCAP, "-i", "4", "-f", "tcp port 8901",
                    "-w", pcap, "-a", f"duration:{duration}"],
                   capture_output=True, timeout=duration + 10)
    print("抓包完成，解析 login 帧...")

    # 用 tshark 导出所有 8901 流
    result = subprocess.run([TSHARK, "-r", pcap, "-Y", "tcp.port==8901",
                             "-T", "fields", "-e", "tcp.stream"],
                            capture_output=True, text=True, timeout=30)
    streams = sorted(set(result.stdout.split()), key=int)
    print(f"  发现 {len(streams)} 条 8901 流")

    for s in streams:
        r = subprocess.run([TSHARK, "-r", pcap, "-qz", f"follow,tcp,raw,{s}"],
                           capture_output=True, text=True, timeout=30)
        client = b""
        for ln in r.stdout.splitlines():
            if len(ln) < 10:
                continue
            if not ln.startswith("\t"):
                h = ln.strip()
                if h and all(c in "0123456789abcdef" for c in h):
                    client += bytes.fromhex(h)
        # 找 login 帧（含 Ask=login + Passport64=）
        MAGIC = b"\xfd\xfd\xfd\xfd"
        pos = 0
        while pos < len(client):
            p = client.find(MAGIC, pos)
            if p < 0 or p + 12 > len(client):
                break
            try:
                bl = int(client[p + 4:p + 12], 16)
            except ValueError:
                pos = p + 4
                continue
            if not (0 < bl < 60000):
                pos = p + 4
                continue
            body = client[p + 12:p + 12 + bl]
            pos = p + 12 + bl
            if b"Ask=login" in body and b"Passport64=" in body:
                txt = body.decode("gbk", errors="replace")
                for line in txt.split("\n"):
                    if line.startswith("Passport64="):
                        p64 = line.split("=", 1)[1].strip()
                        if len(p64) > 100:
                            print(f"  从流 {s} 提取到 Passport64 ({len(p64)} 字符)")
                            return p64
    return None


def test_with_passport(passport64: str) -> None:
    """用给定 Passport64 登录并查行情。"""
    mac64 = generate_mac64()
    login_body = build_login_body_pc(passport64, mac64)

    for host in MARKET_HOSTS:
        try:
            print(f"\n尝试 {host}:{MARKET_PORT} ...")
            s = socket.create_connection((host, MARKET_PORT), timeout=10)
            s.sendall(encode_frame(login_body) + b"\n")
            resp = read_frame(s)
            result = parse_login_response(resp)
            vc = result.get("VerifyCode", "?")
            print(f"  login VerifyCode={vc}")
            if vc != "0":
                s.close()
                continue
            # drain trailing
            s.settimeout(1)
            try:
                s.recv(10)
            except Exception:
                pass
            # 发行情请求
            q = build_list_quote_query(
                ["600056", "600057", "600058", "600059", "600060", "600061"],
                market=17, pageid=1335)
            s.settimeout(15)
            s.sendall(q + b"\n")
            print(f"  发送行情请求 ({len(q)}B)，读响应...")
            for i in range(10):
                try:
                    fr = read_frame(s)
                except socket.timeout:
                    print(f"  frame{i}: timeout")
                    break
                h1 = b"hd1.0" in fr
                h31 = b"hd3.1\x00" in fr
                # hdr[14:16] = 数据长度（真实数据帧也是 0xff 开头，不是错误）
                dlen = struct.unpack("<H", fr[14:16])[0] if len(fr) >= 16 else 0
                cls = "hd1.0" if h1 else ("hd3.1" if h31 else f"datalen={dlen}")
                print(f"  frame{i}: {len(fr)}B [{cls}] {fr[:36].decode('gbk','replace')[:36]!r}")
                if h1:
                    recs = parse_hd1_response(fr)
                    print(f"    ★ hd1.0 解出 {len(recs)} 条:",
                          [(r.get("code"), r.get("dt10")) for r in recs[:3]])
                    s.close()
                    return
                if h31:
                    recs = parse_hd3_response(fr)
                    print(f"    ★ hd3.1 解出 {len(recs)} 条:",
                          [r.get("code") for r in recs[:5]])
                    s.close()
                    return
            s.close()
        except Exception as e:
            print(f"  {host}: {e}")


def main() -> int:
    p64 = capture_and_extract_passport(30)
    if not p64:
        print("\n✗ 未抓到 login 帧。请确认同花顺客户端已打开并登录，再重试。")
        return 1
    print(f"\nPassport64 (前40字符): {p64[:40]}...")
    test_with_passport(p64)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
