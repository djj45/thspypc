#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
诊断 login 响应：连单个 IP，发完整 login 帧，dump 服务器返回的所有原始字节。

用途：当 login 后立即"连接已关闭"时，看服务器到底返回了什么（可能在 RST 前回了
      少量诊断数据，或验证 head128/signature 是否被接受）。

用法：
    py tests/diag_login_response.py                  # 连第一个 MARKET_HOST
    py tests/diag_login_response.py --host 8.134.98.163
    py tests/diag_login_response.py --dump login_resp.bin  # dump 原始响应
"""
import argparse
import os
import socket
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from thspypc.protocol import (
    MARKET_HOSTS, MARKET_PORT,
    full_http_auth, build_passport64, build_login_body_pc,
    generate_mac64, encode_frame, parse_login_response,
)


def load_env():
    env_path = os.path.join(os.path.dirname(__file__), "..", ".env")
    if os.path.exists(env_path):
        for line in open(env_path, encoding="utf-8"):
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, _, v = line.partition("=")
                if k.strip() and k.strip() not in os.environ:
                    os.environ[k.strip()] = v.strip().strip('"').strip("'")


def main():
    load_env()
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default=None, help="目标 IP，默认 MARKET_HOSTS[0]")
    ap.add_argument("--dump", default=None, help="把原始响应 dump 到文件")
    ap.add_argument("--raw", action="store_true", help="打印响应的完整 hex dump")
    args = ap.parse_args()

    user = os.environ.get("THS_USERNAME", "").strip()
    pwd = os.environ.get("THS_PASSWORD", "").strip()
    if not user or not pwd:
        print("✗ 缺账号")
        return 1

    host = args.host or MARKET_HOSTS[0]
    print(f"目标: {host}:{MARKET_PORT}")

    # HTTP 鉴权
    print("HTTP 鉴权中...")
    auth = full_http_auth(user, pwd)
    passport64 = build_passport64(auth)
    mac64 = generate_mac64()
    login_body = build_login_body_pc(passport64, mac64)
    print(f"Passport64 长度: {len(passport64)} 字符")
    print(f"Mac64: {mac64}")
    print(f"login body 长度: {len(login_body)} 字节")

    # 连接 + 发 login
    print(f"\n连接 {host}:{MARKET_PORT}...")
    try:
        sock = socket.create_connection((host, MARKET_PORT), timeout=15)
    except Exception as e:
        print(f"✗ 连接失败: {e}")
        return 1

    sock.settimeout(8)
    try:
        sock.sendall(encode_frame(login_body) + b"\n")
        print("login 帧已发送，等待响应...")
    except Exception as e:
        print(f"✗ 发送失败: {e}")
        sock.close()
        return 1

    # 读取所有响应（不严格解析，收满或超时）
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
            print(f"  [socket 错误，已收 {total} 字节]: {e}")
            break
        if not data:
            print(f"  [对端关闭连接 FIN，已收 {total} 字节]")
            break
        chunks.append(data)
        total += len(data)
        print(f"  收到 {len(data)} 字节，累计 {total}")

    sock.close()
    raw = b"".join(chunks)

    if args.dump:
        with open(args.dump, "wb") as f:
            f.write(raw)
        print(f"\n原始响应已 dump: {args.dump} ({len(raw)} 字节)")

    if not raw:
        print("\n✗ 服务器返回 0 字节（连接建立后直接关闭）")
        print("  可能原因：head128/signature 校验失败，或 IP 不接受此 login 模式")
        return 1

    # 尝试解析
    print(f"\n{'='*60}")
    print(f"服务器响应（{len(raw)} 字节）")
    print(f"{'='*60}")

    if args.raw:
        # 完整 hex dump（每行 32 字节）
        for i in range(0, min(len(raw), 512), 32):
            chunk = raw[i:i+32]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            print(f"  {i:04x}  {hex_part:<96s}  {ascii_part}")
        if len(raw) > 512:
            print(f"  ... (省略 {len(raw)-512} 字节，用 --dump 存盘)")

    # 尝试解码 GBK 文本部分
    text = raw.decode("gbk", errors="replace")
    print(f"\nGBK 文本解码（前 500 字符）:")
    print("  " + text[:500].replace("\r\n", "\n  ").replace("\n", "\n  "))

    # 尝试用 parse_login_response 解析
    result = parse_login_response(raw)
    if "VerifyCode" in result:
        print(f"\n解析结果: VerifyCode={result.get('VerifyCode')}")
        for k, v in result.items():
            if k != "raw":
                print(f"  {k} = {v}")
    else:
        print(f"\n⚠ 未解析到 VerifyCode（响应非标准 login reply 格式）")

    return 0


if __name__ == "__main__":
    sys.exit(main())
