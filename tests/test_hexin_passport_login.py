#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
用 hexin 抓包的真实 Passport64 直接登录，验证 Passport64 内容是否是 -1 根因。

从 pcap 提取 hexin 的 Passport64（那个 VerifyCode=0 的），用它构造 login 帧
发给服务器。如果能登录 → 问题确实在 thspypc 生成的 Passport64 内容；
如果还不行 → 问题在 head128/signature 或其他地方。

用法：
    py tests/test_hexin_passport_login.py --host 8.134.146.31
    py tests/test_hexin_passport_login.py --host 8.134.146.31 --dump resp.bin
"""
import argparse
import os
import socket
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.dirname(__file__))

from thspypc.protocol import (
    MARKET_HOSTS, MARKET_PORT,
    full_http_auth, build_login_body_pc, generate_mac64,
    encode_frame, parse_login_response,
)
from compare_login_frame_bytes import extract_hexin_login_bodies
import re


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
    ap.add_argument("--host", default="8.134.146.31", help="目标 IP（选返回 -1 的）")
    ap.add_argument("--dump", default=None)
    args = ap.parse_args()

    # ---- 提取 hexin 抓包的真实 Passport64 ----
    bodies = extract_hexin_login_bodies()
    if not bodies:
        print("✗ 未提取到 hexin login 帧")
        return 1
    hexin_p64 = None
    for b in bodies:
        m = re.search(rb"Passport64=(\S+)", b)
        if m:
            p64 = m.group(1).decode("ascii")
            if hexin_p64 is None or len(p64) < len(hexin_p64):
                hexin_p64 = p64
    print(f"hexin 抓包 Passport64: {len(hexin_p64)} 字符")

    # ---- 同时生成 thspypc 的 Passport64 做对照 ----
    user = os.environ.get("THS_USERNAME", "").strip()
    pwd = os.environ.get("THS_PASSWORD", "").strip()
    auth = full_http_auth(user, pwd)
    from thspypc.protocol import build_passport64
    thspypc_p64 = build_passport64(auth)
    print(f"thspypc 生成 Passport64: {len(thspypc_p64)} 字符")

    mac64 = generate_mac64()

    # ---- 测试 1: 用 hexin 的 Passport64 ----
    print(f"\n{'='*60}")
    print(f"测试 1: 用 hexin 抓包的 Passport64 登录 {args.host}")
    print(f"{'='*60}")
    rc = _try_login(args.host, hexin_p64, mac64, args.dump)

    # ---- 测试 2: 用 thspypc 的 Passport64（对照）----
    print(f"\n{'='*60}")
    print(f"测试 2: 用 thspypc 生成的 Passport64 登录 {args.host}（对照）")
    print(f"{'='*60}")
    _try_login(args.host, thspypc_p64, mac64, None)

    return rc


def _try_login(host, passport64, mac64, dump_path):
    login_body = build_login_body_pc(passport64, mac64)
    check = login_body[13]
    print(f"  check 字节: 0x{check:02x}, body 长度: {len(login_body)}")

    try:
        sock = socket.create_connection((host, MARKET_PORT), timeout=15)
    except Exception as e:
        print(f"  ✗ 连接失败: {e}")
        return 1
    sock.settimeout(8)
    try:
        sock.sendall(encode_frame(login_body) + b"\n")
    except Exception as e:
        print(f"  ✗ 发送失败: {e}")
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
            print(f"  [socket 错误: {e}, 已收 {total} 字节]")
            break
        if not data:
            print(f"  [对端 FIN，已收 {total} 字节]")
            break
        chunks.append(data)
        total += len(data)
    sock.close()
    raw = b"".join(chunks)

    if dump_path and raw:
        with open(dump_path, "wb") as f:
            f.write(raw)
        print(f"  响应已 dump: {dump_path}")

    if not raw:
        print(f"  ✗ 0 字节（连接建立后直接关闭）")
        return 1

    result = parse_login_response(raw)
    vc = result.get("VerifyCode", "?")
    print(f"  响应 {len(raw)} 字节, VerifyCode={vc}")
    if vc == "0":
        print(f"  ✅ 登录成功！")
    elif vc == "-1":
        print(f"  ❌ VerifyCode=-1")
        # 看响应里的其他字段
        for k in ("PromptText", "PromptCode"):
            if k in result:
                print(f"     {k}={result[k]}")
    else:
        # 显示原始响应
        print(f"  响应文本: {raw[:200].decode('gbk', errors='replace')[:200]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
