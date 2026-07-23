#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
测试不同 Passport64 字段集 + 正确 check 字节，定位 -6 根因。

变体：
  A. 20 字段（hexin 抓包值，过滤 sk/sv）—— 当前实现
  B. 43 字段（含 sk/sv，hexin 缓存值）—— README 表3 说 sk/sv 必须保留
  C. 完全不过滤（53 字段）

用法：py tests/test_passport_variants.py --host 8.134.146.31
"""
import argparse
import base64
import os
import socket
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from thspypc.protocol import (
    MARKET_HOSTS, MARKET_PORT,
    full_http_auth, build_head128_pure, build_passport64,
    build_login_body_pc, generate_mac64, _PASSPORT_DROP_FIELDS,
    encode_frame, parse_login_response,
)


def make_passport64(auth, drop_fields):
    """用指定的 drop_fields 集合构造 Passport64。"""
    signature = auth["signature"]
    pb = auth["passport_bytes"]
    head128, prefix_5b = build_head128_pure(signature)
    fields = [
        f for f in pb.split(b"|")
        if f.split(b"=", 1)[0].decode("gbk", errors="replace").strip()
        not in drop_fields
    ]
    fields_body = b"\r\n".join(fields)
    buffer = head128 + prefix_5b + fields_body + b"\r\n "
    return base64.b64encode(buffer).decode()


def load_env():
    env_path = os.path.join(os.path.dirname(__file__), "..", ".env")
    if os.path.exists(env_path):
        for line in open(env_path, encoding="utf-8"):
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, _, v = line.partition("=")
                if k.strip() and k.strip() not in os.environ:
                    os.environ[k.strip()] = v.strip().strip('"').strip("'")


def try_login(host, passport64, mac64, label):
    login_body = build_login_body_pc(passport64, mac64)
    check = login_body[13]
    print(f"\n  [{label}] Passport64={len(passport64)}字符 check=0x{check:02x}")
    try:
        sock = socket.create_connection((host, MARKET_PORT), timeout=15)
    except Exception as e:
        print(f"    ✗ 连接失败: {e}")
        return
    sock.settimeout(8)
    try:
        sock.sendall(encode_frame(login_body) + b"\n")
    except Exception as e:
        print(f"    ✗ 发送失败: {e}")
        sock.close()
        return
    chunks = []
    t0 = time.time()
    while time.time() - t0 < 8:
        try:
            data = sock.recv(4096)
        except socket.timeout:
            break
        except OSError:
            break
        if not data:
            break
        chunks.append(data)
    sock.close()
    raw = b"".join(chunks)
    if not raw:
        print(f"    → 0 字节（FIN）")
        return
    result = parse_login_response(raw)
    vc = result.get("VerifyCode", "?")
    pt = result.get("PromptText", "")
    sname = result.get("S-Name", "")
    print(f"    → VerifyCode={vc} PromptText={pt} S-Name={sname}")
    if vc == "0":
        print(f"    ✅✅✅ 登录成功！【{label}】是正确的字段集")


def main():
    load_env()
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="8.134.146.31")
    args = ap.parse_args()
    user = os.environ["THS_USERNAME"].strip()
    pwd = os.environ["THS_PASSWORD"].strip()

    auth = full_http_auth(user, pwd)
    mac64 = generate_mac64()

    # 变体定义
    route_only = frozenset({
        "M_hq", "M_hqdns", "M_wg", "M_zx", "UpdateSvr", "download",
        "Foss_url", "DownloadSelfStock", "UploadSelfStock", "signlength",
    })
    variants = [
        ("A: 20字段(过滤sk/sv)", _PASSPORT_DROP_FIELDS),
        ("B: 43字段(含sk/sv,仅过滤路由)", route_only),
        ("C: 53字段(全不过滤)", frozenset()),
    ]
    # 间隔 5 秒避免触发会话冲突
    for i, (label, drop) in enumerate(variants):
        if i > 0:
            time.sleep(5)
        p64 = make_passport64(auth, drop)
        try_login(args.host, p64, mac64, label)


if __name__ == "__main__":
    main()
