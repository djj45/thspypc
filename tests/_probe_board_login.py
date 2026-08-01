#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""活网探针：在 fu4 服务器上对比三种 login 身份（无用户名/__manual/thsuser）。

用法:
    py tests/_probe_board_login.py                 # .env（L2）
    py tests/_probe_board_login.py --env normal    # .env.normal
    py tests/_probe_board_login.py --ip 106.15.249.238

探针：不入库（tests/_*.py 约定）。
"""
from __future__ import annotations

import argparse
import os
import socket
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from thspypc.client import THSClient  # noqa: E402
from thspypc.codecs.framing import encode_frame  # noqa: E402
from thspypc.features.auth_protocol import (  # noqa: E402
    LoginIdentity,
    build_login_body,
)
from thspypc.protocol import (  # noqa: E402
    MARKET_PORT,
    read_frame,
)


def load_env(path: Path) -> dict:
    result = {}
    if not path.exists():
        return result
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        result[k.strip()] = v.strip().strip('"').strip("'")
    return result


def board_login_body(passport64: str, mac64: str, profile) -> bytes:
    """复刻 L2 抓包的板块 login：无用户名，计算 check 字节。"""
    fields = [
        "Ask=login",
        f"C-Version={profile.tcp_version}",
        "VerifyType=1",
        f"Mac64={mac64}",
        "C-SupportPushVer=1.0",
        "C-SupReqDataVer=hq6.0",
        "C-SupPushDataVer=hq6.0",
    ]
    fixed = ("\n".join(fields) + "\nPassport64=").encode("gbk")
    suffix = bytes([(len(fixed) + 1) & 0xFF]) + b"\x09"
    prefix = b"\x09\x41\x09\x00" + b"zh_CN.GBK" + suffix
    return prefix + fixed + passport64.encode("ascii")


def manual_login_body(passport64: str, mac64: str, profile) -> bytes:
    """复刻普通账号板块 login：__manual + \\r\\n\\n。"""
    fixed = (
        "Ask=login\n"
        f"C-Version={profile.tcp_version}\n"
        "UserName=__manual\r\n\n"
        "Password=__manual\r\n\n"
        "VerifyType=1\n"
        f"Mac64={mac64}\n"
        "C-SupportPushVer=1.0\n"
        "C-SupReqDataVer=hq6.0\n"
        "C-SupPushDataVer=hq6.0\n"
        "Passport64="
    ).encode("gbk")
    suffix = bytes([(len(fixed) + 1) & 0xFF]) + b"\x09"
    prefix = b"\x09\x41\x09\x00" + b"zh_CN.GBK" + suffix
    return prefix + fixed + passport64.encode("ascii")


def try_login(host: str, body: bytes, tag: str) -> str:
    try:
        sock = socket.create_connection((host, MARKET_PORT), timeout=15)
    except OSError as e:
        return f"connect fail: {e}"
    try:
        sock.sendall(encode_frame(body) + b"\n")
        sock.settimeout(8.0)
        resp = read_frame(sock)
    except (OSError, ValueError) as e:
        sock.close()
        return f"recv fail: {e}"
    sock.close()
    txt = resp.decode("gbk", "replace").replace("\r\n", "\n")
    vc = prompt = ""
    for line in txt.split("\n"):
        if line.startswith("VerifyCode="):
            vc = line.split("=", 1)[1]
        elif line.startswith("PromptText="):
            prompt = line.split("=", 1)[1]
    return f"{tag}: VerifyCode={vc!r} PromptText={prompt!r} ({len(resp)}B)"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--env", choices=("l2", "normal"), default="l2")
    parser.add_argument("--ip", default="")
    args = parser.parse_args()

    if args.env == "l2":
        env = load_env(ROOT / ".env")
        captured_ip = "106.15.249.238"
    else:
        env = load_env(ROOT / ".env.normal")
        captured_ip = "122.9.78.232"

    user, pwd = env.get("THS_USERNAME", ""), env.get("THS_PASSWORD", "")
    imei = env.get("THS_IMEI") or None
    client = THSClient(username=user, password=pwd, imei=imei)
    client.authenticate()
    material = client._auth_service.require_current()
    profile = material.profile
    print(f"== {user} profile={profile.name} ==")

    bodies = {
        "no-username": board_login_body(material.passport64, client.mac64, profile),
        "__manual": manual_login_body(material.passport64, client.mac64, profile),
        "thsuser": build_login_body(
            material.passport64,
            client.mac64,
            identity=LoginIdentity.STANDARD,
            profile=profile,
        ),
    }
    for name, body in bodies.items():
        print(f"  {name}: {len(body)}B")

    hosts = [args.ip] if args.ip else [captured_ip]
    for host in hosts:
        print(f"\n--- {host} ---")
        for name, body in bodies.items():
            print(" ", try_login(host, body, name))

    client.disconnect()
    return 0


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    raise SystemExit(main())
