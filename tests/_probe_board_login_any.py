#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""对比同一种「无用户名」登录壳在不同服务器组上的结果。

用法:
    py tests/_probe_board_login_any.py                 # .env（L2）
    py tests/_probe_board_login_any.py --env normal    # .env.normal

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
from thspypc.protocol import MARKET_PORT  # noqa: E402


def _run(args):
    r = subprocess.run(args, capture_output=True, timeout=240)
    return r.stdout.decode("utf-8", errors="replace")


def load_env(path: Path) -> dict:
    result = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        result[k.strip()] = v.strip().strip('"').strip("'")
    return result


def build_board_login(passport64: str, mac64: str, profile) -> bytes:
    if profile.supports_manual_identity:
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
    else:
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
        sock = socket.create_connection((host, MARKET_PORT), timeout=12)
        sock.settimeout(8.0)
        sock.sendall(encode_frame(body) + b"\n")
        reply = sock.recv(65536)
    except OSError as e:
        return f"err {e}"
    sock.close()
    txt = reply.decode("gbk", errors="replace")
    vc = pt = ""
    for line in txt.replace("\r\n", "\n").split("\n"):
        if line.startswith("VerifyCode="):
            vc = line.split("=", 1)[1].strip()
        elif line.startswith("PromptText="):
            pt = line.split("=", 1)[1].strip()
    return f"{tag}: VerifyCode={vc} PromptText={pt!r}"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--env", choices=("l2", "normal"), default="l2")
    args = parser.parse_args()
    env_file = ROOT / (".env" if args.env == "l2" else ".env.normal")
    env = load_env(env_file)
    user, pwd = env.get("THS_USERNAME", ""), env.get("THS_PASSWORD", "")
    imei = env.get("THS_IMEI") or None
    client = THSClient(username=user, password=pwd, imei=imei)
    client.authenticate()
    material = client._auth_service.require_current()
    body = build_board_login(material.passport64, client.mac64, material.profile)

    import socket as _socket
    pb = client._auth.get("passport_bytes", b"")
    if isinstance(pb, str):
        pb = pb.encode()
    groups = {}
    for field in pb.split(b"|"):
        text = field.decode("gbk", errors="replace")
        if not text.startswith("M_hqdns="):
            continue
        for entry in text[len("M_hqdns="):].split(","):
            prefix = entry.split(":", 1)[0].split(".")[0]
            if prefix not in ("fu4", "main", "shlv2", "szlv2", "ifindhq"):
                continue
            try:
                _, _, ips = _socket.gethostbyname_ex(entry.split(":", 1)[0])
            except OSError:
                continue
            groups.setdefault(prefix, ips)
    print(f"== {user} ({args.env}) ==")
    for prefix, ips in groups.items():
        print(" ", try_login(ips[0], body, f"{prefix}@{ips[0]}"))
    client.disconnect()
    return 0


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    raise SystemExit(main())
