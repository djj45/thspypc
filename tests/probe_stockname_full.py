#!/usr/bin/env python
"""Live full stock-name download probe (level2 / standard).

Connects to the account-appropriate 123ths.com domain, logs in with the same
passport, replays the captured cold-start bootstrap (ending in the 0x001c
StockNameVer=;; trigger), and decodes the name_16_16 response.

Usage:
    uv run python tests/probe_stockname_full.py
    uv run python tests/probe_stockname_full.py --env .env.normal \
        --domain main.123ths.com \
        --bootstrap bootstrap_normal_215908_frames.json
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_dotenv(path: Path) -> None:
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if key and key not in os.environ:
            os.environ[key] = value.strip().strip('"').strip("'")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--env", default=".env")
    parser.add_argument("--domain", default="shlv2.123ths.com")
    parser.add_argument(
        "--bootstrap", default="bootstrap_214435_frames.json"
    )
    parser.add_argument("--timeout", type=float, default=45.0)
    parser.add_argument(
        "--fake-version",
        default=None,
        help="report this old ConfigVer instead of ;; (server comparison test)",
    )
    parser.add_argument("--kind", default=None, help="level2 or standard")
    args = parser.parse_args()

    load_dotenv(ROOT / args.env)
    from thspypc import THSClient
    from thspypc.codecs.framing import encode_frame, read_frame
    from thspypc.features.stock_name_protocol import decode_name_frame

    user = os.environ.get("THS_USERNAME", "").strip()
    pwd = os.environ.get("THS_PASSWORD", "").strip()
    if not user or not pwd:
        print(f"set THS_USERNAME/THS_PASSWORD in {args.env}")
        return 1

    client = THSClient(user, pwd)
    res = client.connect()
    if not res.success:
        print("login failed", res.error, res.detail)
        return 1
    material = client._auth_service.require_current()
    login_body = client._auth_service.login_body_for_passport(material.passport64)

    ips = sorted(
        {
            addr[4][0]
            for addr in socket.getaddrinfo(
                args.domain, 8901, socket.AF_INET
            )
        }
    )
    target = ips[0] if ips else None
    if target is None:
        print("no ip for", args.domain)
        return 1
    print("domain:", args.domain, "ips:", ips, "using:", target)

    bootstrap_file = ROOT / "captures_live" / args.bootstrap
    if not bootstrap_file.exists():
        print("missing", bootstrap_file)
        return 1
    bodies = [
        bytes.fromhex(item)
        for item in json.loads(bootstrap_file.read_text(encoding="utf-8"))
    ]

    if args.fake_version:
        from thspypc.features.stock_name_cache import (
            build_version_value,
            default_cache_path,
            load_name_cache,
        )
        from thspypc.features.stock_name_protocol import (
            build_stock_name_ver_frame,
        )
        from thspypc.models import AccountKind

        kind = args.kind or ("level2" if args.env == ".env" else "standard")
        last = bodies[-1]
        markets = (
            last.split(b"MarketCode=")[1].split(b"\r\n")[0].decode()
        )
        pageid = int(
            last.split(b"pageid=")[1].split(b"\r")[0].decode()
        )
        loaded = load_name_cache(default_cache_path(AccountKind(kind)))
        if loaded:
            fake_vers = {seg: args.fake_version for seg in loaded[0]}
        else:
            fake_vers = {
                seg: args.fake_version
                for seg in ("16_16", "16_17", "16_18", "16_19", "16_20")
            }
        version_value = build_version_value(fake_vers, markets)
        bodies = bodies[:-1] + [
            build_stock_name_ver_frame(
                markets=markets,
                stock_name_ver=version_value,
                pageid=pageid,
            )
        ]
        print("fake version value:", version_value[:160])

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5.0)
    try:
        sock.connect((target, 8901))
        sock.sendall(encode_frame(login_body) + b"\n")
        sock.settimeout(6.0)
        login_ok = False
        deadline = time.time() + 6
        while time.time() < deadline:
            try:
                reply = read_frame(sock)
            except socket.timeout:
                break
            except (OSError, ValueError):
                break
            if reply and b"VerifyCode=0" in reply:
                login_ok = True
                break
        print("login VerifyCode=0:", login_ok)
        if not login_ok:
            return 1

        for index, body in enumerate(bodies):
            sock.sendall(encode_frame(body) + b"\n")
            if index % 4 == 0:
                time.sleep(0.05)

        print("bootstrap sent; waiting for name_16_16...")
        sock.settimeout(3.0)
        found = None
        deadline = time.time() + args.timeout
        while time.time() < deadline:
            try:
                item = read_frame(sock)
            except socket.timeout:
                continue
            except (OSError, ValueError):
                break
            if not item:
                continue
            if b"[name_16_16]" in item:
                found = item
                break
        if found is None:
            print("NO name_16_16 response")
            return 1
        result = decode_name_frame(found)
        print("frame len:", len(found))
        print("decoded names:", len(result["names"]), "skipped:", result["skipped"])
        for code in ("600000", "601318", "000001", "1A0001", "399001"):
            if code in result["names"]:
                print(code, result["names"][code])
        return 0
    finally:
        try:
            sock.close()
        except OSError:
            pass
        client.disconnect()


if __name__ == "__main__":
    raise SystemExit(main())
