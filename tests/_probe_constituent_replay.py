#!/usr/bin/env python
"""Replay the clean constituent bootstrap bytes on a fresh fu4 session.

Diagnosis probe for the fu4 constituent socket: with a fresh thsuser login,
step through the exact captured bootstrap frames (MKT_INIT variant A = captured
ConfigVer, variant B = local StockLink.ini version), then subreal groups, the
pageid bundle, classification, and finally the captured business Sort frame.
Each step reports what the server replies so we can isolate where the
acceptance breaks.

Usage:
    py tests/_probe_constituent_replay.py [--variant all|captured|local]
"""
from __future__ import annotations

import argparse
import socket
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests")]

import capture_system_blocks as capture  # noqa: E402
from _analyze_clean_constituents import outer_frames  # noqa: E402
from thspypc.client import THSClient  # noqa: E402
from thspypc.codecs.framing import read_frame  # noqa: E402
from thspypc.features.auth_protocol import (  # noqa: E402
    LoginIdentity,
    build_login_body,
)
from thspypc.features.system_blocks_protocol import (  # noqa: E402
    build_board_market_init,
    load_local_board_stocklink_ver,
)
from thspypc.protocol import MARKET_PORT, encode_frame, resolve_fu4_hosts  # noqa: E402

CAPTURE = "system_blocks_20260801_163756.pcap"
STREAM = "0"
DETAIL = b"pageid=4180"


def load_env(path: Path) -> dict:
    result = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        result[k.strip()] = v.strip().strip('"').strip("'")
    return result


def captured_frames() -> list[bytes]:
    streams = {
        sid: client
        for sid, client, _server in capture._tshark_streams(
            str(ROOT / "captures_live" / CAPTURE), 8901
        )
    }
    return outer_frames(streams[STREAM])


def drain(sock: socket.socket, seconds: float) -> list[bytes]:
    sock.settimeout(0.3)
    deadline = time.monotonic() + seconds
    frames = []
    while time.monotonic() < deadline:
        try:
            frames.append(read_frame(sock))
        except socket.timeout:
            break
        except OSError as exc:
            frames.append(f"<OSError:{exc}>".encode())
            break
    return frames


def send_step(sock: socket.socket, payload: bytes, label: str) -> None:
    sock.sendall(payload)
    print(f"  -> {label}: {len(payload)}B")
    for frame in drain(sock, 2.0):
        text = frame.decode("gbk", errors="replace")
        head = text[:70].replace("\r", "\\r").replace("\n", "\\n")
        print(f"     <- {len(frame):7d}B {head!r}")


def run_variant(client: THSClient, variant: str) -> int:
    material = client._auth_service.require_current()
    login = build_login_body(
        material.passport64,
        client.mac64,
        identity=LoginIdentity.STANDARD,
        profile=material.profile,
    )
    hosts = resolve_fu4_hosts(material.passport_bytes)
    if not hosts:
        print("no fu4 hosts")
        return 1
    host = hosts[0]
    print(f"\n===== variant={variant} host={host} =====")
    sock = socket.create_connection((host, MARKET_PORT), timeout=15)
    sock.settimeout(8.0)
    sock.sendall(encode_frame(login) + b"\n")
    reply = read_frame(sock)
    print(f"  -> login {len(login)}B -> reply {len(reply)}B "
          f"VerifyCode={'0' if b'VerifyCode=0' in reply else '?'}")

    frames = captured_frames()
    if variant == "captured":
        market_init = frames[1]
    else:
        market_init = build_board_market_init(
            False,
            market_code="16;32;144;",
            market_date="16(-1738516266);32(-1050958608);144(-924138670);",
            stocklink_ver=load_local_board_stocklink_ver(),
        )
    send_step(sock, encode_frame(market_init) + b"\n", "MKT_INIT")

    send_step(
        sock,
        b"".join(encode_frame(f) + b"\n" for f in frames[2:9]),
        "subreal group1 (capture 2..8)",
    )
    send_step(
        sock,
        b"".join(encode_frame(f) + b"\n" for f in frames[9:16]),
        "subreal group2 (capture 9..15)",
    )
    send_step(
        sock,
        encode_frame(frames[16]) + b"\n",
        "pageid bundle (capture 16)",
    )
    send_step(
        sock,
        encode_frame(frames[17]) + b"\n",
        "classification (capture 17)",
    )
    biz = next(i for i, body in enumerate(frames) if DETAIL in body)
    sock.settimeout(8.0)
    sock.sendall(encode_frame(frames[biz]) + b"\n")
    print(f"  -> business outer={biz} {len(frames[biz])}B")
    got = drain(sock, 12.0)
    for frame in got:
        text = frame.decode("gbk", errors="replace")
        head = text[:70].replace("\r", "\\r").replace("\n", "\\n")
        print(f"     <- {len(frame):7d}B {head!r}")
    sock.close()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--variant", choices=("all", "captured", "local"), default="all")
    args = parser.parse_args()
    env = load_env(ROOT / ".env.normal")
    client = THSClient(
        env["THS_USERNAME"],
        env["THS_PASSWORD"],
        imei=env.get("THS_IMEI") or None,
    )
    client.authenticate()
    variants = ("captured", "local") if args.variant == "all" else (args.variant,)
    for variant in variants:
        try:
            run_variant(client, variant)
        except OSError as exc:
            print(f"  !! {type(exc).__name__}: {exc}")
    client.disconnect()
    return 0


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    raise SystemExit(main())
