#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Capture HFD1 responses for code/name and quote-bearing datatype sets.

This diagnostic deliberately performs one ``get_client()`` login and reuses
the adopted MAIN connection for every request.  It is intended to answer two
questions that the historical ``DataType=[5],[55]`` corpus cannot answer:

1. Does adding quote fields still select ``hfd1.0``?
2. If so, how does the payload/header change as fields are added?

Captured frames are written below ``captures_live/`` (gitignored).
"""
from __future__ import annotations

import argparse
import socket
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from thspypc.codecs.framing import read_frame  # noqa: E402
from thspypc.features.snapshot_protocol import (  # noqa: E402
    build_market_snapshot_query,
)
from thspypc.features.stock_list_protocol import build_init_query  # noqa: E402
from thspypc.models import Capability  # noqa: E402
from thspypc.testing import close_all_clients, get_client, login_socket  # noqa: E402
from thspypc._transport import ConnectionRole  # noqa: E402


CODE_NAME_DATATYPES = [5, 55]
QUOTE_DATATYPES = [5, 6, 7, 8, 9, 10, 13, 18, 19, 48, 49, 55]


def _capture_one(
    connection,
    *,
    markets: list[int],
    datatypes: list[int],
    timeout: float,
) -> bytes:
    request = build_market_snapshot_query(markets=markets, datatype=datatypes)
    with connection.request(request, timeout=timeout) as sock:
        for _ in range(8):
            try:
                body = read_frame(sock)
            except ValueError:
                continue
            if b"hfd1.0" in body:
                return body
    return b""


def _drain_init(sock: socket.socket, timeout: float = 2.0) -> int:
    """Activate one low-level MAIN socket and drain its config response."""
    sock.sendall(build_init_query() + b"\n")
    sock.settimeout(timeout)
    read_frame(sock)  # the first config frame is required
    drained = 1
    sock.settimeout(0.3)
    for _ in range(8):
        try:
            read_frame(sock)
        except socket.timeout:
            break
        drained += 1
    return drained


def _capture_socket(
    sock: socket.socket,
    *,
    markets: list[int],
    datatypes: list[int],
    timeout: float,
) -> tuple[bytes, list[bytes]]:
    """Send one query on a low-level socket and retain unexpected replies."""
    request = build_market_snapshot_query(markets=markets, datatype=datatypes)
    sock.sendall(request + b"\n")
    sock.settimeout(min(timeout, 2.0))
    deadline = time.monotonic() + timeout
    replies: list[bytes] = []
    while time.monotonic() < deadline and len(replies) < 32:
        try:
            body = read_frame(sock)
        except socket.timeout:
            continue
        except ValueError:
            continue
        replies.append(body)
        if b"hfd1.0" in body.lower():
            return body, replies
    return b"", replies


def _reply_kind(body: bytes) -> str:
    lowered = body.lower()
    for marker in (b"hfd1.0", b"hd3.1", b"hd1.0", b"hq6.0", b"hq1.0"):
        if marker in lowered:
            return marker.decode("ascii")
    if b"errorcode=" in lowered:
        return "error"
    return "unknown"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--markets",
        default="16",
        help="comma-separated market codes",
    )
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument(
        "--host",
        help="directly test one 8901 host using the same get_client AuthService passport",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--quote-only",
        action="store_true",
        help="skip the historical [5,55] control request",
    )
    mode.add_argument(
        "--code-only",
        action="store_true",
        help="send only the historical pageid=5716 [5,55] control request",
    )
    args = parser.parse_args()
    markets = [int(value) for value in args.markets.split(",") if value.strip()]
    captures = ROOT / "captures_live"
    captures.mkdir(exist_ok=True)

    variants = []
    if not args.quote_only:
        variants.append(("code_name", CODE_NAME_DATATYPES))
    if not args.code_only:
        variants.append(("quotes", QUOTE_DATATYPES))

    direct_sock: socket.socket | None = None
    try:
        client = get_client(ROOT / ".env")
        connection = None
        if args.host:
            material = client._auth_service.require_current()
            login_body = client._auth_service.login_body_for_passport(material.passport64)
            host, direct_sock = login_socket(
                login_body,
                [args.host],
                max_concurrent=1,
                overall_timeout=max(6.0, args.timeout),
            )
            drained = _drain_init(direct_sock)
            print(f"direct MAIN host: {host}, init frames drained: {drained}")
        else:
            manager = client.sync_service_connections()
            connection = manager.acquire(
                ConnectionRole.MAIN,
                capability=Capability.BASIC_QUOTE,
            )
            sock = connection.socket
            try:
                host = sock.getpeername()[0] if sock is not None else "unknown"
            except OSError:
                host = "unknown"
            print(f"MAIN host: {host}")

        successes = 0
        for label, datatypes in variants:
            print(f"request {label}: markets={markets}, datatypes={datatypes}")
            try:
                if direct_sock is not None:
                    body, replies = _capture_socket(
                        direct_sock,
                        markets=markets,
                        datatypes=datatypes,
                        timeout=args.timeout,
                    )
                else:
                    body = _capture_one(
                        connection,
                        markets=markets,
                        datatypes=datatypes,
                        timeout=args.timeout,
                    )
                    replies = []
            except (socket.timeout, OSError) as exc:
                print(f"  no HFD1 response: {type(exc).__name__}: {exc}")
                continue
            if not body:
                kinds = ", ".join(
                    f"{_reply_kind(reply)}:{len(reply)}B" for reply in replies
                ) or "no frames"
                print(f"  no HFD1 response ({kinds})")
                if replies:
                    largest = max(replies, key=len)
                    datatype_tag = "-".join(str(value) for value in datatypes)
                    market_tag = "-".join(str(value) for value in markets)
                    path = captures / (
                        f"hfd1_host-{host}_markets-{market_tag}_dt-{datatype_tag}_"
                        f"nohit-{_reply_kind(largest)}.bin"
                    )
                    path.write_bytes(largest)
                    print(f"  saved largest unexpected reply: {path} ({len(largest):,}B)")
                continue

            datatype_tag = "-".join(str(value) for value in datatypes)
            market_tag = "-".join(str(value) for value in markets)
            path = captures / f"hfd1_markets-{market_tag}_dt-{datatype_tag}.bin"
            path.write_bytes(body)
            marker = body.find(b"hfd1.0")
            print(f"  captured {len(body):,} bytes, marker={marker}, path={path}")
            print(f"  payload head: {body[marker + 6:marker + 38].hex(' ')}")
            successes += 1
        return 0 if successes else 1
    finally:
        if direct_sock is not None:
            direct_sock.close()
        close_all_clients()


if __name__ == "__main__":
    raise SystemExit(main())
