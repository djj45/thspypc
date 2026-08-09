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
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from thspypc.codecs.framing import read_frame  # noqa: E402
from thspypc.features.snapshot_protocol import (  # noqa: E402
    build_market_snapshot_query,
)
from thspypc.models import Capability  # noqa: E402
from thspypc.testing import close_all_clients, get_client  # noqa: E402
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--markets",
        default="16",
        help="comma-separated market codes",
    )
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument(
        "--quote-only",
        action="store_true",
        help="skip the historical [5,55] control request",
    )
    args = parser.parse_args()
    markets = [int(value) for value in args.markets.split(",") if value.strip()]
    captures = ROOT / "captures_live"
    captures.mkdir(exist_ok=True)

    variants = []
    if not args.quote_only:
        variants.append(("code_name", CODE_NAME_DATATYPES))
    variants.append(("quotes", QUOTE_DATATYPES))

    try:
        client = get_client(ROOT / ".env")
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
                body = _capture_one(
                    connection,
                    markets=markets,
                    datatypes=datatypes,
                    timeout=args.timeout,
                )
            except (socket.timeout, OSError) as exc:
                print(f"  no HFD1 response: {type(exc).__name__}: {exc}")
                continue
            if not body:
                print("  no HFD1 response")
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
        close_all_clients()


if __name__ == "__main__":
    raise SystemExit(main())
