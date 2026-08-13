# -*- coding: utf-8 -*-
"""Probe: does szlv2 (SZ_L2) answer the SortBy ranked query for deep market 33?

The 竞价额/封单额 ranked list currently queries MAIN with markets (17,22,151)
-> 沪市-only.  Mirror the DDE SH/SZ split: send build_stock_list_query on SZ_L2
with markets=(33,) and see whether deep rows come back.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from thspypc.features.stock_list_protocol import (
    build_stock_list_query,
    parse_stock_list_response,
)
from thspypc.models import Capability
from thspypc.testing import get_client
from thspypc._transport import ConnectionRole


def page(client, sock, markets, sort_by, begin):
    req = build_stock_list_query(
        markets=markets,
        sort_begin=begin,
        sort_count=59,
        datatype=[sort_by],
        sort_by=sort_by,
        sort_dir="D",
    )
    conn = client._service_connections.acquire(
        ConnectionRole.SZ_L2, capability=Capability.L2_MARKET_ACCESS
    )
    with conn.request(req, timeout=10.0) as s:
        for _ in range(16):
            try:
                resp = client._stock_list_service._read_frame(s)
            except Exception as exc:
                print("  read break:", type(exc).__name__, exc)
                return None
            if b"SortTotal" in resp:
                meta = parse_stock_list_response(resp)
                return meta
    return None


def main() -> None:
    client = get_client()
    preheat = getattr(client, "preheat_l2_connections", None)
    if preheat is not None:
        try:
            print("preheat:", preheat())
        except Exception as exc:
            print("preheat failed:", type(exc).__name__, exc)
    for sort_by in (68758, 265260):
        t = time.perf_counter()
        meta = page(client, None, (33,), sort_by, 0)
        dt = time.perf_counter() - t
        if meta is None:
            print(f"sort_by={sort_by}: NO RESPONSE ({dt:.2f}s)")
            continue
        stocks = meta["stocks"]
        print(
            f"sort_by={sort_by}: {dt:.2f}s total={meta['sort_total']}"
            f" rows={len(stocks)}"
        )
        if stocks:
            print("   top3:", [(s.get("code"),) for s in stocks[:3]])


if __name__ == "__main__":
    main()
