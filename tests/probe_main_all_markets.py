# -*- coding: utf-8 -*-
"""Probe: does MAIN serve deep (33) ranked for Level2 in ONE SortBy request?

If yes, the SH/SZ split is unnecessary and ranked can be a single MAIN query.
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


def main() -> None:
    client = get_client()
    preheat = getattr(client, "preheat_l2_connections", None)
    if preheat is not None:
        try:
            preheat()
        except Exception as exc:
            print("preheat failed:", type(exc).__name__, exc)
    svc = client._stock_list_service
    for sort_by in (265260, 68758):
        conn = svc._connections.acquire(
            ConnectionRole.MAIN, capability=Capability.BASIC_QUOTE
        )
        req = build_stock_list_query(
            markets=(17, 22, 33, 151),
            sort_begin=0,
            sort_count=59,
            datatype=[sort_by],
            sort_by=sort_by,
            sort_dir="D",
        )
        t = time.perf_counter()
        meta = None
        with conn.request(req, timeout=10.0) as sock:
            for _ in range(16):
                try:
                    resp = svc._read_frame(sock)
                except Exception as exc:
                    print("  read break:", type(exc).__name__, exc)
                    break
                if b"SortTotal" in resp:
                    meta = parse_stock_list_response(resp)
                    break
        dt = time.perf_counter() - t
        if meta is None:
            print(f"sort_by={sort_by}: NO SortTotal response ({dt:.2f}s)")
            continue
        stocks = meta["stocks"]
        deep = [s for s in stocks if str(s.get("code", ""))[:3] in {"000", "001", "002", "003", "300", "301"}]
        print(
            f"sort_by={sort_by}: {dt:.2f}s total={meta['sort_total']} rows={len(stocks)} deep={len(deep)}"
        )
        if stocks:
            print("   top:", [(s.get("code"),) for s in stocks[:5]])


if __name__ == "__main__":
    main()
