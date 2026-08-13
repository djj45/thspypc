# -*- coding: utf-8 -*-
"""Probe: MAIN full-list query for market 22 (沪市风险警示板 ST)."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from thspypc.features.stock_list_protocol import (
    build_full_stock_list_query,
    parse_init_response,
)
from thspypc.models import Capability
from thspypc.testing import get_client
from thspypc._transport import ConnectionRole


def main() -> None:
    client = get_client()
    preheat = getattr(client, "preheat_l2_connections", None)
    if preheat is not None:
        try:
            print("preheat:", preheat())
        except Exception as exc:
            print("preheat failed:", type(exc).__name__, exc)
    svc = client._stock_list_service
    conn = svc._connections.acquire(
        ConnectionRole.MAIN, capability=Capability.BASIC_QUOTE
    )
    req = build_full_stock_list_query(markets=(22,))
    by_code: dict[str, dict] = {}
    import time

    last_data = time.monotonic()
    with conn.request(req, timeout=15.0) as sock:
        while time.monotonic() - last_data < 6.0:
            try:
                resp = svc._read_frame(sock)
            except (TimeoutError, Exception) as exc:
                if not isinstance(exc, TimeoutError):
                    print("read break:", type(exc).__name__, exc)
                    break
                continue
            if not resp:
                continue
            meta = parse_init_response(resp)
            for stock in meta["stocks"]:
                code = stock.get("code", "")
                if code:
                    by_code.setdefault(code, stock)
            last_data = time.monotonic()
    print(f"market 22 rows: {len(by_code)}")
    print("codes:", sorted(by_code)[:20])


if __name__ == "__main__":
    main()
