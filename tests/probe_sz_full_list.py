# -*- coding: utf-8 -*-
"""Probe: does szlv2 (SZ_L2) answer the full stock-code table query?

Level2 MAIN full_list returns 26356 rows but zero deep (00/30x) codes, so
/stocks2 lacks deep names.  This probes whether the same DataType=[5],[55]
query with CodeList=32();33(); returns the deep table on SZ_L2.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from thspypc.codecs.framing import read_frame
from thspypc.features.stock_list_protocol import (
    build_full_stock_list_query,
    parse_init_response,
)
from thspypc.models import Capability
from thspypc.testing import get_client
from thspypc._transport import ConnectionRole


def probe(markets: tuple[int, ...]) -> list[dict]:
    client = get_client()
    # preheat_l2_connections 走 _run_default_service((L2_TIMELINE,))
    # 乐观租借 L2_MARKET_ACCESS 证据并打开 SZ_L2 通道。
    preheat = getattr(client, "preheat_l2_connections", None)
    if preheat is not None:
        try:
            print("preheat result:", preheat())
        except Exception as exc:
            print("preheat failed:", type(exc).__name__, exc)
    svc = client._stock_list_service
    conn = svc._connections.acquire(
        ConnectionRole.SZ_L2,
        capability=Capability.L2_MARKET_ACCESS,
    )
    req = build_full_stock_list_query(markets=markets)
    by_code: dict[str, dict] = {}
    last_data_at: float | None = None
    started = time.monotonic()
    frames_seen = 0
    import socket as _socket
    with conn.request(req, timeout=15.0) as sock:
        while True:
            now = time.monotonic()
            if last_data_at is not None and now - last_data_at >= 15.0:
                break
            if now - started >= 90.0:
                break
            try:
                resp = read_frame(sock)
            except (_socket.timeout, TimeoutError):
                continue
            except Exception as exc:
                print(f"  read break: {type(exc).__name__}: {exc}")
                break
            if not resp:
                continue
            frames_seen += 1
            meta = parse_init_response(resp)
            for stock in meta["stocks"]:
                code = stock.get("code", "")
                if code:
                    by_code.setdefault(code, stock)
            last_data_at = time.monotonic()
    print(f"  frames_seen={frames_seen} union={len(by_code)}")
    return list(by_code.values())


def main() -> None:
    for markets in ((32, 33),):
        print(f"probe markets={markets}")
        stocks = probe(markets)
        print(f"  rows={len(stocks)}")
        if stocks:
            print(f"  first={stocks[0]}")
            print(f"  last={stocks[-1]}")
            deep = [s for s in stocks if str(s.get("code", ""))[:3] in
                    {"000", "001", "002", "003", "300", "301"}]
            sh = [s for s in stocks if str(s.get("code", "")).startswith("6")]
            print(f"  deep={len(deep)} sh6x={len(sh)}")
            print(f"  deep sample={deep[:3]}")
            for target in ("002759", "300846", "002980"):
                hit = [s for s in stocks if str(s.get("code", "")) == target]
                print(f"  has {target}: {bool(hit)}")


if __name__ == "__main__":
    main()
