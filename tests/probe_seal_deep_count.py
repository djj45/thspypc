# -*- coding: utf-8 -*-
"""Count 封单额 non-zero (涨停) stocks: MAIN single vs SZ_L2 deep."""
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


def page(client, role, capability, markets, sort_by, begin):
    conn = client._service_connections.acquire(role, capability=capability)
    req = build_stock_list_query(
        markets=markets, sort_begin=begin, sort_count=59,
        datatype=[sort_by], sort_by=sort_by, sort_dir="D",
    )
    with conn.request(req, timeout=10.0) as sock:
        for _ in range(16):
            try:
                resp = client._stock_list_service._read_frame(sock)
            except Exception as exc:
                return None, f"{type(exc).__name__}: {exc}"
            if b"SortTotal" in resp:
                return parse_stock_list_response(resp), None
    return None, "no SortTotal"


def main() -> None:
    client = get_client()
    preheat = getattr(client, "preheat_l2_connections", None)
    if preheat is not None:
        try:
            preheat()
        except Exception as exc:
            print("preheat:", type(exc).__name__, exc)
    sort_by = 265260

    # SZ_L2 deep (33)
    total_sz = 0
    sz_nonzero = 0
    begin = 0
    while begin < 500:
        meta, err = page(client, ConnectionRole.SZ_L2, Capability.L2_MARKET_ACCESS, (33,), sort_by, begin)
        if err:
            print("SZ_L2 err:", err)
            break
        if not meta:
            break
        total_sz = meta["sort_total"]
        stocks = meta["stocks"]
        sz_nonzero += sum(1 for s in stocks if s.get("dt44"))
        if len(stocks) == 0 or begin + len(stocks) >= min(total_sz, 400):
            break
        begin += len(stocks)
    print(f"SZ_L2(33) 封单额: sort_total={total_sz} 前400页非零封单数~{sz_nonzero}")

    # MAIN single (17,22,33,151)
    main_nonzero_deep = 0
    main_nonzero_sh = 0
    begin = 0
    while begin < 500:
        meta, err = page(client, ConnectionRole.MAIN, Capability.BASIC_QUOTE, (17, 22, 33, 151), sort_by, begin)
        if err:
            print("MAIN err:", err)
            break
        if not meta:
            break
        total = meta["sort_total"]
        for s in meta["stocks"]:
            if s.get("dt44"):
                if str(s["code"])[0] == "6":
                    main_nonzero_sh += 1
                else:
                    main_nonzero_deep += 1
        if len(meta["stocks"]) == 0 or begin + len(meta["stocks"]) >= min(total, 400):
            break
        begin += len(meta["stocks"])
    print(f"MAIN(17,22,33,151) 封单额: sort_total={total} 非零沪={main_nonzero_sh} 非零深={main_nonzero_deep}")


if __name__ == "__main__":
    main()
