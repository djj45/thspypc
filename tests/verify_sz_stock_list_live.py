# -*- coding: utf-8 -*-
"""Live-verify the Level2 SZ_L2 full-list merge, then refresh the daily cache.

MAIN full_list returned 26356 rows with zero deep (00/30x) codes, so
/api/stocks2 lacked deep names.  After the fix, stock_list() merges the
szlv2 table (market 32/33).  This script checks the live result and
rewrites ~/.ths_stock_codes.json so the running backend picks up deep
codes+names on the next /api/stocks2 call (the cache file is re-read per
request and keyed by natural day).
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from thspypc._client.stock_cache import default_stock_cache_path, save_stock_codes
from thspypc.testing import get_client

TARGETS = ("002980", "300846", "002759", "000001", "600000", "600525")


def main() -> None:
    client = get_client()
    stocks = client.stock_list(timeout=30.0, with_names=True)
    print(f"total rows: {len(stocks)}")
    by_code = {s["code"]: s for s in stocks}
    deep = [
        s for s in stocks
        if str(s.get("code", ""))[:3] in {"000", "001", "002", "003", "300", "301"}
    ]
    sh = [s for s in stocks if str(s.get("code", "")).startswith("6")]
    print(f"deep: {len(deep)}  sh6x: {len(sh)}")
    for code in TARGETS:
        row = by_code.get(code)
        if row is None:
            print(f"  MISSING {code}")
        else:
            print(f"  {code} -> [{row.get('name', '')}] market={row.get('market')}")

    path = default_stock_cache_path()
    if deep:
        save_stock_codes(stocks, path)
        print(f"cache rewritten: {path}")
    else:
        print("deep table empty — NOT rewriting cache")


if __name__ == "__main__":
    main()
