# -*- coding: utf-8 -*-
"""Cross-check 涨速 dt48 scale via intraday minute data."""
from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


def main() -> None:
    # top 涨速 stocks from ranked dt48
    u = "http://127.0.0.1:8765/api/stock_list_ranked?sort_by=48&count=5&sort_dir=D&with_values=1"
    ranked = json.load(urllib.request.urlopen(u, timeout=60))
    for r in ranked[:5]:
        code = r["code"]
        dt48 = r["dt48"]
        try:
            intra = json.load(
                urllib.request.urlopen(
                    "http://127.0.0.1:8765/api/intraday/" + code, timeout=60
                )
            )
        except Exception as exc:
            print(code, "intraday err", exc)
            continue
        # intraday rows: find last few with price fields
        prices = []
        for row in intra:
            # try common price keys
            for k in ("price", "close", "last", "dt10", "dt11"):
                if row.get(k) is not None:
                    prices.append((row.get("time") or row.get("dt"), row[k]))
                    break
        # compute 1-min and 5-min pct if we have a few points
        tail = prices[-6:] if len(prices) >= 6 else prices
        print(f"{code} dt48={dt48} points={len(prices)} tail={tail[-3:]}")
        if len(tail) >= 2:
            first = tail[0][1]
            last = tail[-1][1]
            if first:
                span = len(tail) - 1
                pct = (last - first) / first * 100
                print(f"    {span}-bar pct={pct:.4f}  dt48/pct={dt48/pct:.2e}")


if __name__ == "__main__":
    main()
