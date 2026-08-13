# -*- coding: utf-8 -*-
"""Cross-check ranked dt200 vs quote-derived 涨幅% to find the scale factor."""
from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


def main() -> None:
    u = "http://127.0.0.1:8765/api/stock_list_ranked?sort_by=199112&count=200&sort_dir=D&with_values=1"
    ranked = json.load(urllib.request.urlopen(u, timeout=60))
    codes = [r["code"] for r in ranked[:6]]
    q = json.load(
        urllib.request.urlopen(
            "http://127.0.0.1:8765/api/quote?codes=" + ",".join(codes),
            timeout=60,
        )
    )
    by_code = {r.get("code"): r for r in q}
    print("code   dt200         dt6(prev)  dt10(now)   涨幅%      dt200/涨幅")
    for r in ranked[:6]:
        code = r["code"]
        qr = by_code.get(code, {})
        dt6 = qr.get("dt6")
        dt10 = qr.get("dt10")
        pct = None
        if dt6:
            pct = (dt10 - dt6) / dt6 * 100
        ratio = (r["dt200"] / pct) if pct else None
        print(f"{code}  {r['dt200']:>14.1f}  {dt6}  {dt10}  {pct and round(pct,3)}  {ratio and round(ratio)}")


if __name__ == "__main__":
    main()
