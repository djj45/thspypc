# -*- coding: utf-8 -*-
"""Nail 涨速 dt48 scale using closed-session intraday for one code."""
from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


def price_of(row):
    for k in ("price", "close", "last", "dt10", "dt11", "dt8"):
        v = row.get(k)
        if isinstance(v, (int, float)):
            return v
    return None


def main() -> None:
    code = "301158"
    intra = json.load(
        urllib.request.urlopen("http://127.0.0.1:8765/api/intraday/" + code, timeout=60)
    )
    pts = []
    for row in intra:
        p = price_of(row)
        t = row.get("time") or row.get("datetime") or row.get("dt")
        if p is not None:
            pts.append((str(t), p))
    print("total points:", len(pts))
    for t, p in pts[-8:]:
        print("   ", t, p)
    # compute 4-min and 1-min pct ending at the last point
    if len(pts) >= 2:
        last_t, last_p = pts[-1]
        for span in (1, 4, 5):
            if len(pts) > span:
                t0, p0 = pts[-1 - span]
                if p0:
                    pct = (last_p - p0) / p0 * 100
                    print(f"{span}-bar pct={pct:.4f}   dt48/this = {40300000/pct:.3e} if dt48=40300000")


if __name__ == "__main__":
    main()
