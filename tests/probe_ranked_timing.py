# -*- coding: utf-8 -*-
"""Time the ranked stock-list endpoint (竞价金额/封单额) and inspect coverage.

Independent of the web server: drives client.stock_list_hot directly and
reports wall time, row count, and whether deep (00/30x) codes are present.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from thspypc.testing import get_client


def run(sort_by: int, count: int) -> None:
    client = get_client()
    t = time.perf_counter()
    rows = client.stock_list_hot(
        count=count,
        sort_by=sort_by,
        sort_dir="D",
        with_values=True,
    )
    dt = time.perf_counter() - t
    deep = [
        r for r in rows
        if str(r.get("code", ""))[:3] in {"000", "001", "002", "003", "300", "301"}
    ]
    sh = [r for r in rows if str(r.get("code", "")).startswith("6")]
    print(
        f"sort_by={sort_by} count={count}: {dt:.2f}s  rows={len(rows)}"
        f"  deep={len(deep)}  sh6x={len(sh)}"
    )
    if rows:
        print(f"   top3: {[(r.get('code'), r.get('value')) for r in rows[:3]]}")


def main() -> None:
    for count in (59, 200):
        run(68758, count)
    for count in (59, 200):
        run(265260, count)


if __name__ == "__main__":
    main()
