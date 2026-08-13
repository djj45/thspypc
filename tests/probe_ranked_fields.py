# -*- coding: utf-8 -*-
"""Dump ranked row field keys + confirm deep coverage."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from thspypc.testing import get_client


def main() -> None:
    client = get_client()
    for sort_by, dt in ((68758, "dt150"), (265260, "dt44")):
        rows = client.stock_list_hot(
            count=200, sort_by=sort_by, sort_dir="D", with_values=True
        )
        deep = [
            r for r in rows
            if str(r.get("code", ""))[:3] in {"000", "001", "002", "003", "300", "301"}
        ]
        print(f"sort_by={sort_by}: rows={len(rows)} deep={len(deep)}")
        if rows:
            print("  keys:", sorted(rows[0].keys()))
            print("  top3:", [(r.get("code"), r.get(dt)) for r in rows[:3]])


if __name__ == "__main__":
    main()
