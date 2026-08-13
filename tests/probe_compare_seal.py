# -*- coding: utf-8 -*-
"""Compare 封单额 deep coverage: MAIN(17,22,33,151) single vs SZ_L2(33)."""
from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


def fetch(u):
    return json.load(urllib.request.urlopen(u, timeout=60))


def main() -> None:
    # single-lane via HTTP backend
    d = fetch("http://127.0.0.1:8765/api/stock_list_ranked?sort_by=265260&count=236&sort_dir=D&with_values=1")
    print(f"single-lane rows={len(d)}")
    deep = [r for r in d if str(r["code"])[0] != "6"]
    sh = [r for r in d if str(r["code"])[0] == "6"]
    print(f"  deep={len(deep)} sh={len(sh)}")
    print("  positions of deep codes (1-based):")
    pos = [i + 1 for i, r in enumerate(d) if str(r["code"])[0] != "6"]
    print("   ", pos[:40])
    print("  first 15 rows:")
    for i, r in enumerate(d[:15]):
        mkt = "sz" if str(r["code"])[0] != "6" else "sh"
        print(f"    {i+1:>3} {r['code']} {mkt} dt44={r.get('dt44')}")


if __name__ == "__main__":
    main()
