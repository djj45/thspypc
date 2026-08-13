# -*- coding: utf-8 -*-
"""Compare dt value scales for sh vs sz per ranked sort key."""
from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

FIELDS = {199112: "dt200", 48: "dt48", 68762: "dt154"}


def main() -> None:
    for sb in (199112, 48, 68762):
        u = (
            "http://127.0.0.1:8765/api/stock_list_ranked"
            f"?sort_by={sb}&count=200&sort_dir=D&with_values=1"
        )
        d = json.load(urllib.request.urlopen(u, timeout=60))
        f = FIELDS[sb]
        sh = [r for r in d if str(r["code"])[0] == "6"]
        sz = [r for r in d if str(r["code"])[0] != "6"]
        print(f"=== sort_by={sb} field={f} rows={len(d)} sh={len(sh)} sz={len(sz)}")
        if sh:
            print(f"    sh top: {[(r['code'], r.get(f)) for r in sh[:5]]}")
        if sz:
            print(f"    sz top: {[(r['code'], r.get(f)) for r in sz[:5]]}")


if __name__ == "__main__":
    main()
