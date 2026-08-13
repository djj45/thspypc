# -*- coding: utf-8 -*-
"""Dump the _format code per ranked sort field."""
from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

FIELDS = {199112: "dt200", 48: "dt48", 68762: "dt154", 68758: "dt150", 265260: "dt44", 592890: "dt250"}


def main() -> None:
    for sb, f in FIELDS.items():
        u = "http://127.0.0.1:8765/api/stock_list_ranked?sort_by=%d&count=3&sort_dir=D&with_values=1" % sb
        d = json.load(urllib.request.urlopen(u, timeout=60))
        if not d:
            print(f"sort_by={sb}: empty")
            continue
        r = d[0]
        print(f"sort_by={sb} {f}={r.get(f)} {f}_format={r.get(f + '_format')}")


if __name__ == "__main__":
    main()
