# -*- coding: utf-8 -*-
"""Dump raw dt values for each ranked sort key, sh vs sz, to spot scale bugs."""
from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

FIELDS = {
    199112: "dt200",
    48: "dt48",
    592890: "dt250",
    68758: "dt150",
    68762: "dt154",
    265260: "dt44",
}


def main() -> None:
    for sb in (199112, 48, 68762, 68758, 265260):
        u = (
            "http://127.0.0.1:8765/api/stock_list_ranked"
            f"?sort_by={sb}&count=30&sort_dir=D&with_values=1"
        )
        d = json.load(urllib.request.urlopen(u, timeout=60))
        f = FIELDS[sb]
        print(f"=== sort_by={sb} field={f} rows={len(d)}")
        for r in d[:6]:
            market = "sh" if str(r["code"])[0] == "6" else "sz"
            keys = [k for k in r.keys() if k.startswith("dt") and not k.endswith("_format")]
            print(f"    {r['code']} {market} {f}={r.get(f)} keys={keys}")


if __name__ == "__main__":
    main()
