# -*- coding: utf-8 -*-
"""Dump dtN + dtN_format raw contents for one 涨幅 row."""
from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


def main() -> None:
    u = "http://127.0.0.1:8765/api/stock_list_ranked?sort_by=199112&count=5&sort_dir=D&with_values=1"
    d = json.load(urllib.request.urlopen(u, timeout=60))
    for r in d[:5]:
        print(r)


if __name__ == "__main__":
    main()
