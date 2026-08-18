#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""0xc4 金额表活网实验（AGENTS.md：get_client 复用客户端，单进程不重复登录）。

1. 用捕获的原始 DataType 集 + pageid=1334 直发 list_quotes
2. 验证响应为 0xc4 表并解码（dt250 主力净额元 / dt248 DDE 亿）
3. 与 /api/dde_rank 交叉验证
4. 试探扩展 DataType：+265260(封单额) / +19(成交额) 是否被服务器接受
"""
from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from thspypc.testing import get_client  # noqa: E402

# 2026-08-18 抓包原文顺序（stocklist_page pcap，CodeList=17(...) 的请求）
MONEY_DATATYPE = [
    7, 49, 13, 461256, 70, 27, 127, 48, 12, 69, 33,
    1968584, 2942, 592890, 25, 10, 17, 24, 31, 9,
    3541450, 592888, 2947, 30, 8, 6, 45, 66, 1111,
]


def show(recs: list[dict], keys: list[str]) -> None:
    for r in recs:
        parts = [f"{r.get('code')}"]
        for k in keys:
            v = r.get(k)
            parts.append(f"{k}={v if not isinstance(v, float) else round(v, 4)}")
        print("   " + "  ".join(parts))


def main() -> None:
    client = get_client()

    with urllib.request.urlopen(
        "http://127.0.0.1:8765/api/dde_rank?count=5400&sort_dir=D", timeout=120
    ) as resp:
        dde = {r["code"]: r["value"] for r in json.load(resp) if r.get("value")}

    print("== 实验1: 沪市 4 码（抓包同款请求）")
    recs = client.list_quotes(
        ["600519", "600601", "603228", "688693"],
        market=17,
        datatype=MONEY_DATATYPE,
        pageid=1334,
    )
    print(f"   返回 {len(recs)} 行")
    show(recs, ["dt10", "dt6", "dt48", "dt250", "dt248", "dt202", "dt200#2"])
    for r in recs:
        code = r.get("code")
        if code in dde and isinstance(r.get("dt248"), float):
            print(f"   对照 {code}: dt248={r['dt248']:.4f} 亿 vs dde={dde[code]} 亿")

    print("\n== 实验2: 深市 3 码")
    recs = client.list_quotes(
        ["000001", "002953", "300561"],
        market=33,
        datatype=MONEY_DATATYPE,
        pageid=1334,
    )
    print(f"   返回 {len(recs)} 行")
    show(recs, ["dt10", "dt250", "dt248"])
    for r in recs:
        code = r.get("code")
        if code in dde and isinstance(r.get("dt248"), float):
            print(f"   对照 {code}: dt248={r['dt248']:.4f} 亿 vs dde={dde[code]} 亿")

    print("\n== 实验3: 扩展 DataType（+265260 封单额, +19 成交额, +68758 竞价额）")
    ext = MONEY_DATATYPE + [265260, 19, 68758]
    recs = client.list_quotes(
        ["600519", "600601"],
        market=17,
        datatype=ext,
        pageid=1334,
    )
    print(f"   返回 {len(recs)} 行，全部键: {sorted(recs[0].keys()) if recs else '-'}")
    show(recs, ["dt10", "dt250", "dt248", "dt44", "dt19", "dt150"])


if __name__ == "__main__":
    main()
