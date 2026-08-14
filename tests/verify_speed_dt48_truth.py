# -*- coding: utf-8 -*-
"""Print human-checkable truth table for dt48 speed / dt200 chg verification."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from thspypc.testing import get_client
from thspypc.features.stock_list_protocol import (
    build_stock_list_query,
    _parse_stock_list_hd31_records,
)
from thspypc.models import Capability
from thspypc._transport import ConnectionRole


def fetch_records(client, sort_by: int, count: int = 59) -> list[dict]:
    service = client._stock_list_service
    conn = service._connections.acquire(
        ConnectionRole.MAIN, capability=Capability.BASIC_QUOTE
    )
    request = build_stock_list_query(
        markets=(17, 22, 33, 151),
        sort_begin=0,
        sort_count=count,
        datatype=[sort_by],
        sort_by=sort_by,
        sort_dir="D",
    )
    with conn.request(request, timeout=12.0) as sock:
        for _ in range(8):
            candidate = service._read_frame(sock)
            if b"SortTotal" in candidate:
                return _parse_stock_list_hd31_records(candidate)
    return []


def fmt_raw(raw) -> str:
    return f"{raw:08x}" if isinstance(raw, int) else "?"


def main() -> None:
    client = get_client()
    client.stock_list_hot(count=1, sort_by=48, timeout=10.0)

    print("【涨速榜 sort_by=48 -> dt48】（去同花顺客户端『沪深A股→涨速』列核对）")
    print(f"{'代码':<8}{'名称':<10}{'raw':<14}{'decode':<14}{'真值(mant/1e4)':<16}")
    recs = fetch_records(client, 48)
    names = {}
    for s in client.stock_list_hot(count=59, sort_by=48, with_names=True, timeout=12.0):
        names[s["code"]] = s.get("name", "")
    for i, rec in enumerate(recs):
        if 10 <= i < len(recs) - 5:
            if i == 10:
                print("  ...")
            continue
        raw = rec.get("dt48_raw")
        dec = rec.get("dt48")
        mant = (raw & 0x07FFFFFF) if isinstance(raw, int) else None
        truth = (mant / 10000.0) if mant is not None else None
        truth_s = f"{truth:.4f}" if truth is not None else ""
        print(f"{rec.get('code',''):<8}{names.get(rec.get('code',''),'')[:8]:<10}{fmt_raw(raw):<14}{str(dec):<14}{truth_s:<16}")

    print()
    print("【涨幅榜 sort_by=199112 -> dt200】（去客户端『沪深A股→涨幅』列核对）")
    print(f"{'代码':<8}{'名称':<10}{'raw':<14}{'decode':<14}{'真值(mant/1e4)':<16}")
    recs = fetch_records(client, 199112)
    names = {}
    for s in client.stock_list_hot(count=59, sort_by=199112, with_names=True, timeout=12.0):
        names[s["code"]] = s.get("name", "")
    for i, rec in enumerate(recs):
        if 10 <= i < len(recs) - 5:
            if i == 10:
                print("  ...")
            continue
        raw = rec.get("dt200_raw")
        dec = rec.get("dt200")
        mant = (raw & 0x07FFFFFF) if isinstance(raw, int) else None
        truth = (mant / 10000.0) if mant is not None else None
        truth_s = f"{truth:.4f}" if truth is not None else ""
        print(f"{rec.get('code',''):<8}{names.get(rec.get('code',''),'')[:8]:<10}{fmt_raw(raw):<14}{str(dec):<14}{truth_s:<16}")


if __name__ == "__main__":
    main()
