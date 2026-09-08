# -*- coding: utf-8 -*-
"""Dump raw dt48/dt200 LE32 bytes from ranked responses to inspect encodings."""
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


def main() -> None:
    client = get_client()
    # 触发服务上下文懒初始化（stock_list_hot 内部会 ensure）
    client.stock_list_hot(count=1, sort_by=48, timeout=10.0)

    for sort_by, field in ((48, "dt48"), (199112, "dt200")):
        recs = fetch_records(client, sort_by)
        print(f"== sort_by={sort_by} -> {field}: {len(recs)} 条 ==")
        for i, rec in enumerate(recs):
            raw = rec.get(field + "_raw")
            dec = rec.get(field)
            raw_hex = f"{raw:08x}" if isinstance(raw, int) else "?"
            fmt = rec.get(field + "_format")
            print(f"[{i:02d}] {rec.get('code','')} raw=0x{raw_hex} fmt={fmt} dec={dec}")
        print()


if __name__ == "__main__":
    main()
