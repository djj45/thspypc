# -*- coding: utf-8 -*-
"""验证：Level2 账号排序榜走 SH_L2/SZ_L2 连接（pageid=1341, SortCount=20）。

对照抓包（rank_sort_20260814_153726.pcap）客户端行为：
  沪 shlv2: CodeList=17();22();151(); + SortBy + SortCount=20 pageid=1341
  深 szlv2: CodeList=33(); + SortBy + SortCount=20 pageid=1341
"""
from __future__ import annotations

import sys
import struct
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from thspypc._transport import ConnectionRole
from thspypc.features.stock_list_protocol import (
    build_stock_list_query,
    _parse_stock_list_hd31_records,
)
from thspypc.models import AccountKind, Capability
from thspypc.testing import get_client


def fetch_l2_page(client, role: ConnectionRole, markets, sort_by: int,
                  sort_begin: int = 0, sort_count: int = 20,
                  pageid: int = 1341, dir_: str = "D", timeout: float = 12.0):
    service = client._stock_list_service
    conn = service._connections.acquire(
        role, capability=Capability.L2_MARKET_ACCESS
    )
    request = build_stock_list_query(
        markets=markets,
        sort_begin=sort_begin,
        sort_count=sort_count,
        datatype=[sort_by],
        sort_by=sort_by,
        sort_dir=dir_,
        pageid=pageid,
    )
    with conn.request(request, timeout=timeout) as sock:
        for _ in range(16):
            try:
                candidate = service._read_frame(sock)
            except TimeoutError:
                break
            if b"SortTotal" in candidate:
                return _parse_stock_list_hd31_records(candidate)
    return []


def main() -> None:
    client = get_client()
    client.stock_list_hot(count=1, sort_by=48, timeout=10.0)
    preheat = client.preheat_l2_connections()
    print(f"L2 预热: {preheat}")

    print(f"账号类型: {client._service_connections.profile.kind}")
    if client._service_connections.profile.kind is not AccountKind.LEVEL2:
        print("⚠ 非 Level2 账号——L2 连接可能无法使用")

    for sort_by, label in ((199112, "涨幅"), (48, "涨速"), (265260, "封单额")):
        sh = fetch_l2_page(client, ConnectionRole.SH_L2, (17, 22, 151), sort_by)
        sz = fetch_l2_page(client, ConnectionRole.SZ_L2, (33,), sort_by)
        sh_bse = [r["code"] for r in sh if r["code"].startswith(("43", "83", "87", "92"))]
        sz_bse = [r["code"] for r in sz if r["code"].startswith(("43", "83", "87", "92"))]
        print(f"\n{label}榜 (pageid=1341, SortCount=20):")
        print(f"  沪(SH_L2 17/22/151): {len(sh)} 条  北交所 {len(sh_bse)}: {sh_bse[:6]}")
        print(f"  深(SZ_L2 33): {len(sz)} 条  北交所 {len(sz_bse)}")
        if sh:
            codes = [r["code"] for r in sh[:5]]
            vals = [r.get("dt200_raw") or r.get("dt48_raw") for r in sh[:5]]
            print(f"  沪前5: {list(zip(codes, vals))}")
        if sz:
            codes = [r["code"] for r in sz[:5]]
            vals = [r.get("dt200_raw") or r.get("dt48_raw") for r in sz[:5]]
            print(f"  深前5: {list(zip(codes, vals))}")
        if "920083" in {r["code"] for r in sh}:
            rec = next(r for r in sh if r["code"] == "920083")
            raw = rec.get("dt200_raw") or rec.get("dt48_raw")
            print(f"  ★ 920083 金戈新材 找到! raw={raw} "
                  f"真值={(raw & 0x07FFFFFF) / 10000 if isinstance(raw, int) else '?'}")


if __name__ == "__main__":
    main()
