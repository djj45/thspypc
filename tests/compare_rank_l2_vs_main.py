# -*- coding: utf-8 -*-
"""完整榜单对比：L2 拆沪深（pageid=1341） vs MAIN 单请求（pageid=1334）。

验证：L2 路径能否拿全 10~20% 区间 + 北交所；对比两种路径的榜单覆盖。
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from thspypc._transport import ConnectionRole
from thspypc.features.stock_list_protocol import (
    build_stock_list_query,
    _parse_stock_list_hd31_records,
)
from thspypc.models import Capability
from thspypc.testing import get_client


def fetch_page(client, role, markets, sort_by, sort_begin=0, sort_count=59,
               pageid=1334, dir_="D", capability=None, timeout=12.0):
    service = client._stock_list_service
    conn = service._connections.acquire(role, capability=capability)
    request = build_stock_list_query(
        markets=markets, sort_begin=sort_begin, sort_count=sort_count,
        datatype=[sort_by], sort_by=sort_by, sort_dir=dir_, pageid=pageid,
    )
    with conn.request(request, timeout=timeout) as sock:
        for _ in range(24):
            try:
                candidate = service._read_frame(sock)
            except TimeoutError:
                break
            if b"SortTotal" in candidate:
                return _parse_stock_list_hd31_records(candidate)
    return []


def fetch_n(client, role, markets, sort_by, n, pageid, capability):
    out, seen = [], set()
    begin = 0
    while len(out) < n and begin < 8000:
        recs = fetch_page(client, role, markets, sort_by, begin, 59,
                          pageid, capability=capability)
        if not recs:
            break
        for r in recs:
            if r["code"] not in seen:
                seen.add(r["code"])
                out.append(r)
        if len(recs) < 59:
            break
        begin = len(out)
    return out


def val(rec, field):
    raw = rec.get(field + "_raw")
    return (raw & 0x07FFFFFF) / 10000.0 if isinstance(raw, int) else None


def main() -> None:
    client = get_client()
    client.stock_list_hot(count=1, sort_by=48, timeout=10.0)
    client.preheat_l2_connections()

    for sort_by, label, field in ((199112, "涨幅", "dt200"), (48, "涨速", "dt48")):
        print(f"\n{'='*60}")
        print(f"== {label}榜：L2 拆沪深(pageid=1341) vs MAIN 单请求(pageid=1334) ==")
        # L2 路径
        sh = fetch_n(client, ConnectionRole.SH_L2, (17, 22, 151), sort_by,
                     400, 1341, Capability.L2_MARKET_ACCESS)
        sz = fetch_n(client, ConnectionRole.SZ_L2, (33,), sort_by,
                     400, 1341, Capability.L2_MARKET_ACCESS)
        # MAIN 路径
        mn = fetch_n(client, ConnectionRole.MAIN, (17, 22, 33, 151), sort_by,
                     400, 1334, Capability.BASIC_QUOTE)

        def stats(recs, field):
            vals = sorted((v for v in (val(r, field) for r in recs) if v is not None),
                          reverse=True)
            bse = [r["code"] for r in recs if r["code"].startswith(("43", "83", "87", "92"))]
            mid = sum(1 for v in vals if 10.0 < v < 20.0) if label == "涨幅" else None
            return len(recs), len(bse), len(vals), mid

        n_sh, bse_sh, nv_sh, mid_sh = stats(sh, field)
        n_sz, bse_sz, nv_sz, mid_sz = stats(sz, field)
        n_mn, bse_mn, nv_mn, mid_mn = stats(mn, field)
        print(f"  L2沪: {n_sh}条(北交所{bse_sh})  L2深: {n_sz}条  合并: {n_sh + n_sz}条")
        if mid_sh is not None:
            print(f"    10~20%区间: 沪{mid_sh} + 深{mid_sz} = {mid_sh + mid_sz}")
        print(f"  MAIN: {n_mn}条(北交所{bse_mn})")
        if mid_mn is not None:
            print(f"    10~20%区间: {mid_mn}")
        # 合并后按真值降序检查连续性
        merged = [(r["code"], val(r, field)) for r in (sh + sz) if val(r, field) is not None]
        merged.sort(key=lambda x: -x[1])
        jumps = []
        for i in range(1, len(merged)):
            if merged[i - 1][1] - merged[i][1] > 1.2 and merged[i - 1][1] < 20.5:
                jumps.append((merged[i - 1], merged[i]))
        print(f"  L2合并后相邻跳跃(>1.2%): {len(jumps)} 处 {jumps[:5]}")
        codes_l2 = {r["code"] for r in sh + sz}
        codes_mn = {r["code"] for r in mn}
        print(f"  L2有而MAIN缺(在L2前100内): "
              f"{[c for c in list(codes_l2)[:100] if c not in codes_mn][:10]}")


if __name__ == "__main__":
    main()
