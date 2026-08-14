# -*- coding: utf-8 -*-
"""诊断排序榜缺失条目：翻页完整性 + 北交所(151)覆盖 + 编码分界点。

用户在同花顺客户端核对发现：
1. 涨幅榜缺 920083 金戈新材（北交所，疑似涨停 30% 应在榜首）
2. 10-20% 区间缺 n 只股票
3. 涨速榜 0.5-1.46% 区间缺 n 只
"""
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


def fetch_raw_page(client, sort_by: int, sort_begin: int, sort_count: int,
                   markets=(17, 22, 33, 151)) -> list[dict]:
    """直接发一页排序请求并解析原始记录（保留 dt<N>_raw）。"""
    service = client._stock_list_service
    conn = service._connections.acquire(
        ConnectionRole.MAIN, capability=Capability.BASIC_QUOTE
    )
    request = build_stock_list_query(
        markets=markets,
        sort_begin=sort_begin,
        sort_count=sort_count,
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


def mant_value(rec: dict, field: str) -> float | None:
    raw = rec.get(field + "_raw")
    if isinstance(raw, int):
        return (raw & 0x07FFFFFF) / 10000.0
    return None


def main() -> None:
    client = get_client()
    client.stock_list_hot(count=1, sort_by=48, timeout=10.0)

    # ── 1. 翻页拿涨幅榜 400 条（59/页 × 7 页）──
    print("== 涨幅榜 sort_by=199112 翻页完整性检查 ==")
    seen = []
    codes = set()
    enc_c0 = 0
    enc_40 = 0
    for page in range(7):
        recs = fetch_raw_page(client, 199112, sort_begin=page * 59, sort_count=59)
        for rec in recs:
            code = rec.get("code", "")
            raw = rec.get("dt200_raw")
            val = mant_value(rec, "dt200")
            if code and code not in codes:
                codes.add(code)
                seen.append((code, val, raw))
            if isinstance(raw, int) and raw & 0x80000000:
                enc_c0 += 1
            elif isinstance(raw, int):
                enc_40 += 1
        if len(recs) < 59:
            print(f"page {page}: 只返回 {len(recs)} 条，提前结束")
            break
    print(f"翻页 7 页去重后共 {len(codes)} 条；c0编码 {enc_c0} 条、40编码 {enc_40} 条")
    bse = [c for c in codes if c.startswith(("43", "83", "87", "92"))]
    print(f"北交所/新三板前缀(43/83/87/92): {len(bse)} 条 -> {bse[:20]}")
    print(f"含 920083 金戈新材: {'920083' in codes}")
    mid = [(c, v) for c, v, _ in seen if v is not None and 10.0 < v < 20.0]
    print(f"10%<涨幅<20%: {len(mid)} 条")
    # 展示翻页后的边界：每页首尾
    for i, (c, v, _) in enumerate(seen[:200]):
        pass
    for i in range(0, min(len(seen), 413), 59):
        chunk = seen[i:i+59]
        if chunk:
            print(f"  第{i//59+1}页: 首 {chunk[0][0]}={chunk[0][1]:.4f}  尾 {chunk[-1][0]}={chunk[-1][1]:.4f}")

    # ── 2. 单独查北交所 151 ──
    print()
    print("== 单独 CodeList=151(); 查北交所涨幅榜 ==")
    recs151 = fetch_raw_page(client, 199112, sort_begin=0, sort_count=59, markets=(151,))
    for rec in recs151[:10]:
        print(f"  {rec.get('code','')} raw={rec.get('dt200_raw')} dec={rec.get('dt200')}")

    # ── 3. 涨速榜翻页完整性 ──
    print()
    print("== 涨速榜 sort_by=48 翻页完整性检查 ==")
    seen48 = []
    codes48 = set()
    for page in range(7):
        recs = fetch_raw_page(client, 48, sort_begin=page * 59, sort_count=59)
        for rec in recs:
            code = rec.get("code", "")
            val = mant_value(rec, "dt48")
            if code and code not in codes48:
                codes48.add(code)
                seen48.append((code, val))
        if len(recs) < 59:
            print(f"page {page}: 只返回 {len(recs)} 条，提前结束")
            break
    print(f"涨速榜翻页 7 页去重后共 {len(codes48)} 条")
    bse48 = [c for c in codes48 if c.startswith(("43", "83", "87", "92"))]
    print(f"北交所前缀: {len(bse48)} 条 -> {bse48[:20]}")


if __name__ == "__main__":
    main()
