# -*- coding: utf-8 -*-
"""Live-verify dt48 (4-min speed) scale factor against the dt200 anchor.

涨速榜 sort_by=48 响应字段 dt48（文档假设 ×1e8，盘中待核）。
用涨幅榜 sort_by=199112 的 dt200（已活网验证 = 涨幅%×1e8）做锚点，
并对同一批股票 list_quotes 拿 dt6/dt10 计算真实涨幅交叉核对。
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from thspypc.testing import get_client


def market_for(code: str) -> int:
    if code.startswith("6"):
        return 17
    if code.startswith(("4", "8")):
        return 151
    return 33


def main() -> None:
    client = get_client()

    # 1. 涨速榜（sort_by=48 → dt48）
    speed = client.stock_list_hot(
        count=59, sort_by=48, sort_dir="D",
        with_values=True, with_names=True, timeout=15.0,
    )
    print(f"== 涨速榜 sort_by=48: {len(speed)} 条 ==")
    print("code   market  dt48(dec)       全部 dt 字段")
    for s in speed:
        dts = {k: v for k, v in s.items() if k.startswith("dt") and not k.endswith("_format")}
        print(f"{s.get('code','')}  {s.get('market',0):>3}  {s.get('dt48',''):<15} {dts}")

    # 2. 涨幅榜锚点（dt200 = 涨幅%×1e8 已验证）
    chg = client.stock_list_hot(
        count=10, sort_by=199112, sort_dir="D",
        with_values=True, with_names=True, timeout=15.0,
    )
    print()
    print("== 涨幅榜锚点 sort_by=199112（dt200）==")
    by_code = {}
    for c in [s["code"] for s in chg[:6]]:
        qs = client.list_quotes([c], market=market_for(c), timeout=15.0)
        if qs:
            by_code[c] = qs[0]
    print("code   dt200        dt6(prev)  dt10(now)  真实涨幅%   dt200/涨幅")
    for s in chg[:6]:
        code = s["code"]
        dt200 = s.get("dt200")
        qr = by_code.get(code, {})
        dt6, dt10 = qr.get("dt6"), qr.get("dt10")
        pct = None
        if isinstance(dt6, (int, float)) and isinstance(dt10, (int, float)) and dt6:
            pct = (dt10 - dt6) / dt6 * 100
        ratio = (dt200 / pct) if (isinstance(dt200, (int, float)) and pct) else None
        print(f"{code}  {dt200 if dt200 is not None else '':<12} {dt6}  {dt10}  {round(pct,3) if pct else ''}  {round(ratio) if ratio else ''}")

    # 3. 涨速榜头部股票的 quote dt48 交叉对比
    print()
    print("== 涨速榜头部股票 list_quotes dt48（同股对比）==")
    for s in speed[:6]:
        code = s["code"]
        qs = client.list_quotes([code], market=market_for(code), timeout=15.0)
        if qs:
            q = qs[0]
            print(f"{code} ranked_dt48={s.get('dt48')}  quote_dt48={q.get('dt48')}  quote_dt10={q.get('dt10')} quote_dt6={q.get('dt6')}")


if __name__ == "__main__":
    main()
