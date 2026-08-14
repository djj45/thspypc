# -*- coding: utf-8 -*-
"""活网验证：普通账号（.env.normal）ranked() 走 MAIN 单请求。

验证点：
1. 账号类型判定为 STANDARD（不走 L2 拆分）
2. MAIN 单请求 17/22/33/151 + pageid=1334
3. 能否拿到北交所（920083）——抓包显示普通客户端单请求能拿到 151
4. 10~20% 区间完整性 + 数值归一化
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from thspypc.testing import get_client


def main() -> None:
    client = get_client(".env.normal")
    print(f"账号类型: {client.observed_account_profile.kind}")

    print("\n== ranked() 涨幅榜（count=30, with_values=True, with_names=True）==")
    chg = client.stock_list_hot(
        count=30, sort_by=199112, sort_dir="D",
        with_values=True, with_names=True, timeout=20.0,
    )
    print(f"共 {len(chg)} 条；前 10：")
    for s in chg[:10]:
        print(f"  {s['code']} {s.get('name','')[:8]:<9} dt200={s.get('dt200')}")

    bse = [s for s in chg if s["code"].startswith(("43", "83", "87", "92"))]
    print(f"北交所: {len(bse)} 条 {[s['code'] for s in bse][:6]}")
    print(f"含 920083 金戈新材: {'920083' in {s['code'] for s in chg}}")

    print("\n== ranked() 涨速榜（count=30, with_values=True）==")
    spd = client.stock_list_hot(
        count=30, sort_by=48, sort_dir="D",
        with_values=True, timeout=20.0,
    )
    print(f"共 {len(spd)} 条；前 8：")
    for s in spd[:8]:
        print(f"  {s['code']} dt48={s.get('dt48')}")

    print("\n== 封单额榜（count=10, with_values=True，金额类不缩放）==")
    seal = client.stock_list_hot(
        count=10, sort_by=265260, sort_dir="D",
        with_values=True, timeout=20.0,
    )
    for s in seal[:5]:
        print(f"  {s['code']} dt44={s.get('dt44')}")

    # 翻页完整性：拿 200 条看 10~20% 区间
    print("\n== 翻页完整性（count=200）==")
    big = client.stock_list_hot(
        count=200, sort_by=199112, sort_dir="D",
        with_values=True, timeout=25.0,
    )
    codes = [s["code"] for s in big]
    bse_big = [c for c in codes if c.startswith(("43", "83", "87", "92"))]
    mid = [s for s in big if isinstance(s.get("dt200"), (int, float)) and 10.0 < s["dt200"] < 20.0]
    print(f"200 条中北交所 {len(bse_big)} 条 {bse_big[:8]}")
    print(f"10~20% 区间 {len(mid)} 条")
    vals = sorted((s["dt200"] for s in big if isinstance(s.get("dt200"), (int, float))), reverse=True)
    jumps = []
    for i in range(1, len(vals)):
        if vals[i - 1] - vals[i] > 1.2 and vals[i - 1] < 20.5:
            jumps.append((vals[i - 1], vals[i]))
    print(f"相邻跳跃(>1.2%): {len(jumps)} 处 {jumps[:5]}")


if __name__ == "__main__":
    main()
