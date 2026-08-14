# -*- coding: utf-8 -*-
"""活网验证：改造后 ranked() 对 Level2 账号拆 L2 连接，拿北交所 + 数值归一化。"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from thspypc.testing import get_client


def main() -> None:
    client = get_client()

    print("== ranked() 涨幅榜（count=30, with_values=True, with_names=True）==")
    chg = client.stock_list_hot(
        count=30, sort_by=199112, sort_dir="D",
        with_values=True, with_names=True, timeout=20.0,
    )
    print(f"共 {len(chg)} 条；前 10：")
    for s in chg[:10]:
        print(f"  {s['code']} {s.get('name','')[:8]:<9} dt200={s.get('dt200')}")

    bse = [s for s in chg if s["code"].startswith(("43", "83", "87", "92"))]
    print(f"北交所: {len(bse)} 条 {[s['code'] for s in bse][:5]}")
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

    print("\n== 数值归一化抽查 ==")
    for s in chg[:5]:
        v = s.get("dt200")
        if isinstance(v, (int, float)):
            print(f"  {s['code']} dt200={v} (真值应≈涨幅%, 如 20.01 / 10.02)")


if __name__ == "__main__":
    main()
