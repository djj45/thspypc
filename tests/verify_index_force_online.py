#!/usr/bin/env python
"""在线验证五大指数 Level2 分时的买卖力量（buy_force/sell_force/net_force）。

五大指数：
    1A0001 上证指数   market=16  (SH_L2)
    399001 深证成指   market=32  (SZ_L2)
    399006 创业板指   market=32  (SZ_L2)
    1B0680 科创综指   market=16  (SH_L2)
    899050 北证50     market=144 (SH_L2，需显式传 market)

目标：确认 Level2 指数分时响应是否含 dt22/dt23（主动买/卖累计），
从而计算逐分钟买卖力量（红绿柱）。这是普通账号 9355 已实现的功能，
Level2 走 pageid=1334，需验证字段是否一致。

用法:
    py tests/verify_index_force_online.py              # 五大指数全跑
    py tests/verify_index_force_online.py 1A0001       # 单个指数
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from thspypc.client import THSClient  # noqa: E402

# 五大指数：(代码, market, 名称)
INDICES = [
    ("1A0001", 16, "上证指数"),
    ("399001", 32, "深证成指"),
    ("399006", 32, "创业板指"),
    ("1B0680", 16, "科创综指"),
    ("899050", 144, "北证50"),
]


def _summarize(name: str, code: str, market: int, records: list[dict]) -> None:
    """打印一个指数的买卖力量诊断。"""
    tag = f"{code} {name} m={market}"
    if not records:
        print(f"\n  [{tag}] ✗ 空记录")
        return

    n = len(records)
    print(f"\n  [{tag}] n={n}")

    # 检查 dt14/dt15（主动买/卖累计）是否存在
    has_dt14 = any(isinstance(r.get("dt14"), (int, float)) for r in records)
    has_dt15 = any(isinstance(r.get("dt15"), (int, float)) for r in records)
    print(f"    dt14(主动买累计): {'✓ 存在' if has_dt14 else '✗ 缺失'}")
    print(f"    dt15(主动卖累计): {'✓ 存在' if has_dt15 else '✗ 缺失'}")

    # 价格走势（首/中/末）
    prices = []
    for r in records:
        p = r.get("dt10")
        if isinstance(p, (int, float)):
            prices.append(p)
    if prices:
        print(
            f"    价格(dt10): 首={prices[0]:.2f} 中={prices[n // 2]:.2f} "
            f"末={prices[-1]:.2f}"
        )
        trend = "↑涨" if prices[-1] > prices[0] else "↓跌" if prices[-1] < prices[0] else "→平"
        print(f"    全程趋势: {trend} ({prices[-1] - prices[0]:+.2f})")

    # 买卖力量（enrich 后的 buy_force/sell_force/net_force）
    if n >= 2 and isinstance(records[-1].get("net_force"), (int, float)):
        nets = [r.get("net_force", 0) for r in records[1:]]
        buys = [r.get("buy_force", 0) for r in records[1:]]
        sells = [r.get("sell_force", 0) for r in records[1:]]
        red = sum(1 for x in nets if x > 0)
        green = sum(1 for x in nets if x < 0)
        total_net = sum(nets)
        print(f"    买卖力量（{len(nets)} 分钟增量）:")
        print(
            f"      buy_force 总计={sum(buys):.0f}  "
            f"sell_force 总计={sum(sells):.0f}  "
            f"net_force 总计={total_net:+.0f}"
        )
        print(f"      红柱(买强)={red}分钟  绿柱(卖强)={green}分钟")
        print(f"      最近5分钟 net_force: {[round(x) for x in nets[-5:]]}")
        # dt14/dt15 单调性校验
        d14 = [r.get("dt14") for r in records if isinstance(r.get("dt14"), (int, float))]
        d15 = [r.get("dt15") for r in records if isinstance(r.get("dt15"), (int, float))]
        nm14 = sum(1 for i in range(1, len(d14)) if d14[i] < d14[i - 1])
        nm15 = sum(1 for i in range(1, len(d15)) if d15[i] < d15[i - 1])
        print(f"      dt14 非单调={nm14}/{len(d14)-1}  dt15 非单调={nm15}/{len(d15)-1}")


def main():
    args = sys.argv[1:]
    if args:
        # 只跑指定的指数
        targets = [(c, m, n) for c, m, n in INDICES if c in args]
        if not targets:
            print(f"未匹配到指数: {args}，可选: {[c for c, _, _ in INDICES]}")
            sys.exit(1)
    else:
        targets = INDICES

    # 从 .env 加载 level2 账号
    username = os.environ.get("THS_USERNAME")
    password = os.environ.get("THS_PASSWORD")
    imei = os.environ.get("THS_IMEI")
    if not username or not password:
        envpath = ROOT / ".env"
        if envpath.exists():
            for ln in envpath.read_text().splitlines():
                if "=" in ln and not ln.strip().startswith("#"):
                    k, _, v = ln.partition("=")
                    os.environ.setdefault(k.strip(), v.strip())
            username = os.environ.get("THS_USERNAME")
            password = os.environ.get("THS_PASSWORD")
            imei = os.environ.get("THS_IMEI")
    if not username or not password:
        print("✗ 缺少 THS_USERNAME / THS_PASSWORD（.env 或环境变量）")
        sys.exit(1)

    print("=" * 60)
    print("五大指数 Level2 分时买卖力量验证")
    print("=" * 60)
    print(f"登录 level2 账号 {username[:4]}***")

    results = {}
    with THSClient(username, password, imei=imei) as client:
        for code, market, name in targets:
            print(f"\n>>> 请求 {code} {name} (market={market}) ...")
            try:
                records = client.timeline(code, market=market, timeout=15.0)
                _summarize(name, code, market, records)
                results[code] = len(records)
            except Exception as exc:
                print(f"  [{code} {name}] ✗ 异常: {type(exc).__name__}: {exc}")
                results[code] = -1

    # 汇总
    print("\n" + "=" * 60)
    print("汇总")
    print("=" * 60)
    for code, market, name in targets:
        n = results.get(code, -1)
        if n > 0:
            print(f"  {code} {name:6s} m={market:<3d} ✓ {n} 条")
        else:
            print(f"  {code} {name:6s} m={market:<3d} ✗ 失败")


if __name__ == "__main__":
    main()
