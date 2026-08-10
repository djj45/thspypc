#!/usr/bin/env python
"""活网验证 4214 挂单/撤单全量明细（单进程、单 THSClient、不登录 MAIN）。

严格遵守仓库 AGENTS.md：
- 只做一次 HTTP 鉴权（``client.authenticate()``），**不调用** ``connect()``/
  ``get_client()``——MAIN（main.123ths.com）会抢先消费 Passport64 并触发
  ``VerifyCode=-1``（通行证有被修改的痕迹），而 4214 挂单/撤单只走沪深 Level2
  连接（shlv2/szlv2）。让目标市场 L2 连接成为该 passport 的首次成功登录。
- 同一 ConnectionManager 复用已建 L2 socket；跨市场（深→沪）时 L2 建连逻辑
  检测到票据失效会自动重新 HTTP 鉴权取新 passport，不手动重复登录。

用法：
    py -u tests/verify_order_details_online.py
    py -u tests/verify_order_details_online.py --env .env
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from datetime import datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from thspypc import THSClient  # noqa: E402
from thspypc.testing import load_env  # noqa: E402


def _summary(label: str, result: dict) -> bool:
    orders = result["orders"]
    buy_cancels = result["buy_cancels"]
    sell_cancels = result["sell_cancels"]
    cancels = buy_cancels + sell_cancels
    facts = {
        "orders": len(orders),
        "buy_cancels": len(buy_cancels),
        "sell_cancels": len(sell_cancels),
        "events": len(result["events"]),
        "bad_elapsed": sum(row["elapsed_seconds"] < 0 for row in cancels),
        "linked": sum(bool(row.get("linked_order")) for row in cancels),
        "link_exact": sum(bool(row.get("link_exact")) for row in cancels),
        "order_sides": sorted(
            {row.get("side") for row in orders}, key=lambda s: (s is None, s)
        ),
    }
    print(f"{label}: {facts}", flush=True)
    for name, rows in (
        ("order", orders),
        ("buy_cancel", buy_cancels),
        ("sell_cancel", sell_cancels),
    ):
        if not rows:
            continue
        row = rows[0]
        sample = {
            key: row.get(key)
            for key in (
                "side",
                "time",
                "placed_time",
                "cancelled_time",
                "elapsed_seconds",
                "price",
                "volume",
                "order_id",
            )
        }
        print(f"  {name}: {sample}", flush=True)
    return bool(orders and buy_cancels and sell_cancels) and not facts["bad_elapsed"]


def _query(client, label: str, code: str, start, end, timeout: float) -> bool:
    print(f"QUERY {label}", flush=True)
    started = time.monotonic()
    result = client.order_details(
        code,
        start,
        end,
        timeout=timeout,
    )
    print(f"  elapsed={time.monotonic() - started:.1f}s", flush=True)
    return _summary(label, result)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--env", default=str(ROOT / ".env"))
    args = parser.parse_args()

    env_path = load_env(Path(args.env))
    username = os.environ.get("THS_USERNAME", "").strip()
    password = os.environ.get("THS_PASSWORD", "").strip()
    if not username or not password:
        raise RuntimeError(f"THS_USERNAME/THS_PASSWORD missing in {env_path}")

    # 只 HTTP 鉴权，不建 MAIN（见模块 docstring / AGENTS.md）。
    client = THSClient(username, password, enable_heartbeat=False)
    try:
        client.authenticate()
        print("AUTH ok, 跳过 MAIN 直接走 Level2 (shlv2/szlv2)", flush=True)

        checks = []
        checks.append(_query(client, "SZ 002428 latest", "002428", -29, 0, 15.0))
        checks.append(_query(client, "SH 600664 latest", "600664", -29, 0, 15.0))

        # pcap 中已知有较大响应的盘后绝对区间，用来验证非首页的小型全量回查。
        start = datetime(2026, 8, 10, 14, 56, 40)
        end = datetime(2026, 8, 10, 15, 0, 0)
        checks.append(_query(client, "SZ 002428 absolute", "002428", start, end, 45.0))

        passed = all(checks)
        print(f"RESULT {'PASS' if passed else 'FAIL'} checks={checks}", flush=True)
        return 0 if passed else 1
    finally:
        client.disconnect()


if __name__ == "__main__":
    raise SystemExit(main())
