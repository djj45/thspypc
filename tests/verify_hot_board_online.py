#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""热点板块（94 页面）活网冒烟验证：hot_boards（pageid=12480）。

验证内容：
  1. 登录并建立板块通道（fu4）
  2. 显式 codes：热点概念板块（886099/886100 等）+ 行业（881101）
  3. 全量 codes=None：按板块全量代码表发送
  4. 打印返回的 code/pre_close/price/chg_pct/main_inflow/speed_*，判断
     是否与 94 页面 UI 一致（板块按涨幅排序）

用法：
    uv run python tests/verify_hot_board_online.py [--full]
"""
from __future__ import annotations

import datetime
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from thspypc import THSClient


def load_dotenv(env_path: str | None = None) -> None:
    """加载账号配置。``env_path`` 传 ``.env``/``.env.normal`` 等相对项目根
    的文件名；缺省用 ``.env``。已存在的环境变量优先（便于外部注入）。"""
    if env_path is None:
        env_path = ".env"
    if not os.path.isabs(env_path):
        env_path = os.path.join(os.path.dirname(__file__), "..", env_path)
    if not os.path.exists(env_path):
        return
    with open(env_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value


def _fmt(value, ndigits: int = 3) -> str:
    if value is None:
        return "-"
    try:
        return f"{float(value):.{ndigits}f}"
    except (TypeError, ValueError):
        return str(value)


def main() -> int:
    # --env <file> 指定账号配置（.env Level2 / .env.normal 普通）
    env_file = ".env"
    if "--env" in sys.argv:
        i = sys.argv.index("--env")
        if i + 1 < len(sys.argv):
            env_file = sys.argv[i + 1]
    load_dotenv(env_file)
    username = os.environ.get("THS_USERNAME", "").strip()
    password = os.environ.get("THS_PASSWORD", "").strip()
    imei = os.environ.get("THS_IMEI", "").strip() or None
    full = "--full" in sys.argv

    print("=" * 64)
    print(f"热点板块(94) 活网验证 @ {datetime.datetime.now():%Y-%m-%d %H:%M:%S}")
    print(f"账号: {username}  env={env_file}  full={full}")
    print("=" * 64)

    client = THSClient(username, password, imei)
    t0 = time.time()
    try:
        result = client.connect()
    except Exception as exc:  # noqa: BLE001
        print(f"!! 登录异常: {exc}")
        return 1
    if not result.success:
        print(f"!! 登录失败 (error={result.error}): {result.detail}")
        return 1
    print(f"  登录成功: {result.server} ({(time.time() - t0):.1f}s)")

    codes = ["886099", "886100", "886101", "886102", "881101", "885927"]
    _section(f"1. hot_boards(显式 codes={codes})")
    t0 = time.time()
    try:
        boards = client.hot_boards(codes, timeout=50.0)
    except Exception as exc:  # noqa: BLE001
        print(f"  !! hot_boards 失败: {exc}")
        boards = []
    print(f"  返回 {len(boards)} 个板块, 耗时 {time.time() - t0:.2f}s")
    _print_boards(boards)

    _section("2. hot_boards_sorted(涨停数 SortBy=271 降序)")
    try:
        rows = client.hot_boards_sorted(271, timeout=50.0)
        print(f"  返回 {len(rows)} 条, 前 6 (涨停数):")
        for r in rows[:6]:
            print(f"    {r['code']}: 涨停={r['value']}")
    except Exception as exc:  # noqa: BLE001
        print(f"  !! hot_boards_sorted 失败: {exc}")

    _section("3. hot_boards_sorted(涨幅 SortBy=199112 降序)")
    try:
        rows = client.hot_boards_sorted(199112, timeout=50.0)
        print(f"  返回 {len(rows)} 条, 前 6 (涨跌幅%):")
        for r in rows[:6]:
            print(f"    {r['code']}: 涨幅={r['value']}")
    except Exception as exc:  # noqa: BLE001
        print(f"  !! hot_boards_sorted(199112) 失败: {exc}")

    _section("4. hot_boards_sorted(主力 SortBy=592890 降序)")
    try:
        rows = client.hot_boards_sorted(592890, timeout=50.0)
        print(f"  返回 {len(rows)} 条, 前 6 (主力净流入, 亿):")
        for r in rows[:6]:
            print(f"    {r['code']}: 主力={r['value']/1e8:.2f}亿")
    except Exception as exc:  # noqa: BLE001
        print(f"  !! hot_boards_sorted(592890) 失败: {exc}")

    if full:
        _section("2. hot_boards(全量 None)")
        t0 = time.time()
        try:
            boards = client.hot_boards(None, timeout=60.0)
        except Exception as exc:  # noqa: BLE001
            print(f"  !! hot_boards(None) 失败: {exc}")
            boards = []
        print(f"  返回 {len(boards)} 个板块, 耗时 {time.time() - t0:.2f}s")
        valid = [b for b in boards if b.get("chg_pct") is not None]
        valid.sort(key=lambda b: -(b["chg_pct"] or 0))
        print(f"  有涨幅 {len(valid)} 个, 按涨幅前 10:")
        for b in valid[:10]:
            print(f"    {b.get('code')}: {_fmt(b.get('chg_pct'), 2)}%  "
                  f"price={_fmt(b.get('price'))} pre={_fmt(b.get('pre_close'))}")

    client.disconnect()
    return 0


def _section(title: str) -> None:
    print("\n" + "=" * 64)
    print(title)
    print("=" * 64)


def _print_boards(boards: list[dict]) -> None:
    if not boards:
        print("  (无数据)")
        return
    for b in boards:
        print(
            f"    {b.get('code')}: pre={_fmt(b.get('pre_close'))} "
            f"price={_fmt(b.get('price'))} chg={_fmt(b.get('chg_pct'), 2)}% "
            f"涨停={_fmt(b.get('limit_up'), 0)} 涨家={_fmt(b.get('up_count'), 0)} "
            f"跌家={_fmt(b.get('down_count'), 0)} "
            f"4m速={_fmt(b.get('speed_4m'))} "
            f"1m速={_fmt(b.get('speed_1m'))} "
            f"主力={_fmt(b.get('main_inflow'), 0)}"
        )


if __name__ == "__main__":
    sys.exit(main())
