#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
thspypc 短线精灵（异动）功能测试。

登录 8901 后懒连 9601，用 dxjl_latest 查最新异动。

用法：
    uv run python tests/test_dxjl.py

需 .env 配置 THS_USERNAME/THS_PASSWORD（或扫码缓存）。

注意：短线精灵数据**盘中**（9:25-15:00）才有，非交易时段返回空列表（不报错）。
输出：最新一页异动记录（代码/异动类型/金额/涨跌幅），按时间倒序。
"""
from __future__ import annotations

import datetime
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from thspypc import THSClient


def load_dotenv() -> None:
    env_path = os.path.join(os.path.dirname(__file__), "..", ".env")
    if not os.path.exists(env_path):
        return
    with open(env_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value


def main() -> int:
    load_dotenv()
    username = os.environ.get("THS_USERNAME", "").strip()
    password = os.environ.get("THS_PASSWORD", "").strip()
    imei = os.environ.get("THS_IMEI", "").strip() or None

    print("=" * 60)
    print("短线精灵（异动）测试 — 9601 qurealorder")
    print("=" * 60)
    now = datetime.datetime.now()
    # 粗判交易时段（周一-周五 9:25-15:30）
    weekday = now.weekday()  # 0=Mon
    in_session = weekday < 5 and 9 <= now.hour < 16
    print(f"当前时间: {now.strftime('%Y-%m-%d %H:%M:%S')} "
          f"({'交易时段' if in_session else '非交易时段（可能无数据）'})")
    print()

    client = THSClient(username, password, imei)
    try:
        if username and password:
            result = client.connect()
        else:
            print("（.env 无账号密码，走扫码缓存登录）")
            result = client.connect_cached()
    except Exception as e:
        print(f"!! 登录异常: {e}")
        return 1

    if not result.success:
        print(f"✗ 登录失败 (error={result.error}): {result.detail}")
        return 1
    print(f"✓ 8901 登录成功: {result.server}")

    # dxjl_latest 会懒连 9601
    print("查询最新异动（dxjl_latest，沪深）...")
    try:
        recs = client.dxjl_latest()
    except Exception as e:
        print(f"✗ dxjl_latest 异常: {e}")
        import traceback
        traceback.print_exc()
        client.disconnect()
        return 1
    finally:
        client.disconnect()

    if not recs:
        print()
        print("✓ 查询完成，但无数据（非交易时段正常；或 9601 连接失败见日志）")
        print("  盘中 9:25-15:00 重试应有异动记录。")
        return 0

    print(f"\n✓ 取到 {len(recs)} 条异动：")
    print(f"  {'时间':<21} {'市场':<4} {'代码':<8} {'异动类型':<10} {'金额':>12} {'涨跌幅':>8}")
    for r in recs[:30]:
        ts = datetime.datetime.fromtimestamp(r["时间"] / 1_000_000).strftime("%H:%M:%S.%f")[:-3]
        mkt = "深" if r["市场"] == "32" else "沪"
        amt = f"{r['金额']:>12.0f}" if r["金额"] else f"{'-':>12}"
        print(f"  {ts:<21} {mkt:<4} {r['代码']:<8} {r['异动类型']:<10} {amt} {r['涨跌幅']:>7.2f}%")
    if len(recs) > 30:
        print(f"  ... 共 {len(recs)} 条")
    print()
    print("→ 短线精灵链路走通（9601 qurealorder + hq1.0 解析）。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
