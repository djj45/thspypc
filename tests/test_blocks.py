#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
thspypc 自定义板块/自选股功能测试。

登录后用 list_groups / get_group 验证板块管理链路（HTTPS cookie 鉴权）。

用法：
    uv run python tests/test_blocks.py

需 .env 配置 THS_USERNAME/THS_PASSWORD（或扫码缓存）。

输出：所有自定义分组列表 + 「我的自选」成分股（如有）。
"""
from __future__ import annotations

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
    print("自定义板块/自选股测试")
    print("=" * 60)

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
    print(f"✓ 登录成功: {result.server}")

    if client._blocks is None:
        print("✗ 板块功能未初始化（docookie2 可能失败，检查日志）")
        client.disconnect()
        return 1
    print("✓ 板块功能已就绪")
    print()

    # 1. 列出所有分组
    try:
        groups = client.list_groups()
        print(f"自定义分组（{len(groups)} 个）:")
        for g in groups:
            tag = "动态" if getattr(g, "is_dynamic", False) else f"{len(g.items)}只"
            print(f"  - {g.name}  ({tag})")
    except Exception as e:
        print(f"✗ list_groups 失败: {e}")
        client.disconnect()
        return 1

    # 2. 我的自选
    print()
    try:
        sg = client.get_self_stocks()  # StockGroup
        print(f"「我的自选」（{len(sg.items)} 只）:")
        for item in sg.items[:15]:
            print(f"  - {item.code} ({item.market or '?'})")
        if len(sg.items) > 15:
            print(f"  ... 共 {len(sg.items)} 只")
    except Exception as e:
        print(f"（get_self_stocks 失败: {e}）")

    client.disconnect()
    print()
    print("→ 板块/自选股链路走通（HTTPS cookie 鉴权 + ugc.10jqka.com.cn API）。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
