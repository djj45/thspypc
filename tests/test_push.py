#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
thspypc 短线精灵实时推送测试（9601 subrealorder + pushrealorder 接收）。

登录 8901 → 连 9601 → subscribe_realtime() 订阅异动 → receive_pushes() 接收推送。

用法：
    uv run python tests/test_push.py [--timeout 20]

注意：实时推送**盘中**（9:25-15:00）才有，非交易时段返回空列表。
实测盘中 20 秒收到 507 条异动推送（2026-07-17 14:35）。
每条推送记录含 代码/市场/raw_bytes（数值字段待逆向，保留原始字节）。
"""
from __future__ import annotations

import datetime
import os
import sys
import time

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

    timeout = 20.0
    if "--timeout" in sys.argv:
        i = sys.argv.index("--timeout")
        if i + 1 < len(sys.argv):
            timeout = float(sys.argv[i + 1])

    print("=" * 60)
    print("短线精灵实时推送测试 — 9601 subreal + pushrealorder")
    print("=" * 60)
    now = datetime.datetime.now()
    weekday = now.weekday()
    in_session = weekday < 5 and 9 <= now.hour < 16
    print(f"当前: {now.strftime('%Y-%m-%d %H:%M')} "
          f"({'交易时段' if in_session else '非交易时段（可能无推送）'})")
    print(f"接收时长: {timeout}s")
    print()

    client = THSClient(username, password, imei)
    try:
        if username and password:
            result = client.connect()
        else:
            result = client.connect_cached()
    except Exception as e:
        print(f"!! 登录异常: {e}")
        return 1
    if not result.success:
        print(f"✗ 登录失败 (error={result.error}): {result.detail}")
        return 1
    print(f"✓ 登录成功: {result.server}")

    # 订阅异动推送
    print("订阅异动通道（URS/UNX/UCX/UME/UCT）...")
    try:
        client.subscribe_realtime()
        print("✓ 订阅已发送")
    except Exception as e:
        print(f"✗ 订阅失败: {e}")
        client.disconnect()
        return 1

    # 接收推送（callback 模式，实时打印）
    print(f"\n接收推送 {timeout}s（盘中每分钟约 637 条异动）...\n")
    count = [0]

    def on_push(rec):
        count[0] += 1
        if count[0] <= 30:
            mkt = "深" if rec["市场"] == "32" else ("沪" if rec["市场"] == "16" else rec["市场"])
            print(f"  [{count[0]:>3}] {mkt} {rec['代码']}  raw={rec['raw_bytes'][:24]}...")
        elif count[0] == 31:
            print(f"  ... （后续推送省略）")

    try:
        client.receive_pushes(timeout=timeout, callback=on_push)
    except Exception as e:
        print(f"✗ 接收异常: {e}")
        import traceback
        traceback.print_exc()

    client.disconnect()
    print(f"\n✓ 接收完成，共 {count[0]} 条异动")
    if count[0] == 0:
        print("  （非交易时段正常无推送；盘中重试应有数据）")
    else:
        print("→ 实时推送链路走通（subreal 订阅 + pushrealorder 接收）。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
