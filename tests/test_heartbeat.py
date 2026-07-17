#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
thspypc 心跳（keep-alive）测试。

验证 connect() 后后台心跳线程维持长连接：静置 10 秒（让心跳发 3+ 次）后，
list_quotes 仍能成功（证明连接没被服务器因空闲断开）。

用法：
    uv run python tests/test_heartbeat.py

需 .env 配置 THS_USERNAME/THS_PASSWORD。

输出：登录 → 静置 10s（心跳运行）→ 再次查询行情成功 → 线程干净退出。
"""
from __future__ import annotations

import os
import sys
import threading
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

    print("=" * 60)
    print("心跳测试 — 验证长连接保活")
    print("=" * 60)
    print()

    client = THSClient(username, password, imei)
    try:
        result = client.connect()
    except Exception as e:
        print(f"!! 登录异常: {e}")
        return 1
    if not result.success:
        print(f"✗ 登录失败 (error={result.error}): {result.detail}")
        return 1
    print(f"✓ 登录成功: {result.server}")

    # 确认心跳线程已启动
    hb = client._heartbeat_thread
    if hb and hb.is_alive():
        print(f"✓ 心跳线程运行中 (name={hb.name}, daemon={hb.daemon})")
    else:
        print("✗ 心跳线程未启动")
        client.disconnect()
        return 1

    # 第一次查询
    codes = ["600056", "600057", "600058", "600059", "600060", "600061"]
    print(f"\n第 1 次查询（{codes[0]}等6股）...")
    recs1 = client.list_quotes(codes, market=17)
    print(f"  → {len(recs1)} 条: {recs1[0]['code']}={recs1[0].get('dt10')}" if recs1 else "  → 空")

    # 静置 10 秒（心跳应发 3 次 8901 心跳）
    print("\n静置 10 秒（心跳后台运行，8901 每 3 秒一次）...")
    for i in range(10, 0, -1):
        time.sleep(1)
    print(f"  活跃线程数: {threading.active_count()}（含心跳）")
    print(f"  8901 心跳序号: {client._hb_seq_8901}（应 ≥3）")

    # 第二次查询（验证连接未被断开）
    print(f"\n第 2 次查询（静置后，验证连接仍活）...")
    recs2 = client.list_quotes(codes, market=17)
    if recs2:
        print(f"  ✓ {len(recs2)} 条: {recs2[0]['code']}={recs2[0].get('dt10')}")
        print("\n✓ 心跳保活成功：静置 10 秒后连接仍可用。")
        ok = True
    else:
        print("  ✗ 查询为空（连接可能被断开）")
        ok = False

    client.disconnect()
    # 确认线程已退出
    time.sleep(0.5)
    alive = client._heartbeat_thread and client._heartbeat_thread.is_alive()
    print(f"\ndisconnect 后心跳线程存活: {alive}（应为 False）")
    print("✓ 测试完成")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
