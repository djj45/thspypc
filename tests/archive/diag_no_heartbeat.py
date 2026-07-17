#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
对比测试：不发心跳时，8901 连接多久会被服务器断开？

策略：enable_heartbeat=False 连接，静置 N 秒后查询，看是否还能用。
逐个递增 N（30/60/90/120/150/180/240/300），找出断连临界点。
每次用新连接（避免前一次失败影响）。

用法：
    uv run python tests/test_no_heartbeat.py [--max 300]

注意：整个测试耗时较长（累计静置时间），且需多次登录（注意限流，每次间隔 40s）。
"""
from __future__ import annotations

import os
import socket
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


def test_idle_disconnect(username, password, imei, idle_seconds):
    """禁用心跳连接，静置 idle_seconds 后查询，返回 (登录成功, 查询结果描述)。"""
    client = THSClient(username, password, imei, enable_heartbeat=False)
    try:
        result = client.connect()
    except Exception as e:
        return False, f"登录异常: {e}"
    if not result.success:
        return False, f"登录失败({result.error})"

    # 静置
    time.sleep(idle_seconds)

    # 尝试查询
    try:
        recs = client.list_quotes(["600056", "600057", "600058", "600059", "600060", "600061"],
                                  market=17)
        if recs:
            return True, f"✓ 仍可用（{len(recs)} 条，{recs[0]['code']}={recs[0].get('dt10')}）"
        else:
            return True, "连接在但查询返回空（可能被服务器软断开）"
    except (socket.timeout, ConnectionError, OSError) as e:
        return True, f"✗ 断开: {type(e).__name__}: {e}"
    except Exception as e:
        return True, f"✗ 异常: {type(e).__name__}: {e}"
    finally:
        client.disconnect()


def main() -> int:
    load_dotenv()
    username = os.environ.get("THS_USERNAME", "").strip()
    password = os.environ.get("THS_PASSWORD", "").strip()
    imei = os.environ.get("THS_IMEI", "").strip() or None

    # 解析 --max
    max_idle = 300
    if "--max" in sys.argv:
        i = sys.argv.index("--max")
        if i + 1 < len(sys.argv):
            max_idle = int(sys.argv[i + 1])

    # 测试间隔点
    intervals = [s for s in [30, 60, 90, 120, 150, 180, 240, 300] if s <= max_idle]
    if not intervals:
        intervals = [max_idle]

    print("=" * 60)
    print("对比测试：不发心跳，连接多久会断？")
    print("=" * 60)
    print(f"测试间隔点: {intervals} 秒")
    print(f"（每组之间间隔 40s 避免限流）")
    print()
    print(f"{'静置秒数':>8} {'结果'}")
    print("-" * 60)

    results = []
    for idx, idle in enumerate(intervals):
        # 组间冷却（避免限流）
        if idx > 0:
            print(f"  （冷却 40s 避免限流...）")
            time.sleep(40)

        ok, desc = test_idle_disconnect(username, password, imei, idle)
        status = "保活" if "✓" in desc and "✗" not in desc else ("断开" if "✗" in desc else "?")
        print(f"{idle:>7}s [{status}] {desc}")
        results.append((idle, status, desc))

        # 如果已断开，后续更长间隔大概率也断，可提前结束
        if status == "断开" and idx < len(intervals) - 1:
            print(f"\n→ 已在 {idle}s 断开，后续间隔可能也断，但继续测确认...")

    print()
    print("=" * 60)
    print("结论：")
    alive = [r[0] for r in results if r[1] == "保活"]
    dead = [r[0] for r in results if r[1] == "断开"]
    if dead and alive:
        threshold = dead[0]
        last_alive = max(alive)
        print(f"  不发心跳时，连接在静置 {last_alive}s~{threshold}s 之间被断开。")
        print(f"  → 心跳（每3秒）对维持长连接是必要的。")
    elif dead and not alive:
        print(f"  不发心跳时，{dead[0]}s 内就断了（所有测试点都断）。")
    elif alive and not dead:
        print(f"  不发心跳时，静置到 {max(alive)}s 仍未断（服务器超时更长）。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
