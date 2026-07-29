#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
验证 market_snapshot() 全流程：登录 → 发快照请求 → 解析。

用法：
    py tests/test_market_snapshot.py              # 活网
    py tests/test_market_snapshot.py --offline     # 离线（用已有 hfd1_0_response.bin）
"""
from __future__ import annotations

# 可直接运行的活网/语料诊断脚本，不属于默认 pytest 离线套件。
__test__ = False

import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from thspypc import THSClient
from thspypc.parse_hfd1 import parse_hfd1_response


def _load_env():
    env_path = os.path.join(os.path.dirname(__file__), "..", ".env")
    if os.path.exists(env_path):
        for line in open(env_path, encoding="utf-8"):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                if k.strip() and k.strip() not in os.environ:
                    os.environ[k.strip()] = v.strip().strip('"').strip("'")


def test_offline():
    """离线测试：用已有 hfd1_0_response.bin。"""
    path = os.path.join(os.path.dirname(__file__), "..", "data", "hfd1_0_response.bin")
    if not os.path.exists(path):
        print(f"✗ 缺少 {path}")
        return False

    raw = open(path, "rb").read()
    t0 = time.time()
    records = parse_hfd1_response(raw)
    elapsed = time.time() - t0

    print(f"离线测试:")
    print(f"  响应大小: {len(raw):,}B")
    print(f"  解析耗时: {elapsed*1000:.1f}ms")
    print(f"  记录数: {len(records)}")
    n_price = sum(1 for r in records if r.get("price"))
    print(f"  含价格: {n_price}/{len(records)}")

    # 前缀分布
    prefixes = {}
    for r in records:
        p = r["code"][:3]
        prefixes[p] = prefixes.get(p, 0) + 1
    top = sorted(prefixes.items(), key=lambda x: -x[1])[:10]
    print(f"  前缀分布(前10): {dict(top)}")

    # 前 10 条
    print(f"\n  前 10 条:")
    for r in records[:10]:
        print(f"    {r['code']:>8s} {r['name']:12s}  price={r.get('price', 'N/A')}")
    return True


def test_live():
    """活网测试。"""
    _load_env()
    user = os.environ.get("THS_USERNAME", "").strip()
    pwd = os.environ.get("THS_PASSWORD", "").strip()
    if not user or not pwd:
        print("✗ 未配置 .env")
        return False

    print("活网测试 (market_snapshot 在主连接上发，不再循环重连)...")
    client = THSClient(user, pwd)
    r = client.connect()
    if not r.success:
        print(f"✗ 登录失败: {r.error}")
        return False
    print(f"  已连接 {r.server}")

    t0 = time.time()
    recs = client.market_snapshot(timeout=10.0)
    elapsed = time.time() - t0

    print(f"  耗时: {elapsed*1000:.1f}ms")
    print(f"  记录数: {len(recs)}")

    if recs:
        # 统计
        codes_600 = sum(1 for r in recs if r["code"].startswith("6"))
        codes_000 = sum(1 for r in recs if r["code"].startswith("000"))
        codes_300 = sum(1 for r in recs if r["code"].startswith("3"))
        print(f"  沪A(6xx): {codes_600}, 深A(000): {codes_000}, 创业板(3xx): {codes_300}")
        for r in recs[:5]:
            print(f"    {r['code']:>8s} {r['name']:12s}  price={r.get('price', 'N/A')}")
    else:
        print("  （当前 host 不支持 hfd1.0；用 market_snapshot_with_quotes 走 list_quotes 兜底）")

    client.disconnect()
    return bool(recs)


def main():
    offline = "--offline" in sys.argv
    if offline:
        return 0 if test_offline() else 1
    else:
        return 0 if test_live() else 1


if __name__ == "__main__":
    sys.exit(main())
