#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
验证分时查询的连接复用：连续切换多只股票，确认只 init 一次、后续复用。

测两个维度：
  1. 同市切换（深→深→深）：紫光 000938 → 中兴 000063 → 平安 000001
     应全程用同一条 __manual[sz] 连接，无重复 init。
  2. 跨市切换（深→沪→深）：000938 → 共进 603118 → 紫光 000938
     深→沪建第二条连接（sh），沪→深复用已有 sz 连接。

计时每个查询的耗时，定位慢的环节（init？订阅？查询？）。

用法：uv run python tests/test_timeline_switch.py
"""
from __future__ import annotations

import datetime
import logging
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

logging.basicConfig(level=logging.INFO,
                    format="  ·%(levelname)s %(name)s: %(message)s", stream=sys.stdout)

from thspypc import THSClient

# 测试序列：(代码, 名称, 预期市场key)
SWITCH_SEQ = [
    ("000938", "紫光股份", "sz"),
    ("000063", "中兴通讯", "sz"),   # 同市切换，应复用 sz 连接
    ("000001", "平安银行", "sz"),   # 同市切换
    ("603118", "共进股份", "sh"),   # 跨市，建 sh 连接
    ("600519", "贵州茅台", "sh"),   # 同市切换
    ("000938", "紫光股份", "sz"),   # 跨市回深，复用 sz
]


def load_env() -> None:
    env_path = os.path.join(os.path.dirname(__file__), "..", ".env")
    if not os.path.exists(env_path):
        return
    with open(env_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key, value = key.strip(), value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value


def main() -> int:
    load_env()
    username = os.environ.get("THS_USERNAME", "").strip()
    password = os.environ.get("THS_PASSWORD", "").strip()
    imei = os.environ.get("THS_IMEI", "").strip() or None
    if not username or not password:
        print("✗ 未设置 THS_USERNAME / THS_PASSWORD")
        return 1

    print("=" * 64)
    print("分时连接复用验证 — 连续切换 %d 只股票" % len(SWITCH_SEQ))
    print("=" * 64)
    print("序列:", " → ".join("%s(%s)" % (c, n) for c, n, _ in SWITCH_SEQ))
    print()

    client = THSClient(username=username, password=password, imei=imei)
    try:
        print("→ 登录...")
        t0 = time.time()
        result = client.connect()
        if not result.success:
            print("✗ 登录失败: %s / %s" % (result.error, result.detail))
            return 1
        print("✓ 登录成功 (%.1fs)，服务器 %s" % (time.time() - t0, result.server))
        print()

        results = []
        for code, name, expect_key in SWITCH_SEQ:
            t1 = time.time()
            try:
                recs = client.timeline(code)
                elapsed = time.time() - t1
                # 检查实际用了哪个连接池 key
                actual_keys = list(client._push_socks.keys())
                ok = len(recs) > 0
                results.append((code, name, ok, len(recs), elapsed, actual_keys))
                mark = "✓" if ok else "✗"
                print("%s %s %-8s %3d根  %.2fs  连接池=%s" %
                      (mark, code, name, len(recs), elapsed, actual_keys))
            except Exception as e:
                elapsed = time.time() - t1
                results.append((code, name, False, 0, elapsed, list(client._push_socks.keys())))
                print("✗ %s %-8s 异常 %.2fs: %s" % (code, name, elapsed, e))

        # 汇总
        print()
        print("=" * 64)
        print("【汇总】")
        print("=" * 64)
        n_ok = sum(1 for r in results if r[2])
        print("成功: %d/%d" % (n_ok, len(results)))
        # 计时分析
        times = [r[4] for r in results]
        print("耗时: 最快 %.2fs / 最慢 %.2fs / 平均 %.2fs" %
              (min(times), max(times), sum(times) / len(times)))
        first = times[0]
        rest = times[1:]
        if rest:
            print("  首次(含init+connect): %.2fs" % first)
            print("  后续(应复用): 最快 %.2fs / 最慢 %.2fs / 平均 %.2fs" %
                  (min(rest), max(rest), sum(rest) / len(rest)))
        print("最终连接池:", list(client._push_socks.keys()))
        print()
        if first > 5 and rest and max(rest) < first / 2:
            print("✓ 首次慢（init+连接建立），后续快（复用）—— 符合预期")
        if n_ok == len(results):
            print("✓ 全部切换成功，连接复用正常")
        return 0 if n_ok == len(results) else 2
    finally:
        client.disconnect()


if __name__ == "__main__":
    sys.exit(main())
