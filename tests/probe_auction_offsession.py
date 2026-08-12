#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""探针:盘后/非竞价时段,测三条竞价路径的耗时。

背景
----
切股票慢的最大单点是 auction 盘后死等 12s timeout。根因(services/auction.py):
  - trade_date=None → historical=False → 走 pageid=1334 实时竞价路径
  - 非竞价时段(不在 9:15-9:25)服务端不响应 → 死等 timeout=12s

三条候选路径:
  1. 当前默认:trade_date=None,L2 实时 1334 → 预期死等 12s
  2. L2 历史:trade_date=<历史日> → 4417,实测 ~39ms(已采纳为修复方案)
  3. ★ MAIN 历史路径:build_basic_auction_query(historical=True),pageid=9355,
     走 MAIN 连接,无需订阅,实测 11ms

⚠ 路径3 虽最快,但**偏离 Level2 客户端真实拓扑**(真实客户端个股业务全走 shlv2/szlv2,
不逃 MAIN)。最终修复方案采用**路径2**(L2 历史 4417),保持拓扑一致:见
``services/auction.py`` 的 ``_in_auction_session`` 判断 —— 非竞价时段走 L2 历史路径。
路径3 在本探针里仅作对照(证明 MAIN 也能查 9355,但不采用)。

用法:
    uv run python tests/probe_auction_offsession.py
    uv run python tests/probe_auction_offsession.py --code 000001
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from datetime import date, timedelta

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from thspypc.testing import get_client  # noqa: E402
from thspypc.features.auction_protocol import build_basic_auction_query  # noqa: E402
from thspypc.codecs.framing import read_frame  # noqa: E402


def probe_path1_default(client, code: str, market: int) -> None:
    """路径1:当前默认(trade_date=None,L2 实时 1334)。"""
    print(f"\n{'='*64}")
    print("【路径1】当前默认 trade_date=None(L2 实时 1334)")
    print(f"{'='*64}")
    t0 = time.time()
    try:
        recs = client.auction(code, market=market, timeout=12.0)
        print(f"  耗时: {(time.time()-t0)*1000:.0f}ms  返回 {len(recs)} 条")
    except Exception as e:
        print(f"  ✗ {(time.time()-t0)*1000:.0f}ms 失败: {type(e).__name__}: {e}")


def probe_path2_l2_history(client, code: str, market: int, hist_date) -> None:
    """路径2:L2 历史(trade_date=历史日, 4417 + ensure_registered)。"""
    print(f"\n{'='*64}")
    print(f"【路径2】L2 历史 trade_date={hist_date}(4417 + 订阅)")
    print(f"{'='*64}")
    t0 = time.time()
    try:
        recs = client.auction(code, market=market, trade_date=hist_date, timeout=12.0)
        print(f"  耗时: {(time.time()-t0)*1000:.0f}ms  返回 {len(recs)} 条")
    except Exception as e:
        print(f"  ✗ {(time.time()-t0)*1000:.0f}ms 失败: {type(e).__name__}: {e}")


def probe_path3_main_history(client, code: str, market: int, hist_date) -> None:
    """路径3:★ MAIN 历史路径(build_basic_auction_query historical=True, pageid=9355)。

    直接构造 frame,用 client._sock(MAIN)发送,完全绕开 L2 订阅。
    """
    print(f"\n{'='*64}")
    print(f"【路径3】★ MAIN 历史 pageid=9355(绕开 L2 订阅)")
    print(f"{'='*64}")
    frame = build_basic_auction_query(
        code, market=market, trade_date=hist_date, historical=True,
    )
    if not client.is_connected:
        client.connect()
    sock = client._sock
    if sock is None:
        print("  ✗ 无 MAIN 连接")
        return
    sock.settimeout(12.0)
    t0 = time.time()
    total = b""
    try:
        with client._sock_lock:
            if client._sock:
                client._sock.sendall(frame + b"\n")
        for _ in range(8):
            try:
                chunk = read_frame(sock)
            except Exception:
                break
            if not chunk:
                break
            total += chunk
            if b"hd1.0" in total or b"hd3.1" in total:
                break
    except Exception as e:
        print(f"  ✗ {(time.time()-t0)*1000:.0f}ms 失败: {type(e).__name__}: {e}")
        return
    elapsed = (time.time() - t0) * 1000
    has_hd = b"hd1.0" in total or b"hd3.1" in total
    print(f"  耗时: {elapsed:.0f}ms  响应: {len(total)} 字节  含 hd 表: {has_hd}")
    if has_hd:
        # 看返回的竞价记录数(粗略:Count 数)
        import re
        text = total.decode("gbk", errors="replace")
        m = re.search(r"SortDataCount=(\d+)", text)
        if m:
            print(f"  SortDataCount = {m.group(1)}")
        # 看有没有 dt10(撮合价)
        if "dt10" in text or "10=" in text:
            print(f"  ★ 含竞价数据(盘后能拿到历史竞价)")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--code", default="000001")
    ap.add_argument("--env", default=".env")
    args = ap.parse_args()
    market = 17 if args.code.startswith("6") else 33

    print("="*64)
    print(f"竞价路径探针 @ {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"code={args.code} market={market}")
    print("="*64)

    client = get_client(args.env)
    print(f"已登录: {client.is_connected}")

    # 历史日期:昨天(确保是历史路径)
    today = date.today()
    hist = today - timedelta(days=1)
    # 跳到工作日
    while hist.weekday() >= 5:
        hist -= timedelta(days=1)

    probe_path1_default(client, args.code, market)
    probe_path3_main_history(client, args.code, market, hist)
    probe_path2_l2_history(client, args.code, market, hist)

    print(f"\n{'='*64}")
    print("结论看路径3(MAIN 历史)耗时 —— 若 <3000ms 则修复方案可行")
    print(f"{'='*64}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
