#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""主动探测个股 K 线「快路径」(DataType=272,229,271,228 + period=0x2000)。

背景
----
抓包 frame 88 子帧[3] 确认同花顺切股票时,K 线请求是::

    CodeList=17(600025,);
    DataType=272,229,271,228,13,227,19,40,226,54,39,...
    DateTime=8192(0-0)     ← 8192=0x2000,period 编码在 DateTime 里
    pageid=1334

thspypc 当前用 ``period=0x4000``(KLINE_PERIOD_DAY)+ ``DataType=7,8,9,11,13,19``,
~2000ms。本脚本用 monkeypatch 改这两个常量,通过 client.kline() 测试不同组合,
定位 2s 慢的根源。

用法:
    uv run python tests/probe_kline_datatype.py
    uv run python tests/probe_kline_datatype.py --code 600025
"""
from __future__ import annotations

import argparse
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from thspypc.testing import get_client  # noqa: E402
import thspypc.features.kline_protocol as kp  # noqa: E402

HEXIN_KLINE_DATATYPE = [272, 229, 271, 228, 13, 227, 19, 40, 226, 54, 39,
                        225, 10, 38, 224, 223, 230, 1110, 1111, 380]
OUR_KLINE_DATATYPE = [7, 8, 9, 11, 13, 19]
_ORIG_DATATYPE = kp.KLINE_DATATYPE


def probe(client, label: str, datatype: list[int], period_name: str,
          period_code: int, code: str, count: int = 100) -> None:
    """monkeypatch 常量后调 client.kline,计时。"""
    print(f"\n{'='*64}")
    print(f"【{label}】")
    print(f"  DataType={datatype[:6]}{'...' if len(datatype)>6 else ''}  "
          f"period={period_name}=0x{period_code:x}")
    print(f"{'='*64}")
    kp.KLINE_DATATYPE = datatype
    # 改 facade 的 period 映射
    client._KLINE_PERIOD_CODES = dict(client._KLINE_PERIOD_CODES)
    client._KLINE_PERIOD_CODES[period_name] = period_code
    t0 = time.time()
    try:
        recs = client.kline(code, period=period_name, count=count, timeout=15.0)
        elapsed = time.time() - t0
        print(f"  耗时: {elapsed*1000:.0f}ms  返回 {len(recs)} 根 K 线")
        if recs:
            print(f"  字段: {sorted(recs[0].keys())[:10]}")
            # 前 2 根
            for r in recs[:2]:
                sample = {k: v for k, v in list(r.items())[:6]}
                print(f"    {sample}")
    except Exception as e:
        elapsed = time.time() - t0
        print(f"  ✗ 失败 ({elapsed*1000:.0f}ms): {type(e).__name__}: {e}")
    finally:
        kp.KLINE_DATATYPE = _ORIG_DATATYPE


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--code", default="600025")
    ap.add_argument("--env", default=".env")
    args = ap.parse_args()

    print("="*64)
    print(f"K 线快路径探测 @ {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"code={args.code}")
    print("="*64)

    client = get_client(args.env)
    print(f"已登录: {client.is_connected}\n")

    # 先用默认参数跑一次(baseline,确认连接 + 当前耗时)
    probe(client, "baseline: 我们当前实现",
          OUR_KLINE_DATATYPE, "day", 0x4000, args.code)

    # 同花顺路径:DataType=272,229,271,228 + period=0x2000
    probe(client, "同花顺路径: DataType=272,229 + period=0x2000",
          HEXIN_KLINE_DATATYPE, "day", 0x2000, args.code)

    # 拆分变量 A:只改 period
    probe(client, "只改 period=0x2000(DataType 不变)",
          OUR_KLINE_DATATYPE, "day", 0x2000, args.code)

    # 拆分变量 B:只改 DataType
    probe(client, "只改 DataType=272,229(period 0x4000 不变)",
          HEXIN_KLINE_DATATYPE, "day", 0x4000, args.code)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
