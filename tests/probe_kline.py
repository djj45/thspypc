#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
thspypc K线/分时主动探测（复用 8901 长连接，复刻 hexin 单连接连发模式）。

用 ``THSClient.kline()`` 在同一条连接上连发多周期 K线，验证连接复用 +
响应解码。抓包确认 hexin 不轮换 IP，靠长连接复用连发所有请求。

用法::

    py tests/probe_kline.py                              # 默认 000089 日/周/月/5分K
    py tests/probe_kline.py --code 000089                # 同上
    py tests/probe_kline.py --code 600000 --periods day month
    py tests/probe_kline.py --code 000089 --timeline     # 分时（当日逐点）

前置条件：.env 的 THS_USERNAME/THS_PASSWORD；同花顺客户端须先退出
（同账号不能两个客户端同时在线）。
"""
from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from thspypc import THSClient
from thspypc.protocol import (
    build_timeline_query, parse_kline_hd3_response, read_frame,
)

ALL_PERIODS = ["day", "week", "month", "5min"]


def load_dotenv():
    env_path = os.path.join(os.path.dirname(__file__), "..", ".env")
    if not os.path.exists(env_path):
        return
    for line in open(env_path, encoding="utf-8"):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            if k.strip() and k.strip() not in os.environ:
                os.environ[k.strip()] = v.strip().strip('"').strip("'").strip(" ")


def _financial_ok(o, h, l, c):
    if not (0 < o < 10000 and 0 < h < 10000 and 0 < l < 10000 and 0 < c < 10000):
        return False
    eps = 0.001
    return h >= o - eps and h >= l - eps and h >= c - eps and l <= c + eps


def show_kline(code: str, period: str, recs: list[dict]) -> None:
    has_ohlc = recs and all(k in recs[0] for k in ("open", "high", "low", "close"))
    if has_ohlc:
        ok = sum(1 for r in recs if _financial_ok(r["open"], r["high"], r["low"], r["close"]))
        print(f"  {period:6s}: {len(recs)} 根，金融约束 {ok}/{len(recs)} "
              f"({100*ok/len(recs):.0f}%)")
    else:
        print(f"  {period:6s}: {len(recs)} 根（非 OHLC，逐点现价模式）")
    for r in recs[:2]:
        t = r.get("time")
        ts = t.strftime("%Y-%m-%d %H:%M") if t else f"bar#{r.get('bar_index')}"
        if has_ohlc:
            print(f"          {ts} O={r['open']:.2f} H={r['high']:.2f} "
                  f"L={r['low']:.2f} C={r['close']:.2f}")
        else:
            print(f"          {ts} dt10={r.get('dt10', '?')} vol={r.get('volume', r.get('dt49', '?'))}")
    if recs:
        r = recs[-1]
        t = r.get("time")
        ts = t.strftime("%Y-%m-%d %H:%M") if t else f"bar#{r.get('bar_index')}"
        print(f"    末根 {ts} C={r.get('close', r.get('dt10', '?'))}")


def show_timeline(code: str, recs: list[dict]) -> None:
    print(f"  分时: {len(recs)} 个点")
    for r in recs[:3]:
        t = r.get("time")
        ts = t.strftime("%H:%M:%S") if t else "?"
        print(f"    {ts} dt10(现价)={r.get('dt10', '?')} dt6(昨收)={r.get('dt6', '?')} "
              f"dt13(量)={r.get('dt13', '?')}")
    if recs:
        r = recs[-1]
        t = r.get("time")
        ts = t.strftime("%H:%M:%S") if t else "?"
        print(f"    末点 {ts} dt10={r.get('dt10', '?')}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--code", default="000089")
    ap.add_argument("--periods", nargs="*", default=ALL_PERIODS,
                    help=f"K线周期（默认全部 {ALL_PERIODS}）")
    ap.add_argument("--count", type=int, default=335)
    ap.add_argument("--timeline", action="store_true", help="额外测分时（当日逐点）")
    args = ap.parse_args()

    load_dotenv()
    username = os.environ.get("THS_USERNAME", "").strip()
    password = os.environ.get("THS_PASSWORD", "").strip()
    imei = os.environ.get("THS_IMEI", "").strip() or None
    if not username or not password:
        print("✗ 缺少 THS_USERNAME/THS_PASSWORD（写在 .env 或环境变量）")
        return 1

    client = THSClient(username, password, imei)
    print(f"K线探测 {args.code}（连接复用，同花顺客户端须已退出）\n")

    # K线：在同一条连接上连发多周期（kline() 自动首次 connect + 复用）
    print("=== K线 ===")
    for period in args.periods:
        try:
            recs = client.kline(args.code, period=period, count=args.count)
            show_kline(args.code, period, recs)
        except Exception as e:
            print(f"  {period:6s}: FAIL {type(e).__name__}: {e}")

    # 分时（可选）
    if args.timeline:
        print("\n=== 分时（当日逐点）===")
        try:
            recs = query_timeline(client, args.code)
            show_timeline(args.code, recs)
        except Exception as e:
            print(f"  分时: FAIL {type(e).__name__}: {e}")

    return 0


def query_timeline(client: THSClient, code: str, retries: int = 3) -> list[dict]:
    """发分时请求并解析（复用 client 连接 + 自动重试，逻辑同 kline()）。"""
    market = 17 if code.startswith("6") else 33
    last_err = ""
    for attempt in range(retries + 1):
        if not client.is_connected:
            lr = client.connect()
            if not lr.success:
                last_err = f"connect 失败: {lr.error}"
                continue
        try:
            sock = client._sock
            assert sock is not None
            frame = build_timeline_query(code, market=market)
            sock.settimeout(12.0)
            with client._sock_lock:
                if client._sock:
                    client._sock.sendall(frame + b"\n")
            for _ in range(8):
                resp = read_frame(sock)
                if b"hd3.1\x00" in resp:
                    recs = parse_kline_hd3_response(resp)
                    if recs:
                        return recs
            return []
        except (ConnectionError, OSError, TimeoutError) as e:
            last_err = str(e)
            client._drop_connection()
    raise RuntimeError(f"分时 {code} 重试 {retries} 次仍失败: {last_err}")


if __name__ == "__main__":
    sys.exit(main())
