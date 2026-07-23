#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
thspypc K线响应解码测试。

离线回归（无需账号/网络）—— 用抓包的 K线响应验证解码链::

    uv run python tests/test_kline.py
    uv run python tests/test_kline.py --pcap <其他kline pcap对应的stream bin>

验证 ``parse_kline_hd3_response`` 把 hd3.1 变体（flag=0x0042/0x0046）的 BitRLE
位平面流解成 OHLCV K线。默认数据是 2026-07-23 抓包（000089 月K 336 根 +
000069 日K 2147 根等多只票）。

输出：每个 OHLC 帧的根数 / 代码 / 首末时间 / 金融约束通过率，以及样本 OHLC。
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from thspypc import parse_kline_hd3_response

# 抓包产物：用户在 hexin 切换 5分K/日K/周K/月K 时抓取的 8901 响应（stream1 是
# 服务器下行的 K线数据流，含多只票多周期的 hd3.1 变体帧）
DEFAULT_STREAM = os.path.join(
    os.path.dirname(__file__), "..", "captures_live",
    "kline_20260724_000441_resp_stream1.bin")


def _find_all(haystack: bytes, needle: bytes) -> list[int]:
    out, i = [], 0
    while True:
        i = haystack.find(needle, i)
        if i < 0:
            break
        out.append(i)
        i += 1
    return out


def _financial_ok(o: float, h: float, l: float, c: float) -> bool:
    """K线金融约束：价格在合理区间且 high>=open/low/close, low<=open/close。"""
    if not (0 < o < 10000 and 0 < h < 10000 and 0 < l < 10000 and 0 < c < 10000):
        return False
    eps = 0.001
    return (h >= o - eps and h >= l - eps and h >= c - eps
            and l <= o + eps and l <= c + eps)


def main(stream_path: str = DEFAULT_STREAM) -> int:
    if not os.path.exists(stream_path):
        print(f"✗ 响应流文件不存在: {stream_path}")
        print("  先跑 tests/capture_kline.py 抓包生成 captures_live/kline_*.bin")
        return 1
    raw = open(stream_path, "rb").read()
    print(f"响应流: {stream_path} ({len(raw)} bytes)\n")

    ohlc_frames = 0
    total_ok = total = 0
    for pos in _find_all(raw, b"hd3.1\x00"):
        recs = parse_kline_hd3_response(raw[pos:])
        if not recs:
            continue
        r0 = recs[0]
        if not all(k in r0 for k in ("open", "high", "low", "close")):
            continue  # 非 OHLC K线（如分笔/tick 帧），跳过
        ohlc_frames += 1
        fok = fbad = 0
        for r in recs:
            if _financial_ok(r["open"], r["high"], r["low"], r["close"]):
                fok += 1
            else:
                fbad += 1
        total_ok += fok
        total += fok + fbad
        print(f"@0x{pos:x}  code={r0.get('code')}  bars={len(recs)}  "
              f"约束通过 {fok}/{fok+fbad}")
        t0 = recs[0].get('time')
        tL = recs[-1].get('time')
        t0s = t0.date() if t0 else f"bar#{recs[0].get('bar_index')}"
        tLs = tL.date() if tL else f"bar#{recs[-1].get('bar_index')}"
        print(f"    首根 {t0s}  "
              f"O={recs[0]['open']:.2f} H={recs[0]['high']:.2f} "
              f"L={recs[0]['low']:.2f} C={recs[0]['close']:.2f}")
        print(f"    末根 {tLs}  "
              f"O={recs[-1]['open']:.2f} H={recs[-1]['high']:.2f} "
              f"L={recs[-1]['low']:.2f} C={recs[-1]['close']:.2f} "
              f"V={recs[-1].get('volume', 0):.0f}")

    print(f"\n共 {ohlc_frames} 个 OHLC K线帧，{total_ok}/{total} 根通过金融约束"
          f"（{100*total_ok/total:.1f}%）" if total else "\n✗ 未找到 OHLC K线帧")
    return 0 if total_ok == total and total > 0 else 1


if __name__ == "__main__":
    path = sys.argv[sys.argv.index("--pcap") + 1] if "--pcap" in sys.argv else DEFAULT_STREAM
    sys.exit(main(path))
