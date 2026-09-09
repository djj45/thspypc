#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""94板块页面板块日K活网探针（tests/_*.py 约定：不入库）。

验证 BoardService.board_kline（period=16384 → 0x42 日K 表）。
按 AGENTS.md 规则：单进程复用 get_client()，不重复登录。
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from thspypc.testing import get_client


def main() -> None:
    client = get_client()
    print(f"connected={client.is_connected}")
    for code in ("881101", "885927"):
        bars = client.board_kline(code, count=320, fuquan="Q")
        print(f"{code}: {len(bars)} bars")
        if bars:
            first, last = bars[0], bars[-1]
            print(
                f"  first {first['time']} o={first.get('open')} "
                f"c={first.get('close')} v={first.get('volume')}"
            )
            print(
                f"  last  {last['time']} o={last.get('open')} "
                f"c={last.get('close')} v={last.get('volume')}"
            )
    # 顺带核对板块分时（前端 (1,2) 用）
    tl = client.board_timeline("881101")
    print(f"timeline 881101: {len(tl)} pts, first keys={sorted(tl[0].keys())[:8] if tl else None}")


if __name__ == "__main__":
    main()
