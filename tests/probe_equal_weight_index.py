#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""等权平均指数验证探针（盘中用）。

用全市场个股实时行情计算"平均"点位，对比同花顺指数分时页黄线：
    平均点位 = 指数昨收 × (1 + 全部成分股涨幅的算术平均)

用法：
    uv run python tests/probe_equal_weight_index.py [--batch 150]
"""
from __future__ import annotations

import datetime
import os
import pathlib
import re
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


def pct(v) -> float | None:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def infer_market(code: str) -> int | None:
    if code.startswith(("600", "601", "603", "605", "688", "689")):
        return 17
    if code.startswith(("000", "001", "002", "003", "300", "301")):
        return 33
    if code.startswith(("4", "8", "92")):
        return 151
    return None


def load_codes_from_stockname() -> dict[int, list[str]]:
    """从本地同花顺 stockname 文件构建 A 股代码表。"""
    stockname_dir = pathlib.Path(r"D:\同花顺软件\同花顺\stockname")
    codes: dict[int, set[str]] = {17: set(), 33: set(), 151: set()}
    pat = re.compile(r"(\d{6})=")
    for f in stockname_dir.glob("stockname_*.txt"):
        try:
            text = f.read_text(encoding="gbk", errors="replace")
        except OSError:
            continue
        for m in pat.finditer(text):
            code = m.group(1)
            mkt = infer_market(code)
            if mkt is not None:
                codes[mkt].add(code)
    return {k: sorted(v) for k, v in codes.items()}


def main() -> int:
    load_dotenv()
    batch = 150
    if "--batch" in sys.argv:
        i = sys.argv.index("--batch")
        if i + 1 < len(sys.argv):
            batch = int(sys.argv[i + 1])

    username = os.environ.get("THS_USERNAME", "").strip()
    password = os.environ.get("THS_PASSWORD", "").strip()
    imei = os.environ.get("THS_IMEI", "").strip() or None

    print("登录 ...", flush=True)
    client = THSClient(username, password, imei)
    result = client.connect()
    if not result.success:
        print(f"!! 登录失败: {result.error} {result.detail}")
        return 1
    print(f"  登录成功 {result.server}")

    print("从本地 stockname 构建 A 股代码表 ...", flush=True)
    by_market = load_codes_from_stockname()
    sh_codes = by_market[17]
    print(f"  沪A(mkt=17): {len(sh_codes)} | 深A(mkt=33): {len(by_market[33])} "
          f"| 北交所(mkt=151): {len(by_market[151])}")

    def fetch_quotes(codes: list[str], market: int) -> list[dict]:
        out: list[dict] = []
        for i in range(0, len(codes), batch):
            chunk = codes[i:i + batch]
            for attempt in range(3):
                try:
                    out.extend(client.list_quotes(chunk, market=market, timeout=20.0))
                    break
                except Exception as exc:  # noqa: BLE001
                    if attempt == 2:
                        print(f"  !! batch {i} 失败: {exc}")
        return out

    print("拉沪A行情 ...", flush=True)
    t0 = time.time()
    sh_quotes = fetch_quotes(sh_codes, 17)
    print(f"  拿到 {len(sh_quotes)} 条, {time.time()-t0:.1f}s")

    changes: list[float] = []
    for q in sh_quotes:
        px = pct(q.get("dt10"))
        pre = pct(q.get("dt6"))
        if px and pre and pre > 0:
            changes.append(px / pre - 1)
    mean_sh = sum(changes) / len(changes) if changes else 0.0
    print(f"  有效涨幅 {len(changes)} 条, 平均涨幅 {mean_sh*100:+.3f}%")

    # 上证指数昨收（2026-08-03 收盘，来自快照帧）
    sh_pre_close = 3809.66
    avg_point = sh_pre_close * (1 + mean_sh)
    print(f"\n上证等权平均点位 = {sh_pre_close} × (1+{mean_sh*100:.3f}%) "
          f"= {avg_point:.2f}")

    # 全A对照
    print("拉深A行情 ...", flush=True)
    t0 = time.time()
    sz_quotes = fetch_quotes(by_market[33], 33)
    print(f"  拿到 {len(sz_quotes)} 条, {time.time()-t0:.1f}s")
    all_quotes = list(sh_quotes) + list(sz_quotes)
    changes_all = []
    for q in all_quotes:
        px = pct(q.get("dt10"))
        pre = pct(q.get("dt6"))
        if px and pre and pre > 0:
            changes_all.append(px / pre - 1)
    if changes_all:
        mean_all = sum(changes_all) / len(changes_all)
        print(f"  全A {len(changes_all)} 条, 平均涨幅 {mean_all*100:+.3f}%")
        print(f"  全A等权(按上证昨收映射) = "
              f"{sh_pre_close * (1 + mean_all):.2f}")

    now = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"\n计算时刻: {now}（请与同花顺黄线数值对照）")
    client.disconnect()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
