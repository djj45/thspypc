#!/usr/bin/env python
"""双账号活网验证：历史分时 241 点 + 早盘/尾盘集合竞价。

分别用 Level2 账号（``.env``）和普通账号（``.env.normal``）登录同花顺，
对 2026-06-30 / 2026-07-23 查：

    - ``history_timeline``：期望 241 点（L2 走 4417、普通走 9355）
    - ``auction``：早盘集合竞价（9:15-9:25 逐 tick）
    - ``closing_auction``：尾盘集合竞价（14:57-15:00 逐 tick）

用法：
    py tests/verify_accounts_241_auction.py                # 两个账号都跑
    py tests/verify_accounts_241_auction.py --env .env     # 只跑 L2
    py tests/verify_accounts_241_auction.py --env .env.normal
    py tests/verify_accounts_241_auction.py --code 600519 --market 17
"""
from __future__ import annotations

import argparse
import os
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, ValueError):
    pass

from thspypc.client import THSClient  # noqa: E402

DATES = (date(2026, 7, 23), date(2026, 6, 30))


def load_env(path: Path) -> dict[str, str]:
    env: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        env[key.strip()] = value.strip().strip("\"'")
    return env


def _summarize(tag: str, records: list[dict], expect: int | None = None) -> bool:
    if not records:
        print(f"  [{tag}] 空")
        return expect is None
    first = records[0]
    last = records[-1]
    detail = ""
    if "dt10" in first:
        detail = f" dt10[{first.get('dt10')}→{last.get('dt10')}]"
    if "time" in first:
        detail += f" time[{first.get('time')}→{last.get('time')}]"
    ok = expect is None or len(records) == expect
    mark = "✓" if ok else "✗"
    print(f"  [{mark} {tag}] n={len(records)}{detail}")
    return ok


def run_account(env_path: Path, code: str, market: int) -> bool:
    env = load_env(env_path)
    user = env.get("THS_USERNAME", "")
    pwd = env.get("THS_PASSWORD", "")
    if not user or not pwd:
        print(f"✗ {env_path.name}: 缺少 THS_USERNAME/THS_PASSWORD")
        return False
    print(f"\n{'='*64}\n账号: {env_path.name} ({user[:6]}...)\n{'='*64}")
    client = THSClient(username=user, password=pwd, imei=env.get("THS_IMEI") or None)
    lr = client.connect()
    if not lr.success:
        print(f"✗ 登录失败: {lr.error or lr.detail}")
        return False
    profile = client.observed_account_profile
    print(f"登录成功 profile.kind={profile.kind}")

    all_ok = True
    for d in DATES:
        print(f"\n-- {code} @ {d} (market={market}) --")
        try:
            tl = client.history_timeline(code, d, market=market, timeout=20)
        except Exception as exc:
            print(f"  ✗ history_timeline 异常: {type(exc).__name__}: {exc}")
            tl = []
        all_ok &= _summarize("历史分时", tl, expect=241)
        if tl:
            b0, b1 = tl[0]["bar_index"], tl[-1]["bar_index"]
            print(f"     bar {b0}..{b1}")

        try:
            op = client.auction(code, market=market, trade_date=d, timeout=20)
        except Exception as exc:
            print(f"  ✗ auction 异常: {type(exc).__name__}: {exc}")
            op = []
        all_ok &= _summarize("早盘竞价", op)

        try:
            cl = client.closing_auction(code, market=market, trade_date=d, timeout=20)
        except Exception as exc:
            print(f"  ✗ closing_auction 异常: {type(exc).__name__}: {exc}")
            cl = []
        all_ok &= _summarize("尾盘竞价", cl)

    print(f"\n{env_path.name} 结果: {'全部通过' if all_ok else '有失败'}")
    return all_ok


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--env", choices=(".env", ".env.normal"), default=None)
    ap.add_argument("--code", default="000938")
    ap.add_argument("--market", type=int, default=33)
    args = ap.parse_args()

    envs = [Path(args.env)] if args.env else [Path(".env"), Path(".env.normal")]
    results = []
    for env_path in envs:
        if not env_path.exists():
            print(f"✗ {env_path} 不存在，跳过")
            continue
        results.append(run_account(env_path, args.code, args.market))
    return 0 if all(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
