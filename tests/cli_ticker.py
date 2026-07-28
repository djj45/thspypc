#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
命令行实时行情看板（同花顺风格，终端刷新）。

用法：
    uv run python tests/cli_ticker.py
    uv run python tests/cli_ticker.py --codes 600000,000001,600519
"""
import argparse
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from thspypc.client import THSClient

# 默认自选股
DEFAULT_CODES = {
    17: ["600000", "601398", "601288", "601939", "600519", "600036",
         "601318", "600276", "601012", "600900"],
    33: ["000001", "000002", "000333", "000651", "002594", "300750",
         "000858", "002475", "300059", "000725"],
}

# ANSI 颜色（同花顺风格：涨红跌绿）
RED = "\033[31m"
GREEN = "\033[32m"
GRAY = "\033[90m"
BOLD = "\033[1m"
RESET = "\033[0m"


def color_chg(val):
    """涨红跌绿。"""
    if val is None:
        return GRAY
    return RED if val > 0 else (GREEN if val < 0 else GRAY)


def fmt_pct(val):
    if val is None:
        return f"{GRAY}      --{RESET}"
    sign = "+" if val >= 0 else ""
    return f"{color_chg(val)}{sign}{val:>6.2f}%{RESET}"


def fmt_price(val):
    if val is None:
        return f"{GRAY}------{RESET}"
    return f"{color_chg(val)}{val:>8.2f}{RESET}"


def fmt_amt(v):
    if v is None or v == 0:
        return "--"
    a = abs(v)
    if a >= 1e8:
        return f"{v/1e8:.2f}亿"
    if a >= 1e4:
        return f"{v/1e4:.0f}万"
    return str(round(v))


def load_env():
    env_path = os.path.join(os.path.dirname(__file__), "..", ".env")
    if not os.path.exists(env_path):
        return
    for line in open(env_path, encoding="utf-8"):
        line = line.strip()
        if "=" in line and not line.startswith("#"):
            k, _, v = line.partition("=")
            k = k.strip()
            if k and k not in os.environ:
                os.environ[k] = v.strip().strip('"').strip("'")


def render_quotes(client, codes_by_market):
    """渲染自选行情表。"""
    rows = []
    for market, codes in codes_by_market.items():
        try:
            recs = client.list_quotes(codes, market=market)
        except Exception:
            recs = []
        for r in recs:
            price = r.get("dt10")
            prev = r.get("dt6")
            open_p = r.get("dt7")
            chg = (price - prev) / prev * 100 if price and prev else None
            rows.append((r.get("code", ""), price, prev, open_p, chg))

    # 表头
    print(f"{GRAY}{'代码':<8} {'现价':>10} {'涨跌幅':>10} {'昨收':>8} {'开盘':>8}{RESET}")
    print(f"{GRAY}{'─'*48}{RESET}")
    for code, price, prev, open_p, chg in rows:
        print(f"{BOLD}{code:<8}{RESET} {fmt_price(price)} {fmt_pct(chg)} "
              f"{GRAY}{prev:>8.2f}{RESET} {GRAY}{open_p:>8.2f}{RESET}" if prev and open_p
              else f"{BOLD}{code:<8}{RESET} {fmt_price(price)} {fmt_pct(chg)} "
              f"{GRAY}      --{RESET} {GRAY}      --{RESET}")
    return len(rows)


def render_dxjl(client):
    """渲染短线精灵。"""
    try:
        recs = client.dxjl_latest()
    except Exception:
        recs = []
    if not recs:
        print(f"\n{GRAY}⚡ 短线精灵：暂无异动{RESET}")
        return
    print(f"\n{BOLD}⚡ 短线精灵异动{RESET}（最新 {len(recs)} 条）")
    print(f"{GRAY}{'时间':<10} {'代码':<8} {'异动类型':<12} {'金额':>8} {'涨幅':>8}{RESET}")
    print(f"{GRAY}{'─'*52}{RESET}")
    for r in recs[:15]:
        t = time.strftime("%H:%M:%S", time.localtime(r["时间"] / 1_000_000))
        code = r["代码"]
        atype = r["异动类型"]
        amt = r.get("金额", 0)
        chg = r.get("涨跌幅")
        c = color_chg(chg)
        print(f"{GRAY}{t:<10}{RESET} {BOLD}{code:<8}{RESET} "
              f"{atype:<12} {fmt_amt(amt):>8} {c}{chg:>+7.2f}%{RESET}" if chg
              else f"{GRAY}{t:<10}{RESET} {BOLD}{code:<8}{RESET} "
              f"{atype:<12} {fmt_amt(amt):>8}")


def main():
    load_env()
    ap = argparse.ArgumentParser(description="命令行实时行情看板")
    ap.add_argument("--codes", default=None, help="自选股（逗号分隔）")
    ap.add_argument("--interval", type=float, default=5.0, help="刷新间隔（秒）")
    ap.add_argument("--no-dxjl", action="store_true", help="不显示短线精灵")
    args = ap.parse_args()

    if args.codes:
        sh = [c.strip() for c in args.codes.split(",") if c.strip().startswith("6")]
        sz = [c.strip() for c in args.codes.split(",") if c.strip().startswith(("0", "3"))]
        codes_by_market = {17: sh, 33: sz}
    else:
        codes_by_market = DEFAULT_CODES

    username = os.environ.get("THS_USERNAME", "")
    password = os.environ.get("THS_PASSWORD", "")
    if not username or not password:
        print("✗ 缺账号/密码，请在 .env 配 THS_USERNAME/THS_PASSWORD")
        sys.exit(1)

    print("登录中...", flush=True)
    client = THSClient(username, password)
    result = client.connect()
    if not result.success:
        print(f"✗ 登录失败: {result.error}")
        sys.exit(1)
    print(f"✓ {result.server}  (Ctrl+C 退出)\n", flush=True)
    # MAIN 普通登录不发送 L2 init，VerifyCode=0 后可直接查询。

    try:
        while True:
            # 清屏 + 渲染
            print("\033[2J\033[H", end="")  # ANSI 清屏
            print(f"{BOLD}📊 实时行情{RESET} {GRAY}{time.strftime('%Y-%m-%d %H:%M:%S')} "
                  f"{result.server}{RESET}\n")
            n = render_quotes(client, codes_by_market)
            if not args.no_dxjl:
                render_dxjl(client)
            print(f"\n{GRAY}下次刷新 {args.interval}s 后...{RESET}", flush=True)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print(f"\n{GRAY}退出{RESET}")
        client.disconnect()


if __name__ == "__main__":
    main()
