#!/usr/bin/env python
"""在线验证板块专用通道：全量行情（527527）+ 四接口（行情 / 分时 / 竞价 / 成分股）。

板块查询走 fu4.123ths.com 独立 8901 连接（专用板块通道），首次调用自动完成
login + subreal 注册 + MarketCode 初始化 + 分类表 + StockNameVer 引导。

用法:
    py tests/verify_board_online.py                  # .env（L2 账号）
    py tests/verify_board_online.py --env normal     # .env.normal（普通账号）

退出码：0=四接口全部拿到预期数据；1=任一接口失败。
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from thspypc.client import THSClient  # noqa: E402


def load_env(path: Path) -> dict:
    result = {}
    if not path.exists():
        return result
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        result[k.strip()] = v.strip().strip('"').strip("'")
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--env", choices=("l2", "normal"), default="l2")
    parser.add_argument(
        "--dump-dir",
        default=os.environ.get("THS_FRAME_DUMP_DIR", ""),
        help="逐帧收发转储目录（设置后自动 export THS_FRAME_DUMP_DIR）",
    )
    args = parser.parse_args()
    if args.dump_dir:
        os.environ["THS_FRAME_DUMP_DIR"] = args.dump_dir
        os.makedirs(args.dump_dir, exist_ok=True)
        print(f"鉁?逐帧收发转储已开启：{args.dump_dir}")

    env = load_env(ROOT / (".env" if args.env == "l2" else ".env.normal"))
    user, pwd = env.get("THS_USERNAME", ""), env.get("THS_PASSWORD", "")
    imei = env.get("THS_IMEI") or None
    if not user or not pwd:
        print("缺少账号凭据（.env / .env.normal）")
        return 1

    print(f"== 板块通道在线验证：{user}（{args.env}）==")
    client = THSClient(username=user, password=pwd, imei=imei)
    lr = client.connect()
    if not lr.success:
        print(f"✗ MAIN 登录失败: {lr.error} {lr.detail[:120]}")
        return 1
    print(f"✓ MAIN 登录 {lr.server}")

    failures = 0

    # 0. 板块指数全量行情（DataType=527527：0x20/0x1c/0x22 三表合并，513 条）
    t0 = time.monotonic()
    try:
        full = client.board_quotes(None, timeout=40.0)
        dt = (time.monotonic() - t0) * 1000
        by_code = {q.get("code"): q for q in full}
        if len(by_code) != 513:
            print(f"✗ 全量行情 {dt:.0f}ms: {len(by_code)} 条（期望 513）")
            failures += 1
        else:
            sample = by_code.get("885998", {})
            new = by_code.get("886112", {})

            def _fmt(value: float | None) -> str:
                return "-" if value is None else f"{value:.2f}"

            print(f"✓ 全量行情 {dt:.0f}ms: {len(by_code)} 条")
            print(
                f"    885998: 涨幅={_fmt(sample.get('chg_pct'))}% "
                f"1分={sample.get('speed_1m')} "
                f"4分={sample.get('speed_4m')} "
                f"主力={sample.get('main_inflow')}"
            )
            print(
                f"    886112(新): 涨幅={_fmt(new.get('chg_pct'))}% "
                f"1分={new.get('speed_1m')} "
                f"4分={new.get('speed_4m')} "
                f"主力={new.get('main_inflow')}"
            )
            if any(
                sample.get(key) is None
                for key in ("chg_pct", "speed_1m", "speed_4m", "main_inflow")
            ):
                print("  ✗ 885998 字段缺失（正常板块应有完整四列）")
                failures += 1
    except Exception as exc:
        print(f"✗ 全量行情异常: {type(exc).__name__}: {exc}")
        failures += 1

    # 1. 板块行情列表（08-02 起服务端对该请求回 0x20/0x1c/0x22 紧凑表，
    #    无名称列；旧 0x130 名称表与旧路由 0x0039/0x0139 已不再回复）
    t0 = time.monotonic()
    try:
        quotes = client.board_quotes(["881101", "881121", "885480"], timeout=20.0)
        dt = (time.monotonic() - t0) * 1000
        names = {q.get("code"): q.get("name") for q in quotes}
        if not quotes:
            print(f"✗ 板块行情 {dt:.0f}ms: 空列表")
            failures += 1
        elif quotes[0].get("dt10") is None:
            print(f"✗ 板块行情 {dt:.0f}ms: 缺少 dt10（最新价）")
            failures += 1
        else:
            print(f"✓ 板块行情 {dt:.0f}ms: {len(quotes)} 条 "
                  f"{ {k: names.get(k) for k in ('881101', '881121', '885480')} }")
    except Exception as exc:
        print(f"✗ 板块行情异常: {type(exc).__name__}: {exc}")
        failures += 1

    # 2. 板块指数历史分时（0x42：242 点/日）
    t0 = time.monotonic()
    try:
        tl = client.board_timeline("881121", date="2026-07-23", timeout=15.0)
        dt = (time.monotonic() - t0) * 1000
        print(f"✓ 板块分时 2026-07-23 {dt:.0f}ms: {len(tl)} 点 "
              f"(期望 242；首 {tl[0].get('dt10') if tl else '-'} → "
              f"末 {tl[-1].get('dt10') if tl else '-'})")
        if len(tl) < 200:
            print(f"  ✗ 点数不足（{len(tl)} < 200）")
            failures += 1
    except Exception as exc:
        print(f"✗ 板块分时异常: {type(exc).__name__}: {exc}")
        failures += 1

    # 3. 板块集合竞价（0x32：unix 秒 + 撮合价 + 累计量）
    t0 = time.monotonic()
    try:
        auction = client.board_auction("881121", date="2026-07-23", timeout=15.0)
        dt = (time.monotonic() - t0) * 1000
        first = auction[0] if auction else {}
        valid_date = (
            first.get("time") is not None
            and first["time"].date().isoformat() == "2026-07-23"
        )
        if len(auction) < 5 or not valid_date:
            print(f"✗ 板块竞价 2026-07-23 {dt:.0f}ms: {len(auction)} tick "
                  f"(首 {first.get('time')})")
            failures += 1
        else:
            print(f"✓ 板块竞价 2026-07-23 {dt:.0f}ms: {len(auction)} tick "
                  f"(首 {first.get('time')} dt10={first.get('dt10')} "
                  f"dt49={first.get('dt49')})")
    except Exception as exc:
        print(f"✗ 板块竞价异常: {type(exc).__name__}: {exc}")
        failures += 1

    # 4. 板块成分股行情（0x64：6 位股票代码 + 行情字段）
    t0 = time.monotonic()
    try:
        members = client.board_constituents(["881121"], timeout=45.0)
        dt = (time.monotonic() - t0) * 1000
        codes = [m.get("code", "") for m in members][:6]
        if not members:
            print(f"✗ 板块成分股 881121 {dt:.0f}ms: 空列表")
            failures += 1
        elif any(len(str(c)) != 6 for c in codes):
            print(f"✗ 板块成分股 881121 {dt:.0f}ms: 存在非 6 位股票代码")
            failures += 1
        else:
            print(f"✓ 板块成分股 881121 {dt:.0f}ms: {len(members)} 条 "
                  f"(前 6: {codes})")
    except Exception as exc:
        print(f"✗ 板块成分股异常: {type(exc).__name__}: {exc}")
        failures += 1

    client.disconnect()
    if args.dump_dir:
        print(
            "鉁?成分股连接逐帧转储目录："
            f"{Path(args.dump_dir).resolve()}/board_constituent_*"
        )
    if failures:
        print(f"\n✗ {failures} 个接口失败")
        return 1
    print("\n✓✓ 板块通道全量行情 + 四接口全部通过")
    return 0


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    raise SystemExit(main())
