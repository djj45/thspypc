#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
批量测试**多只沪市股票**的集合竞价，横向对比不同票的竞价特征。

沪市竞价响应由 shlv2 返回 ``cmd=0x0a`` 外层压缩，协议层会先正规化为定长
``hd1.0`` 表体。记录数和真实间隔会随样本变化。本脚本对每只票统计：

  - tick 总数 + 时间覆盖范围
  - 时间戳间隔分布
  - 撮合价曲线：首根/末根/最高/最低/振幅
  - 撮合价变化次数（含 b0 标记的 tick 数）+ 价格不动率（沿用前价的占比）
  - 收敛形态：9:15-9:20（自由撮合）vs 9:20-9:25（不可撤单）两段对比

用法：
    py tests/test_auction_sh_compare.py                          # 默认 6 只沪市票
    py tests/test_auction_sh_compare.py 603118,600519,601318     # 自定义
    py tests/test_auction_sh_compare.py --date 2026-07-24        # 指定交易日
    py tests/test_auction_sh_compare.py --all                    # 测试全部默认票

★ 盘后/周末都能跑（拿最近交易日数据）。
⚠ 需要 **level2 账号**（.env 里的 THS_USERNAME/THS_PASSWORD）。
⚠ 沪市 shlv2 IP 偶有超时，失败会标注并继续下一只。
"""
from __future__ import annotations

import datetime
import logging
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

logging.basicConfig(
    level=logging.INFO,
    format="  ·%(levelname)s %(name)s: %(message)s",
    stream=sys.stdout,
)

from thspypc import THSClient


# 默认测试的沪市票（覆盖不同价位/行业，全是 6 开头沪市 A 股）
DEFAULT_CODES = [
    "603118",  # 共进股份（低价股 ~15）
    "600519",  # 贵州茅台（高价股 ~1700）
    "601318",  # 中国平安（金融权重 ~50）
    "600036",  # 招商银行（银行 ~35）
    "601012",  # 隆基绿能（新能源 ~25）
    "600276",  # 恒瑞医药（医药 ~45）
]


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


def analyze_one(code: str, recs: list[dict]) -> dict:
    """统计分析单只票的竞价特征。"""
    if not recs:
        return {}

    times = [r["time"] for r in recs if r.get("time")]
    prices = [r.get("dt10") for r in recs]
    price_valid = [p for p in prices if isinstance(p, (int, float))]

    # 间隔分布
    gaps = {}
    for i in range(1, len(times)):
        g = int((times[i] - times[i - 1]).total_seconds())
        gaps[g] = gaps.get(g, 0) + 1

    # 撮合价变化次数：找含价格变化的 tick（与上一条不同）
    change_count = 0
    prev = None
    for p in prices:
        if isinstance(p, (int, float)):
            if prev is None or abs(p - prev) > 1e-9:
                change_count += 1
            prev = p
    # 不动率：价格沿用的 tick 占比
    hold_rate = (len(prices) - change_count) / len(prices) * 100 if prices else 0

    # 9:15-9:20 vs 9:20-9:25 分段
    def seg(start_min: int, end_min: int) -> tuple[int, float | None, float | None]:
        """返回 (条数, 首价, 末价)。"""
        seg_recs = [r for r in recs if r.get("time") and start_min <= r["time"].minute < end_min]
        seg_prices = [r["dt10"] for r in seg_recs if isinstance(r.get("dt10"), (int, float))]
        first = seg_prices[0] if seg_prices else None
        last = seg_prices[-1] if seg_prices else None
        return len(seg_recs), first, last

    seg1_cnt, seg1_first, seg1_last = seg(15, 20)   # 9:15-9:20 自由撮合
    seg2_cnt, seg2_first, seg2_last = seg(20, 25)   # 9:20-9:25 不可撤单

    # 振幅
    amp = (max(price_valid) - min(price_valid)) / min(price_valid) * 100 if price_valid and min(price_valid) else 0

    return {
        "count": len(recs),
        "time_first": times[0].strftime("%H:%M:%S") if times else "?",
        "time_last": times[-1].strftime("%H:%M:%S") if times else "?",
        "gaps": gaps,
        "price_first": price_valid[0] if price_valid else None,
        "price_last": price_valid[-1] if price_valid else None,
        "price_high": max(price_valid) if price_valid else None,
        "price_low": min(price_valid) if price_valid else None,
        "amplitude": amp,
        "change_count": change_count,
        "hold_rate": hold_rate,
        "seg1": (seg1_cnt, seg1_first, seg1_last),
        "seg2": (seg2_cnt, seg2_first, seg2_last),
    }


def fmt_pct(x: float | None) -> str:
    return f"{x:+.2f}%" if x is not None else "?"


def price_change_pct(first: float | None, last: float | None) -> float | None:
    if first is None or last is None or first == 0:
        return None
    return (last - first) / first * 100


def print_detail(code: str, recs: list[dict]) -> None:
    """打印单只票的详细曲线（采样）。"""
    if not recs:
        print(f"  （无数据）")
        return
    # 打印前 5 + 中间 + 后 5
    n = len(recs)
    show = list(range(min(5, n)))
    if n > 12:
        mid = n // 2
        show += [None] + list(range(mid - 1, mid + 2))
    if n > 8:
        show += [None] + list(range(max(5, n - 5), n))

    seen = set()
    for i in show:
        if i is None:
            print(f"    ...")
            continue
        if i in seen:
            continue
        seen.add(i)
        r = recs[i]
        t = r["time"].strftime("%H:%M:%S") if r.get("time") else "?"
        p = f"{r['dt10']:.2f}" if isinstance(r.get("dt10"), (int, float)) else "?"
        print(f"    [{i:>3}] {t}  价={p}")


def main() -> int:
    load_dotenv()
    username = os.environ.get("THS_USERNAME", "").strip()
    password = os.environ.get("THS_PASSWORD", "").strip()
    imei = os.environ.get("THS_IMEI", "").strip() or None
    if not username or not password:
        print("✗ 未设置 THS_USERNAME / THS_PASSWORD（.env 或环境变量）")
        return 1

    # 解析参数
    args = sys.argv[1:]
    trade_date = None
    if "--date" in args:
        i = args.index("--date")
        if i + 1 < len(args):
            try:
                trade_date = datetime.date.fromisoformat(args[i + 1])
                args = args[:i] + args[i + 2:]
            except ValueError:
                print(f"✗ 日期格式错误：{args[i + 1]}")
                return 1

    if args and not args[0].startswith("-"):
        codes = [c.strip() for c in args[0].split(",") if c.strip()]
    else:
        codes = DEFAULT_CODES

    # 校验全是沪市票
    bad = [c for c in codes if not c.startswith("6") or len(c) != 6]
    if bad:
        print(f"✗ 非沪市票（应以 6 开头）：{bad}")
        return 1

    now = datetime.datetime.now()
    print("=" * 78)
    print("沪市集合竞价批量对比  —  验证 shlv2 变长格式解析（3 秒/tick）")
    print("=" * 78)
    weekday = now.weekday()
    if weekday >= 5:
        print(f"⚠ 今天是周{weekday + 1}（非交易日），拿到的是最近交易日的竞价数据。")
    elif now.hour < 9 or now.hour >= 15:
        print(f"⚠ 当前 {now.strftime('%H:%M')} 非盘中，拿到的是已收盘竞价数据。")
    date_desc = trade_date.isoformat() if trade_date else "最近交易日"
    print(f"日期: {date_desc}")
    print(f"沪市票: {codes}")
    print(f"  (shlv2 服务器，init MarketCode=16;144;)")
    print()

    client = THSClient(username=username, password=password, imei=imei)
    all_stats: list[tuple[str, list[dict], dict]] = []
    try:
        print("→ 登录 8901...")
        result = client.connect()
        if not result.success:
            print(f"✗ 登录失败: {result.error} / {result.detail}")
            return 1
        print(f"✓ 登录成功，服务器 {result.server}")
        print()

        for code in codes:
            print(f"→ 查 {code} 沪市竞价...")
            # 沪市 shlv2 IP 偶有超时（DNS 轮询），失败时重试最多 3 次
            # 每次重试会重建 __manual[sh] 连接（_push_socks.pop 触发换 IP）
            recs: list[dict] = []
            last_err: str = ""
            for attempt in range(3):
                t0 = time.time()
                try:
                    recs = client.auction(code, trade_date=trade_date)
                    break
                except Exception as e:
                    last_err = f"{type(e).__name__}: {e}"
                    elapsed = time.time() - t0
                    print(f"  ⚠ 尝试{attempt+1}/3 失败 ({elapsed:.1f}s): {last_err}")
                    # 强制重建沪市连接（下次换 IP）
                    client._push_socks.pop("sh", None)
                    client._snapshot_codes.discard(code)
                    if attempt < 2:
                        time.sleep(1)
            elapsed = time.time() - t0 if recs else 0
            stat = analyze_one(code, recs)
            all_stats.append((code, recs, stat))
            if recs:
                print(f"  ✓ {len(recs)} 条 ({elapsed:.1f}s)  "
                      f"{stat['time_first']}-{stat['time_last']}  "
                      f"价 {stat['price_first']:.2f}→{stat['price_last']:.2f}")
            else:
                print(f"  ✗ {code} 无数据（3 次重试均失败：{last_err}）")
            print()

        # === 详细曲线 ===
        print("=" * 78)
        print("逐票详情（采样曲线）")
        print("=" * 78)
        for code, recs, _ in all_stats:
            print(f"\n  {code}:")
            print_detail(code, recs)

        # === 横向对比表 ===
        print()
        print("=" * 78)
        print("横向对比")
        print("=" * 78)
        header = f"{'票码':<8} {'条数':>5} {'时间范围':<18} {'首价':>8} {'末价':>8} {'涨跌':>8} {'振幅':>8} {'变化':>5} {'不动率':>7}"
        print(header)
        print("-" * 78)
        for code, _, s in all_stats:
            if not s:
                print(f"{code:<8} {'-':>5} {'(失败/无数据)':<18}")
                continue
            chg = price_change_pct(s["price_first"], s["price_last"])
            print(f"{code:<8} {s['count']:>5} "
                  f"{s['time_first']+'-'+s['time_last']:<18} "
                  f"{s['price_first']:>8.2f} {s['price_last']:>8.2f} "
                  f"{fmt_pct(chg):>8} {s['amplitude']:>7.2f}% "
                  f"{s['change_count']:>5} {s['hold_rate']:>6.1f}%")

        # === 间隔分布对比（验证「每 3 秒一条」）===
        print()
        print("=" * 78)
        print("时间戳间隔分布（验证 shlv2 每 3 秒一条 tick）")
        print("=" * 78)
        all_gaps_keys = sorted({g for _, _, s in all_stats if s for g in s["gaps"]})
        header = f"{'票码':<8} " + " ".join(f"{g}s" for g in all_gaps_keys)
        print(header)
        print("-" * 78)
        for code, _, s in all_stats:
            if not s:
                print(f"{code:<8} (无数据)")
                continue
            row = f"{code:<8} "
            for g in all_gaps_keys:
                row += f"{s['gaps'].get(g, 0):>5} "
            print(row)

        # === 9:15-9:20 vs 9:20-9:25 分段对比 ===
        print()
        print("=" * 78)
        print("分段对比：9:15-9:20（自由撮合）vs 9:20-9:25（不可撤单）")
        print("=" * 78)
        print(f"{'票码':<8} {'9:15-9:20':<28} {'9:20-9:25':<28}")
        print(f"{'':<8} {'条数  首价→末价  涨跌':<28} {'条数  首价→末价  涨跌':<28}")
        print("-" * 78)
        for code, _, s in all_stats:
            if not s:
                print(f"{code:<8} (无数据)")
                continue
            seg1_cnt, seg1_f, seg1_l = s["seg1"]
            seg2_cnt, seg2_f, seg2_l = s["seg2"]
            seg1_chg = price_change_pct(seg1_f, seg1_l)
            seg2_chg = price_change_pct(seg2_f, seg2_l)
            seg1_str = f"{seg1_cnt:>3}  {seg1_f or 0:.2f}→{seg2_f or 0:.2f} {fmt_pct(seg1_chg):>7}"
            # 注：9:20-9:25 首价用 seg2_f（实际是 9:20:00 后第一根）
            seg1_str = (f"{seg1_cnt:>3}条  "
                        f"{seg1_f:.2f}→{seg1_l:.2f} " if seg1_f else f"{seg1_cnt:>3}条  无价  ")
            seg1_str += fmt_pct(seg1_chg)
            seg2_str = (f"{seg2_cnt:>3}条  "
                        f"{seg2_f:.2f}→{seg2_l:.2f} " if seg2_f else f"{seg2_cnt:>3}条  无价  ")
            seg2_str += fmt_pct(seg2_chg)
            print(f"{code:<8} {seg1_str:<28} {seg2_str:<28}")

        # === 总结 ===
        print()
        print("=" * 78)
        ok = [s for _, _, s in all_stats if s]
        if ok:
            counts = [s["count"] for s in ok]
            print(f"✓ 成功 {len(ok)}/{len(codes)} 只")
            print(f"  tick 数: {min(counts)}-{max(counts)} (均 {sum(counts)//len(counts)})")
            print(f"  覆盖时段: {'/'.join(s['time_last'] for s in ok[:3])} 等（应都到 9:24:5x）")
            # 验证 3 秒间隔占主导
            for code, _, s in all_stats:
                if not s:
                    continue
                total = sum(s["gaps"].values())
                p3 = s["gaps"].get(3, 0) / total * 100 if total else 0
                print(f"  {code}: 3秒间隔占比 {p3:.0f}%")
        else:
            print("✗ 全部失败。可重试（DNS 轮询 + IP 健康度每次不同）。")
            print("  若反复失败：检查账号是否有 level2 权限，或同花顺客户端是否已退出。")
        return 0 if ok else 2
    finally:
        client.disconnect()


if __name__ == "__main__":
    sys.exit(main())
