#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""普通账号探测：指数「当日 vs 历史」分时，定位零轴红绿买卖力量柱来源。

背景
----
同花顺指数分时图零轴上下有红绿柱（每分钟一根，红=主动买>主动卖，绿反之）。
历史分时无此柱。怀疑是某组「主动买卖」字段只在当日表下发、历史表不下发。

本脚本用**普通账号**（.env.normal）拉：
  1. 当日指数分时（1A0001 上证指数）
  2. 历史指数分时（1A0001 昨日 / 前一交易日）
然后逐字段对比：哪些 dt 字段当日有、历史没有；并对候选字段（dt14/15/38/39/
227/229/202/203/208/209/210 等）打印逐分钟差分，看正负是否能对上红绿。

用法：
    uv run python tests/probe_index_buyforce_normal.py
    uv run python tests/probe_index_buyforce_normal.py --code 399001 --days 3
"""
from __future__ import annotations

import argparse
import datetime
import logging
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

logging.basicConfig(
    level=logging.INFO,
    format="  ·%(levelname)s %(name)s: %(message)s",
    stream=sys.stdout,
)

from thspypc import THSClient


def load_env(path: str) -> None:
    if not os.path.exists(path):
        return
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value


# ---- 字段语义提示（已知 + 候选买卖力量字段）----
FIELD_HINT = {
    "bar_index": "时间序号",
    "dt10": "白线点位",
    "dt13": "累计成交量",
    "dt14": "★累计主动买量?",
    "dt15": "★累计主动卖量?",
    "dt19": "累计成交额",
    "dt22": "委买额",
    "dt23": "委卖额",
    "dt38": "★候选买卖字段?",
    "dt39": "★候选买卖字段?",
    "dt40": "黄线基点",
    # L2 大单额双线（普通账号可能不返回）
    "dt202": "★候选?",
    "dt203": "★候选?",
    "dt208": "★候选?",
    "dt209": "★候选?",
    "dt210": "★候选?",
    "dt227": "★主动买额?",
    "dt229": "★主动卖额?",
}


def _to_int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _to_float(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def summarize_fields(label: str, recs: list[dict]) -> set[str]:
    """返回该批记录里实际有值（非 None）的字段集合。"""
    present: set[str] = set()
    for r in recs:
        for k, v in r.items():
            if v is None:
                continue
            if isinstance(v, (int, float)) and v != v:  # NaN
                continue
            present.add(k)
    print(f"\n[{label}] 共 {len(recs)} 根，实际有值字段:")
    for k in sorted(present):
        hint = FIELD_HINT.get(k, "")
        print(f"    {k:<12} {hint}")
    return present


def show_candidate_diffs(label: str, recs: list[dict]) -> None:
    """对候选买卖字段做逐分钟差分，打印正负分布。"""
    if not recs:
        return
    candidates = ["dt14", "dt15", "dt38", "dt39",
                  "dt202", "dt203", "dt208", "dt209", "dt210",
                  "dt227", "dt229"]
    present = [c for c in candidates if any(r.get(c) is not None for r in recs)]
    if not present:
        print(f"[{label}] 无任何候选买卖字段有值")
        return
    print(f"\n[{label}] 候选买卖字段逐分钟差分（前 15 根 + 统计）:")
    header = "  idx | " + " | ".join(f"{c:>10}" for c in present)
    print(header)
    print("  " + "-" * (len(header) - 2))
    stats = {c: {"pos": 0, "neg": 0, "zero": 0} for c in present}
    prev = {c: None for c in present}
    shown = 0
    for i, r in enumerate(recs):
        row_vals = []
        any_change = False
        for c in present:
            cur = _to_float(r.get(c))
            p = prev[c]
            if cur is None or p is None:
                row_vals.append("       -   ")
                prev[c] = cur
                continue
            d = cur - p
            any_change = any_change or True
            if d > 0:
                stats[c]["pos"] += 1
            elif d < 0:
                stats[c]["neg"] += 1
            else:
                stats[c]["zero"] += 1
            row_vals.append(f"{d:+10.1f}")
            prev[c] = cur
        if i < 15 or (i < len(recs) and shown < 15):
            print(f"  {i:>3} | " + " | ".join(row_vals))
            shown += 1
        if i == 15 and len(recs) > 18:
            print("  ...")
            shown = 15
    print("  正/负/零 分布:")
    for c in present:
        s = stats[c]
        total = s["pos"] + s["neg"] + s["zero"]
        print(f"    {c:<8} pos={s['pos']:>3}  neg={s['neg']:>3}  zero={s['zero']:>3}  (n={total})")

    # 重点：dt14-dt15 差分（个股已验证语义）
    if "dt14" in present and "dt15" in present:
        print(f"\n[{label}] ★ dt14-dt15 逐分钟差分（正=红柱候选, 负=绿柱候选）:")
        prev14 = prev15 = None
        pos = neg = zero = 0
        sample = []
        for r in recs:
            c14 = _to_float(r.get("dt14"))
            c15 = _to_float(r.get("dt15"))
            if c14 is None or c15 is None:
                continue
            if prev14 is not None and prev15 is not None:
                d = (c14 - prev14) - (c15 - prev15)
                if d > 0:
                    pos += 1
                elif d < 0:
                    neg += 1
                else:
                    zero += 1
                if len(sample) < 15:
                    sample.append(d)
            prev14, prev15 = c14, c15
        print(f"    前15根差分: {[f'{x:+.1f}' for x in sample]}")
        print(f"    正(红候选)={pos}  负(绿候选)={neg}  零={zero}")


def print_head_tail(label: str, recs: list[dict], n: int = 5) -> None:
    if not recs:
        print(f"[{label}] （空）")
        return
    keys = list(recs[0].keys())
    print(f"\n[{label}] 字段顺序: {keys}")
    show = list(range(min(n, len(recs))))
    if len(recs) > n * 2:
        show.append(None)
        show += list(range(len(recs) - 3, len(recs)))
    for i in show:
        if i is None:
            print("  ...")
            continue
        r = recs[i]
        parts = []
        for k in keys:
            v = r.get(k)
            hint = FIELD_HINT.get(k, "")
            tag = f"{k}({hint})" if hint else k
            if isinstance(v, float):
                parts.append(f"{tag}={v:.3f}")
            elif isinstance(v, int) and abs(v) > 100_000:
                parts.append(f"{tag}={v:,}")
            else:
                parts.append(f"{tag}={v}")
        print(f"  [{i:>3}] " + "  ".join(parts))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--code", default="1A0001", help="指数代码")
    ap.add_argument("--days", type=int, default=2,
                    help="往前回溯几个交易日查历史分时")
    ap.add_argument("--env", default=None, help="env 文件路径（默认 .env.normal）")
    args = ap.parse_args()

    env_path = args.env or os.path.join(
        os.path.dirname(__file__), "..", ".env.normal"
    )
    load_env(env_path)
    username = os.environ.get("THS_USERNAME", "").strip()
    password = os.environ.get("THS_PASSWORD", "").strip()
    imei = os.environ.get("THS_IMEI", "").strip() or None
    if not username or not password:
        print(f"✗ 未从 {env_path} 读到 THS_USERNAME / THS_PASSWORD")
        return 1

    code = args.code
    print("=" * 70)
    print(f"普通账号指数分时对比  code={code}  (.env.normal)")
    print("=" * 70)

    client = THSClient(username=username, password=password, imei=imei)
    try:
        print("→ 登录...")
        result = client.connect()
        if not result.success:
            print(f"✗ 登录失败: {result.error} / {result.detail}")
            return 1
        print(f"✓ 登录成功  server={result.server}")
        profile = client.observed_account_profile
        print(f"✓ 账号类型: {profile.kind.value}  (期望 standard)")

        # ── 当日分时（先个股对照验证 MAIN 通道，再指数）──
        probe_stock = "600000" if code.startswith(("1A", "1B")) else "000001"
        print(f"\n→ [对照] 查当日个股分时 {probe_stock} ...")
        try:
            stock_recs = client.timeline(probe_stock, timeout=30.0)
            print(f"  个股 {probe_stock}: {len(stock_recs)} 根，"
                  f"字段={sorted(stock_recs[0].keys()) if stock_recs else '空'}")
        except Exception as e:
            print(f"  ✗ 个股对照失败: {e!r}")

        print(f"\n→ 查当日分时 {code} ...")
        today_recs: list[dict] = []
        for attempt in range(3):
            try:
                today_recs = client.timeline(code, timeout=30.0)
                if today_recs:
                    break
                print(f"  attempt{attempt+1}: 返回空")
            except Exception as e:
                print(f"  attempt{attempt+1} 失败: {e!r}")
        print_head_tail(f"当日 {code}", today_recs)
        today_fields = summarize_fields(f"当日 {code}", today_recs)
        show_candidate_diffs(f"当日 {code}", today_recs)

        # ── 历史分时（往前回溯交易日）──
        today = datetime.date.today()
        d = today - datetime.timedelta(days=1)
        checked = 0
        hist_fields_union: set[str] = set()
        while checked < args.days and d > today - datetime.timedelta(days=30):
            # 跳过周末
            if d.weekday() < 5:
                print(f"\n→ 查历史分时 {code} @ {d} ...")
                try:
                    hist_recs = client.history_timeline(code, date=d)
                except Exception as e:
                    print(f"✗ 历史 {d} 失败: {e!r}")
                    hist_recs = []
                print_head_tail(f"历史 {code} {d}", hist_recs)
                hf = summarize_fields(f"历史 {code} {d}", hist_recs)
                hist_fields_union |= hf
                show_candidate_diffs(f"历史 {code} {d}", hist_recs)
                checked += 1
            d -= datetime.timedelta(days=1)

        # ── 对比 ──
        print("\n" + "=" * 70)
        print("字段对比：当日独有（历史没有）= 买卖力量柱候选")
        print("=" * 70)
        only_today = today_fields - hist_fields_union - {"lead_change_bp",
                                                        "lead_change_pct",
                                                        "prev_close",
                                                        "lead_price"}
        only_hist = hist_fields_union - today_fields
        common = today_fields & hist_fields_union
        print(f"  当日独有: {sorted(only_today) if only_today else '（无）'}")
        print(f"  历史独有: {sorted(only_hist) if only_hist else '（无）'}")
        print(f"  两者共有: {sorted(common)}")
        return 0
    finally:
        try:
            client.disconnect()
        except Exception:
            pass


if __name__ == "__main__":
    sys.exit(main())
