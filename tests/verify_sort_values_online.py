#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""活网验证排序榜响应里的 dt 数值字段(封单额/竞价金额/涨幅)。

2026-08-11 活网验证结论
-----------------------
| 排序键   | sort_by | 响应 dt | 首条值     | 语义验证           |
|----------|---------|---------|-----------|--------------------|
| 涨幅     | 199112  | dt200   | 419.5     | 涨幅%(新股合理)    |
| 竞价金额 | 68758   | dt150   | 4.493e+08 | 竞价金额(元),4.49亿|
| 封单额   | 265260  | dt44    | 3.434e+08 | 封单额(元),3.43亿  |

★ 封单额在 **dt44**(不是抓包里看到的 461256 —— 那是另一条带行情刷新请求的
DataType 列表里的字段,不是排序响应字段)。

用法:
    uv run python tests/verify_sort_values_online.py
    uv run python tests/verify_sort_values_online.py --env .env.normal
"""
from __future__ import annotations

import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from thspypc.testing import get_client  # noqa: E402

# 待验证的排序键(语义名 -> sort_by)
SORT_KEYS = {
    "涨幅": 199112,
    "竞价金额": 68758,
    "封单额": 265260,
}


def load_env_if_needed(env_file: str) -> None:
    """get_client 内部会 load_env,这里仅显式触发一次便于报错。"""
    env_path = os.path.join(ROOT, env_file)
    if not os.path.exists(env_path):
        print(f"✗ 找不到 {env_path}")
        sys.exit(1)


def main() -> int:
    env_file = ".env"
    if "--env" in sys.argv:
        i = sys.argv.index("--env")
        if i + 1 < len(sys.argv):
            env_file = sys.argv[i + 1]
    load_env_if_needed(env_file)

    print("=" * 70)
    print(f"排序榜 dt 数值字段活网验证 @ {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"env={env_file}")
    print("=" * 70)

    client = get_client(env_file)
    print(f"已登录: {client.is_connected}\n")

    for sem, sort_by in SORT_KEYS.items():
        print(f"{'='*70}")
        print(f"【{sem}】sort_by={sort_by}")
        print(f"{'='*70}")
        try:
            stocks = client.stock_list_hot(
                count=10, sort_by=sort_by, with_values=True, timeout=15.0,
            )
        except Exception as exc:
            print(f"  ✗ 请求失败: {exc}")
            continue

        if not stocks:
            print("  (空结果)")
            continue

        # 收集所有出现过的 dt 字段名
        all_dt = set()
        for s in stocks:
            for k in s:
                if k.startswith("dt") and not k.endswith("_format"):
                    all_dt.add(k)
        print(f"  返回 {len(stocks)} 条,出现的 dt 字段: {sorted(all_dt)}")
        print()

        # 打印前 5 条的关键字段
        print(f"  {'code':>8} {'name':>8}  dt 字段值(非 None)")
        print(f"  {'-'*60}")
        for s in stocks[:5]:
            code = s.get("code", "")
            name = s.get("name", "") or "-"
            dt_vals = {k: v for k, v in s.items()
                       if k.startswith("dt") and not k.endswith("_format") and v is not None}
            # 简短展示
            dt_str = " ".join(f"{k}={_fmt(v)}" for k, v in sorted(dt_vals.items()))
            print(f"  {code:>8} {name:>8}  {dt_str}")
        print()

        # 重点:哪个 dt 的值随排序单调(SortDir=D 时第一条应最大)?
        # 找出"疑似排序值"字段:非 None、数值型、首条最大的那个
        candidate = _guess_sort_field(stocks, sort_by)
        if candidate:
            print(f"  ★ 疑似「{sem}」排序值字段: dt{candidate}")
            print(f"    首条 dt{candidate} = {_fmt(stocks[0].get(f'dt{candidate}'))}")
        else:
            print(f"  ? 未能从 dt 字段里猜出排序值(可能需手动看)")
        print()

    return 0


def _fmt(v) -> str:
    if v is None:
        return "-"
    if isinstance(v, float):
        return f"{v:.4g}"
    return str(v)


def _guess_sort_field(stocks: list[dict], sort_by: int) -> int | None:
    """从响应里猜哪个 dt 是排序值。

    启发式:SortDir=D(降序),排序值字段应满足——首条最大、单调不增、非 None。
    返回该 dt 的编号(int),找不到返回 None。
    """
    if len(stocks) < 2:
        return None
    candidates = []
    for s in stocks[0]:
        if not s.startswith("dt") or s.endswith("_format"):
            continue
        try:
            dt_no = int(s[2:])
        except ValueError:
            continue
        vals = []
        for st in stocks:
            v = st.get(s)
            if v is None:
                vals = None
                break
            try:
                vals.append(float(v))
            except (TypeError, ValueError):
                vals = None
                break
        if vals is None or len(vals) < 2:
            continue
        # 降序:单调不增(允许相邻相等)
        if all(vals[i] >= vals[i + 1] for i in range(len(vals) - 1)):
            candidates.append((dt_no, vals[0]))
    if not candidates:
        return None
    # 多个候选时,优先选和 sort_by 低字节相关的;否则选首条值最大的
    low_byte = sort_by & 0xFF
    for dt_no, _ in candidates:
        if dt_no == low_byte:
            return dt_no
    candidates.sort(key=lambda x: -abs(x[1]))
    return candidates[0][0]


if __name__ == "__main__":
    raise SystemExit(main())
