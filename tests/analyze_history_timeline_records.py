"""历史分时 ``flag=0x0082`` 记录区结构分析器（离线，全局 DP 对齐）。

背景与攻坚路径见 docs/investigations/HISTORY_TIMELINE_OMISSION_CODEC_HANDOFF.md 第 1 步。
本工具**不**用 ``bytes.find(full_bar)`` 作为唯一行边界（那会漏掉省略高位的
记录，也会偶发命中字段 payload），而是：

1. 收集每个预期 bar 在记录区内的**全部**候选偏移（full 4B、low 2B、low 1B）；
2. 用动态规划在「记录单调、相邻记录跨度落在物理合理区间、总长贴近 region」
   这三条约束下求最优对齐，得到 241 条记录的边界；
3. 输出每条记录的物理跨度、命中方式、无法解释的字节区间、控制字节候选。

语料：``tests/fixtures/history_timeline/*_record_region.bin``（由
``build_history_timeline_fixtures.py`` 切出）。两表是不同标的，只能各自独立
统计形态，不能互为字段 oracle。
"""
from __future__ import annotations

import argparse
import json
import struct
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from thspypc.features.history_timeline_protocol import (  # noqa: E402
    _HISTORY_TIMELINE_BAR_OFFSETS,
    TIMELINE_BAR_DAYS_SCALE,
    TIMELINE_INTRADAY_BAR,
)


# ---- bar 常量 ---------------------------------------------------------------

def _bar_is_plausible(value: int) -> bool:
    """判断一个 4 字节值是否长得像一个合法历史分时 bar 索引。"""
    return (
        100_000_000 < value < 200_000_000
        and value % TIMELINE_BAR_DAYS_SCALE == TIMELINE_INTRADAY_BAR
    )


def collect_bar_candidates(
    region: bytes,
    first_bar: int,
) -> dict[int, list[tuple[int, str]]]:
    """为每个预期 bar 收集 (偏移, 命中方式) 候选。

    命中方式分三档，越靠前越可信：
    - ``full``: 完整 4 字节 LE 匹配（高位也保留）。
    - ``low2`` : 只匹配低 2 字节（高位被省略，需由日期序列恢复高位）。
    - ``low1`` : 只匹配最低字节（极省略形式，弱信号）。

    全表扫描而非 ``find`` 的第一个命中，避免偶发 payload 命中误导边界。
    """
    expected = [first_bar + d for d in _HISTORY_TIMELINE_BAR_OFFSETS]
    candidates: dict[int, list[tuple[int, str]]] = {b: [] for b in expected}

    # full 4B
    for off in range(len(region) - 3):
        value = struct.unpack_from("<I", region, off)[0]
        if value in candidates:
            candidates[value].append((off, "full"))

    # low 2B（去重：full 命中已覆盖的不重复记 low2）
    for b in expected:
        low2 = struct.pack("<H", b & 0xFFFF)
        start = 0
        while True:
            idx = region.find(low2, start)
            if idx < 0:
                break
            # 只记录尚未被 full 命中覆盖的偏移
            if not any(o == idx for o, _ in candidates[b] if _ == "full"):
                candidates[b].append((idx, "low2"))
            start = idx + 1
    return candidates


# ---- DP 全局对齐 -----------------------------------------------------------

# 物理跨度合理区间：标称 hs=92；省略/控制字节可能让单条略小或略大。
MIN_STRIDE = 80
MAX_STRIDE = 100
# 单条缺失/聚合时允许的倍数跨度（最多连续跳过 MAX_SKIP 条记录）。
MAX_SKIP = 6
NEG_INF = float("-inf")


def _score_stride(stride: int, hops: int) -> float:
    """对一段跨度评分。hops=1 表示相邻记录，>1 表示跨过了 hops-1 条缺失记录。

    相邻 92B 最优；偏离越远扣分；多 hop 的聚合跨度按「接近 hops×92」给分但降权，
    鼓励优先用真实相邻记录而不是聚合跳跃。
    """
    if hops <= 0:
        return NEG_INF
    ideal = 92 * hops
    diff = abs(stride - ideal)
    # 相邻记录（hops=1）容忍较紧；跨记录聚合容忍更宽
    tol = 6 if hops == 1 else 10 * hops
    if diff <= tol:
        return 1.0 / hops - 0.001 * diff  # hops 越大基准分越低
    return NEG_INF


def align_records_dp(
    region: bytes,
    candidates: dict[int, list[tuple[int, str]]],
    first_bar: int,
) -> tuple[list[tuple[int, int, str]], float]:
    """动态规划求 241 条记录的最优偏移序列。

    返回 ``[(bar_value, offset, hit_kind), ...]`` 与总得分。某条记录若完全
    无候选，offset 记为 -1、hit_kind 记为 ``missing``。
    """
    expected = [first_bar + d for d in _HISTORY_TIMELINE_BAR_OFFSETS]
    n = len(expected)
    cand_lists = [candidates[b] for b in expected]

    # 首条记录必须落在 region 较靠前的位置（bar anchor 是整表的起点）。
    # 用 (offset) 作为状态，对每条记录维护候选偏移集合。
    # 为控制状态空间，每条记录只保留 topK 个最早候选。
    TOPK = 12

    # dp[i] = list of (score, offset, back_ptr_to_(i-1)_state_index, hit_kind)
    states: list[list[tuple[float, int, int, str]]] = []
    # i=0
    init = []
    for off, kind in cand_lists[0]:
        if kind == "full":  # 首条要求 full 命中，否则后续序列无锚
            init.append((0.0, off, -1, kind))
    if not init:
        # 退化：首条无 full 命中，用任意候选
        for off, kind in cand_lists[0]:
            init.append((0.0, off, -1, kind))
    states.append(init[:TOPK])

    for i in range(1, n):
        prev_states = states[i - 1]
        cur: dict[int, tuple[float, int, int, str]] = {}
        for pi, (pscore, poff, _, _) in enumerate(prev_states):
            if poff < 0:
                continue
            best_local: dict[int, tuple[float, int, int, str]] = {}
            # 允许 1..MAX_SKIP 跳，对每个 hop 在候选里找最贴近 poff+hops*92 的偏移
            seen_offsets: set[int] = set()
            for hops in range(1, MAX_SKIP + 1):
                target_lo = poff + MIN_STRIDE * hops
                target_hi = poff + MAX_STRIDE * hops + 4
                for off, kind in cand_lists[i]:
                    if off in seen_offsets:
                        continue
                    if not (target_lo <= off <= target_hi):
                        continue
                    s = _score_stride(off - poff, hops)
                    # full 命中加分；low2/low1 降权（弱信号）
                    kind_bonus = {"full": 0.05, "low2": -0.1, "low1": -0.3}.get(
                        kind, -0.2
                    )
                    total = pscore + s + kind_bonus
                    if off not in best_local or total > best_local[off][0]:
                        best_local[off] = (total, off, pi, kind)
                seen_offsets |= set(best_local.keys())
            # 该 prev state 下每个候选偏移的最优分合并进 cur
            for off, (total, _, pi2, kind) in best_local.items():
                if off not in cur or total > cur[off][0]:
                    cur[off] = (total, off, pi2, kind)
        # 没有任何候选可对齐 -> 允许 missing（offset=-1，不推进物理位置）
        # 这种情况只在末尾省略段出现；这里先记 missing 让 DP 继续。
        if not cur and prev_states:
            # 用前一个 state 继承，offset=-1
            cur[-1] = (prev_states[0][0] - 0.5, -1, 0, "missing")
        states.append(list(cur.values())[:TOPK])

    if not states[n - 1]:
        return [], NEG_INF

    # 回溯
    best_end = max(range(len(states[n - 1])), key=lambda k: states[n - 1][k][0])
    path: list[tuple[int, int, str]] = []
    i = n - 1
    si = best_end
    while i >= 0:
        score, off, back, kind = states[i][si]
        bar = expected[i]
        path.append((bar, off, kind))
        si = back
        i -= 1
    path.reverse()
    return path, states[n - 1][best_end][0]


# ---- 报告 ------------------------------------------------------------------

def report(
    code: str,
    region: bytes,
    first_bar: int,
    path: list[tuple[int, int, str]],
    score: float,
) -> dict:
    """汇总一条记录的结构分析结果。"""
    n = len(_HISTORY_TIMELINE_BAR_OFFSETS)
    offsets = [p[1] for p in path]
    kinds = Counter(p[2] for p in path)
    strides: list[int] = []
    big_gaps: list[dict] = []
    prev_off = None
    prev_bar = None
    for bar, off, kind in path:
        if prev_off is not None and off >= 0:
            stride = off - prev_off
            strides.append(stride)
            bar_delta = bar - prev_bar
            if bar_delta > 1:
                big_gaps.append(
                    {
                        "after_bar_offset": prev_bar - first_bar,
                        "to_bar_offset": bar - first_bar,
                        "stride": stride,
                        "bars_skipped": bar_delta - 1,
                    }
                )
        if off >= 0:
            prev_off = off
        prev_bar = bar

    # 末尾无法对齐的 region 尾部（最后一条 full 偏移之后到 region 末）
    last_off = max((o for _, o, _ in path if o >= 0), default=0)
    tail_unconsumed = len(region) - (last_off + 92)

    # 控制字节候选：相邻记录之间、92B 之外多出的字节。
    # 即 stride - 92 为正时，多出部分可能是控制状态。
    extra_bytes = Counter()
    for s in strides:
        if s > 92:
            extra_bytes[s - 92] += 1

    # 统计「尾部省略区」：连续 missing 或 low2 的末段
    tail_missing_start = None
    for idx in range(len(path) - 1, -1, -1):
        if path[idx][2] == "full":
            tail_missing_start = idx + 1
            break
    tail_block = path[tail_missing_start:] if tail_missing_start else []

    return {
        "code": code,
        "region_length": len(region),
        "expected_records": n,
        "aligned_records": sum(1 for _, o, _ in path if o >= 0),
        "missing_records": sum(1 for _, o, _ in path if o < 0),
        "hit_kind_counts": dict(kinds),
        "dp_score": round(score, 3),
        "stride_histogram": dict(Counter(strides).most_common(10)),
        "aggregation_gaps": big_gaps[:12],
        "tail_unconsumed_bytes": tail_unconsumed,
        "extra_bytes_after_92": dict(extra_bytes.most_common(8)),
        "tail_omission_block": {
            "start_bar_offset": tail_block[0][0] - first_bar if tail_block else None,
            "length": len(tail_block),
            "kinds": dict(Counter(k for _, _, k in tail_block)),
        },
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--fixture-dir",
        default=str(ROOT / "tests" / "fixtures" / "history_timeline"),
    )
    ap.add_argument("--first-bar", type=int, default=132477534, help="2026-05-14 锚")
    ap.add_argument("--code", default=None, help="只分析指定代码")
    ap.add_argument("--json", action="store_true", help="输出 JSON 而非人类可读")
    args = ap.parse_args()
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    fdir = Path(args.fixture_dir)
    files = sorted(fdir.glob("*_record_region.bin"))
    if args.code:
        files = [f for f in files if f.name.startswith(args.code + "_")]

    reports = []
    for f in files:
        code = f.name.split("_")[0]
        region = f.read_bytes()
        cands = collect_bar_candidates(region, args.first_bar)
        path, score = align_records_dp(region, cands, args.first_bar)
        rep = report(code, region, args.first_bar, path, score)
        rep["record_region_file"] = f.name
        rep["path"] = [
            {"bar_offset": b - args.first_bar, "offset": o, "kind": k}
            for b, o, k in path
        ]
        reports.append(rep)

    if args.json:
        print(json.dumps(reports, indent=2, ensure_ascii=False))
    else:
        for r in reports:
            print(f"===== {r['code']}  ({r['record_region_file']}) =====")
            print(f"  region_length      : {r['region_length']}")
            print(
                f"  aligned/missing    : {r['aligned_records']}/"
                f"{r['missing_records']} of {r['expected_records']}"
            )
            print(f"  hit_kind_counts    : {r['hit_kind_counts']}")
            print(f"  dp_score           : {r['dp_score']}")
            print(f"  stride_histogram   : {r['stride_histogram']}")
            print(f"  aggregation_gaps   : {r['aggregation_gaps']}")
            print(f"  tail_unconsumed    : {r['tail_unconsumed_bytes']}B")
            print(f"  extra_after_92     : {r['extra_bytes_after_92']}")
            print(f"  tail_omission_block: {r['tail_omission_block']}")
            print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
