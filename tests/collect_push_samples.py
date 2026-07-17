#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
大量采集实时推送 raw_bytes + 历史异动对照样本，存到持久目录供离线逆向。

采集策略（约 60 秒）：
  1. subscribe_realtime 订阅 9601 推送
  2. 交替采集（推送和查询共用 9601 socket，必须串行不能并发）：
       每轮 ~8s：
         [0-5s]  receive_pushes_locked 持锁收推送（累积 raw_bytes + 本地 ts + 完整帧）
         [5-8s]  释放锁，dxjl_history(pages=3) 翻 3 页历史
                 （覆盖最近 ~30 条异动，确保推送窗口内的异动没被挤出）
       循环 6 轮
  3. 匹配：代码相同 且 |hist_ts - push_ts| ≤ TIME_WINDOW 秒，取时间最近
     （收盘后跑必然 0 命中——历史异动时间 ≤15:00:00，推送 >15:00:00，代码不重叠。
      必须盘中跑：9:30-15:00，推送和历史的异动发生时间在同一窗口内。）

产物（D:\\code\\ths_takehome\\thspypc\\data\\）：
  pushes.jsonl       每行一个推送记录 {ts, market, code, raw_bytes}
  push_frames.jsonl  每行一个完整推送帧 {ts, len, hex}（含 hq1.0 字段表头，核心逆向数据）
  history.jsonl      每行一条历史异动（完整字段）
  matched.csv        按代码+时间窗口匹配的对照样本（核心逆向数据）
  summary.txt        采集统计 + 异动类型分布

⚠️ 必须盘中运行（周一~周五 9:30-15:00），否则 matched.csv=0。
"""
import csv
import datetime
import json
import os
import sys
import time
from collections import Counter, defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
DATA_DIR = r"D:\code\ths_takehome\thspypc\data"

from thspypc import THSClient

# 匹配时间窗口（秒）。异动从发生到落盘历史有几秒延迟，留余量。
TIME_WINDOW_S = 10.0


def load_dotenv():
    env_path = os.path.join(os.path.dirname(__file__), "..", ".env")
    if not os.path.exists(env_path):
        return
    for line in open(env_path, encoding="utf-8"):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            if k.strip() and k.strip() not in os.environ:
                os.environ[k.strip()] = v.strip().strip('"').strip("'").strip(" ")


# ── 匹配逻辑（独立函数，供离线测试复用）──


def match_pushes_with_history(pushes: list[dict], history: list[dict],
                              time_window_s: float = TIME_WINDOW_S) -> list[dict]:
    """按代码 + 时间窗口匹配推送记录与历史异动。

    推送记录无内部时间戳（只有本地接收 ts），历史记录有微秒级异动时间戳。
    匹配规则：code 相同 且 |hist_ts - push_ts| ≤ time_window_s。
    同一代码可能短时间多次异动，取时间差最小的那条历史。

    Args:
        pushes: 每项含 {ts(秒级本地时间), code, market, raw_bytes}。
        history: 每项含 {时间(微秒戳), 代码, 异动类型, 异动编码, 金额, 涨跌幅, ...}。
        time_window_s: 时间窗口（秒）。

    Returns:
        list[dict]，按 (code, hist_time) 去重，保留同代码不同时刻的多条对照。
    """
    # 按代码建历史索引
    hist_by_code: dict[str, list[dict]] = defaultdict(list)
    for h in history:
        code = h.get("代码", "")
        if code:
            hist_by_code[code].append(h)

    matched_rows = []
    seen = set()  # (code, hist_time) 去重
    for p in pushes:
        code = p.get("code") or p.get("代码", "")
        if not code:
            continue
        p_ts = p.get("ts", 0)
        candidates = hist_by_code.get(code, [])
        if not candidates:
            continue
        # 在时间窗口内找最近的历史记录
        best = None
        best_diff = None
        for h in candidates:
            h_ts = h.get("时间", 0)
            if not h_ts:
                continue
            # 历史时间是微秒戳，推送 ts 是秒
            diff = abs(h_ts / 1_000_000 - p_ts)
            if diff > time_window_s:
                continue
            if best_diff is None or diff < best_diff:
                best = h
                best_diff = diff
        if not best:
            continue
        key = (code, best.get("时间", 0))
        if key in seen:
            continue
        seen.add(key)
        matched_rows.append({
            "code": code,
            "hist_type": best.get("异动类型", ""),
            "hist_code_byte": f"0x{best.get('异动编码', 0):02x}",
            "hist_amount": best.get("金额", ""),
            "hist_change": best.get("涨跌幅", ""),
            "hist_time": best.get("时间", ""),
            "push_market": p.get("market", ""),
            "push_ts": round(p_ts, 3),
            "time_diff_s": round(best_diff, 3) if best_diff is not None else "",
            "push_raw_bytes": p.get("raw_bytes", ""),
        })
    return matched_rows


def main():
    load_dotenv()
    os.makedirs(DATA_DIR, exist_ok=True)
    username = os.environ.get("THS_USERNAME", "").strip()
    password = os.environ.get("THS_PASSWORD", "").strip()
    imei = os.environ.get("THS_IMEI", "").strip() or None

    # 采集参数
    rounds = 6
    push_secs = 5
    hist_pages = 3
    duration = rounds * (push_secs + 4)  # 每轮推送 5s + 历史翻页 ~4s

    print("=" * 60)
    print("推送 + 历史对照采集（带锁交替，盘中运行）")
    print("=" * 60)
    print(f"当前: {datetime.datetime.now().strftime('%H:%M:%S')}")
    print(f"采集 {duration}s（{rounds} 轮 × 推送 {push_secs}s + 历史 {hist_pages}页）→ {DATA_DIR}")

    client = THSClient(username, password, imei)
    r = client.connect()
    if not r.success:
        print(f"登录失败: {r.error}")
        return 1
    print(f"登录: {r.server}")
    client.subscribe_realtime()
    print("已订阅推送\n")

    pushes = []
    full_frames = []
    history = []

    for rnd in range(rounds):
        rnd_start = time.time()

        # 阶段A：带锁收推送（完整帧 + 解析记录）
        def on_rec(rec):
            pushes.append({"ts": time.time(), **rec})

        def on_frame(frame):
            full_frames.append({
                "ts": time.time(), "len": len(frame), "hex": frame.hex()
            })

        n = client.receive_pushes_locked(
            timeout=push_secs, callback=on_rec, full_frame_callback=on_frame)
        push_dt = time.time() - rnd_start
        print(f"  轮{rnd} 推送: {n} 帧 / {push_dt:.1f}s", flush=True)

        # 阶段B：翻 3 页历史（与推送串行，不并发读 socket）
        t0 = time.time()
        try:
            recs = client.dxjl_history(pages=hist_pages, markets=(32, 16))
            for h in recs:
                h["fetch_ts"] = time.time()
            history.extend(recs)
            print(f"  轮{rnd} 历史: {len(recs)} 条 / {time.time()-t0:.1f}s",
                  flush=True)
        except Exception as e:
            print(f"  轮{rnd} 历史失败: {e}", flush=True)

    client.disconnect()
    print(f"\n采集完成: 推送帧 {len(full_frames)}, 推送记录 {len(pushes)}, "
          f"历史 {len(history)}")

    # === 存盘 ===
    _save(pushes, "pushes.jsonl")
    _save(full_frames, "push_frames.jsonl")
    _save(history, "history.jsonl")

    # === 匹配 ===
    matched_rows = match_pushes_with_history(pushes, history)
    matched_path = os.path.join(DATA_DIR, "matched.csv")
    with open(matched_path, "w", encoding="utf-8", newline="") as f:
        if matched_rows:
            w = csv.DictWriter(f, fieldnames=list(matched_rows[0].keys()))
            w.writeheader()
            w.writerows(matched_rows)
    print(f"存: {matched_path} ({len(matched_rows)} 条匹配)")

    # === summary（含异动类型分布，用于判断样本均衡性）===
    type_dist = Counter(h.get("异动类型", "") for h in history)
    summary_path = os.path.join(DATA_DIR, "summary.txt")
    with open(summary_path, "w", encoding="utf-8") as f:
        f.write(f"采集时间: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"推送帧数: {len(pushes)}\n")
        f.write(f"推送唯一代码: {len(set(p['code'] for p in pushes if 'code' in p))}\n")
        f.write(f"历史记录: {len(history)}\n")
        f.write(f"历史唯一代码: {len(set(h.get('代码','') for h in history))}\n")
        f.write(f"匹配样本: {len(matched_rows)}\n")
        f.write(f"\n历史异动类型分布（数值逆向需覆盖多种类型）:\n")
        for t, c in type_dist.most_common():
            f.write(f"  {t}: {c}\n")
        if matched_rows:
            matched_types = Counter(r["hist_type"] for r in matched_rows)
            f.write(f"\n匹配样本异动类型分布:\n")
            for t, c in matched_types.most_common():
                f.write(f"  {t}: {c}\n")
        else:
            # 0 匹配时输出时间窗口诊断
            f.write("\n[诊断] 0 匹配。检查时间窗口是否错开：\n")
            if pushes:
                push_ts = [p["ts"] for p in pushes]
                f.write(f"  推送 ts: {datetime.datetime.fromtimestamp(min(push_ts))}"
                        f" ~ {datetime.datetime.fromtimestamp(max(push_ts))}\n")
            if history:
                hts = [h.get("时间", 0) for h in history if h.get("时间")]
                if hts:
                    f.write(f"  历史时间: {datetime.datetime.fromtimestamp(min(hts)/1e6)}"
                            f" ~ {datetime.datetime.fromtimestamp(max(hts)/1e6)}\n")
            push_codes = set(p.get("code","") for p in pushes)
            hist_codes = set(h.get("代码","") for h in history)
            f.write(f"  推送代码 {len(push_codes)} 个 ∩ 历史代码 {len(hist_codes)} 个"
                    f" = {len(push_codes & hist_codes)} 个重叠\n")
            f.write("  → 若重叠 0，说明收盘后跑（必须盘中 9:30-15:00）。\n")
    print(f"存: {summary_path}")
    return 0


def _save(items: list[dict], name: str) -> None:
    path = os.path.join(DATA_DIR, name)
    with open(path, "w", encoding="utf-8") as f:
        for it in items:
            f.write(json.dumps(it, ensure_ascii=False) + "\n")
    print(f"存: {path} ({len(items)} 行)")


if __name__ == "__main__":
    raise SystemExit(main())
