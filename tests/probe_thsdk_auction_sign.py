"""采集带正负未匹配量的竞价 ground truth（2026-07-27 周一盘后）。

目标：覆盖「买盘主导」(撮合价>前收，未匹配量应为正) 与「卖盘主导」
(撮合价<前收，未匹配量应为负) 两种情况，验证 thsdk 买2量/卖2量 与
hexin 协议 dt27 符号的关系。

每只票输出：
  - 首/末根价（看撮合方向）
  - 买2量/卖2量的 0x80000000 哨兵分布
  - 当前量、记录数、间隔
  - 全量导出 JSON
"""
import json
import sys
import time
from datetime import datetime, timezone, timedelta

from thsdk import THS

CST = timezone(timedelta(hours=8))
SENTINEL = 2147483648  # 0x80000000

# 覆盖不同价位 + 预期不同方向（实际方向以开盘为准，这里多采几只）
CODES = [
    "USHA603118",  # 共进（中低价沪）
    "USHA600519",  # 贵州茅台（高价沪）
    "USHA600276",  # 恒瑞医药
    "USHA601318",  # 中国平安
    "USZA000938",  # 紫光（深）
    "USZA300033",  # 深创业板
    "USZA000001",  # 平安银行
    "USHA688981",  # 中芯(科创)
]


def fetch(ths, code):
    t0 = time.perf_counter()
    resp = ths.call_auction(code)
    elapsed = time.perf_counter() - t0
    return resp, elapsed


def summarize(code, data, elapsed):
    if not data:
        print(f"\n=== {code} === 无数据 ({elapsed:.2f}s)")
        return None
    first, last = data[0], data[-1]
    ts0, ts1 = first["时间"], last["时间"]
    n = len(data)
    # 买/卖哨兵统计
    b2_sentinel = sum(1 for r in data if r["买2量"] == SENTINEL)
    s2_sentinel = sum(1 for r in data if r["卖2量"] == SENTINEL)
    both_real = sum(1 for r in data if r["买2量"] != SENTINEL and r["卖2量"] != SENTINEL)
    both_sent = sum(1 for r in data if r["买2量"] == SENTINEL and r["卖2量"] == SENTINEL)
    # 间隔
    gaps = {}
    prev = data[0]["时间"]
    for r in data[1:]:
        g = r["时间"] - prev
        gaps[g] = gaps.get(g, 0) + 1
        prev = r["时间"]
    info = {
        "code": code,
        "n": n,
        "elapsed": elapsed,
        "first_price": first["价格"],
        "last_price": last["价格"],
        "ts0": ts0,
        "ts1": ts1,
        "t0_str": datetime.fromtimestamp(ts0, CST).strftime("%H:%M:%S"),
        "t1_str": datetime.fromtimestamp(ts1, CST).strftime("%H:%M:%S"),
        "b2_sentinel_count": b2_sentinel,
        "s2_sentinel_count": s2_sentinel,
        "both_real_count": both_real,
        "both_sentinel_count": both_sent,
        "gaps": dict(sorted(gaps.items())),
        "last_cur_vol": last["当前量"],
    }
    print(f"\n=== {code} ({n}条, {elapsed:.2f}s) ===")
    print(f"  时间 {info['t0_str']}~{info['t1_str']}  间隔={info['gaps']}")
    print(f"  价: 首{first['价格']} → 末{last['价格']}  当前量(末)={last['当前量']}")
    print(f"  哨兵: 买2={b2_sentinel}  卖2={s2_sentinel}  双实={both_real}  双哨={both_sent}")
    print(f"  首条: {json.dumps(first, ensure_ascii=False)}")
    print(f"  末条: {json.dumps(last, ensure_ascii=False)}")
    return info


def main():
    out_infos = []
    stamp = int(time.time())
    with THS() as ths:
        for code in CODES:
            try:
                resp, elapsed = fetch(ths, code)
                data = resp.data
                info = summarize(code, data, elapsed)
                if info:
                    info["error"] = resp.error
                    out_infos.append(info)
                    # 全量导出
                    out = f"captures_live/_thsdk_auction_{code}_{stamp}.json"
                    try:
                        with open(out, "w", encoding="utf-8") as f:
                            json.dump({"code": code, "data": data}, f, ensure_ascii=False, indent=2)
                    except OSError:
                        pass
            except Exception as e:
                print(f"\n=== {code} === 异常: {type(e).__name__}: {e}")

    # 汇总
    print("\n" + "=" * 70)
    print("汇总（验证 dt27 符号语义）")
    print("=" * 70)
    print(f"{'代码':<14}{'条数':>5}{'首价':>9}{'末价':>9}{'买2哨':>6}{'卖2哨':>6}{'双实':>5}{'双哨':>5}")
    for i in out_infos:
        print(f"{i['code']:<14}{i['n']:>5}{i['first_price']:>9}{i['last_price']:>9}"
              f"{i['b2_sentinel_count']:>6}{i['s2_sentinel_count']:>6}"
              f"{i['both_real_count']:>5}{i['both_sentinel_count']:>5}")

    # 保存汇总
    summary_path = f"captures_live/_thsdk_auction_sign_summary_{stamp}.json"
    try:
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump(out_infos, f, ensure_ascii=False, indent=2)
        print(f"\n汇总已保存: {summary_path}")
    except OSError:
        pass


if __name__ == "__main__":
    main()
