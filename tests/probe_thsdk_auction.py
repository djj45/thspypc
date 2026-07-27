"""探针：用 thsdk (hq.dll) 查沪市竞价，看库返回的真实字段名与值。

目的：
1. 确认沪市竞价的真实字段（README 例子和 call_auction.py 示例字段名不一致）。
2. 看量/未匹配量/额的语义与单位（股 vs 手），对照 thspypc 的 12 锚点。
3. 拿到一份「权威正确答案」，作为 thspypc 沪市解析器的回归基准。

用法（盘中 9:15-9:25 或盘后查当日）：
    uv run python tests/probe_thsdk_auction.py USHA603118
    uv run python tests/probe_thsdk_auction.py USZA300033
"""
import json
import sys
import time
from datetime import datetime

from thsdk import THS


def main() -> int:
    code = sys.argv[1] if len(sys.argv) > 1 else "USHA603118"
    with THS() as ths:
        t0 = time.perf_counter()
        resp = ths.call_auction(code)
        elapsed = time.perf_counter() - t0

        print(f"=== thsdk.call_auction({code!r}) ===")
        print(f"耗时: {elapsed:.3f}s  error: {resp.error!r}")
        data = resp.data
        print(f"记录数: {len(data) if isinstance(data, list) else 'N/A'}")

        if not data:
            print("(无数据——可能非交易时段或非当日竞价时段)")
            # dump 原始 JSON 看看到底返回了什么
            print("原始 payload:", resp.payload if hasattr(resp, "payload") else "?")
            return 1

        # 打印字段名全集（第一条记录的所有 key）
        first = data[0]
        print(f"\n字段名全集 ({len(first)} 个): {list(first.keys())}")

        # 打印前 5 条 + 后 3 条原始记录
        print("\n--- 前 5 条原始记录 ---")
        for r in data[:5]:
            print(json.dumps(r, ensure_ascii=False))
        print("--- 后 3 条原始记录 ---")
        for r in data[-3:]:
            print(json.dumps(r, ensure_ascii=False))

        # 时间字段转换（unix 秒 → 北京时间）
        if data and "时间" in first:
            print("\n--- 时间范围 ---")
            ts_first = data[0]["时间"]
            ts_last = data[-1]["时间"]
            print(f"首条: {ts_first} = {datetime.fromtimestamp(ts_first)}")
            print(f"末条: {ts_last} = {datetime.fromtimestamp(ts_last)}")
            # 间隔分布
            if len(data) >= 2:
                gaps = {}
                prev = data[0]["时间"]
                for r in data[1:]:
                    g = r["时间"] - prev
                    gaps[g] = gaps.get(g, 0) + 1
                    prev = r["时间"]
                print(f"间隔分布(秒:次数): {dict(sorted(gaps.items()))}")

        # 全量导出，便于后续逐字段对照
        out = f"captures_live/_thsdk_auction_{code}_{int(time.time())}.json"
        try:
            with open(out, "w", encoding="utf-8") as f:
                json.dump({"code": code, "data": data}, f, ensure_ascii=False, indent=2)
            print(f"\n全量数据已导出: {out}")
        except OSError as e:
            print(f"(导出失败: {e})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
