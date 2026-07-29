#!/usr/bin/env python
"""在线验证 client.auction("603118") 生产链路
（docs/handoffs/HANDOFF_SUPERORDER_20260726.md 17.4 第 1 条）。

确认无需 DMP/Unicorn，仅凭 .env 的 lv2 账号 + 网络，即可在线拿到 603118
7-27 集合竞价的 200 条五字段记录。顺带：
  - 多次重跑，看是否复现文档 17.3 末尾的 r2/r3 尾行 dt27/dt33 异常负数
  - 落盘每份 raw 到 captures_live/，供后续离线对照

用法:
    py tests/verify_auction_online_603118.py            # 查 603118 @ 7-27，重跑 3 次
    py tests/verify_auction_online_603118.py 600276 5   # 查 600276，重跑 5 次
"""
from __future__ import annotations

import hashlib
import os
import sys
import time
from datetime import date, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from thspypc.client import THSClient  # noqa: E402

CAPTURES = ROOT / "captures_live"


def _summarize(tag: str, records: list[dict]) -> None:
    if not records:
        print(f"  [{tag}] 空（无竞价数据或非交易日）")
        return
    keys = set(records[0])
    first = records[0]
    last = records[-1]
    # 文档 17.3 悬而未决：r2/r3 尾行 dt27/dt33 异常负数
    bad_tail = []
    for r in records[-5:]:
        for f in ("dt27", "dt33"):
            v = r.get(f)
            if isinstance(v, (int, float)) and v < 0:
                bad_tail.append((r.get("time"), f, v))
    print(f"  [{tag}] n={len(records)} keys={sorted(keys)}")
    print(f"    首: {first.get('time')} dt10={first.get('dt10')} "
          f"dt49={first.get('dt49')} dt27={first.get('dt27')} dt33={first.get('dt33')}")
    print(f"    末: {last.get('time')}  dt10={last.get('dt10')} "
          f"dt49={last.get('dt49')} dt27={last.get('dt27')} dt33={last.get('dt33')}")
    if bad_tail:
        print(f"    ⚠ 尾行异常负数: {bad_tail}")


def main() -> int:
    code = sys.argv[1] if len(sys.argv) > 1 else "603118"
    repeat = int(sys.argv[2]) if len(sys.argv) > 2 else 3
    # 7-27 是已确认可查的交易日（文档 11.2/12.1 均基于该日数据）
    td = date(2026, 7, 27)

    user = os.environ.get("THS_USERNAME") or ""
    pwd = os.environ.get("THS_PASSWORD") or ""
    imei = os.environ.get("THS_IMEI")
    if not user or not pwd:
        # 从 .env 读
        env = (ROOT / ".env").read_text(encoding="utf-8")
        for line in env.splitlines():
            line = line.strip()
            if line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip())
        user = os.environ["THS_USERNAME"]
        pwd = os.environ["THS_PASSWORD"]
        imei = os.environ.get("THS_IMEI") or None

    client = THSClient(username=user, password=pwd, imei=imei or None)
    lr = client.connect()
    if not lr.success:
        print(f"connect 失败: {lr.error}")
        return 1
    print(f"登录成功，开始查 {code} @ {td}，重跑 {repeat} 次\n")

    digests: dict[str, int] = {}
    for i in range(1, repeat + 1):
        t0 = time.monotonic()
        try:
            records = client.auction(code, trade_date=td, timeout=15.0)
        except Exception as e:
            print(f"  [r{i}] 异常: {type(e).__name__}: {e}")
            continue
        dt_ms = (time.monotonic() - t0) * 1000
        print(f"=== r{i} ({dt_ms:.0f}ms) ===")
        _summarize(f"r{i}", records)

        # 落盘 raw 用于离线对照（再次发请求拿原始字节代价大，这里只存解析结果摘要）
        # 真正的 raw 抓取走 capture_auction_raw.py；此处仅做生产链路验证。
        if records:
            sample = hashlib.sha256(
                repr([(r.get("time"), r.get("dt10")) for r in records[:3]]).encode()
            ).hexdigest()[:12]
            digests[sample] = digests.get(sample, 0) + 1
        time.sleep(0.5)

    print(f"\n唯一结果指纹数: {len(digests)}（{digests}）")
    client.disconnect()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
