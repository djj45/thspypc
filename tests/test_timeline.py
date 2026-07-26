#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
获取个股**当日分时**（盘后也能拿到当天完整 240 根，盘中拿到截至当前的部分）。

调用 ``client.timeline(code)`` —— 内部走刚改造的沪深分服推送连接：
按股票市场连 shlv2（沪）/szlv2（深）IP + 匹配的 init MarketCode。
所以本脚本同时验证了「沪深 L2 分服」改造是否生效。

用法：
    uv run python tests/test_timeline.py 000938            # 深市（紫光股份）
    uv run python tests/test_timeline.py 603118            # 沪市（共进股份）
    uv run python tests/test_timeline.py 000938,603118     # 沪深各一只（同时测两套服务器）

★ 想多试几次就重复运行；脚本退出时会自动 disconnect。
⚠ 需要 **level2 账号**（.env 里的 THS_USERNAME/THS_PASSWORD）。
⚠ timeline 内部会关主连接（_drop_connection）只留 __manual 推送连接，
   所以本脚本运行期间不能同时用 kline/list_quotes。
"""
from __future__ import annotations

import datetime
import logging
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

# ★ 让 thspypc 内部 logger.info 可见——诊断 init 响应大小、CodeListSize、
# __manual 登录逐 IP 尝试过程的关键信息。默认无 handler 时这些会被吞掉。
logging.basicConfig(
    level=logging.INFO,
    format="  ·%(levelname)s %(name)s: %(message)s",
    stream=sys.stdout,
)

from thspypc import THSClient


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


# ---- 字段格式化（不假设固定字段名，按实际返回动态处理）----

# 已知语义字段的友好名（dt 编号 → 含义，2026-07-26 实测 + 外部行情核对）
# 核对锚点：000938 收盘 41.45、量 360.54 万手、额 152.19 亿。
_FIELD_HINT = {
    "bar_index": "时间",        # dt1：分时 bar 序号（连续递增，非时间戳）
    "dt10": "现价",            # 分时白线
    "dt13": "量(累计·股)",     # 分时图柱状 = 逐根差分（无独立「当根量」字段）
    "dt14": "主动买(累计)",    # dt14+dt15=dt13
    "dt15": "主动卖(累计)",    # dt14+dt15=dt13
    "dt19": "额(累计·元)",     # 均价 = dt19/dt13
}


def _bar_index_to_time(bar_index: int) -> str:
    """把分时 bar 序号近似转成 HH:MM（A股 9:30 开盘，每根 1 分钟）。

    bar_index 的绝对基准随交易日变化，这里只取「当天第几根」做粗略换算，
    仅供阅读；精确时间以同花顺客户端为准。
    """
    if not isinstance(bar_index, int) or bar_index < 0:
        return "??"
    # 当天第几根：bar_index 对 240 取余是粗估（实际基准非 0）
    day_bar = bar_index % 240
    base = datetime.datetime.combine(datetime.date.today(), datetime.time(9, 30))
    try:
        t = base + datetime.timedelta(minutes=day_bar)
        return t.strftime("%H:%M")
    except OverflowError:
        return "??"


def _fmt_value(key: str, val) -> str:
    """单字段的友好格式化。"""
    if key == "bar_index":
        return f"{val}({_bar_index_to_time(val)})"
    if isinstance(val, float):
        return f"{val:.3f}"
    if isinstance(val, int) and val > 100_000:
        # 量/额类大数加千分位
        return f"{val:,}"
    return str(val)


def print_records(code: str, recs: list[dict]) -> None:
    """打印一只票的分时记录。"""
    print(f"\n{'=' * 64}")
    print(f"  {code}  —  共 {len(recs)} 根分时")
    print("=" * 64)
    if not recs:
        print("  （空。可能：非交易日 / 盘前当天还没数据 / 注册失败）")
        return

    # 字段表（第一根的字段决定，全部记录字段一致）
    sample = recs[0]
    keys = list(sample.keys())
    print(f"  字段: {keys}")
    hinted = [(k, _FIELD_HINT.get(k, "")) for k in keys]
    print("  含义: " + "  ".join(f"{k}({h})" if h else k for k, h in hinted))
    print()

    # 打印前 5 + 后 3 根
    show_idx = list(range(min(5, len(recs))))
    if len(recs) > 8:
        show_idx.append(None)  # 分隔
        show_idx += list(range(len(recs) - 3, len(recs)))
    elif len(recs) > 5:
        show_idx += list(range(5, len(recs)))

    for i in show_idx:
        if i is None:
            print("  ...")
            continue
        rec = recs[i]
        parts = []
        for k in keys:
            hint = _FIELD_HINT.get(k)
            label = f"{hint}={_fmt_value(k, rec[k])}" if hint else f"{k}={_fmt_value(k, rec[k])}"
            parts.append(label)
        print(f"  [{i:>3}] " + "  ".join(parts))

    # 现价简略序列（如果有 dt10）
    if "dt10" in sample:
        prices = [r.get("dt10") for r in recs if r.get("dt10") is not None]
        if prices:
            f_prices = [p for p in prices if isinstance(p, (int, float))]
            if f_prices:
                lo, hi = min(f_prices), max(f_prices)
                last = f_prices[-1]
                first = f_prices[0]
                chg = (last - first) / first * 100 if first else 0
                print(f"\n  现价: 开 {first:.2f} → 收 {last:.2f}  "
                      f"({chg:+.2f}%)  低 {lo:.2f}  高 {hi:.2f}")


def main() -> int:
    load_dotenv()
    username = os.environ.get("THS_USERNAME", "").strip()
    password = os.environ.get("THS_PASSWORD", "").strip()
    imei = os.environ.get("THS_IMEI", "").strip() or None
    if not username or not password:
        print("✗ 未设置 THS_USERNAME / THS_PASSWORD（.env 或环境变量）")
        return 1

    codes_arg = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("-") else "000938"
    codes = [c.strip() for c in codes_arg.split(",") if c.strip()]
    skip_init = "--no-init" in sys.argv
    use_main_ip = "--main-ip" in sys.argv

    now = datetime.datetime.now()
    print("=" * 64)
    print("个股当日分时获取  —  验证沪深 L2 分服（shlv2 沪 / szlv2 深）")
    print("=" * 64)
    weekday = now.weekday()
    if weekday >= 5:
        print(f"⚠ 今天是周{weekday+1}（非交易日），只能拿到上个交易日的分时。")
    elif now.hour < 9 or now.hour >= 15:
        print(f"⚠ 当前 {now.strftime('%H:%M')} 非盘中，拿到的是已收盘/昨日完整分时。")
    else:
        print(f"✓ 盘中（{now.strftime('%H:%M')}），拿到截至当前的部分分时。")
    print(f"代码: {codes}")
    for c in codes:
        mkt = "沪市(17→shlv2)" if c.startswith("6") else "深市(33→szlv2)"
        print(f"  {c}: {mkt}")
    print()

    client = THSClient(username=username, password=password, imei=imei)
    try:
        print("→ 登录 8901...")
        result = client.connect()
        if not result.success:
            print(f"✗ 登录失败: {result.error} / {result.detail}")
            return 1
        print(f"✓ 登录成功，服务器 {result.server}")

        all_ok = True
        for code in codes:
            print(f"\n→ 查 {code} 当日分时（首次会建 __manual[{('sh' if code.startswith('6') else 'sz')}] 推送连接）...")
            if skip_init:
                print("  ⚙ skip_init=True（复刻 _replay_exact 成功路径：不发 init）")
            if use_main_ip:
                print("  ⚙ use_main_ip=True（__manual 连主连接同 IP，复刻 _replay_exact）")
            try:
                recs = client.timeline(code, skip_init=skip_init, use_main_ip=use_main_ip)
            except Exception as e:
                print(f"✗ {code} 查询异常: {type(e).__name__}: {e}")
                all_ok = False
                continue
            print_records(code, recs)
            if not recs:
                all_ok = False

        print("\n" + "=" * 64)
        if all_ok:
            print("✓ 全部成功")
        else:
            print("⚠ 有失败项。可重试（DNS 轮询 + IP 健康度每次不同）。")
            print("  若反复失败：检查账号是否有 level2 权限，或同花顺客户端是否已退出。")
        return 0 if all_ok else 2
    finally:
        client.disconnect()


if __name__ == "__main__":
    sys.exit(main())
