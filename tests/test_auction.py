#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
获取个股**集合竞价**（9:15-9:25 虚拟撮合：撮合价/累计量/未匹配量）。

调用 ``client.auction(code)`` —— 与 ``client.timeline()`` 走**同一条** __manual
推送连接（pageid=4214 通道），只是请求用周期码 7176 + unix 时间戳参数
（2026-07-26 抓包 auction_20260726 破解）。

用法：
    py tests/test_auction.py 000938                 # 深市（紫光股份，最近交易日）
    py tests/test_auction.py 603118                 # 沪市（共进股份）
    py tests/test_auction.py 000938,603118          # 沪深各一只（同时测两套服务器）
    py tests/test_auction.py 000938 --date 2026-07-24   # 指定交易日

★ 盘后/盘中/周末都能拿到（非交易日拿到的是最近交易日的竞价数据）。
⚠ 需要 **level2 账号**（.env 里的 THS_USERNAME/THS_PASSWORD）。
⚠ auction 内部会关主连接（_drop_connection）只留 __manual 推送连接，
   所以本脚本运行期间不能同时用 kline/list_quotes。
"""
from __future__ import annotations

import datetime
import logging
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

# ★ 让 thspypc 内部 logger.info 可见——诊断 init 响应、订阅 CodeListSize、
# __manual 登录逐 IP 尝试过程的关键信息。
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


# ---- 字段格式化 ----

# 已知语义字段的友好名（dt 编号 → 含义，2026-07-26 实测 + 9:21:03 锚点验证）
_FIELD_HINT = {
    "time": "时间",          # dt1：unix 时间戳 → datetime
    "dt10": "撮合价",        # 集合竞价撮合价（虚拟开盘价）
    "dt49": "累计量(股)",    # ÷100 = 手
    "dt27": "未匹配(股)",    # ÷100 = 手
}


def _fmt_value(key: str, val) -> str:
    """单字段的友好格式化。"""
    if key == "time":
        if isinstance(val, datetime.datetime):
            return val.strftime("%H:%M:%S")
        return str(val)
    if isinstance(val, float):
        # dt49/dt27 显示「股(手)」双重单位
        if key in ("dt49", "dt27"):
            return f"{val:.0f}股({val/100:.0f}手)"
        return f"{val:.2f}"
    return str(val)


def print_records(code: str, recs: list[dict]) -> None:
    """打印一只票的集合竞价记录。"""
    print(f"\n{'=' * 64}")
    print(f"  {code}  —  共 {len(recs)} 条竞价记录")
    print("=" * 64)
    if not recs:
        print("  （空。可能：非交易日 / 无竞价数据 / 注册失败）")
        return

    sample = recs[0]
    keys = list(sample.keys())
    print(f"  字段: {keys}")
    hinted = [(k, _FIELD_HINT.get(k, "")) for k in keys]
    print("  含义: " + "  ".join(f"{k}({h})" if h else k for k, h in hinted))
    print()

    # 打印前 5 + 后 3 条
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
            label = (f"{hint}={_fmt_value(k, rec[k])}" if hint
                     else f"{k}={_fmt_value(k, rec[k])}")
            parts.append(label)
        print(f"  [{i:>3}] " + "  ".join(parts))

    # 撮合价收敛总结
    prices = [r.get("dt10") for r in recs if isinstance(r.get("dt10"), (int, float))]
    if len(prices) >= 2:
        first, last = prices[0], prices[-1]
        hi, lo = max(prices), min(prices)
        chg = (last - first) / first * 100 if first else 0
        print(f"\n  撮合价: 首根 {first:.2f} → 末根 {last:.2f}  "
              f"({chg:+.2f}%)  区间 {lo:.2f}~{hi:.2f}")
    vols = [r.get("dt49") for r in recs if isinstance(r.get("dt49"), (int, float))]
    if vols:
        print(f"  累计量: 末根 {vols[-1]/100:,.0f} 手")


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
                print(f"✗ 日期格式错误，应为 YYYY-MM-DD：{args[i + 1]}")
                return 1
    codes_arg = args[0] if args and not args[0].startswith("-") else "000938"
    codes = [c.strip() for c in codes_arg.split(",") if c.strip()]

    now = datetime.datetime.now()
    print("=" * 64)
    print("个股集合竞价获取  —  验证周期码 7176 协议（pageid=4214 推送通道）")
    print("=" * 64)
    weekday = now.weekday()
    if weekday >= 5:
        print(f"⚠ 今天是周{weekday + 1}（非交易日），拿到的是最近交易日的竞价数据。")
    elif now.hour < 9 or now.hour >= 15:
        print(f"⚠ 当前 {now.strftime('%H:%M')} 非盘中，拿到的是已收盘竞价数据。")
    else:
        print(f"✓ 盘中（{now.strftime('%H:%M')}），可能拿到部分竞价数据。")
    date_desc = trade_date.isoformat() if trade_date else "最近交易日"
    print(f"日期: {date_desc}")
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
            print(f"\n→ 查 {code} 集合竞价（首次会建 __manual[{('sh' if code.startswith('6') else 'sz')}] 推送连接）...")
            try:
                recs = client.auction(code, trade_date=trade_date)
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
