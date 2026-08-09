#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
thspypc 个股实时分时推送测试（8901 pageid=4214 逐 tick 快照）。

登录 8901 → snapshot_subscribe(code) 订阅 → 收到现价逐 tick 推送。

★ 2026-07-24 抓包破解：订阅 pageid=4214（子帧0x0002 + 路由0x0002）后，服务端
在 8901 主连接上持续推送 71B 快照帧（现价/量随每笔成交跳动）= 分时白线数据源。

⚠ 需要 **level2 账号**：L2 账号打开分时发 pageid=4214（路由0x0002）触发持续推送；
普通账号打开分时发 pageid=9355（路由0x000a）走请求-响应，无逐 tick 推送。
2026-07-24 L2 冷启动包逐字节确认激活帧，订阅后 0.26s 即收到首个推送。

用法：
    uv run python tests/test_snapshot_push.py 603118           # 订阅共进股份
    uv run python tests/test_snapshot_push.py 603118 --secs 60 # 收 60 秒
    uv run python tests/test_snapshot_push.py 000938,603118    # 多只

注意：实时推送**盘中**（9:25-15:00）才有现价跳动，非交易时段只收开/收/高低
等静态字段跳动很慢。建议盘中运行。
"""
from __future__ import annotations

import datetime
import os
import sys
import time
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

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


def main() -> int:
    load_dotenv()
    username = os.environ.get("THS_USERNAME", "").strip()
    password = os.environ.get("THS_PASSWORD", "").strip()
    imei = os.environ.get("THS_IMEI", "").strip() or None
    if not username or not password:
        print("✗ 未设置 THS_USERNAME / THS_PASSWORD（.env 或环境变量）")
        return 1

    # 解析参数：代码列表 + --secs
    codes_arg = "603118"
    secs = 30.0
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    if args:
        codes_arg = args[0]
    if "--secs" in sys.argv:
        i = sys.argv.index("--secs")
        if i + 1 < len(sys.argv):
            secs = float(sys.argv[i + 1])
    codes = [c.strip() for c in codes_arg.split(",") if c.strip()]

    print("=" * 60)
    print("个股实时分时推送测试 — 8901 pageid=4214 逐 tick 快照")
    print("=" * 60)
    now = datetime.datetime.now()
    weekday = now.weekday()
    in_session = weekday < 5 and 9 <= now.hour < 16
    if not in_session:
        print(f"⚠ 当前 {now.strftime('%A %H:%M')} 非盘中（9:25-15:00 工作日），")
        print("  现价可能不跳动（只有静态字段慢更新）。建议盘中运行。")
    print(f"订阅代码: {codes}")
    print(f"采集时长: {secs}s")
    print()

    client = THSClient(username=username, password=password, imei=imei)
    try:
        print("→ 登录 8901...")
        result = client.connect()
        if not result.success:
            print(f"✗ 登录失败: {result.error} / {result.detail}")
            return 1
        print(f"✓ 登录成功，服务器 {result.server}")
        print()

        # 收到的推送计数
        push_count = {"n": 0}
        price_log: dict[str, list] = {c: [] for c in codes}
        lock = threading.Lock()

        def on_push(code, market, price, volume):
            with lock:
                push_count["n"] += 1
                if code in price_log:
                    price_log[code].append((time.time(), price))
                n = push_count["n"]
                ts = datetime.datetime.now().strftime("%H:%M:%S")
                if n <= 50 or n % 20 == 0:
                    print(f"  [{ts}] #{n:<4} {code} ({market}) "
                          f"现价={price:.3f} 量={volume}")

        # 订阅每只股票（自动用 __manual 身份开推送连接）
        print("→ __manual 推送连接 + pageid=4214 订阅...")
        any_ok = False
        for code in codes:
            ok = client.snapshot_subscribe(code, callback=on_push)
            any_ok = any_ok or ok
            status = "注册成功（CodeListSize≥1）" if ok else "注册失败（CodeListSize=0，检查L2权限）"
            print(f"  {'✓' if ok else '✗'} 订阅 {code}: {status}")
        if not any_ok:
            print("\n✗ 所有订阅都失败了")
            return 2
        print()

        # 等待推送
        print(f"→ 等待 {secs}s 收集推送（盯现价是否跳动）...")
        print("-" * 60)
        t0 = time.time()
        while time.time() - t0 < secs:
            time.sleep(1.0)
        print("-" * 60)

        # 汇总
        print()
        print("=" * 60)
        print("【汇总】")
        print("=" * 60)
        print(f"总推送帧数: {push_count['n']}")
        for code in codes:
            log = price_log[code]
            if not log:
                print(f"  {code}: 未收到推送")
                continue
            prices = [p for _, p in log]
            dur = log[-1][0] - log[0][0] if len(log) > 1 else 0
            print(f"  {code}: {len(log)} 帧，{dur:.1f}s 内，"
                  f"现价 {min(prices):.3f}-{max(prices):.3f}")
            # 打印现价序列（前 10 + 末 5）
            seq = " → ".join(f"{p:.2f}" for _, p in log[:10])
            if len(log) > 15:
                seq += " → ... → " + " → ".join(f"{p:.2f}" for _, p in log[-5:])
            elif len(log) > 10:
                seq += " → " + " → ".join(f"{p:.2f}" for _, p in log[10:])
            print(f"    序列: {seq}")

        if push_count["n"] == 0:
            print()
            print("✗ 未收到任何推送。可能原因：")
            print("  ① 非交易时段（盘后无逐笔成交）")
            print("  ② 账号无 level2 权限（普通账号走 9355 请求-响应，无逐 tick 推送）")
            print("  ③ 同花顺客户端未退出（同账号会话冲突，被 VerifyCode=-1 拒）")
            return 2

        print()
        print("✓ 实时分时推送验证成功！现价逐 tick 跳动 = 分时白线数据源。")
        return 0
    finally:
        client.disconnect()


if __name__ == "__main__":
    sys.exit(main())
