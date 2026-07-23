#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
测试反复 connect/disconnect 的行为：验证 IP 轮换 + 账号级 -1 封禁的时间窗口。

循环 N 次：connect → 立即 disconnect → 等待 interval 秒 → 重复。
对比不同 interval 下能否连续登录成功，以及每次是否连不同 IP。

用法：
    py tests/test_repeated_connect.py --rounds 5 --interval 0    # 立即重连（最易触发-1）
    py tests/test_repeated_connect.py --rounds 5 --interval 25   # 间隔25秒
"""
import argparse
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from thspypc.client import THSClient


def load_env():
    env_path = os.path.join(os.path.dirname(__file__), "..", ".env")
    if os.path.exists(env_path):
        for line in open(env_path, encoding="utf-8"):
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, _, v = line.partition("=")
                if k.strip() and k.strip() not in os.environ:
                    os.environ[k.strip()] = v.strip().strip('"').strip("'")


def main():
    load_env()
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, default=5, help="循环次数")
    ap.add_argument("--interval", type=float, default=0,
                    help="每次 disconnect 后等待秒数（0=立即重连，最易触发-1）")
    args = ap.parse_args()

    user = os.environ["THS_USERNAME"].strip()
    pwd = os.environ["THS_PASSWORD"].strip()

    print(f"反复 connect 测试：{args.rounds} 轮，间隔 {args.interval}s")
    print(f"{'轮次':<6}{'结果':<10}{'IP':<20}{'耗时':<10}{'备注'}")
    print("-" * 70)

    success_ips = []
    fail_streak = 0
    for i in range(1, args.rounds + 1):
        # 每轮用新 client（模拟每次新进程 connect/disconnect）。
        # IP 轮换偏移通过磁盘（~/.ths_ip_state.json）跨进程共享，所以新实例
        # 也能读到上一轮的 offset，实现跨进程 IP 分散。
        client = THSClient(user, pwd)
        t0 = time.time()
        r = client.connect()
        dt = time.time() - t0
        if r.success:
            ip = r.server.split(":")[0] if ":" in r.server else r.server
            reused = "复用" if r.error == "reused_existing_connection" else ""
            print(f"{i:<6}{'✓ 成功':<10}{ip:<20}{dt:>6.2f}s    {reused}")
            success_ips.append(ip)
            fail_streak = 0
        else:
            print(f"{i:<6}{'✗ 失败':<10}{'-':<20}{dt:>6.2f}s    {r.error}")
            fail_streak += 1
            # 连续失败 2 次说明已封禁，不必继续浪费
            if fail_streak >= 2:
                print(f"\n⚠ 连续 {fail_streak} 次失败，疑似 level2 单点登录会话冲突，停止测试")
                print(f"  （停止反复 connect 即恢复，无需等待；根本对策是长连接不反复 connect）")
                break
        client.disconnect()

        # 间隔等待（最后一轮不等）
        if i < args.rounds and args.interval > 0:
            print(f"      ... 等待 {args.interval}s ...")
            time.sleep(args.interval)

    # 汇总
    print(f"\n{'='*70}")
    print(f"成功 {len(success_ips)}/{args.rounds} 次")
    if success_ips:
        unique = len(set(success_ips))
        print(f"连接的 IP: {success_ips}")
        print(f"不同 IP 数: {unique}/{len(success_ips)}"
              + ("（IP 轮换生效）" if unique > 1 else "（同一 IP，轮换未生效或被冷却复用）"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
