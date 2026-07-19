#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
thspypc 全市场股票列表（stock_list）测试。

两种模式：

1. 离线回归（无需账号/网络）—— 用 cold_start.pcap 验证解码链：
       uv run python tests/test_stock_list.py --offline
   验证 parse_init_response 把 dc=7526 全量帧解出 7524+ 条代码。

2. 活网端到端（需账号）—— 登录后重放请求序列拿全量代码表：
       uv run python tests/test_stock_list.py
   默认读 .env 的 THS_USERNAME/THS_PASSWORD。重放 4 个请求段后服务器推送
   dc≈7422 全量 hd3.1 帧，解码出 ~7400 条代码（600000/600009/...920992）。

输出：获取的代码总数 + 前/后若干样本 + 前缀分布。
"""
from __future__ import annotations

import os
import sys
import subprocess
import struct
from collections import Counter

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from thspypc import THSClient, parse_init_response

# cold_start.pcap 是 thspy 项目里的 Windows 冷启动抓包（含 dc=7526 全量帧）
COLD_START_PCAP = r"D:\code\thspy\captures\cold_start.pcap"
TSHARK = r"D:\software\Wireshark_4.6.7_Portable\Wireshark\WiresharkPortable64\App\Wireshark\tshark.exe"
FRAME_MAGIC = b"\xfd\xfd\xfd\xfd"


def test_offline():
    """离线回归：用 cold_start.pcap 验证 parse_init_response 解码 dc=7526 全量帧。"""
    if not os.path.exists(COLD_START_PCAP):
        print(f"✗ 离线 pcap 不存在: {COLD_START_PCAP}")
        print("  （cold_start.pcap 是 Windows 冷启动抓包，含 dc=7526 全量帧）")
        return 1
    print(f"离线 pcap: {COLD_START_PCAP}")

    # 重组 stream 44 服务器下行
    r = subprocess.run(
        [TSHARK, "-r", COLD_START_PCAP, "-Y",
         "tcp.stream==44 and tcp.len>0",
         "-T", "fields", "-e", "ip.src", "-e", "tcp.payload"],
        capture_output=True, timeout=120)
    server_data = b""
    for ln in r.stdout.decode().splitlines():
        p = ln.split("\t")
        if len(p) < 2 or p[0].startswith("192.168"):
            continue
        try:
            server_data += bytes.fromhex(p[1].replace(":", ""))
        except ValueError:
            continue

    # 用项目 magic 切帧
    frames = []
    i = 0
    while i < len(server_data):
        p = server_data.find(FRAME_MAGIC, i)
        if p < 0 or p + 12 > len(server_data):
            break
        try:
            bl = int(server_data[p+4:p+12], 16)
        except ValueError:
            i = p + 4
            continue
        if 0 < bl < 500000:
            frames.append(server_data[p+12:p+12+bl])
            i = p + 12 + bl
        else:
            i = p + 4
    print(f"切出 {len(frames)} 个完整帧")

    # 用 parse_init_response 解码，取 stocks 最多的帧
    best_stocks = []
    full_dc = 0
    for fr in frames:
        meta = parse_init_response(fr)
        if len(meta["stocks"]) > len(best_stocks):
            best_stocks = meta["stocks"]
            for f in meta.get("hd31_frames", []):
                if f["unk"] == 0x18 and f["dc"] > 5000:
                    full_dc = f["dc"]

    print(f"\n=== 结果 ===")
    print(f"全量帧 dc={full_dc}")
    print(f"解码 {len(best_stocks)} 条代码")
    if best_stocks:
        valid = sum(1 for s in best_stocks
                    if len(s["code"]) == 6 and s["code"].isdigit())
        print(f"完整 6 位数字代码: {valid}/{len(best_stocks)}")
        print(f"前 8: {[s['code'] for s in best_stocks[:8]]}")
        print(f"后 5: {[s['code'] for s in best_stocks[-5:]]}")
        pre = Counter(s["code"][:3] for s in best_stocks if len(s["code"]) >= 3)
        print(f"前缀分布(top10): {dict(pre.most_common(10))}")
        if len(best_stocks) >= 7000:
            print(f"\n✓ 离线解码成功（{len(best_stocks)} 条 >= 7000）")
            return 0
        else:
            print(f"\n✗ 解码数量不足（{len(best_stocks)} < 7000）")
            return 1
    print("\n✗ 未解码出 stocks")
    return 1


def load_dotenv():
    env_path = os.path.join(os.path.dirname(__file__), "..", ".env")
    if not os.path.exists(env_path):
        return
    for line in open(env_path, encoding="utf-8"):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            if k.strip() and k.strip() not in os.environ:
                os.environ[k.strip()] = v.strip().strip('"').strip("'")


def test_live():
    """活网端到端：登录 + 重放请求序列 + 解码全量代码表。"""
    load_dotenv()
    user = os.environ.get("THS_USERNAME", "").strip()
    pwd = os.environ.get("THS_PASSWORD", "").strip()
    if not user or not pwd:
        print("✗ 未配置 .env 的 THS_USERNAME/THS_PASSWORD")
        return 1
    print(f"账号: {user[:3]}***")

    client = THSClient(user, pwd, enable_heartbeat=False)
    r = client.connect()
    if not r.success:
        print(f"✗ 登录失败: {r.error}")
        return 1
    print(f"✓ 登录成功: {r.server}")

    print(f"\n调用 stock_list()（重放请求序列，~30s）...")
    import time
    t0 = time.time()
    stocks = client.stock_list(timeout=30)
    elapsed = time.time() - t0
    print(f"✓ 获取 {len(stocks)} 条代码（{elapsed:.1f}s）")

    if stocks:
        print(f"  前 8: {[s['code'] for s in stocks[:8]]}")
        print(f"  后 5: {[s['code'] for s in stocks[-5:]]}")
        pre = Counter(s["code"][:3] for s in stocks if len(s["code"]) >= 3)
        print(f"  前缀分布(top10): {dict(pre.most_common(10))}")
        if len(stocks) >= 7000:
            print(f"\n✓ 活网测试成功（{len(stocks)} 条）")
            rc = 0
        else:
            print(f"\n⚠ 数量偏少（{len(stocks)} < 7000，可能服务器未响应全量）")
            rc = 1
    else:
        print("\n✗ 未获取到代码（重放失败，可能需要换 IP 重试）")
        rc = 1

    client.disconnect()
    return rc


def main():
    if "--offline" in sys.argv:
        return test_offline()
    return test_live()


if __name__ == "__main__":
    raise SystemExit(main())
