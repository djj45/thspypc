#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
探针脚本：在 stock_list 重放序列末尾追加 upstockname 请求，捕获名称响应帧。

关键发现：upstockname 请求必须在 stock_list 重放后、读取响应前发送。
若单独发送或在 stock_list 之后发送，服务器不响应或断连。

用法：
  py tests/probe_upstockname.py                        # 默认 ;; 测试
  py tests/probe_upstockname.py --save-all             # 保存所有收到的帧
"""
from __future__ import annotations

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from thspypc.client import THSClient
from thspypc.protocol import read_frame, parse_init_response

CAPTURE_DIR = os.path.join(os.path.dirname(__file__), "..", "captures_live")
os.makedirs(CAPTURE_DIR, exist_ok=True)


def build_upstockname_request(market: str = "URS",
                               stock_name_ver: str = ";;") -> bytes:
    """构造 upstockname 请求帧（纯文本帧，\\x09 分隔）。"""
    body = (
        f"instid=65536\n"
        f"method=upstockname\n"
        f"market={market}\n"
        f"StockNameVer={stock_name_ver}\n"
        f"prototype=kvproto\n"
        f"pageid=5716\n"
    )
    return b"\x09" + body.encode("gbk")


def main():
    parser = argparse.ArgumentParser(description="upstockname 探针")
    parser.add_argument("--market", default="URS",
                        help="市场代码，默认 URS")
    parser.add_argument("--ver", default=";;",
                        help="StockNameVer 值，默认 ';;'")
    parser.add_argument("--user", default=None, help="同花顺账号")
    parser.add_argument("--pwd", default=None, help="同花顺密码")
    parser.add_argument("--save-all", action="store_true",
                        help="保存所有收到的帧（不只是名称帧）")
    parser.add_argument("--timeout", type=float, default=20.0,
                        help="总等待时间（秒），默认 20")
    args = parser.parse_args()

    # 加载 .env
    env_path = os.path.join(os.path.dirname(__file__), "..", ".env")
    if os.path.exists(env_path):
        with open(env_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    if k.strip() and k.strip() not in os.environ:
                        os.environ[k.strip()] = v.strip().strip('"').strip("'")
    user = args.user or os.environ.get("THS_USERNAME", "").strip()
    pwd = args.pwd or os.environ.get("THS_PASSWORD", "").strip()
    if not user or not pwd:
        print("请设置 .env 的 THS_USERNAME/THS_PASSWORD 或用 --user/--pwd 指定")
        return 1

    # ── 连接 ──
    print("连接 thspypc...")
    client = THSClient(user, pwd)
    client.connect()
    print(f"已登录 (instance={client._instance})")

    # ── 加载重放段 ──
    replay_path = os.path.join(os.path.dirname(__file__), "..",
                               "src", "thspypc", "data", "stock_list_replay.bin")
    if not os.path.exists(replay_path):
        print(f"重放文件不存在: {replay_path}")
        client._sock.close()
        return 1
    with open(replay_path, "rb") as f:
        data = f.read()
    n = int.from_bytes(data[:4], "little")
    off = 4
    segments = []
    for _ in range(n):
        ln = int.from_bytes(data[off:off + 4], "little")
        off += 4
        segments.append(data[off:off + ln])
        off += ln
    print(f"加载 {n} 个重放段")

    # ── 构造 upstockname 请求 ──
    up_req = build_upstockname_request(args.market, args.ver)
    print(f"upstockname 请求 ({len(up_req)}B): {up_req[:120]}...")

    # ── 发送：重放段 + upstockname（都在读取响应之前）──
    with client._sock_lock:
        sock = client._sock
        print("发送重放段...")
        for i, seg in enumerate(segments):
            sock.sendall(seg)
            time.sleep(0.3)
        print("发送 upstockname 请求...")
        sock.sendall(up_req)

        # ── 读取响应 ──
        sock.settimeout(2.0)
        t0 = time.time()
        got_full_at = None
        best_stocks = []
        name_frames = []
        all_frames = []

        while True:
            if got_full_at and (time.time() - got_full_at > 3):
                break
            if not got_full_at and (time.time() - t0 > args.timeout):
                break
            try:
                resp = read_frame(sock)
                if not resp:
                    continue
            except (socket.timeout, OSError):
                continue
            except ValueError:
                try:
                    sock.settimeout(1.0)
                    sock.recv(8192)
                    sock.settimeout(2.0)
                except Exception:
                    pass
                continue

            all_frames.append(resp)

            # 检查是否 hd3.1 全量代码表帧
            meta = parse_init_response(resp)
            if len(meta["stocks"]) > len(best_stocks):
                best_stocks = meta["stocks"]
                for f in meta.get("hd31_frames", []):
                    if f["unk"] == 0x18 and f["dc"] > 5000:
                        full_dc = f["dc"]
                        got_full_at = time.time()
                        print(f"  ✓ 全量代码表帧 dc={full_dc}")
                        break

            # 检查是否 upstockname 名称帧（包含 "MarketCode=" 关键字）
            if b"MarketCode" in resp or b"StockNameVer" in resp or b"[name_" in resp:
                name_frames.append(resp)
                print(f"  ✓ 名称帧 ({len(resp)}B)")

    print(f"\n结果: {len(best_stocks)} 条代码, {len(name_frames)} 个名称帧, "
          f"{len(all_frames)} 个总帧")

    # ── 保存名称帧 ──
    if name_frames:
        for i, nf in enumerate(name_frames):
            fname = f"upstockname_m{args.market}_v{args.ver.replace(';','_')}_{i}.bin"
            fpath = os.path.join(CAPTURE_DIR, fname)
            with open(fpath, "wb") as f:
                f.write(nf)
            print(f"保存名称帧: {fpath} ({len(nf)}B)")

            # 预览
            preview = ""
            for b in nf[:400]:
                if 32 <= b < 127:
                    preview += chr(b)
                else:
                    preview += "."
            print(f"  预览: {preview}")

    # ── 保存所有帧 ──
    if args.save_all and all_frames:
        for i, af in enumerate(all_frames):
            fpath = os.path.join(CAPTURE_DIR, f"upstockname_all_{i}.bin")
            with open(fpath, "wb") as f:
                f.write(af)

    # 清理
    if client._sock:
        try:
            client._sock.close()
        except Exception:
            pass
    print("\n完成")
    return 0


if __name__ == "__main__":
    import socket
    raise SystemExit(main())
