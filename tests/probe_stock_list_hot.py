#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
探针脚本：定位 thspypc 的 stock_list_hot()（DataType=199112）为何超时无响应。

背景：2026-07-23 开盘抓包发现 hexin 客户端的 199112 请求能走通（每页 40 条
倒序翻页），但 thspypc 发同样的请求始终超时。对比 hexin vs thspypc 的请求帧，
定位到 4 个候选差异。本脚本对每个差异做 A/B 测试，找出真凶。

候选差异（hexin 走通值 → thspypc 当前值）：
  1. route 标签：  0x0139 (hexin) vs 0x0156 (thspypc)
  2. 市场码：      17();22();33(); (hexin) vs 17();22();151(); (thspypc)
  3. pageid：      1333 (hexin) vs 1334 (thspypc)
  4. SortCount：   40 (hexin) vs 29 (thspypc)

用法：
    uv run python tests/probe_stock_list_hot.py
"""
import argparse
import os
import socket
import struct
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from thspypc.client import THSClient
from thspypc import protocol as proto
from thspypc.protocol import (
    encode_frame, read_frame, parse_stock_list_response, FRAME_MAGIC,
)


def build_199112_query(
    markets=(17, 22, 33),
    sort_count=40,
    sort_begin=0,
    pageid=1333,
    route=0x0139,
    seq=0x1124,
):
    """构造 199112 请求帧（参数可调，默认用 hexin 抓包真值）。

    与 protocol.build_stock_list_query 的差异：route/pageid/seq/markets 默认值
    对齐 hexin 抓包（route=0x0139, pageid=1333, seq=0x1124, markets 含 33）。
    """
    codelist = "".join(f"{m}();" for m in markets)
    text = (
        f"CodeList={codelist}\r\nDataType=199112,\r\n"
        f"SortType=Sort\r\nSortBy=199112\r\nSortDir=D\r\nSortAppend=YC\r\n"
        f"SortBegin={sort_begin}\r\nSortCount={sort_count}\r\n"
        f"FuncPeriod=0\r\nDateTime=0(0-0)\r\n"
        f"LackTime=0,0,0,0,0,0,0,0\r\npageid={pageid}\r"
    ).encode("gbk")
    hdr = bytearray(23)
    hdr[0] = 0x09
    hdr[1:5] = b"\x00\x16\x00\x00"
    struct.pack_into("<H", hdr, 5, seq & 0xFFFF)
    hdr[7:11] = b"\x12\x00\x0f\x00"  # subtype 0x000f（排序代码表查询）
    struct.pack_into("<H", hdr, 11, route & 0xFFFF)
    struct.pack_into("<H", hdr, 19, len(text) + 1)
    return encode_frame(bytes(hdr) + text)


def try_request(client, label, dump=False, **kwargs):
    """发一个 199112 请求，循环读帧直到拿到 stock_list 数据帧。

    服务器响应可能含多个子帧（心跳/CodeListSize/MarketTime 等文本帧在前，
    hd3.1 数据帧在后），需循环读取（同 list_quotes 的已知模式）。
    """
    req = build_199112_query(**kwargs)
    sock = client._sock
    timeout = 8.0
    frames_read = []
    with client._sock_lock:
        sock.sendall(req)
        sock.settimeout(timeout)
        t0 = time.time()
        # 循环读帧（最多 8 帧 / 6 秒），找 stock_list 数据帧
        for _ in range(8):
            if time.time() - t0 > 6:
                break
            try:
                resp = read_frame(sock)
            except (socket.timeout, OSError):
                break
            except ValueError:
                # read_frame 魔数碰撞，跳过
                try:
                    sock.settimeout(1.0)
                    sock.recv(8192)
                except Exception:
                    pass
                continue
            if not resp:
                continue
            frames_read.append(resp)
            meta = parse_stock_list_response(resp)
            n = len(meta.get("stocks", []))
            if n > 0:
                total = meta.get("sort_total", 0)
                print(f"  [{label}] ✓ 拿到 {n} 条（共 {total}），读了 {len(frames_read)} 帧")
                return True, n, f"sort_total={total}, {len(frames_read)}帧"

    if not frames_read:
        print(f"  [{label}] ✗ 超时/失败: 无响应")
        return False, 0, "timeout"
    # 读到帧但都不是 stock_list 数据帧
    if dump:
        print(f"  [{label}] 读到 {len(frames_read)} 帧，均非 stock_list 数据帧:")
        for i, fr in enumerate(frames_read[:3]):
            head = fr[:50].decode("gbk", errors="replace")
            markers = [m.decode("ascii", errors="replace") for m in
                       (b"hd3.1", b"hd1.0", b"SortTotal", b"10,") if m in fr]
            print(f"    帧{i}({len(fr)}B): {head[:40]!r} 标记={markers}")
    else:
        head = frames_read[0][:60].decode("gbk", errors="replace").replace("\r", "\\r").replace("\n", "\\n")
        print(f"  [{label}] ~ {len(frames_read)} 帧非 stock_list: {head[:50]}")
    return True, 0, f"{len(frames_read)}帧非数据帧"


def main():
    ap = argparse.ArgumentParser(description="探测 199112 请求为何超时")
    ap.add_argument("--user", default=None)
    ap.add_argument("--pwd", default=None)
    ap.add_argument("--host", default=None,
                    help="强制连指定 8901 IP（如 hexin 抓包里的 139.9.188.254）")
    args = ap.parse_args()

    # --host: 把指定 IP 前置到 MARKET_HOSTS（只连这个 IP）
    if args.host:
        proto.MARKET_HOSTS.insert(0, args.host)
        print(f"⚠ 强制连 {args.host}:8901（前置到 MARKET_HOSTS）")

    # 读 .env
    env_path = os.path.join(os.path.dirname(__file__), "..", ".env")
    if os.path.exists(env_path):
        for line in open(env_path, encoding="utf-8"):
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, _, v = line.partition("=")
                k = k.strip()
                if k and k not in os.environ:
                    os.environ[k] = v.strip().strip('"').strip("'")
    username = args.user or os.environ.get("THS_USERNAME", "")
    password = args.pwd or os.environ.get("THS_PASSWORD", "")

    print("登录中...")
    client = THSClient(username, password)
    result = client.connect()
    server = result.server if result and result.success else "?"
    print(f"✓ 登录成功，服务器: {server}\n")

    if not result.success:
        print("✗ 登录失败，无法测试")
        return

    # 步骤 1：先用 list_quotes 确认这条连接本身是好的（对照组）
    print("=" * 60)
    print("步骤 1：list_quotes 对照（确认连接可用）")
    print("=" * 60)
    try:
        recs = client.list_quotes(["600000", "600001", "600002"], market=17)
        print(f"  ✓ list_quotes 成功，拿到 {len(recs)} 条")
        lq_ok = len(recs) > 0
    except Exception as e:
        print(f"  ✗ list_quotes 失败: {e}")
        lq_ok = False

    # 步骤 2：同一条连接上发 199112（route=0x0139，hexin 今天抓包真值）
    print(f"\n{'=' * 60}")
    print("步骤 2：同连接发 199112（route=0x0139，hexin 抓包真值）")
    print("=" * 60)
    ok1, n1, d1 = try_request(client, "route=0x0139", dump=True, markets=(17, 22, 33),
                               route=0x0139, pageid=1333, sort_count=40, seq=0x1124)

    # 步骤 3：如果还不行，试 route=0x0001（和 list_quotes 一样的路由）
    if not ok1 or n1 == 0:
        print(f"\n{'=' * 60}")
        print("步骤 3：试 route=0x0001（和 list_quotes 相同的路由标签）")
        print("=" * 60)
        ok2, n2, d2 = try_request(client, "route=0x0001", dump=True, markets=(17, 22, 33),
                                   route=0x0001, pageid=1333, sort_count=40, seq=0x1124)
    else:
        ok2, n2, d2 = False, 0, "跳过"

    print(f"\n{'=' * 60}")
    print("结论")
    print("=" * 60)
    print(f"  服务器:          {server}")
    print(f"  list_quotes:     {'✓ 能用' if lq_ok else '✗ 也不能用'}")
    print(f"  199112 r=0x0139: {'✓' if ok1 and n1>0 else '✗'} ({d1})")
    print(f"  199112 r=0x0001: {'✓' if ok2 and n2>0 else '✗'} ({d2})")
    if lq_ok and (ok1 and n1 > 0):
        print("\n  ★ route=0x0139 成功！根因就是 route 标签，与 login 无关。")
    elif lq_ok and (ok2 and n2 > 0):
        print("\n  ★ route=0x0001 成功！0x0139/0x0156 路由不到，用 list_quotes 的路由。")
    elif lq_ok and not (ok1 and n1 > 0) and not (ok2 and n2 > 0):
        print(f"\n  ⚠ list_quotes 能用但 199112 两种 route 都超时。")
        print(f"    → 不是 route 问题，也不是 login 问题。")
        print(f"    → 下一步：抓包看 hexin 的 199112 连的哪个服务器（IP={server.split(':')[0] if ':' in server else server}）")

    try:
        client.disconnect()
    except Exception:
        pass


if __name__ == "__main__":
    main()
