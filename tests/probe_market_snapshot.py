#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
探针：发送全市场快照请求（空括号语法），分析响应格式。

这是路径 A 的验证工具——确认 build_market_snapshot_query 构造的请求能否让
服务器一次性返回沪深全市场行情。抓包发现 hexin 用 frame 1046 的
``DataType=[5],[55]`` + ``CodeList=16();17();...`` 空括号请求，~0.13s 拿全量。

本脚本：
  1. 登录 8901（复用已有 socket）
  2. 发送 build_market_snapshot_query
  3. 读多帧响应，dump 每帧的标记/大小/格式特征
  4. 尝试 snappy 解压 + hd3.1/hd1.0 解码，判断响应格式
  5. 把原始响应存盘供离线逆向

用法：
    py tests/probe_market_snapshot.py              # 默认市场（沪深全）
    py tests/probe_market_snapshot.py --markets 17 # 只沪市
    py tests/probe_market_snapshot.py --verbose    # 详细 hex dump
"""
from __future__ import annotations

import os
import struct
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from thspypc import THSClient
from thspypc.protocol import (
    build_market_snapshot_query,
    parse_hd3_response,
    parse_hd1_response,
    read_frame,
)


def _load_env():
    env_path = os.path.join(os.path.dirname(__file__), "..", ".env")
    if not os.path.exists(env_path):
        return
    for line in open(env_path, encoding="utf-8"):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            if k.strip() and k.strip() not in os.environ:
                os.environ[k.strip()] = v.strip().strip('"').strip("'")


def _try_snappy(data: bytes) -> bytes | None:
    """尝试 snappy 解压，失败返回 None。"""
    try:
        import snappy
        return snappy.decompress(data)
    except Exception:
        return None


def _analyze_frame(frame: bytes, idx: int, verbose: bool) -> dict:
    """分析单帧响应，返回格式特征 dict。"""
    info = {"idx": idx, "len": len(frame), "markers": [], "format": "?"}
    # 扫描标记
    for marker, name in [
        (b"hd3.1\x00", "hd3.1"), (b"hd1.0", "hd1.0"),
        (b"MarketTime=", "MarketTime"), (b"MarketCode=", "MarketCode"),
        (b"CodeListSize=", "CodeListSize"), (b"SortTotal=", "SortTotal"),
        (b"errorcode=", "errorcode"), (b"rettype=", "rettype"),
        (b"fdfdfdfd", "fdfdfdfd"),
    ]:
        if marker in frame:
            pos = frame.find(marker)
            info["markers"].append(f"{name}@{pos}")
    # 判断格式
    if b"hd3.1\x00" in frame:
        info["format"] = "hd3.1"
    elif b"hd1.0" in frame:
        info["format"] = "hd1.0"
    elif b"errorcode=" in frame:
        info["format"] = "error/ack"
    elif frame[:4] != b"\xfd\xfd\xfd\xfd" and len(frame) > 100:
        # 无 magic 的大块二进制 → 可能是 snappy/裸数据
        decompressed = _try_snappy(frame)
        if decompressed:
            info["format"] = f"snappy→{len(decompressed)}B"
            info["decompressed"] = decompressed
        else:
            info["format"] = "binary(未知)"
    return info


def main():
    verbose = "--verbose" in sys.argv
    _load_env()
    user = os.environ.get("THS_USERNAME", "").strip()
    pwd = os.environ.get("THS_PASSWORD", "").strip()
    if not user or not pwd:
        print("✗ 未配置 .env 的 THS_USERNAME/THS_PASSWORD")
        return 1

    # 解析 --markets
    markets = None
    for i, a in enumerate(sys.argv):
        if a == "--markets" and i + 1 < len(sys.argv):
            markets = [int(x) for x in sys.argv[i + 1].split(",")]

    print(f"账号: {user[:3]}***")
    client = THSClient(user, pwd, enable_heartbeat=False)
    r = client.connect()
    if not r.success:
        print(f"✗ 登录失败: {r.error}")
        return 1
    print(f"✓ 登录成功: {r.server}")

    # 构造并发送快照请求
    req = build_market_snapshot_query(markets=markets)
    print(f"\n发送全市场快照请求（markets={markets or '沪深全'}, {len(req)}B）...")
    text_preview = req[12 + 23:12 + 23 + 80].decode("gbk", errors="replace")
    print(f"  请求文本预览: {text_preview[:70]!r}")

    import socket
    sock = client._sock
    sock.sendall(req + b"\n")
    sock.settimeout(3.0)

    # 读多帧响应（最多读 20 帧 / 15s）
    frames_raw = []
    deadline = time.time() + 15
    while time.time() < deadline and len(frames_raw) < 20:
        try:
            resp = read_frame(sock)
            if resp:
                frames_raw.append(resp)
        except (socket.timeout, OSError):
            break
        except ValueError:
            # 魔数碰撞/帧错位，尝试跳过
            try:
                sock.settimeout(1.0)
                sock.recv(8192)
                sock.settimeout(3.0)
            except Exception:
                pass
            continue
        # 拿到数据后再读 2s 确认无更多帧
        if frames_raw:
            sock.settimeout(2.0)

    print(f"\n收到 {len(frames_raw)} 帧，总 {sum(len(f) for f in frames_raw):,} 字节")
    if not frames_raw:
        print("✗ 无响应（可能请求格式未被服务器接受，或需盘中）")
        client.disconnect()
        return 1

    # 分析每帧
    print(f"\n{'帧':>3} {'大小':>8}  {'格式':<16} 标记")
    print("-" * 70)
    total_records = 0
    big_binary_frames = []
    for i, fr in enumerate(frames_raw):
        info = _analyze_frame(fr, i, verbose)
        print(f"{i:>3} {info['len']:>8,}  {info['format']:<16} {', '.join(info['markers'])}")
        if info["format"].startswith("snappy") or info["format"] == "binary(未知)":
            big_binary_frames.append((i, fr, info))

        # 尝试用现有解码器解析 hd3.1/hd1.0
        if b"hd3.1\x00" in fr:
            recs = parse_hd3_response(fr)
            if recs:
                total_records += len(recs)
                print(f"     ↳ hd3.1 解出 {len(recs)} 条记录, 示例: {recs[0]}")
        elif b"hd1.0" in fr:
            recs = parse_hd1_response(fr)
            if recs:
                total_records += len(recs)
                print(f"     ↳ hd1.0 解出 {len(recs)} 条记录, 示例: {recs[0]}")

    if total_records:
        print(f"\n★ 现有解码器共解出 {total_records} 条记录")

    # 重点分析大二进制帧（可能是 snappy/hqfile）
    if big_binary_frames:
        print(f"\n{'='*70}")
        print(f"大二进制帧分析（{len(big_binary_frames)} 帧，可能是 snappy 压缩的全量数据）")
        print(f"{'='*70}")
        for i, fr, info in big_binary_frames[:3]:
            print(f"\n帧 {i} ({len(fr):,}B), 格式={info['format']}")
            print(f"  前 64B hex: {fr[:64].hex(' ')}")
            decompressed = info.get("decompressed")
            if decompressed:
                print(f"  snappy 解压后 {len(decompressed):,}B")
                print(f"  解压后前 100B hex: {decompressed[:100].hex(' ')}")
                # 解压后找 hd3.1/hd1.0 标记
                for marker in [b"hd3.1\x00", b"hd1.0", b"MarketTime"]:
                    if marker in decompressed:
                        print(f"  解压后含标记: {marker}")
                text = decompressed[:200].decode("gbk", errors="replace")
                print(f"  解压后文本预览: {text[:100]!r}")
            if verbose:
                print(f"  完整 hex (前 256B): {fr[:256].hex(' ')}")

    # 存盘供离线逆向
    dump_dir = os.path.join(os.path.dirname(__file__), "..", "captures_live")
    os.makedirs(dump_dir, exist_ok=True)
    dump_path = os.path.join(dump_dir, "snapshot_response_0.bin")
    # 存最大的那一帧
    biggest = max(frames_raw, key=len)
    with open(dump_path, "wb") as f:
        f.write(biggest)
    print(f"\n最大帧已存盘: {dump_path} ({len(biggest):,}B)")
    print("可用 hexdump / Wireshark 离线分析")

    client.disconnect()
    return 0


if __name__ == "__main__":
    sys.exit(main())
