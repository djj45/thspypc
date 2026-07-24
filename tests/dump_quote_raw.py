#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
在线抓取 list_quotes 响应原始字节，用于手动对照字段值。

★ 用途：找封单额等未知字段的 dt 编号。
   原理：发 list_quotes 请求（带一堆字段），把服务器响应的原始字节存盘，
   你在同花顺界面上看某只股票（如 600000）的封单额精确数字，
   然后在存的字节里搜这个数字（THS float 编码），定位字段偏移。

⚠ 现在解析器不支持 cmd=0x0a 复合帧格式，所以只能存原始字节手动分析。
   这个脚本就是为这个场景写的。

用法：
    uv run python tests/dump_quote_raw.py
    uv run python tests/dump_quote_raw.py --codes 600000,600519
    uv run python tests/dump_quote_raw.py --codes 600000 --datatype 7,10,13,19,6,66,24,25,26,27,28,29,30,31,69

操作：
    1. 运行本脚本（自动登录、发请求、存原始字节）
    2. 在同花顺里看 600000 的封单额精确数字（如 12345678）
    3. 脚本会把数字转成 THS float 编码，你在输出里搜匹配的字节偏移

产物：
    captures_live/quote_raw_<时间戳>.bin  （原始响应字节）
    控制台打印：MarketTime + hd1.0 标记位置 + 前若干字节的 hex dump
"""
import argparse
import datetime
import json
import os
import sys
import struct

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from thspypc.client import THSClient
from thspypc.protocol import build_list_quote_query, read_frame, decode_ths_float

DUMP_DIR = os.path.join(os.path.dirname(__file__), "..", "captures_live")


def load_env():
    env_path = os.path.join(os.path.dirname(__file__), "..", ".env")
    if not os.path.exists(env_path):
        return
    for line in open(env_path, encoding="utf-8"):
        line = line.strip()
        if "=" in line and not line.startswith("#"):
            k, _, v = line.partition("=")
            k = k.strip()
            if k and k not in os.environ:
                os.environ[k] = v.strip().strip('"').strip("'")


def ths_float_to_bytes(value: float) -> list[bytes]:
    """把一个数值转成可能的 THS float 字节序列（4字节 LE，多种小数位尝试）。

    THS float 编码：把数值 ×10^dec 后存为 LE32 整数。dec 未知，所以尝试多种。
    返回所有可能的 4 字节编码。
    """
    candidates = []
    for dec in range(0, 5):  # 小数位 0~4
        scaled = int(round(value * (10 ** dec)))
        if 0 < abs(scaled) < 2**32:
            b = struct.pack("<I", scaled & 0xFFFFFFFF)
            candidates.append((dec, b))
            b_signed = struct.pack("<i", scaled if scaled < 2**31 else scaled - 2**32)
            if b_signed != b:
                candidates.append((dec, b_signed))
    return candidates


def search_value(raw: bytes, value: float, label: str):
    """在原始字节里搜一个数值的所有 THS float 编码位置。"""
    print(f"\n  搜 {label}={value}:")
    candidates = ths_float_to_bytes(value)
    found = False
    for dec, b in candidates:
        positions = []
        start = 0
        while True:
            p = raw.find(b, start)
            if p < 0:
                break
            positions.append(p)
            start = p + 1
        if positions:
            found = True
            for p in positions:
                # 显示该位置周围 12 字节
                ctx = raw[max(0, p-4):p+8].hex(' ')
                print(f"    dec={dec} 字节={b.hex()} 命中偏移 {p} (上下文: {ctx})")
    if not found:
        print(f"    ✗ 未找到（数值可能用了其他编码或不在本响应里）")


def main():
    load_env()
    ap = argparse.ArgumentParser(description="dump list_quotes 响应原始字节")
    ap.add_argument("--codes", default="600000",
                    help="股票代码（逗号分隔，默认 600000）")
    ap.add_argument("--datatype", default="7,10,13,19,6,66,24,25,26,27,28,29,30,31,69",
                    help="DataType 字段集（默认含已知+一堆未知编号）")
    ap.add_argument("--market", type=int, default=17, help="市场码 17=沪 33=深")
    args = ap.parse_args()

    codes = [c.strip() for c in args.codes.split(",") if c.strip()]
    datatype = [int(d) for d in args.datatype.split(",") if d.strip()]

    username = os.environ.get("THS_USERNAME", "")
    password = os.environ.get("THS_PASSWORD", "")
    if not username or not password:
        print("✗ 缺账号/密码")
        sys.exit(1)

    print("登录中...")
    client = THSClient(username, password)
    r = client.connect()
    if not r.success:
        print(f"✗ 登录失败: {r.error}")
        sys.exit(1)
    print(f"✓ {r.server}")

    # 构造请求，手动发 + 读原始响应（绕过 list_quotes 的解析）
    req = build_list_quote_query(codes, market=args.market, datatype=datatype)
    print(f"\n请求: {len(codes)} 只股票, DataType={datatype}")

    import threading
    with client._sock_lock:
        sock = client._sock
        sock.sendall(req + b"\n")
        sock.settimeout(10)
        # 读所有帧（可能多帧），拼成完整原始字节
        all_raw = b""
        for i in range(10):
            try:
                frame = read_frame(sock)
                all_raw += frame
            except Exception as e:
                print(f"  读帧{i}结束: {type(e).__name__}")
                break

    print(f"\n收到 {len(all_raw)} 字节原始响应")

    # 存盘
    os.makedirs(DUMP_DIR, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    bin_path = os.path.join(DUMP_DIR, f"quote_raw_{ts}.bin")
    with open(bin_path, "wb") as f:
        f.write(all_raw)
    print(f"已存: {bin_path}")

    # 分析：找 MarketTime / hd1.0 标记位置
    print(f"\n{'='*60}")
    print("响应结构分析:")
    print(f"{'='*60}")
    for marker in [b"MarketTime", b"hd1.0", b"hd3.1"]:
        pos = all_raw.find(marker)
        if pos >= 0:
            print(f"  {marker.decode()} @ 偏移 {pos}")
            print(f"    周围: {all_raw[pos:pos+40].hex(' ')}")

    # hex dump（前 256 字节 + hd1.0 附近）
    print(f"\n前 256 字节 hex dump:")
    for off in range(0, min(256, len(all_raw)), 16):
        chunk = all_raw[off:off+16]
        hexs = ' '.join(f'{b:02x}' for b in chunk)
        ascii_s = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        print(f"  {off:4d}: {hexs:<48} {ascii_s}")

    # ★ 核心：搜你关心的数值
    print(f"\n{'='*60}")
    print("★ 在同花顺里看 " + codes[0] + " 的以下数据，输入精确数字来搜:")
    print(f"{'='*60}")
    for label in ["封单额(元)", "成交额(元)", "现价", "昨收"]:
        try:
            val = input(f"  {label} (直接回车跳过): ").strip()
            if val:
                num = float(val)
                search_value(all_raw, num, label)
        except (ValueError, EOFError):
            continue

    client.disconnect()
    print(f"\n原始字节已存: {bin_path}")
    print(f"可用 hex 编辑器打开，对照同花顺数字手动分析")


if __name__ == "__main__":
    main()
