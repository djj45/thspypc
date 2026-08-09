#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
hfd1.0 格式逆向对照采集器（路径 ①：thspypc 自造明文真值）。

原理：hfd1.0 是 PC 版"空括号全市场快照"的响应格式（位压缩，未解）。
本脚本同时采集两份数据，供离线对照逆向：

  1. 密文：发空括号请求 → 拿 hfd1.0 完整响应（326KB，仅含 code+name）
  2. 明文：用 list_quotes 逐批查 [5(code), 55(name)] → 拿到明文 code+name 真值

两份的「(code, name GBK 字节)」应一一对应。用明文锚点定位 hfd1.0 记录边界，
进而破解其位压缩格式。

采集产物（data/ 目录）：
  - hfd1_0_response.bin    完整 hfd1.0 密文响应
  - oracle_code_names.json 明文 (code, name, name_gbk_hex) 列表（list_quotes）
  - hfd1_0_name_anchors.json  密文中定位到的 (name_gbk_hex, offset) 锚点

用法：
    py tests/collect_snapshot_oracle.py                # 默认采沪市前 60 只
    py tests/collect_snapshot_oracle.py --count 200    # 采 200 只（更密锚点）
    py tests/collect_snapshot_oracle.py --sh --sz      # 沪+深
"""
from __future__ import annotations

import json
import os
import re
import struct
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from thspypc import THSClient
from thspypc.protocol import build_market_snapshot_query, read_frame


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


def collect_hfd1_0_response(client: THSClient) -> bytes:
    """发空括号全市场请求，拿 hfd1.0 完整响应（raw 字节）。"""
    req = build_market_snapshot_query()
    import socket
    sock = client._sock
    sock.sendall(req + b"\n")
    # 用 read_frame 拿帧体（探针验证过：单帧 ~326KB）
    sock.settimeout(10.0)
    # 跳过可能的 leading 0x0a
    try:
        resp = read_frame(sock)
    except (socket.timeout, OSError, ValueError):
        resp = b""
    return resp


def connect_working_host(username: str, password: str, max_tries: int = 5) -> THSClient | None:
    """反复重试连接，直到拿到能响应 hfd1.0 的 host（服务器实例行为不一致）。

    实测 122.9.202.190 能返回 326KB 全量，但有时 VerifyCode=-1 导致 connect()
    回退到 .125.190（该实例不响应空括号快照）。本函数重试直到连上能用的 host。
    """
    for attempt in range(max_tries):
        client = THSClient(username, password, enable_heartbeat=False)
        r = client.connect()
        if not r.success:
            print(f"  尝试 {attempt+1}: 登录失败 ({r.error})，重试...")
            continue
        # 验证该 host 能响应 hfd1.0（发一个小试探）
        print(f"  尝试 {attempt+1}: 连上 {r.server}，验证快照响应...")
        test = collect_hfd1_0_response(client)
        if len(test) > 10000 and b"hfd1.0" in test:
            print(f"  ✓ 该 host 响应正常（{len(test):,}B）")
            # 把这次的响应存为缓存（避免下面重复请求）
            client._cached_hfd1 = test
            return client
        print(f"  ✗ 该 host 快照响应异常（{len(test)}B），换 host 重试...")
        client.disconnect()
    return None


def collect_oracle_names(client: THSClient, codes: list[str], market: int) -> list[dict]:
    """用 list_quotes(datatype=[5,55]) 采明文 code+name，分批查询。

    batch_size=5（≤5 走 hd1.0 明文格式，最稳定；大批量 hd3.1 偶发解析问题）。
    """
    oracle = []
    batch_size = 5
    for i in range(0, len(codes), batch_size):
        batch = codes[i:i + batch_size]
        try:
            recs = client.list_quotes(batch, market=market, datatype=[5, 55], timeout=12)
        except Exception as e:
            print(f"  批 {i}-{i+len(batch)} 查询失败: {e}")
            continue
        for r in recs:
            code = r.get("code", "")
            raw = r.get("dt55_raw", b"")
            # dt55_raw 是 64B，名称在开头（GBK），\x00 结束
            name_gbk = raw.split(b"\x00")[0] if raw else b""
            try:
                name = name_gbk.decode("gbk")
            except UnicodeDecodeError:
                name = name_gbk.decode("gbk", errors="replace")
            if code and name_gbk:
                oracle.append({
                    "code": code,
                    "name": name,
                    "name_gbk_hex": name_gbk.hex(),
                })
        time.sleep(0.15)  # 避免太快被限流
    return oracle


def find_name_anchors(hfd1_data: bytes, oracle: list[dict]) -> list[dict]:
    """在 hfd1.0 密文中定位 oracle 名称的 GBK 字节，记录锚点 + 前后上下文。"""
    anchors = []
    for item in oracle:
        name_gbk = bytes.fromhex(item["name_gbk_hex"])
        idx = hfd1_data.find(name_gbk)
        if idx >= 0:
            # 名称前的上下文（含被压缩的代码）
            pre = hfd1_data[max(0, idx - 15):idx]
            post = hfd1_data[idx:idx + len(name_gbk) + 8]
            anchors.append({
                "code": item["code"],
                "name": item["name"],
                "name_offset": idx,
                "pre_hex": pre.hex(),
                "post_hex": post.hex(),
                "pre_text": pre.decode("ascii", errors="replace"),
            })
    return anchors


def analyze_compression(anchors: list[dict]) -> None:
    """分析锚点前缀的代码压缩模式。"""
    print(f"\n{'='*70}")
    print("【代码压缩模式分析】（名称前的字节 vs 真实代码）")
    print(f"{'='*70}")
    print(f"{'code':8s} {'pre_hex':30s} pre_ascii")
    print("-" * 70)
    for a in anchors[:20]:
        print(f"{a['code']:8s} {a['pre_hex']:30s} {a['pre_text']!r}")


def main():
    count = 60
    do_sh = True
    do_sz = False
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "--count" and i + 1 < len(args):
            count = int(args[i + 1]); i += 2
        elif args[i] == "--sh":
            do_sh = True; i += 1
        elif args[i] == "--sz":
            do_sz = True; i += 1
        else:
            i += 1

    _load_env()
    user = os.environ.get("THS_USERNAME", "").strip()
    pwd = os.environ.get("THS_PASSWORD", "").strip()
    if not user or not pwd:
        print("✗ 未配置 .env")
        return 1

    data_dir = os.path.join(os.path.dirname(__file__), "..", "data")
    os.makedirs(data_dir, exist_ok=True)

    # ── 1. 先采明文 code+name（用独立连接 A，避免空括号请求干扰）──
    print("[1/3] 采明文 code+name（list_queries [5,55]，连接 A）...")
    client_a = THSClient(user, pwd, enable_heartbeat=False)
    r = client_a.connect()
    if not r.success:
        print(f"✗ 登录失败: {r.error}")
        return 1
    print(f"  连接 A: {r.server}")
    oracle: list[dict] = []
    names_cache = client_a.fetch_stock_names_full()["names"]
    if do_sh:
        sh_codes = sorted(c for c in names_cache if c.startswith("6"))[:count]
        print(f"  沪市: 查前 {len(sh_codes)} 只（取自本地缓存）...")
        oracle += collect_oracle_names(client_a, sh_codes, market=17)
    if do_sz:
        sz_codes = sorted(c for c in names_cache if c[:3] in ("000", "001", "002", "300"))[:count]
        print(f"  深市: 查前 {len(sz_codes)} 只（取自本地缓存）...")
        oracle += collect_oracle_names(client_a, sz_codes, market=33)
    print(f"  采集到 {len(oracle)} 条明文 (code, name)")
    client_a.disconnect()

    oracle_path = os.path.join(data_dir, "oracle_code_names.json")
    with open(oracle_path, "w", encoding="utf-8") as f:
        json.dump(oracle, f, ensure_ascii=False, indent=2)
    print(f"  已存盘: {oracle_path}")

    # ── 2. 拿 hfd1.0 密文（独立连接 B，反复重试找能响应的 host）──
    print(f"\n[2/3] 发空括号请求，采集 hfd1.0 密文（连接 B，找可用 host）...")
    client_b = connect_working_host(user, pwd)
    if client_b is None:
        print("✗ 多次重试均未连上可用 host（明文已采集，可后续补密文）")
        hfd1 = b""
    else:
        hfd1 = getattr(client_b, "_cached_hfd1", b"")
        client_b.disconnect()
    print(f"  收到 {len(hfd1):,} 字节")
    if not hfd1 or len(hfd1) < 1000:
        print("✗ hfd1.0 响应过小（仅有明文，无法做锚点对照）")
        return 1
    hfd1_path = os.path.join(data_dir, "hfd1_0_response.bin")
    with open(hfd1_path, "wb") as f:
        f.write(hfd1)
    print(f"  已存盘: {hfd1_path}")
    pos = hfd1.find(b"hfd1.0")
    print(f"  hfd1.0 标记 @ offset {pos}")

    # ── 3. 在密文中定位锚点 + 分析压缩（离线，无需连接）──
    print(f"\n[3/3] 在 hfd1.0 密文中定位明文锚点...")
    anchors = find_name_anchors(hfd1, oracle)
    hit = len(anchors)
    print(f"  {hit}/{len(oracle)} 条名称在密文中命中 ({hit*100//max(len(oracle),1)}%)")

    anchors_path = os.path.join(data_dir, "hfd1_0_name_anchors.json")
    with open(anchors_path, "w", encoding="utf-8") as f:
        json.dump(anchors, f, ensure_ascii=False, indent=2)
    print(f"  已存盘: {anchors_path}")

    if anchors:
        analyze_compression(anchors)

    print(f"\n{'='*70}")
    print("采集完成。产物：")
    print(f"  {hfd1_path}     — hfd1.0 密文（{len(hfd1):,}B）")
    print(f"  {oracle_path}   — 明文真值（{len(oracle)} 条）")
    print(f"  {anchors_path}  — 密文锚点（{hit} 命中）")
    print("用 anchors 的 pre_hex 对照真实 code，可破解 hfd1.0 的代码压缩格式。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
