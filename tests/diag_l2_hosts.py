#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
诊断脚本：验证"沪深 L2 行情服务器分服"猜想。

只跑 HTTP 鉴权拿 passport（不碰 8901/TCP），打印 M_hqdns 原文 + 按 lv2 域名分组
DNS 解析，确认：
  1. shlv2（沪市）和 szlv2（深市）是否解析出【不同】的 IP 组
  2. M_hqdns 里每个 lv2 域名对应的市场码（16/144/32）

用法：
    uv run python tests/diag_l2_hosts.py

结论判读：
  - 若 shlv2 和 szlv2 的 IP 集合【不同】 → 猜想成立：现代码把两者合并取 l2_ips[0]
    会随机连错市的 IP，这极可能就是"部分 IP 连不上/init 只回 210B"的真因。
  - 若 IP 集合【相同】→ 不是分服问题，需另查。
"""
from __future__ import annotations

import os
import re
import socket
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


def load_env() -> None:
    env_path = os.path.join(os.path.dirname(__file__), "..", ".env")
    if not os.path.exists(env_path):
        return
    with open(env_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key, val = key.strip(), val.strip()
            if key and key not in os.environ:
                os.environ[key] = val


def main() -> int:
    load_env()
    username = os.environ.get("THS_USERNAME", "").strip()
    password = os.environ.get("THS_PASSWORD", "").strip()
    imei = os.environ.get("THS_IMEI", "").strip() or None
    if not username or not password:
        print("✗ 未设置 THS_USERNAME / THS_PASSWORD（.env 或环境变量）")
        return 1

    from thspypc import full_http_auth

    print(f"→ HTTP 鉴权（账号 {username[:3]}***）...")
    auth = full_http_auth(username, password, imei)
    pb = auth.get("passport_bytes", b"")
    if isinstance(pb, str):
        pb = pb.encode("latin-1", "replace")
    print(f"  passport_bytes: {len(pb)} 字节\n")

    text = pb.decode("latin-1", "replace")
    # 1) M_hqdns 原文
    m = re.search(r'M_hqdns="([^"]*)"', text)
    if not m:
        for field in text.split("|"):
            if field.startswith("M_hqdns="):
                m_hqdns = field.split("=", 1)[1]
                break
        else:
            print("✗ passport 里没找到 M_hqdns 字段")
            return 2
    else:
        m_hqdns = m.group(1)

    print("=" * 70)
    print("M_hqdns 原文：")
    print(m_hqdns)
    print("=" * 70, "\n")

    # 2) 解析所有 8901 条目，按域名分组
    MARKET_PORT = 8901
    entries: dict[str, list[str]] = {}  # domain -> [market codes]
    all_domains: list[str] = []
    for entry in m_hqdns.split(","):
        dm = re.match(r'([\w.]+):(\d+):([^;]*);?', entry.strip())
        if not dm:
            continue
        domain, port, markets = dm.group(1), dm.group(2), dm.group(3)
        if port != str(MARKET_PORT):
            continue
        entries.setdefault(domain, []).append(markets)
        all_domains.append(domain)

    print(f"所有 :8901 域名（{len(all_domains)} 条，去重 {len(entries)} 个）：")
    for d in sorted(entries):
        is_l2 = "lv2" in d.lower()
        tag = "  ★ L2" if is_l2 else ""
        print(f"  {d:30s}  市场={';'.join(entries[d]):12s}{tag}")
    print()

    # 3) 重点：lv2 域名分别 DNS 解析，看沪深是否分服
    l2_domains = sorted({d for d in entries if "lv2" in d.lower()})
    if not l2_domains:
        print("✗ M_hqdns 中无 lv2 域名 → 账号可能无 L2 权限")
        return 3

    print("=" * 70)
    print("★ L2 服务器 DNS 解析结果（验证沪深是否分服）：")
    print("=" * 70)
    domain_ips: dict[str, list[str]] = {}
    for d in l2_domains:
        try:
            _, _, addrs = socket.gethostbyname_ex(d)
        except OSError as e:
            print(f"  {d:20s} → DNS 失败: {e}")
            domain_ips[d] = []
            continue
        domain_ips[d] = addrs
        markets = ";".join(entries[d])
        print(f"  {d:20s} 市场={markets:8s} → {len(addrs)} 个 IP: {addrs}")
    print()

    # 4) 交集对比
    if len(domain_ips) >= 2:
        sets = {d: set(ips) for d, ips in domain_ips.items()}
        ds = list(sets)
        print("=" * 70)
        print("★ 关键判读：shlv2 与 szlv2 的 IP 集合对比")
        print("=" * 70)
        for i in range(len(ds)):
            for j in range(i + 1, len(ds)):
                a, b = ds[i], ds[j]
                common = sets[a] & sets[b]
                only_a = sets[a] - sets[b]
                only_b = sets[b] - sets[a]
                verdict = "【相同】→ 不分服" if not only_a and not only_b else "【不同】→ 沪深分服成立"
                print(f"\n  {a}  vs  {b} :  {verdict}")
                print(f"    共有 IP  ({len(common):2d}): {sorted(common)}")
                print(f"    仅 {a} ({len(only_a):2d}): {sorted(only_a)}")
                print(f"    仅 {b} ({len(only_b):2d}): {sorted(only_b)}")

    print("\n" + "=" * 70)
    print("现代码行为（client.py:_open_manual_push_connection）：")
    print("  l2_ips = resolve_l2_hosts(...)  # shlv2+szlv2 合并去重")
    print("  host = l2_ips[0]               # 取第一个，不区分沪深")
    print("  init(market_code='32;')        # 写死深市")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())
