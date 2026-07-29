#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
探针：尝试不同市场码发深市全市场快照请求，看是否返回深市股票。

⚠ **一次性探针，结论已存档
（docs/handoffs/HANDOFF_STOCKLIST_PUSH.md §11e：深市 hfd1.0 不支持）。**
本脚本循环 connect/disconnect 5 次，**会触发 VerifyCode=-1**（同账号同 IP
短时间重复 login 的会话冲突，见 docs/handoffs/HANDOFF.md §7）。如需重跑，务必先确保同花顺
客户端已退出，并接受每次运行后需等 ≥20s 冷却。新代码请勿照搬此 connect
循环模式——参考 :meth:`THSClient.market_snapshot`（主连接单次发）。

历史结论：市场 32/33 单独请求返回 26B 错误，深市 A 股 hfd1.0 不支持。
"""
from __future__ import annotations

import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from thspypc import THSClient
from thspypc.protocol import build_market_snapshot_query, read_frame

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")


def _load_env():
    env_path = os.path.join(os.path.dirname(__file__), "..", ".env")
    if os.path.exists(env_path):
        for line in open(env_path, encoding="utf-8"):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                if k.strip() and k.strip() not in os.environ:
                    os.environ[k.strip()] = v.strip().strip('"').strip("'")


def try_snapshot(user, pwd, imei, markets, label, max_attempts=5):
    """发快照请求并分析响应。"""
    for attempt in range(max_attempts):
        client = THSClient(user, pwd, imei=imei, enable_heartbeat=False)
        r = client.connect()
        if not r.success:
            client.disconnect()
            continue
        
        req = build_market_snapshot_query(markets=markets)
        try:
            client._sock.sendall(req + b"\n")
            client._sock.settimeout(10.0)
            resp = read_frame(client._sock)
        except Exception as e:
            print(f"  {label}: 尝试{attempt+1} 读响应失败: {e}")
            client.disconnect()
            continue
        
        if not resp:
            client.disconnect()
            continue
        
        has_hfd1 = b"hfd1.0" in resp
        sz_000 = resp.count(b"000")
        sh_600 = resp.count(b"600")
        
        print(f"\n{'='*50}")
        print(f"{label} (尝试{attempt+1} @ {r.server})")
        print(f"{'='*50}")
        print(f"  大小: {len(resp):,}B")
        print(f"  含 hfd1.0: {'✅' if has_hfd1 else '❌'}")
        print(f"  '000'出现: {sz_000} 次")
        print(f"  '600'出现: {sh_600} 次")
        
        # 搜索深市代码
        import re
        sz_codes = set(re.findall(rb'000\d{3}|002\d{3}|300\d{3}', resp))
        sh_codes = set(re.findall(rb'6\d{5}', resp))
        print(f"  深市代码数: {len(sz_codes)}")
        if sz_codes:
            sample = list(sz_codes)[:5]
            print(f"  深市示例: {[c.decode() for c in sample]}")
        print(f"  沪市代码数: {len(sh_codes)}")
        
        client.disconnect()
        return resp
    
    return None


def main():
    _load_env()
    user = os.environ.get("THS_USERNAME", "").strip()
    pwd = os.environ.get("THS_PASSWORD", "").strip()
    imei = os.environ.get("THS_IMEI", "")
    if not user or not pwd:
        print("✗ 未配置 .env")
        return 1
    
    # 测试不同的市场码组合
    test_cases = [
        ([32], "深市(32)"),
        ([33], "深市(33)"),
        ([144, 145, 146, 147, 150, 151], "深市(144-151)"),
        ([16, 17, 18, 19, 20, 22], "沪市(16-22)"),
        ([32, 33], "深市(32+33)"),
        ([16, 32], "沪16+深32"),
    ]
    
    for markets, label in test_cases:
        resp = try_snapshot(user, pwd, imei, markets, label)
        if resp and len(resp) > 1000:
            # 存盘供后续分析
            safe_name = label.replace("(", "_").replace(")", "").replace("+", "_")
            path = os.path.join(DATA_DIR, f"snapshot_{safe_name}.bin")
            open(path, "wb").write(resp)
            print(f"  已存: {path}")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
