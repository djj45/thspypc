#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
thspypc 全市场股票代码表本地缓存测试。

两种模式：

1. 离线单测（无需账号/网络）—— 验证缓存函数逻辑：
       uv run python tests/test_stock_cache.py
   测 market_from_code 映射、save/load 往返、自然日过期判断。

2. 活网端到端（需账号）—— 验证 stock_list_cached() 缓存命中：
       uv run python tests/test_stock_cache.py --live
   第一次走网络拉取并写盘（~6s），第二次直接命中缓存（<0.1s）。
   默认读 .env 的 THS_USERNAME/THS_PASSWORD。
"""
from __future__ import annotations

# 可直接运行的缓存/活网诊断脚本；缓存单元契约由正式 pytest 模块覆盖。
__test__ = False

import json
import os
import sys
import tempfile
import time
from collections import Counter

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from thspypc import (
    THSClient,
    market_from_code,
    default_stock_cache_path,
    save_stock_codes,
    load_stock_codes,
    is_stock_cache_expired,
)


def test_market_from_code():
    """验证代码前缀 → 市场码映射。"""
    print("=== market_from_code 映射 ===")
    cases = [
        # 沪市 A 股（market=17）
        ("600000", 17, "沪市主板"),
        ("601318", 17, "沪市主板"),
        ("603259", 17, "沪市主板"),
        ("605555", 17, "沪市主板"),
        ("688981", 17, "科创板"),
        ("689009", 17, "科创板CDR"),
        # 深市 A 股（market=33）
        ("000001", 33, "深市主板"),
        ("001872", 33, "深市主板"),
        ("002230", 33, "中小板"),
        ("003816", 33, "深市主板"),
        ("300750", 33, "创业板"),
        ("301308", 33, "创业板"),
        # 非 list_quotes 支持的市场（market=None）
        ("872925", None, "北交所"),
        ("920819", None, "北交所"),
        ("833527", None, "新三板"),
        ("159915", None, "基金"),
        ("510300", None, "沪市基金"),
        ("399001", None, "深证成指"),
        ("", None, "空代码"),
        ("12", None, "过短代码"),
    ]
    ok = True
    for code, expected, desc in cases:
        got = market_from_code(code)
        mark = "✓" if got == expected else "✗"
        if got != expected:
            ok = False
        print(f"  {mark} {code or '(空)':8s} {desc:10s} -> {got} (期望 {expected})")
    print(f"\n{'✓' if ok else '✗'} market_from_code: {'全部通过' if ok else '有失败'}")
    return 0 if ok else 1


def test_save_load_roundtrip():
    """验证 save → load 往返完整性。"""
    print("\n=== save/load 往返 ===")
    stocks = [
        {"code": "600000", "name": "浦发银行", "market": 0},   # market 会被派生覆盖
        {"code": "000001", "name": "平安银行", "market": 0},
        {"code": "872925", "name": "锦波生物", "market": 0},   # 北交所 → None
        {"code": "600519", "name": "贵州茅台"},
        {"code": "", "name": "空代码应被跳过"},
        {"code": "300750", "name": "宁德时代"},
    ]
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "codes.json")
        written = save_stock_codes(stocks, path)

        # 验证写盘的字段结构
        with open(path, encoding="utf-8") as f:
            raw = json.load(f)
        assert "saved_date" in raw, "缺 saved_date"
        assert "saved_at" in raw, "缺 saved_at"
        assert raw["count"] == 5, f"count 应为 5（跳过空 code），实际 {raw['count']}"
        print(f"  ✓ 写盘字段完整: saved_date={raw['saved_date']}, count={raw['count']}")

        # load 往返
        loaded = load_stock_codes(path)
        assert loaded is not None, "load 返回 None"
        loaded_stocks, saved_date = loaded
        assert len(loaded_stocks) == 5, f"load 条数 {len(loaded_stocks)} != 5"

        # 验证 market 被派生覆盖（600000→17, 000001→33, 872925→None）
        by_code = {s["code"]: s for s in loaded_stocks}
        assert by_code["600000"]["market"] == 17, "600000 market 应为 17"
        assert by_code["000001"]["market"] == 33, "000001 market 应为 33"
        assert by_code["872925"]["market"] is None, "872925 market 应为 None"
        assert by_code["600519"]["name"] == "贵州茅台", "名称应保留"
        print(f"  ✓ load 往返完整: {len(loaded_stocks)} 条, market 已派生覆盖")

        # 缺 market 字段的记录应被补 None（market_from_code 派生）
        assert by_code["600519"]["market"] == 17, "600519 应补 market=17"
        print(f"  ✓ 缺 market 字段记录已自动补全")

    print(f"\n✓ save/load 往返: 全部通过")
    return 0


def test_expiry_by_date():
    """验证自然日过期判断（写昨天的日期 → 判过期）。"""
    print("\n=== 自然日过期判断 ===")
    import datetime
    yesterday = (datetime.date.today() - datetime.timedelta(days=1)).isoformat()
    old_data = {
        "saved_date": yesterday,
        "saved_at": int(time.time()) - 86400,
        "count": 2,
        "stocks": [
            {"code": "600000", "name": "浦发银行", "market": 17},
            {"code": "000001", "name": "平安银行", "market": 33},
        ],
    }
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "old.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(old_data, f)

        # 昨天的缓存 → load 返回 None（过期）
        loaded = load_stock_codes(path)
        assert loaded is None, f"昨天的缓存应过期返回 None，实际 {loaded}"
        print(f"  ✓ 昨天的缓存 (saved_date={yesterday}) → load 返回 None")

        # is_stock_cache_expired → True
        expired = is_stock_cache_expired(path)
        assert expired is True, "昨天的缓存应判过期"
        print(f"  ✓ is_stock_cache_expired → True")

        # 不存在的文件 → expired True
        nofile = os.path.join(d, "nope.json")
        assert is_stock_cache_expired(nofile) is True
        assert load_stock_codes(nofile) is None
        print(f"  ✓ 不存在的文件 → expired True, load None")

        # 损坏 JSON → load None, expired True
        bad = os.path.join(d, "bad.json")
        with open(bad, "w") as f:
            f.write("{not valid json")
        assert load_stock_codes(bad) is None
        assert is_stock_cache_expired(bad) is True
        print(f"  ✓ 损坏 JSON → load None, expired True")

    print(f"\n✓ 过期判断: 全部通过")
    return 0


def _load_dotenv():
    """读取项目根的 .env 到环境变量（不依赖 python-dotenv 包）。"""
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
    """活网端到端：验证 stock_list_cached() 首次拉取 + 二次命中缓存。"""
    _load_dotenv()
    user = os.environ.get("THS_USERNAME", "").strip()
    pwd = os.environ.get("THS_PASSWORD", "").strip()
    if not user or not pwd:
        print("✗ 未配置 .env 的 THS_USERNAME/THS_PASSWORD")
        return 1
    print(f"账号: {user[:3]}***")

    # 用临时路径，不污染默认缓存
    cache_path = os.path.join(tempfile.gettempdir(), "ths_stock_codes_test.json")
    if os.path.exists(cache_path):
        os.remove(cache_path)

    client = THSClient(user, pwd, enable_heartbeat=False)
    r = client.connect()
    if not r.success:
        print(f"✗ 登录失败: {r.error}")
        return 1
    print(f"✓ 登录成功: {r.server}")

    # 第一次：缓存未命中 → 走网络
    print(f"\n第一次调用（缓存未命中，走网络）...")
    t0 = time.time()
    stocks = client.stock_list_cached(cache_path=cache_path)
    elapsed1 = time.time() - t0
    print(f"  ✓ 获取 {len(stocks)} 条代码（{elapsed1:.1f}s）")
    if stocks:
        # market 字段应是派生值（17/33/None），不是 0
        mk_dist = Counter(s.get("market") for s in stocks)
        print(f"  market 分布: {dict(mk_dist)}")
        named = sum(1 for s in stocks if s.get("name"))
        print(f"  带名称: {named}/{len(stocks)}")
        print(f"  示例: {stocks[0]}")

    if len(stocks) < 7000:
        print(f"\n⚠ 数量偏少（{len(stocks)} < 7000，可能服务器未响应全量）")

    if not stocks:
        # 拉取失败（服务器实例未响应，docs/handoffs/HANDOFF.md 已知现象），
        # 无法验证缓存命中
        print("\n✗ 拉取为空（服务器实例未响应全量，可重试换 IP）")
        print("  离线测试已验证缓存逻辑正确，活网拉取是 stock_list 本身的稳定性问题")
        client.disconnect()
        return 1

    # 第二次：缓存命中 → 瞬时
    print(f"\n第二次调用（应命中缓存，<0.1s）...")
    t0 = time.time()
    stocks2 = client.stock_list_cached(cache_path=cache_path)
    elapsed2 = time.time() - t0
    print(f"  ✓ 获取 {len(stocks2)} 条代码（{elapsed2:.3f}s）")
    print(f"  缓存文件: {cache_path}")

    # 验证两次结果一致
    if len(stocks) == len(stocks2) and stocks[0]["code"] == stocks2[0]["code"]:
        print(f"\n✓ 两次结果一致（{len(stocks)} 条），缓存命中")
        if elapsed2 < 0.5:
            print(f"✓ 缓存命中速度正常（{elapsed2:.3f}s << 首次 {elapsed1:.1f}s）")
            rc = 0
        else:
            print(f"⚠ 缓存命中偏慢（{elapsed2:.3f}s），可能未命中")
            rc = 1
    else:
        print(f"\n✗ 两次结果不一致")
        rc = 1

    client.disconnect()
    return rc


def main():
    if "--live" in sys.argv:
        return test_live()
    rc = 0
    rc |= test_market_from_code()
    rc |= test_save_load_roundtrip()
    rc |= test_expiry_by_date()
    print(f"\n{'='*50}")
    if rc == 0:
        print("✓ 全部离线测试通过")
    else:
        print("✗ 有测试失败")
    print("（活网测试: py tests/test_stock_cache.py --live）")
    return rc


if __name__ == "__main__":
    sys.exit(main())
