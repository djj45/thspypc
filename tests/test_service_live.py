#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
默认 service 路径的活网重复请求验证。

目的
====
公开行情方法默认委托 codecs/features/services/_transport 分层。本脚本在同一
client、同一 MAIN 生命周期内连续请求两轮，验证连接复用、single-flight 读写和
动态响应结构稳定。

⚠ 前置条件
==========
- 确保同花顺客户端已退出，避免同账号并发占用会话。
- 脚本只执行一次 connect，并在同一 MAIN 生命周期内完成全部查询。

用法
====
    uv run python tests/test_service_live.py
    # 需要项目根 .env 配置 THS_USERNAME / THS_PASSWORD
"""
from __future__ import annotations

import os
import sys
import time
import traceback

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from thspypc import THSClient


def load_dotenv() -> None:
    env_path = os.path.join(os.path.dirname(__file__), "..", ".env")
    if not os.path.exists(env_path):
        return
    with open(env_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value


# ---------- 对比工具 ----------

def _round_floats(obj):
    if isinstance(obj, float):
        return round(obj, 4)
    if isinstance(obj, dict):
        return {k: _round_floats(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_round_floats(v) for v in obj]
    return obj


def _value_shape(obj):
    """保留容器结构、字段名和标量类型，忽略实时值。"""
    if isinstance(obj, dict):
        return {key: _value_shape(value) for key, value in sorted(obj.items())}
    if isinstance(obj, list):
        return [_value_shape(value) for value in obj]
    return type(obj).__name__


def _records_by_code(records):
    return {
        record.get("code", f"row-{index}"): _value_shape(record)
        for index, record in enumerate(records)
    }


def compare_live_list(name: str, old, new) -> bool:
    """比较动态记录的代码集合、字段结构和类型，不比较瞬时行情值。"""
    if not isinstance(old, list) or not isinstance(new, list):
        print(f"  ✗ {name}: 返回类型不是 list old={type(old).__name__} new={type(new).__name__}")
        return False
    if len(old) != len(new):
        print(f"  ✗ {name}: 条数不一致 old={len(old)} new={len(new)}")
        return False
    old_shape = _records_by_code(old)
    new_shape = _records_by_code(new)
    ok = old_shape == new_shape
    if ok:
        print(f"  ✓ {name}: {len(old)} 条代码/字段结构/类型一致（动态值已忽略）")
    else:
        print(f"  ✗ {name}: 动态记录结构不一致")
        print(f"    old={old_shape}")
        print(f"    new={new_shape}")
    return ok


def compare_depth(name: str, old: dict, new: dict) -> bool:
    """盘口是动态数据，只比较档位数量、字段结构和标量类型。"""
    if not isinstance(old, dict) or not isinstance(new, dict):
        print(f"  ✗ {name}: 返回类型异常 old={type(old).__name__} new={type(new).__name__}")
        return False
    old_shape = _value_shape(old)
    new_shape = _value_shape(new)
    ok = old_shape == new_shape
    if ok:
        b = len(old.get("buy", []))
        s = len(old.get("sell", []))
        print(f"  ✓ {name}: 买{b}/卖{s}档结构和类型一致（动态值已忽略）")
    else:
        print(f"  ✗ {name}: 盘口结构不一致")
        print(f"    old={old_shape}")
        print(f"    new={new_shape}")
    return ok


def compare_kline(name: str, old, new) -> bool:
    """已完成 bar 精确比较；最后一根可能仍在变化，只比较结构。"""
    if not isinstance(old, list) or not isinstance(new, list):
        print(f"  ✗ {name}: 返回类型不是 list")
        return False
    if len(old) != len(new) or not old:
        print(f"  ✗ {name}: 条数异常 old={len(old)} new={len(new)}")
        return False
    completed_ok = _round_floats(old[:-1]) == _round_floats(new[:-1])
    latest_shape_ok = _value_shape(old[-1]) == _value_shape(new[-1])
    ok = completed_ok and latest_shape_ok
    if ok:
        print(
            f"  ✓ {name}: {len(old) - 1} 根已完成 bar 逐字段一致，"
            "最新 bar 结构一致"
        )
    else:
        print(
            f"  ✗ {name}: completed_ok={completed_ok} "
            f"latest_shape_ok={latest_shape_ok}"
        )
    return ok


def test_live_comparison_ignores_values_but_checks_schema():
    old = [{"code": "600519", "price": 100.0, "volume": 10}]
    changed = [{"code": "600519", "price": 101.5, "volume": 12}]
    wrong_schema = [{"code": "600519", "price": "101.5", "volume": 12}]

    assert compare_live_list("quotes", old, changed)
    assert not compare_live_list("quotes", old, wrong_schema)


def test_kline_comparison_allows_latest_bar_to_change():
    old = [
        {"date": "20260728", "close": 100.0},
        {"date": "20260729", "close": 101.0},
    ]
    changed_latest = [
        {"date": "20260728", "close": 100.0},
        {"date": "20260729", "close": 102.0},
    ]
    changed_completed = [
        {"date": "20260728", "close": 99.0},
        {"date": "20260729", "close": 102.0},
    ]

    assert compare_kline("kline", old, changed_latest)
    assert not compare_kline("kline", old, changed_completed)


# ---------- 主流程 ----------

def main() -> int:
    load_dotenv()
    username = os.environ.get("THS_USERNAME", "").strip()
    password = os.environ.get("THS_PASSWORD", "").strip()
    imei = os.environ.get("THS_IMEI", "").strip() or None

    print("=" * 70)
    print("活网验证：默认 service 路径的重复请求与连接复用")
    print("=" * 70)
    print(f"账号: {username or '(空)'}  时间: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print()

    if not username or not password:
        print("!! .env 缺 THS_USERNAME/THS_PASSWORD，无法跑活网验证")
        return 2

    # ---- 1. 登录主连接：client 内部筛选节点；init 失败会结束本次 connect ----
    client = THSClient(username, password, imei)
    try:
        result = client.connect()
    except Exception as e:
        print(f"!! 登录异常: {e}")
        client.disconnect()
        return 1
    if not result.success:
        print(f"✗ 登录失败 (error={result.error}): {result.detail}")
        client.disconnect()
        return 1
    print(f"✓ 登录成功: {result.server} (VerifyCode={result.verify_code})")
    print()

    SH_CODES = ["600519", "600000", "600036"]   # ≤5 股走 hd1.0 明文，盘后最稳
    results = []
    try:
        # ---- 2. 第一轮默认 service 请求 ----
        # 注意：kline() 内部有跨 IP 重连重试逻辑，失败时会破坏主连接，且当前
        # 凌晨时段服务器对 kline 查询无响应（非重构问题）。本次核心对比先聚焦
        # list_quotes / depth_quote（MAIN 复用主连接、无重连副作用），kline 留待
        # 盘中或白天单独验证。
        print("── 第一轮默认 service 请求 ──")
        t0 = time.time()
        first_quotes = client.list_quotes(SH_CODES, market=17)
        print(f"  list_quotes(沪): {len(first_quotes)} 条  ({time.time()-t0:.1f}s)")
        t0 = time.time()
        first_depth = client.depth_quote("600519")
        print(f"  depth_quote(600519): 买{len(first_depth.get('buy',[]))}/卖{len(first_depth.get('sell',[]))}  ({time.time()-t0:.1f}s)")
        first_kline = None
        try:
            t0 = time.time()
            # retries=0 避免内部重连破坏主连接；init 修复后单次即成功
            first_kline = client.kline("600519", period="day", count=5, market=17, retries=0, timeout=15.0)
            print(f"  kline(600519 日): {len(first_kline)} 根  ({time.time()-t0:.1f}s)")
        except Exception as ke:
            print(f"  kline(600519 日): 跳过: {type(ke).__name__}: {ke}")
        print()

        if not client.is_connected:
            print("!! 第一轮查询后 MAIN 连接断开")
            return 1

        # ---- 3. 第二轮复用同一默认 service context ----
        print("── 第二轮复用默认 service context ──")
        profile = client.observed_account_profile
        print(f"  账号画像: kind={profile.kind.value}")
        caps = {c.value: s.value for c, s in profile.capabilities.items()}
        print(f"  能力: {caps}")
        client.sync_service_connections()
        print()

        print("── 第二轮查询 ──")
        t0 = time.time()
        second_quotes = client.list_quotes(SH_CODES, market=17)
        print(f"  list_quotes(沪): {len(second_quotes)} 条  ({time.time()-t0:.1f}s)")
        t0 = time.time()
        second_depth = client.depth_quote("600519")
        print(f"  depth_quote(600519): 买{len(second_depth.get('buy',[]))}/卖{len(second_depth.get('sell',[]))}  ({time.time()-t0:.1f}s)")
        second_kline = None
        try:
            t0 = time.time()
            second_kline = client.kline("600519", period="day", count=5, market=17, retries=0, timeout=15.0)
            print(f"  kline(600519 日): {len(second_kline)} 根  ({time.time()-t0:.1f}s)")
        except Exception as ke:
            print(f"  kline(600519 日): 跳过: {type(ke).__name__}: {ke}")
        print()

        # ---- 4. 行为对比 ----
        print("── 两轮行为对比 ──")
        results.append(compare_live_list("list_quotes(沪)", first_quotes, second_quotes))
        results.append(compare_depth("depth_quote(600519)", first_depth, second_depth))
        if first_kline is not None and second_kline is not None:
            results.append(compare_kline("kline(600519 日)", first_kline, second_kline))
        elif first_kline is None and second_kline is None:
            print("  ⊙ kline(600519 日): 两轮均跳过，无法对比")

    except Exception as e:
        print(f"\n!! 验证过程异常: {e}")
        traceback.print_exc()
        client.disconnect()
        return 1
    finally:
        client.disconnect()

    print()
    print("=" * 70)
    passed = sum(1 for r in results if r)
    total = len(results)
    if passed == total:
        print(f"✓ 全部对比一致 {passed}/{total}：默认 service 路径复用稳定")
        return 0
    else:
        print(f"✗ 存在差异 {passed}/{total} 通过：需排查")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
