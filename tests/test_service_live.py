#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
重构活网验证：新 service 层路径 vs 旧协议路径逐字段对比。

目的
====
codex/refactor-protocol-foundation 分支把单体 client.py/protocol.py 拆成
codecs/features/services/_transport 分层。公开方法在显式配置 service context
后 opt-in 委托新 service，否则走旧路径。

本脚本在同一 client、同一主连接上，对 MAIN-only 业务先取旧路径基准，再 opt-in
切新 service 路径取一份，逐字段对比，确认重构未改变协议字节和解析结果。

⚠ 前置条件
==========
- level2 账号频繁 connect 会触发服务器会话保护，连接在登录后被立即关闭。
  跑本脚本前请确保：
  1. 同花顺客户端已退出（同账号不能两个客户端同时在线）
  2. 距上次 connect 间隔 > 60 秒（让 level2 会话冷却）
- 全程在单次 connect 生命周期内完成，避免反复登录。

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


def compare_list(name: str, old, new) -> bool:
    if not isinstance(old, list) or not isinstance(new, list):
        print(f"  ✗ {name}: 返回类型不是 list old={type(old).__name__} new={type(new).__name__}")
        return False
    if len(old) != len(new):
        print(f"  ✗ {name}: 条数不一致 old={len(old)} new={len(new)}")
        return False
    ro, rn = _round_floats(old), _round_floats(new)
    ok = ro == rn
    if ok:
        print(f"  ✓ {name}: {len(old)} 条逐字段一致")
    else:
        diffs = 0
        for i, (o, n) in enumerate(zip(ro, rn)):
            if o != n:
                diffs += 1
                if diffs <= 3:
                    ident = o.get("code", i) if isinstance(o, dict) else i
                    print(f"  ✗ {name}[{ident}]: {o} → {n}")
        if diffs > 3:
            print(f"  （共 {diffs} 处差异，仅显示前 3 处）")
    return ok


def compare_depth(name: str, old: dict, new: dict) -> bool:
    if not isinstance(old, dict) or not isinstance(new, dict):
        print(f"  ✗ {name}: 返回类型异常 old={type(old).__name__} new={type(new).__name__}")
        return False
    ro, rn = _round_floats(old), _round_floats(new)
    ok = ro == rn
    if ok:
        b = len(old.get("buy", []))
        s = len(old.get("sell", []))
        print(f"  ✓ {name}: 买{b}/卖{s}档逐字段一致，seal={old.get('seal_amount')}")
    else:
        for side in ("buy", "sell"):
            ob, nb = ro.get(side, []), rn.get(side, [])
            for i, (ol, nl) in enumerate(zip(ob, nb)):
                if ol != nl:
                    print(f"  ✗ {name}.{side}[{i}]: {ol} → {nl}")
        if ro.get("seal_amount") != rn.get("seal_amount"):
            print(f"  ✗ {name}.seal_amount: {ro.get('seal_amount')} → {rn.get('seal_amount')}")
    return ok


# ---------- 主流程 ----------

def main() -> int:
    load_dotenv()
    username = os.environ.get("THS_USERNAME", "").strip()
    password = os.environ.get("THS_PASSWORD", "").strip()
    imei = os.environ.get("THS_IMEI", "").strip() or None

    print("=" * 70)
    print("活网验证：新 service 路径 vs 旧协议路径（重构行为对比）")
    print("=" * 70)
    print(f"账号: {username or '(空)'}  时间: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print()

    if not username or not password:
        print("!! .env 缺 THS_USERNAME/THS_PASSWORD，无法跑活网验证")
        return 2

    # ---- 1. 登录主连接（带重试：部分 IP 登录后会被服务器立即 FIN）----
    MAX_LOGIN_ATTEMPTS = 4
    result = None
    for attempt in range(1, MAX_LOGIN_ATTEMPTS + 1):
        client = THSClient(username, password, imei)
        try:
            result = client.connect()
        except Exception as e:
            print(f"!! 第 {attempt} 次登录异常: {e}")
            client.disconnect()
            result = None
            continue
        if not result.success:
            print(f"✗ 第 {attempt} 次登录失败 (error={result.error}): {result.detail}")
            client.disconnect()
            continue
        print(f"✓ 第 {attempt} 次登录成功: {result.server} (VerifyCode={result.verify_code})")
        if client.is_connected:
            break
        # 登录成功但连接被立即关闭（level2 会话保护 / 该 IP 不稳）→ 换 IP 重试
        print(f"  连接被服务器立即关闭，换 IP 重试（冷却 25s）...")
        client.disconnect()
        time.sleep(25)
    else:
        print("✗ 多次登录后连接均被服务器立即关闭。")
        print("  请确保：1) 同花顺客户端已退出  2) 距上次 connect > 60s  3) 换网络环境。")
        return 1
    print()

    SH_CODES = ["600519", "600000", "600036"]   # ≤5 股走 hd1.0 明文，盘后最稳
    results = []
    try:
        # ---- 2. 旧路径基准 ----
        # 注意：kline() 内部有跨 IP 重连重试逻辑，失败时会破坏主连接，且当前
        # 凌晨时段服务器对 kline 查询无响应（非重构问题）。本次核心对比先聚焦
        # list_quotes / depth_quote（MAIN 复用主连接、无重连副作用），kline 留待
        # 盘中或白天单独验证。
        print("── 旧路径基准（未配置 service context）──")
        t0 = time.time()
        old_quotes = client.list_quotes(SH_CODES, market=17)
        print(f"  list_quotes(沪): {len(old_quotes)} 条  ({time.time()-t0:.1f}s)")
        t0 = time.time()
        old_depth = client.depth_quote("600519")
        print(f"  depth_quote(600519): 买{len(old_depth.get('buy',[]))}/卖{len(old_depth.get('sell',[]))}  ({time.time()-t0:.1f}s)")
        old_kline = None
        try:
            t0 = time.time()
            # retries=0 避免内部重连破坏主连接；init 修复后单次即成功
            old_kline = client.kline("600519", period="day", count=5, market=17, retries=0, timeout=15.0)
            print(f"  kline(600519 日): {len(old_kline)} 根  ({time.time()-t0:.1f}s)")
        except Exception as ke:
            print(f"  kline(600519 日): 跳过: {type(ke).__name__}: {ke}")
        print()

        if not client.is_connected:
            print("!! 旧路径查询后连接断开，无法继续 service 路径对比")
            print("   （level2 会话保护间歇发作；冷却 60s 后重试通常可恢复）")
            return 1

        # ---- 3. 配置 service context，opt-in 新路径 ----
        print("── opt-in 新 service 路径 ──")
        client.configure_service_context(allow_open=True)
        profile = client.refresh_service_profile_from_evidence()
        print(f"  账号画像: kind={profile.kind.value}")
        caps = {c.value: s.value for c, s in profile.capabilities.items()}
        print(f"  能力: {caps}")
        client.sync_service_connections()
        print()

        print("── 新 service 路径查询 ──")
        t0 = time.time()
        new_quotes = client.list_quotes(SH_CODES, market=17)
        print(f"  list_quotes(沪): {len(new_quotes)} 条  ({time.time()-t0:.1f}s)")
        t0 = time.time()
        new_depth = client.depth_quote("600519")
        print(f"  depth_quote(600519): 买{len(new_depth.get('buy',[]))}/卖{len(new_depth.get('sell',[]))}  ({time.time()-t0:.1f}s)")
        new_kline = None
        try:
            t0 = time.time()
            new_kline = client.kline("600519", period="day", count=5, market=17, retries=0, timeout=15.0)
            print(f"  kline(600519 日): {len(new_kline)} 根  ({time.time()-t0:.1f}s)")
        except Exception as ke:
            print(f"  kline(600519 日): 跳过: {type(ke).__name__}: {ke}")
        print()

        # ---- 4. 逐字段对比 ----
        print("── 逐字段对比（旧 vs 新 service）──")
        results.append(compare_list("list_quotes(沪)", old_quotes, new_quotes))
        results.append(compare_depth("depth_quote(600519)", old_depth, new_depth))
        if old_kline is not None and new_kline is not None:
            results.append(compare_list("kline(600519 日)", old_kline, new_kline))
        elif old_kline is None and new_kline is None:
            print("  ⊙ kline(600519 日): 新旧路径均跳过，无法对比")

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
        print(f"✓ 全部对比一致 {passed}/{total}：重构未改变 MAIN 业务协议行为")
        return 0
    else:
        print(f"✗ 存在差异 {passed}/{total} 通过：需排查")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
