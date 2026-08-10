#!/usr/bin/env python
"""全服务器登录冒烟验证（单 client、逐角色、不依赖交易时段）。

验证 6 类连接角色在协议修复（account_type 0xC8 + check +13 + L2 身份）后
都能 VerifyCode=0：
  MAIN         connect()          — main.123ths.com:8901
  SH_L2/SZ_L2  order_details      — shlv2/szlv2:8901（LoginIdentity.L2）
  REALORDER    dxjl_latest        — 106.14.65.90:9601（LoginIdentity.STANDARD）
  BOARD        board_timeline     — fu4.123ths.com:8901（LoginIdentity.BOARD）
  BOARD_CONST  board_constituents — shlv2/szlv2（SH=STANDARD, SZ=MANUAL）
  BOARD_STATS  board_stats        — 8.132.233.77:9601（STANDARD）

严格遵守 AGENTS.md：单 client、connect() 先建 MAIN（消费一次 passport），
其余角色复用同一 passport（客户端内部治理 IP 轮换/冷却，见 live_check.py 模式）。

用法：
    py -u tests/verify_all_logins.py
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from thspypc import THSClient  # noqa: E402
from thspypc.testing import load_env  # noqa: E402

results: list[tuple[str, str, str]] = []  # (role, status, detail)


def _record(role: str, ok: bool, detail: str) -> None:
    mark = "✅" if ok else "❌"
    status = "OK" if ok else "FAIL"
    results.append((role, status, detail))
    print(f"  {mark} {role}: {detail}", flush=True)


def _safe_call(label: str, fn):
    """调用 fn()，返回 (ok, result_or_error)。"""
    t0 = time.monotonic()
    try:
        result = fn()
        dt = time.monotonic() - t0
        return True, result, dt
    except Exception as exc:  # noqa: BLE001
        dt = time.monotonic() - t0
        return False, exc, dt


def main() -> int:
    load_env(ROOT / ".env")
    username = os.environ.get("THS_USERNAME", "").strip()
    password = os.environ.get("THS_PASSWORD", "").strip()
    if not username or not password:
        raise RuntimeError("THS_USERNAME/THS_PASSWORD missing in .env")

    print("=" * 64, flush=True)
    print("全服务器登录冒烟验证", flush=True)
    print("=" * 64, flush=True)

    client = THSClient(username, password, enable_heartbeat=False)
    try:
        # ── MAIN ──────────────────────────────────────────────
        print("\n[MAIN] connect() → main.123ths.com:8901", flush=True)
        ok, result, dt = _safe_call("MAIN", client.connect)
        if ok:
            if result.success:
                _record("MAIN", True,
                        f"VerifyCode=0 server={result.server} {dt:.1f}s")
            else:
                _record("MAIN", False,
                        f"error={result.error} vc={result.verify_code} "
                        f"detail={result.detail}")
        else:
            _record("MAIN", False, f"异常: {result}")

        # ── SH_L2 / SZ_L2（LoginIdentity.L2）──────────────────
        # 用 order_details 触发 L2 连接（szlv2 + shlv2）
        print("\n[SH_L2/SZ_L2] order_details → shlv2/szlv2:8901", flush=True)
        ok, result, dt = _safe_call(
            "SZ_L2", lambda: client.order_details("002428", -29, 0, timeout=15.0)
        )
        if ok:
            n = len(result.get("orders", []))
            _record("SZ_L2", True,
                    f"VerifyCode=0 orders={n} events={len(result.get('events', []))} {dt:.1f}s")
        else:
            _record("SZ_L2", False, f"异常: {result}")

        ok, result, dt = _safe_call(
            "SH_L2", lambda: client.order_details("600664", -29, 0, timeout=15.0)
        )
        if ok:
            n = len(result.get("orders", []))
            _record("SH_L2", True,
                    f"VerifyCode=0 orders={n} events={len(result.get('events', []))} {dt:.1f}s")
        else:
            _record("SH_L2", False, f"异常: {result}")

        # ── REALORDER（STANDARD, 9601）────────────────────────
        print("\n[REALORDER] dxjl_latest → 106.14.65.90:9601", flush=True)
        ok, result, dt = _safe_call("REALORDER", client.dxjl_latest)
        if ok:
            _record("REALORDER", True,
                    f"VerifyCode=0 异动={len(result)}条 {dt:.1f}s")
        else:
            _record("REALORDER", False, f"异常: {result}")

        # ── BOARD（BOARD 身份, fu4:8901）──────────────────────
        # 用 latest_trade_date() 传明确日期，避免盘后 accept 判据日期不匹配
        # 导致读满 timeout 返回空（verify_all_logins 只验登录不依赖数据量）。
        from thspypc.testing import latest_trade_date
        trade_date = latest_trade_date()
        print(f"\n[BOARD] board_timeline({trade_date}) → fu4.123ths.com:8901",
              flush=True)
        ok, result, dt = _safe_call(
            "BOARD",
            lambda: client.board_timeline("881121", date=trade_date, timeout=15.0),
        )
        if ok:
            _record("BOARD", True,
                    f"VerifyCode=0 分时点={len(result)} {dt:.1f}s")
        else:
            _record("BOARD", False, f"异常: {result}")

        # ── BOARD_CONSTITUENT（SH=STANDARD, SZ=MANUAL）────────
        print("\n[BOARD_CONSTITUENT] board_constituents → shlv2/szlv2",
              flush=True)
        ok, result, dt = _safe_call(
            "BOARD_CONSTITUENT",
            lambda: client.board_constituents(["881121"]),
        )
        if ok:
            _record("BOARD_CONSTITUENT", True,
                    f"VerifyCode=0 成分股={len(result)} {dt:.1f}s")
        else:
            _record("BOARD_CONSTITUENT", False, f"异常: {result}")

        # ── BOARD_STATS（STANDARD, 8.132.233.77:9601）─────────
        print("\n[BOARD_STATS] board_stats_interval → 8.132.233.77:9601",
              flush=True)
        ok, result, dt = _safe_call(
            "BOARD_STATS",
            lambda: client.board_stats_interval(["881121"]),
        )
        if ok:
            _record("BOARD_STATS", True,
                    f"VerifyCode=0 统计={len(result)} {dt:.1f}s")
        else:
            _record("BOARD_STATS", False, f"异常: {result}")

    finally:
        client.disconnect()

    # ── 汇总 ────────────────────────────────────────────────
    print("\n" + "=" * 64, flush=True)
    passed = sum(1 for _, s, _ in results if s == "OK")
    total = len(results)
    for role, status, detail in results:
        mark = "✅" if status == "OK" else "❌"
        print(f"  {mark} {role:20s} {detail}", flush=True)
    print(f"\nRESULT {'PASS' if passed == total else 'FAIL'} "
          f"({passed}/{total} 角色登录成功)", flush=True)
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
