#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""普通账号指数当日分时 —— 原始帧诊断（绕过高层封装，手工发请求并逐帧转储）。

目的：定位普通账号 timeline(指数) 卡住 / 返回空的原因。
直接用 ConnectionManager 拿 socket，build_timeline_query 发请求，read_frame
逐帧读，每帧打印前 64 字节 hex + 是否含 hd3.1，再用 parse_index_timeline_response
尝试解析，把字段全部 dump 出来。

用法：
    py -3 tests/probe_index_today_rawframes.py
    py -3 tests/probe_index_today_rawframes.py --code 600000
    py -3 tests/probe_index_today_rawframes.py --frames 12
"""
from __future__ import annotations

import argparse
import datetime
import logging
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

logging.basicConfig(
    level=logging.INFO,
    format="  ·%(levelname)s %(name)s: %(message)s",
    stream=sys.stdout,
)

from thspypc import THSClient
from thspypc._transport import ConnectionRole
from thspypc.codecs.framing import read_frame
from thspypc.features.timeline_protocol import (
    build_timeline_query,
    parse_timeline_response,
    parse_index_timeline_response,
    TIMELINE_DATATYPE,
)


def load_env(path: str) -> None:
    if not os.path.exists(path):
        return
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value


def hexdump(b: bytes, n: int = 64) -> str:
    head = b[:n]
    hexs = " ".join(f"{x:02x}" for x in head)
    asc = "".join(chr(x) if 32 <= x < 127 else "." for x in head)
    return f"len={len(b)} hex[{n}]: {hexs} | {asc}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--code", default="1A0001")
    ap.add_argument("--frames", type=int, default=12, help="最多读几帧")
    ap.add_argument("--timeout", type=float, default=20.0)
    ap.add_argument("--env", default=None)
    args = ap.parse_args()

    env_path = args.env or os.path.join(
        os.path.dirname(__file__), "..", ".env.normal"
    )
    load_env(env_path)
    username = os.environ.get("THS_USERNAME", "").strip()
    password = os.environ.get("THS_PASSWORD", "").strip()
    imei = os.environ.get("THS_IMEI", "").strip() or None

    code = args.code
    client = THSClient(username=username, password=password, imei=imei)
    try:
        print("=" * 70)
        print(f"普通账号指数当日分时原始帧诊断  code={code}")
        print("=" * 70)
        print("→ 登录...")
        result = client.connect()
        if not result.success:
            print(f"✗ 登录失败: {result.error} / {result.detail}")
            return 1
        print(f"✓ 登录成功  server={result.server}")
        profile = client.observed_account_profile
        print(f"✓ 账号类型: {profile.kind.value}")

        # market
        if code.startswith(("1A", "1B")):
            market = 16
        elif code.startswith("39"):
            market = 32
        elif code.startswith("6"):
            market = 17
        else:
            market = 33
        is_index = market in (16, 32, 144)
        print(f"  market={market}  is_index={is_index}")

        # market
        if code.startswith(("1A", "1B")):
            market = 16
        elif code.startswith("39"):
            market = 32
        elif code.startswith("6"):
            market = 17
        else:
            market = 33
        is_index = market in (16, 32, 144)
        print(f"  market={market}  is_index={is_index}")

        # 拦截 read_frame，把每帧原始 hex 转储出来（不改生产路径）。
        # TimelineService 是惰性构造的，所以在 timeline() 之前 patch 类本身，
        # 让任何实例都走 traced reader；同时 patch 模块符号以防直接引用。
        import thspypc.services.timeline as tls_mod
        from thspypc.services.timeline import TimelineService
        orig_read_frame = read_frame

        def traced_read_frame(sock):
            nonlocal seen_hd31
            resp = orig_read_frame(sock)
            idx = len(dumped)
            dumped.append(resp)
            compressed = resp.startswith(b"\x0a")
            has_hd31 = b"hd3.1\x00" in resp
            has_hd10 = b"hd1.0" in resp
            if has_hd31:
                seen_hd31 = True
            print(f"\n  [frame {idx}] {hexdump(resp, 80)}")
            print(f"           compressed(0x0a)={compressed} "
                  f"hd3.1={has_hd31} hd1.0={has_hd10}")
            if has_hd31:
                try:
                    recs_n = parse_timeline_response(resp)
                except Exception as e:
                    print(f"           parse_normal 异常: {e!r}")
                    recs_n = []
                try:
                    recs_i = parse_index_timeline_response(resp)
                except Exception as e:
                    print(f"           parse_index 异常: {e!r}")
                    recs_i = []
                print(f"           解析: 普通={len(recs_n)} 指数={len(recs_i)}")
            return resp

        dumped: list[bytes] = []
        seen_hd31 = False
        tls_mod.read_frame = traced_read_frame
        TimelineService._read_frame = traced_read_frame
        print("  ✓ 已挂载帧追踪（patch 模块 + TimelineService._read_frame）")

        # 构造请求预览（实际请求由 timeline() 内部发出）
        preview = build_timeline_query(code, market=market)
        print(f"\n→ 请求预览 ({len(preview)}B), DataType={TIMELINE_DATATYPE}")
        print("  " + hexdump(preview, 96))

        print(f"\n→ 调 client.timeline({code!r}, timeout={args.timeout}s) ...")
        try:
            parsed = client.timeline(code, market=market, timeout=args.timeout)
        except Exception as e:
            print(f"✗ timeline 异常: {type(e).__name__}: {e}")
            parsed = []

        print("\n" + "=" * 70)
        if parsed:
            print(f"✓ 成功解析 {len(parsed)} 根，字段={sorted(parsed[0].keys())}")
            # 候选买卖字段
            cands = ["dt14", "dt15", "dt38", "dt39",
                     "dt202", "dt203", "dt208", "dt209", "dt210",
                     "dt227", "dt229"]
            present = [c for c in cands if any(r.get(c) is not None for r in parsed)]
            print(f"  候选买卖字段有值: {present if present else '（无）'}")
        elif seen_hd31:
            print("✗ 收到 hd3.1 帧但解析为空（flag/字段表不匹配）")
        else:
            print(f"✗ {args.frames} 帧内未见 hd3.1 分时表")
        return 0
    finally:
        try:
            client.disconnect()
        except Exception:
            pass


if __name__ == "__main__":
    sys.exit(main())
