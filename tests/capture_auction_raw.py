#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
抓沪市集合竞价的【原始响应字节】，用于跨样本对比 fmt 参数化编码（2026-07-27）。

背景
----
跨样本对比发现：同一只票 603118，不同抓包的 dt49/dt33 fmt 子标记完全不同
（单帧 [0x11,0x1a] vs superorder [0x22,0x34]），呈 1/2/4 倍数关系。沪市用的是
【参数化变长编码】，需要多次抓包锁定 N 的取值与触发条件。

`test_auction.py` 只返回解析后的 dict，丢弃了原始字节；本脚本复用 client 的
登录/连接，但直接截获 __manual 推送连接上的原始响应帧并保存为 .bin，供离线
对比 fmt 参数。

用法
----
    # 同一只票抓多次（看 N 是否每次都变）
    py tests/capture_auction_raw.py 603118 --repeat 5

    # 多只不同价位票各抓一次（看 N 与价位是否相关）
    py tests/capture_auction_raw.py 603118,600276,601318

    # 指定交易日
    py tests/capture_auction_raw.py 603118 --date 2026-07-24 --repeat 3

★ 盘后/周末都能跑（拿最近交易日数据）。
⚠ 需要 level2 账号（.env 里的 THS_USERNAME/THS_PASSWORD）。
⚠ 沪市 shlv2 IP 偶有超时，失败会标注并继续。

产物
----
captures_live/auction_raw_<code>_<timestamp>.bin   — 原始响应帧（含 hd1.0 + 字段表 + tick）
终端打印字段表的 fmt 子标记（对比关键）
"""
from __future__ import annotations

import datetime
import logging
import os
import re
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

logging.basicConfig(
    level=logging.INFO,
    format="  ·%(levelname)s %(name)s: %(message)s",
    stream=sys.stdout,
)

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


def parse_field_table_fmt(body: bytes) -> list[tuple[int, list[int]]]:
    """从原始响应里提取字段表的 fmt 子标记（跨样本对比的关键）。

    字段表在 ``hd1.0`` 标记之后，以 ``0a 70 04``（dt10 起点）开始，到个股壳
    ``0x11+code`` 前。每条 = ``[dt][fmt字节...][0x04]``。
    """
    start = body.find(b"\x0a\x70\x04")
    if start < 0:
        return []
    # 找个股壳（0x11 + 6 位数字）
    shell_pos = -1
    for i in range(start + 2, min(len(body), start + 60)):
        if body[i] == 0x11 and i + 6 < len(body):
            code = body[i + 1:i + 7]
            if re.match(rb"^\d{6}$", code):
                shell_pos = i
                break
    if shell_pos < 0:
        return []
    table = body[start:shell_pos]
    # 按 0x04 切分
    fields: list[tuple[int, list[int]]] = []
    cur: list[int] = []
    for b in table:
        if b == 0x04:
            if cur:
                dt = cur[0]
                fmt = cur[1:]
                fields.append((dt, fmt))
            cur = []
        else:
            cur.append(b)
    return fields


def fetch_raw_auction(client: THSClient, code: str, market: int,
                      trade_date, timeout: float = 30.0) -> bytes | None:
    """调用 ``client.auction()``，但用 monkey-patch 截获原始响应帧。

    ``client.auction()`` 内部调用 ``parse_auction_response(resp)`` 解析。这里
    把该函数替换成一个会先把 ``resp`` 存到 ``captured`` 的 wrapper，从而拿到
    原始字节，同时仍返回正常的解析结果（保证 client 内部流程不中断）。

    timeout 默认 30s（比 client.auction 默认 12s 更宽裕，沪市 shlv2 响应慢）。
    """
    import thspypc.protocol as proto
    captured: dict[str, bytes | None] = {"resp": None}
    original = proto.parse_auction_response

    def spy(resp: bytes):
        captured["resp"] = resp
        return original(resp)

    proto.parse_auction_response = spy
    try:
        # 复用 client.auction() 的完整连接管理（建 __manual、订阅、查询）
        client.auction(code, market=market, trade_date=trade_date, timeout=timeout)
    finally:
        proto.parse_auction_response = original
    return captured["resp"]




def save_and_report(code: str, resp: bytes, idx: int, out_dir: str) -> None:
    """保存原始响应并打印字段表 fmt 参数。"""
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = os.path.join(out_dir, f"auction_raw_{code}_{ts}_r{idx}.bin")
    with open(fname, "wb") as f:
        f.write(resp)
    print(f"  ✓ 保存 {fname} ({len(resp)}B)")

    # 解析字段表 fmt
    fields = parse_field_table_fmt(resp)
    if fields:
        print(f"  字段表 fmt 参数:")
        for dt, fmt in fields:
            name = {10: "价", 49: "量", 27: "未匹配", 33: "额"}.get(dt, "?")
            fmt_hex = ",".join(f"0x{b:02x}" for b in fmt)
            print(f"    dt{dt}({name}): fmt=[{fmt_hex}]")
        # 单独高亮 dt49/dt33 的 N 值
        dt49 = next((f for d, f in fields if d == 49), [])
        dt33 = next((f for d, f in fields if d == 33), [])
        if dt49 and dt33:
            # N = dt49子标记 / 17（基准）
            sub49 = dt49[0] if dt49[0] != 0x70 else dt49[1]
            print(f"  ★ dt49 子标记={sub49} (N≈{sub49/17:.1f}x基准17)")
    else:
        print(f"  ⚠ 未找到字段表（可能不是竞价帧）")


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(description="抓沪市竞价原始响应（对比 fmt 参数）")
    ap.add_argument("codes", help="股票代码，逗号分隔（如 603118,600276）")
    ap.add_argument("--repeat", type=int, default=1,
                    help="每只票重复抓几次（看 N 是否每次都变），默认 1")
    ap.add_argument("--date", default=None,
                    help="交易日 YYYY-MM-DD，默认最近交易日")
    ap.add_argument("--interval", type=float, default=2.0,
                    help="重复抓之间的间隔（秒），默认 2.0")
    args = ap.parse_args()

    load_dotenv()
    username = os.environ.get("THS_USERNAME")
    password = os.environ.get("THS_PASSWORD")
    imei = os.environ.get("THS_IMEI")
    if not username or not password:
        print("✗ 缺少 THS_USERNAME/THS_PASSWORD（.env）")
        return 1

    codes = [c.strip() for c in args.codes.split(",") if c.strip()]
    # ★ 必须显式传日期：trade_date=None 会发 DateTime=7176(0-0)，服务器不响应
    # 默认算最近交易日（跳过周末），可用 --date 覆盖
    if args.date:
        trade_date = datetime.date.fromisoformat(args.date)
    else:
        trade_date = datetime.date.today()
        while trade_date.weekday() >= 5:  # 5=周六 6=周日，回退到周五
            trade_date -= datetime.timedelta(days=1)

    out_dir = os.path.join(os.path.dirname(__file__), "..", "captures_live")
    os.makedirs(out_dir, exist_ok=True)

    print("=" * 64)
    print(f"抓沪市竞价原始响应（每只票 × {args.repeat} 次）")
    print(f"日期: {trade_date or '最近交易日'}")
    print(f"代码: {codes}")
    print("=" * 64)

    client = THSClient(username=username, password=password, imei=imei)
    try:
        print("→ 登录 8901...")
        result = client.connect()
        if not result.success:
            print(f"✗ 登录失败: {result.error} / {result.detail}")
            return 1
        print(f"✓ 登录成功，服务器 {result.server}")

        for code in codes:
            market = 17 if code.startswith("6") else 33
            mkt = "沪市(17→shlv2)" if code.startswith("6") else "深市(33→szlv2)"
            print(f"\n{'─' * 64}")
            print(f"→ {code} ({mkt})，抓 {args.repeat} 次")
            for i in range(args.repeat):
                print(f"  [第 {i + 1}/{args.repeat} 次]")
                try:
                    resp = fetch_raw_auction(client, code, market, trade_date)
                except Exception as e:
                    print(f"  ✗ 异常: {type(e).__name__}: {e}")
                    continue
                if resp:
                    save_and_report(code, resp, i + 1, out_dir)
                else:
                    print(f"  ✗ 无响应（client.auction 返回空）")
                if i + 1 < args.repeat:
                    time.sleep(args.interval)

        print(f"\n{'=' * 64}")
        print("完成。对比每次抓包的 dt49/dt33 fmt 子标记：")
        print("  - 若同一只票多次抓的 N 值不同 → N 随机")
        print("  - 若相同 → N 会话内稳定")
        return 0
    finally:
        client.disconnect()


if __name__ == "__main__":
    sys.exit(main())
