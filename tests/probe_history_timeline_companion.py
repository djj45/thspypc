"""实发历史分时伴随代码替换实验，并用 thsdk 逐点核对。

默认把 PC 抓包中的 ``32(399002,)`` 等长替换为 ``33(000001,)``，
目标票保持为 ``000938``。请求通过已经完成 ``__manual + init(32)``
的 szlv2 连接发送，避免主行情连接与 L2 历史通道混用。

用法：
    python tests/probe_history_timeline_companion.py
    python tests/probe_history_timeline_companion.py --date 20260514
"""
from __future__ import annotations

import argparse
import datetime as dt
import logging
import os
import socket
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from thspypc import THSClient
from thspypc.protocol import (
    _HISTORY_TIMELINE_BAR_OFFSETS,
    build_history_timeline_query,
    normalize_8901_response,
    parse_history_timeline_response,
    read_frame,
)


def load_env() -> None:
    env_path = ROOT / ".env"
    if not env_path.exists():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip("\"'"))


def build_replaced_request(
    target: str,
    companion: str,
    date: str,
    merge_same_market: bool,
) -> bytes:
    if merge_same_market:
        return build_history_timeline_query(
            target,
            date=date,
            market=33,
            benchmark_market=33,
            benchmark_code=companion,
        )
    captured_shape = build_history_timeline_query(
        target,
        date=date,
        market=33,
        benchmark_market=32,
        benchmark_code="399002",
    )
    old = b"32(399002,)"
    new = f"33({companion},)".encode("ascii")
    if len(old) != len(new):
        raise ValueError("伴随代码替换必须保持字节长度不变")
    if captured_shape.count(old) != 2:
        raise RuntimeError("请求中没有找到两处 399002，当前构造器结构已变化")
    return captured_shape.replace(old, new)


def drain_socket(sock) -> None:
    sock.settimeout(0.2)
    for _ in range(20):
        try:
            read_frame(sock)
        except (socket.timeout, OSError, ValueError):
            break


def query_mixed_history(
    client: THSClient,
    target: str,
    companion: str,
    date: str,
    merge_same_market: bool,
) -> tuple[dict[str, list[dict]], bytes]:
    # timeline() 负责建立正确的 __manual szlv2 连接并完成 init(32)。
    current = client.timeline(target, market=33, timeout=20)
    print(f"szlv2 初始化完成；当日分时预热返回 {len(current)} 点")
    sock = client._push_socks.get("sz")
    if sock is None:
        raise RuntimeError("未建立 szlv2 __manual 连接")
    drain_socket(sock)

    request = build_replaced_request(
        target, companion, date, merge_same_market=merge_same_market
    )
    body = request[12:]
    print(
        "发送历史请求：",
        [
            part.decode("ascii")
            for part in (b"33(" + companion.encode() + b",)", b"33(" + target.encode() + b",)")
        ],
        f"body={len(body)}B",
        "同市场合并写法" if merge_same_market else "等长原位替换",
    )

    wanted = (companion, target)
    for attempt in range(1, 6):
        sock.settimeout(12)
        sock.sendall(request + b"\n")
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            sock.settimeout(min(4.0, max(0.2, deadline - time.monotonic())))
            try:
                response = read_frame(sock)
            except socket.timeout:
                continue
            except (OSError, ValueError) as exc:
                raise ConnectionError(f"读取历史响应失败: {exc}") from exc

            normalized = normalize_8901_response(response)
            if b"hd1.0\x00" not in normalized:
                continue
            parsed = {
                code: parse_history_timeline_response(response, code=code)
                for code in wanted
            }
            generic_first = parse_history_timeline_response(response, code=None)
            if not parsed[companion] and generic_first:
                # 强状态变体可能省略数据子表内的 ASCII 代码。完整查询的第一项
                # 就是 companion，因此可按请求顺序绑定第一张表，再交给 thsdk
                # 业务值确认，不能只靠代码字符串。
                parsed[companion] = generic_first
            print(
                f"第 {attempt} 次收到混合响应：raw={len(response)}B "
                f"normalized={len(normalized)}B "
                + ", ".join(f"{code}={len(rows)}点" for code, rows in parsed.items())
            )
            # 本实验的首要问题是“替换后的伴随代码是否真的返回该股票分时”。
            # 目标票可能因服务端只下发一个主表，或落入尚未支持的强省略变体而为空；
            # 只要伴随票可验证就立即进入 thsdk 对照。
            if parsed[companion]:
                stamp = time.strftime("%Y%m%d_%H%M%S")
                output = (
                    ROOT
                    / "captures_live"
                    / f"history_companion_{companion}_{target}_{date}_{stamp}.bin"
                )
                output.write_bytes(response)
                print(f"原始混合响应已保存：{output}")
                return parsed, response
        print(f"第 {attempt} 次未同时得到两个可验证子表，重发")
    raise RuntimeError("5 次请求后仍未解析出替换后的伴随股票子表")


def oracle_rows(ths, code: str, date: str) -> list[dict]:
    response = ths.min_snapshot(f"USZA{code}", date=date)
    if not response or not response.data:
        raise RuntimeError(f"thsdk {code} {date} 无数据: {response.error}")
    return response.data


def comparison_stats(
    parsed: list[dict],
    oracle: list[dict],
    request_bar_start: int,
) -> tuple[dict[str, int], int, list[str]]:
    offset_to_row = {
        offset: index for index, offset in enumerate(_HISTORY_TIMELINE_BAR_OFFSETS)
    }
    checks = {"price": 0, "volume": 0, "amount": 0}
    compared = 0
    mismatches: list[str] = []
    for row in parsed:
        oracle_index = offset_to_row.get(row["bar_index"] - request_bar_start)
        if oracle_index is None or oracle_index >= len(oracle):
            continue
        expected_price = float(oracle[oracle_index]["价格"])
        expected_volume = float(oracle[oracle_index]["成交量"])
        expected_amount = float(oracle[oracle_index]["总金额"])
        actual = (row.get("dt10"), row.get("dt13"), row.get("dt19"))
        expected = (expected_price, expected_volume, expected_amount)
        compared += 1
        for name, got, want in zip(checks, actual, expected):
            if got is not None and abs(float(got) - want) < 1e-6:
                checks[name] += 1
            elif len(mismatches) < 5:
                mismatches.append(
                    f"row={oracle_index} {name}: thspypc={got} thsdk={want}"
                )
    return checks, compared, mismatches


def compare_with_oracle(
    code: str,
    parsed: list[dict],
    oracle: list[dict],
    request_bar_start: int,
    oracle_date: str,
) -> tuple[int, int]:
    checks, compared, mismatches = comparison_stats(
        parsed, oracle, request_bar_start
    )
    print(
        f"{code} 对照 thsdk {oracle_date}："
        f"解析 {len(parsed)}点 / thsdk {len(oracle)}点，"
        f"实际比较 {compared}点；价格 {checks['price']}/{compared}，"
        f"成交量 {checks['volume']}/{compared}，"
        f"成交额 {checks['amount']}/{compared}"
    )
    for mismatch in mismatches:
        print("  mismatch:", mismatch)
    return sum(checks.values()), compared * 3


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--date", default="20260514")
    parser.add_argument("--target", default="000938")
    parser.add_argument("--companion", default="000001")
    parser.add_argument(
        "--merge-same-market",
        action="store_true",
        help="完整查询写成 33(000001,000938,)；默认做等长原位替换",
    )
    args = parser.parse_args()

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    load_env()
    username = os.environ.get("THS_USERNAME", "").strip()
    password = os.environ.get("THS_PASSWORD", "").strip()
    if not username or not password:
        raise RuntimeError(".env 缺少 THS_USERNAME/THS_PASSWORD")

    client = THSClient(
        username,
        password,
        imei=os.environ.get("THS_IMEI", "").strip() or None,
        enable_heartbeat=False,
    )
    try:
        parsed, _raw = query_mixed_history(
            client,
            args.target,
            args.companion,
            args.date,
            args.merge_same_market,
        )
    finally:
        client.disconnect()

    from thsdk import THS
    from thspypc.protocol import date_to_timeline_bar

    request_bar_start = date_to_timeline_bar(args.date)
    with THS() as ths:
        for code in (args.companion, args.target):
            if not parsed[code]:
                print(f"{code}：响应中没有当前解析器可验证的子表，跳过 thsdk 对照")
                continue
            requested_day = dt.datetime.strptime(args.date, "%Y%m%d").date()
            candidates = []
            for delta in range(-2, 4):
                candidate = (requested_day + dt.timedelta(days=delta)).strftime(
                    "%Y%m%d"
                )
                try:
                    oracle = oracle_rows(ths, code, candidate)
                except RuntimeError:
                    continue
                checks, compared, _ = comparison_stats(
                    parsed[code], oracle, request_bar_start
                )
                candidates.append((sum(checks.values()), compared * 3, candidate, oracle))
            if not candidates:
                raise RuntimeError(f"thsdk {code} 相邻日期均无数据")
            _score, _total, oracle_date, oracle = max(candidates, key=lambda item: item[0])
            print(
                f"{code} 响应首末：{parsed[code][0]} → {parsed[code][-1]}"
            )
            compare_with_oracle(
                code,
                parsed[code],
                oracle,
                request_bar_start,
                oracle_date,
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
