#!/usr/bin/env python
"""同环境受控复验：板块列表旧路由 vs 当前路由（同一 BOARD socket）。

路线图存疑项：2026-08-02 抓包称旧列表形态（route=0x0039/0x0139、无
history flag、LackTime 全 0）服务端静默不回复，但“纯服务端变化”仍需同环境
受控复验。本脚本在同一板块连接（ConnectionRole.BOARD）上：

  1) 先发旧路由列表帧——除 route 字段外其余字节与当前实现完全一致
     （普通 0x006C/0x016C → 0x0039/0x0139；L2 0x0052/0x0152 → 0x0039/0x0139），
     期望超时无数据（服务端静默）；
  2) 再发当前路由列表帧，期望返回数据（证明通道/会话健康，差异来自路由）。

用法:
    py tests/_probe_board_route_compare.py            # .env（L2 账号）
    py tests/_probe_board_route_compare.py --env normal

注意：08-02（周日）的“旧路由静默”观测在周末；2026-08-03 交易日（收盘后）
复验旧路由仍被受理。旧路由可能是**盘中可用路径**，请于 08-04 开盘时段
（9:30-11:30 / 13:00-15:00）再跑一次双账号对照，并与
`tests/capture_system_blocks.py` 的【4b】路由分布交叉确认。

退出码：0=旧路由静默且当前路由有数据；1=其他。
（若旧路由返回数据则退出码 2，表示与服务端迁移结论矛盾。）
"""
from __future__ import annotations

import argparse
import socket
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from thspypc.client import THSClient  # noqa: E402
from thspypc.codecs.framing import read_frame  # noqa: E402
from thspypc.features.system_blocks_protocol import (  # noqa: E402
    build_board_list_query,
    load_board_full_codes,
    parse_board_full_quote_response,
)


def load_env(path: Path) -> dict:
    result = {}
    if not path.exists():
        return result
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        result[k.strip()] = v.strip().strip('"').strip("'")
    return result


def _route_bytes(frame: bytes) -> tuple[int, int]:
    """提取前缀/查询子帧 route。

    帧 = fdfdfdfd + 8 位 hex 长度 + body；body = 0x09 + 前缀子帧(22B头+文本)
    + 查询子帧(22B头+文本)。子帧头 route 在 offset 10（u16 LE），文本长度在
    offset 18（u32 LE）。
    """
    body = frame[12:]
    prefix_route = int.from_bytes(body[1 + 10:1 + 12], "little")
    # 前缀文本长度在子帧头 offset 18，紧跟在文本后是查询子帧头
    text_len = int.from_bytes(body[1 + 18:1 + 22], "little")
    query_header = 1 + 22 + text_len
    query_route = int.from_bytes(
        body[query_header + 10:query_header + 12], "little"
    )
    return prefix_route, query_route


def patch_old_route(frame: bytes, level2: bool) -> bytes:
    """把当前列表帧的 route 换成旧路由 0x0039/0x0139，其余字节不动。"""
    if level2:
        pairs = ((b"\x52\x00", b"\x39\x00"), (b"\x52\x01", b"\x39\x01"))
        label = "L2 0x0052/0x0152 -> 0x0039/0x0139"
    else:
        pairs = ((b"\x6c\x00", b"\x39\x00"), (b"\x6c\x01", b"\x39\x01"))
        label = "普通 0x006C/0x016C -> 0x0039/0x0139"
    patched = frame
    for old, new in pairs:
        count = frame.count(old)
        assert count == 1, f"{label}: 字节模式 {old.hex()} 出现 {count} 次（期望 1）"
        patched = patched.replace(old, new)
    print(f"  route 替换：{label}")
    return patched


def raw_request(
    service,
    frame: bytes,
    wanted: set[str],
    *,
    timeout: float,
) -> list[dict]:
    """直接占用 BOARD socket 发送请求并逐帧收集响应，返回解析出的记录。"""
    from thspypc._transport import ConnectionRole

    connection = service._connections.acquire(
        ConnectionRole.BOARD,
        capability=None,
    )
    records: list[dict] = []
    with connection.request(
        frame,
        timeout=timeout,
        trailing_newline=True,
    ) as sock:
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
            try:
                resp = read_frame(sock)
            except socket.timeout:
                break
            try:
                parsed = parse_board_full_quote_response(resp)
            except Exception:
                parsed = []
            matched = [
                r.get("code") for r in parsed if str(r.get("code", "")) in wanted
            ]
            print(
                f"    帧 {len(resp):>6}B 前24B={resp[:24].hex(' ')} "
                f"解析{len(parsed)}条 命中{len(matched)}: {matched[:5]}"
            )
            records.extend(parsed)
            if matched:
                break  # 命中目标代码即可停止，剩余时间窗口不吞后续帧
    return records


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--env", choices=("l2", "normal"), default="l2")
    args = parser.parse_args()
    env = load_env(ROOT / (".env" if args.env == "l2" else ".env.normal"))
    user, pwd = env.get("THS_USERNAME", ""), env.get("THS_PASSWORD", "")
    imei = env.get("THS_IMEI") or None
    if not user or not pwd:
        print("缺少账号凭据（.env / .env.normal）")
        return 1
    level2 = args.env == "l2"

    print(f"== 板块列表路由对照：{user}（{args.env}）==")
    client = THSClient(username=user, password=pwd, imei=imei)
    lr = client.connect()
    if not lr.success:
        print(f"✗ MAIN 登录失败: {lr.error} {lr.detail[:120]}")
        return 1
    print(f"✓ MAIN 登录 {lr.server}")
    client.configure_service_context(allow_open=True)
    service = client._board_service

    wanted = ["881101", "881121", "885480"]
    universe = list(load_board_full_codes())
    new_frame = build_board_list_query(
        wanted,
        level2=level2,
        universe_codes=universe,
    )
    old_frame = patch_old_route(new_frame, level2=level2)
    print(f"  当前路由：{_route_bytes(new_frame)}；旧路由：{_route_bytes(old_frame)}")
    print(f"  查询代码：{wanted}（universe {len(universe)} 个）")

    wanted_set = set(wanted)

    # 1) 旧路由：期望超时静默（[]）
    t0 = time.monotonic()
    old_records = raw_request(
        service,
        old_frame,
        wanted_set,
        timeout=8.0,
    )
    old_dt = (time.monotonic() - t0) * 1000
    got_old = [r.get("code") for r in old_records if r.get("code") in wanted]
    print(
        f"{'✗ 旧路由' if got_old else '✓ 旧路由'} {old_dt:.0f}ms "
        f"返回 {len(old_records)} 条，命中 {len(got_old)}：{got_old[:5]}"
    )

    # 2) 当前路由：期望返回数据（证明同一 socket/会话健康）
    t0 = time.monotonic()
    new_records = raw_request(
        service,
        new_frame,
        wanted_set,
        timeout=12.0,
    )
    new_dt = (time.monotonic() - t0) * 1000
    got_new = [r.get("code") for r in new_records if r.get("code") in wanted]
    print(
        f"{'✗ 当前路由' if not got_new else '✓ 当前路由'} {new_dt:.0f}ms "
        f"返回 {len(new_records)} 条，命中 {len(got_new)}：{got_new[:5]}"
    )

    client.disconnect()
    old_ok = not got_old
    new_ok = bool(got_new)
    if old_ok and new_ok:
        print("\n✓✓ 受控复验通过：旧路由静默、当前路由有数据（纯服务端路由迁移成立）")
        return 0
    if not old_ok and new_ok:
        print("\n★ 旧路由在当前环境仍返回数据——与服务端迁移结论矛盾，需复查！")
        return 2
    print("\n✗ 当前路由无数据，通道/会话检查失败")
    return 1


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    raise SystemExit(main())
