"""北交所超级盘口逐笔窗口协议测试（金样本取自 2026-09-08 L2 账号抓包）。"""

from __future__ import annotations

import struct
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from thspypc.features.superorder_protocol import (
    bse_tick_window_identity,
    build_bse_tick_window_query,
    parse_bse_tick_response,
)

# 920118 早盘竞价窗（09:15-09:25）响应：flag=0x003a，7 行逐笔。
GOLDEN_TICK_920118 = bytes.fromhex(
    "fdfdfdfd3030303030303965090016ff0f140112000900fc0100010000081c84000000"
    "000000006864332e3100070000003a0014000500013000040a700004317000041b700"
    "004217000041600010097393230313138000000000000000000070046000000000000"
    "8c090f0135f8f451cf793f2af8e801071cfe803fe00ff8140180efef083a803f804f1"
    "ff007fc0168f003fe1b7ec040c0ef0f047cf0247e7f5beba7216f4b831b04c006"
)


def test_parse_bse_tick_golden():
    rows = parse_bse_tick_response(GOLDEN_TICK_920118[12:])

    assert len(rows) == 7
    assert all(r["code"] == "920118" for r in rows)
    first = rows[0]
    assert first["ts"] == 1788830105
    assert first["price"] == pytest.approx(22.19)
    assert first["volume"] == 100
    assert first["dt27"] == 0
    assert first["dt33"] == 900
    # dt49 累计、volume 差分
    assert rows[1]["dt49"] == 205
    assert rows[1]["volume"] == 105
    assert rows[6]["ts"] == 1788830684


def test_build_bse_tick_window_request_shape():
    frame = build_bse_tick_window_query(
        "920118", start_ts=1788830100, end_ts=1788830700, seq=0x0300
    )
    body = frame[12:]
    assert body[:1] == b"\x09"
    assert b"DateTime=7176(1788830100-1788830700)" in body
    assert b"pageid=10443" in body
    assert body[11:13] == b"\xfc\x01"  # route 0x01fc
    assert body[15:17] == b"\x40\x00"  # flag14=0x0040


# ---------------------------------------------------------------------------
# 6144 历史竞价窗（分时页历史日期 09:15-09:25，pageid=10444/route=0x0100）
# 金样本取自 2026-09-08 日期标定抓包（bse_920083_20260908_161904.pcapng）。
# ---------------------------------------------------------------------------

from pathlib import Path

# 官方 6144 请求（920118，09-04 竞价窗，seq=0x016d）。
OFFICIAL_REQ_6144_0904_BODY = bytes.fromhex(
    "09001600006d011200090000010000000000187d000000436f64654c6973743d31353128"
    "3932303131382c293b0d0a44617461547970653d31302c32372c33332c34392c0d0a4461"
    "746554696d653d3631343428313738383438343530302d31373838343835313030290d0a"
    "4c61636b54696d653d302c302c302c302c302c302c302c300d0a7061676569643d313034"
    "34340d0a"
)


def test_build_bse_auction_window_query_matches_official_frame():
    frame = build_bse_tick_window_query(
        "920118",
        start_ts=1788484500,
        end_ts=1788485100,
        tag=6144,
        pageid=10444,
        seq=0x016D,
        route=0x0100,
        flag14=0x0000,
        byte16=0x00,
        byte17=0x18,
    )
    assert frame[12:] == OFFICIAL_REQ_6144_0904_BODY


def test_build_bse_tick_window_request_header_bytes():
    # 7176 变体：[14:18] = 40 00 08 1c（两次抓包一致）。
    frame = build_bse_tick_window_query(
        "920118", start_ts=1788830100, end_ts=1788830700, seq=0x0106
    )
    body = frame[12:]
    assert body[11:13] == b"\xfc\x01"  # route 0x01fc
    assert body[15:17] == b"\x40\x00"  # flag14=0x0040
    assert body[17:19] == b"\x08\x1c"  # byte16=0x08 byte17=0x1c


def test_parse_bse_auction_golden_covers_dc_high_bits():
    # 09-04 竞价响应：dc=0x0600001c（高 16 位 0x0600 修饰位），28 笔。
    fixture = (
        Path(__file__).parent
        / "fixtures"
        / "history_timeline"
        / "bse_920118_20260904_6144.bin"
    ).read_bytes()
    rows = parse_bse_tick_response(fixture)

    assert len(rows) == 28
    assert all(r["code"] == "920118" for r in rows)
    first = rows[0]
    assert first["ts"] == 1788484502  # 09-04 09:15:02
    assert first["price"] == pytest.approx(21.19)
    last = rows[-1]
    assert last["ts"] == 1788485099  # 09-04 09:24:59
    assert last["price"] == pytest.approx(21.6)


# ---------------------------------------------------------------------------
# 空表识别：bse_tick_window 必须把 0 行 0x003a 表当作合法空窗口返回，
# 否则前端整日 10 分钟桶扫描会被每个安静桶的读超时（≥timeout 秒）拖死。
# ---------------------------------------------------------------------------


def test_bse_tick_window_identity_golden_table():
    assert bse_tick_window_identity(GOLDEN_TICK_920118[12:]) == ("920118", 7)


def _empty_003a_table() -> bytes:
    # 与金样本同形的表头（rs=20/fc=5），dc 低 16 位 = 0 行；空表无壳/行区。
    return b"hd3.1\x00" + struct.pack("<IHHH", 0x06000000, 0x003A, 20, 5)


def test_bse_tick_window_identity_empty_table():
    assert bse_tick_window_identity(_empty_003a_table()) == (None, 0)


def test_bse_tick_window_identity_rejects_unrelated_frames():
    assert bse_tick_window_identity(b"\x0a\x01\x02push") is None
    assert bse_tick_window_identity(b"hd2.1\x00" + b"\x00" * 16) is None


class _FakeSock:
    def settimeout(self, value):  # noqa: D102 - bse_tick_window 每轮调用
        pass


class _FakeConnection:
    def __init__(self, frames: list[bytes]):
        self._frames = list(frames)

    @contextmanager
    def request(self, request, timeout=None):
        yield _FakeSock()


def _fake_service(frames: list[bytes]):
    return SimpleNamespace(
        _connections=SimpleNamespace(
            acquire=lambda *args, **kwargs: _FakeConnection(frames)
        ),
        _read_frame=lambda sock: frames.pop(0),
    )


def test_bse_tick_window_returns_empty_for_zero_row_table():
    from thspypc.services.superorder import bse_tick_window

    service = _fake_service([_empty_003a_table()])
    rows = bse_tick_window(
        service,
        "920118",
        market=151,
        start_ts=1788830100,
        end_ts=1788830700,
        timeout=0.5,
    )
    assert rows == []


def test_bse_tick_window_parses_golden_rows():
    from thspypc.services.superorder import bse_tick_window

    service = _fake_service([GOLDEN_TICK_920118[12:]])
    rows = bse_tick_window(
        service,
        "920118",
        market=151,
        start_ts=1788830100,
        end_ts=1788830700,
        timeout=0.5,
    )
    assert len(rows) == 7
    assert rows[0]["price"] == pytest.approx(22.19)


def test_bse_tick_window_filters_rows_to_request_window():
    """窗口过滤：老交易日（2026-09-01 活网实测）响应首行是 ts=2038 年的
    哨兵/基线行，非窗口内逐笔；行必须落在 [start_ts, end_ts] 内才返回。
    用金样本表 + 缩窄窗口验证同一条过滤路径。"""
    from thspypc.services.superorder import bse_tick_window

    service = _fake_service([GOLDEN_TICK_920118[12:]])
    rows = bse_tick_window(
        service,
        "920118",
        market=151,
        start_ts=1788830300,  # 金样本 7 行的 ts 范围是 09:15:05~09:24:44
        end_ts=1788830700,
        timeout=0.5,
    )
    assert [r["ts"] for r in rows] == [
        1788830387, 1788830453, 1788830513,
        1788830564, 1788830624, 1788830684,
    ]


# ---------------------------------------------------------------------------
# 盘中超级盘口（pageid=1207 + DateTime=4096，2026-09-08 20:30 复抓）。
# 官方"超级盘口"页当日 = 注册 + 4096 全日窗 + 状态三子帧一包；响应
# flag=0x0096 大表（rsize=112 / 28 字段），每行逐笔 + 完整五档快照。
# ---------------------------------------------------------------------------

SUPERORDER_FIXTURES = Path(__file__).parent / "fixtures" / "superorder"


def test_build_bse_superorder_query_matches_official_frame():
    """官方帧 frame1468（全日 0-0 三子帧）帧体逐字节对比。

    长度前缀除外：官方客户端写 len-1（不含 0x09 子帧标记字节），服务端
    按 magic 扫描自同步，两种写法等价（本项目 encode_frame 全长度写法
    已在 7176/6144 活网验证）。"""
    from thspypc.features.superorder_protocol import build_bse_superorder_query

    golden = (
        SUPERORDER_FIXTURES / "bse_920118_superorder_req_frame1468.bin"
    ).read_bytes()
    frame = build_bse_superorder_query(
        "920118",
        seqs=(0x0000, 0x0159, 0x015B),
    )
    assert frame[12:] == golden[12:]


def test_parse_bse_superorder_today_table():
    from thspypc.features.superorder_protocol import parse_bse_superorder_response

    body = (
        SUPERORDER_FIXTURES / "bse_920118_superorder_4096_0096_977rows.bin"
    ).read_bytes()
    rows = parse_bse_superorder_response(body, code="920118")

    # 首行 = 竞价金样本首笔；哨兵行已丢弃。
    assert len(rows) == 977
    first = rows[0]
    assert first["ts"] == 1788830105  # 09-08 09:15:05
    assert first["price"] == pytest.approx(22.19)
    assert first["volume"] == pytest.approx(100.0)
    # 竞价首行盘口：买一/卖一 22.19@100（撮合点），卖二量 900 = 7176
    # 金样本首行的卖未匹配 dt33=900，交叉对拍。
    assert first["bids"][0] == {"price": pytest.approx(22.19), "volume": pytest.approx(100.0)}
    assert first["asks"][1]["volume"] == pytest.approx(900.0)
    last = rows[-1]
    assert last["ts"] == 1788850802  # 09-08 15:00:02
    assert last["price"] == pytest.approx(22.15)
    assert last["dt13"] == pytest.approx(450164.0)  # 与页面总量 45.0 万一致
    assert last["dt19"] == pytest.approx(9_930_020.0)  # 与页面总额 993.0 万一致
    # 末行五档：买 22.05/22.04/22.03/22.01/22.00 递减，
    # 卖 22.15/22.16/22.17/22.18/22.19 递增（收盘盘口，末笔 22.15=卖一）。
    assert [lv["price"] for lv in last["bids"]] == pytest.approx(
        [22.05, 22.04, 22.03, 22.01, 22.0],
    )
    assert [lv["price"] for lv in last["asks"]] == pytest.approx(
        [22.15, 22.16, 22.17, 22.18, 22.19],
    )
    assert last["bids"][4]["volume"] == pytest.approx(22077.0)
    assert last["asks"][0]["volume"] == pytest.approx(73.0)


def test_parse_bse_superorder_preday_table_drops_sentinel():
    """PreDay 响应（T-1 全日 1265 行）首行是哨兵行，应被丢弃。"""
    from thspypc.features.superorder_protocol import parse_bse_superorder_response

    body = (
        SUPERORDER_FIXTURES / "bse_920118_superorder_4096_0096_1265rows.bin"
    ).read_bytes()
    rows = parse_bse_superorder_response(body, code="920118")
    assert len(rows) == 1264
    assert all(1_700_000_000 <= r["ts"] <= 1_900_000_000 for r in rows)
    assert rows[0]["ts"] == 1788743820  # 09-07 09:17:00


def test_bse_superorder_day_service_golden_roundtrip():
    from thspypc.services.superorder import bse_superorder_day

    body = (
        SUPERORDER_FIXTURES / "bse_920118_superorder_4096_0096_977rows.bin"
    ).read_bytes()
    service = _fake_service([body])
    rows = bse_superorder_day(service, "920118", market=151, timeout=0.5)
    assert len(rows) == 977
    assert rows[0]["price"] == pytest.approx(22.19)
