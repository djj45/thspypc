"""系统板块 8901 协议离线回归（2026-08-01 抓包样本）。"""
from __future__ import annotations

import datetime
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from thspypc.features.system_blocks_protocol import (  # noqa: E402
    BOARD_AUCTION_DATATYPE,
    BOARD_CONSTITUENT_DATATYPE,
    BOARD_CONSTITUENT_DATATYPE_L2,
    BOARD_HISTORY_DATATYPE,
    BOARD_QUOTE_DATATYPE,
    BOARD_QUOTE_DATATYPE_L2,
    PAGEID_BOARD_HISTORY,
    PAGEID_BOARD_LIST,
    PAGEID_BOARD_LIST_L2,
    PAGEID_BOARD_TL,
    build_board_auction_query,
    build_board_constituents_query,
    build_board_constituents_selection_query,
    build_board_constituents_sort_query,
    build_board_list_query,
    build_board_timeline_query,
    parse_board_auction_response,
    parse_board_constituents_response,
    parse_board_quote_response,
    parse_board_timeline_response,
)
from thspypc.features.history_timeline_protocol import (
    date_to_normal_timeline_bar,
    normal_timeline_bar_to_date,
)
from thspypc.protocol import parse_kline_hd3_response
import thspypc.features.system_blocks_protocol as board_protocol


def _sample(name: str) -> Path:
    return Path(__file__).resolve().parents[1] / "captures_live" / name


def _fixture(name: str) -> Path:
    return Path(__file__).resolve().parent / "fixtures" / "board" / name


def test_board_history_date_cursor_matches_captured_sample():
    # 抓包 6002 请求 DateTime=8192(132258398-132258753) → 2026-02-03
    assert date_to_normal_timeline_bar("2026-02-03") == 132_258_398
    assert (
        normal_timeline_bar_to_date(132_258_398).date().isoformat()
        == "2026-02-03"
    )


def test_build_board_history_query_shape():
    frame = build_board_timeline_query("886090", date="2026-02-03")
    body = frame[12:]
    text = body.decode("gbk", errors="replace")
    assert "CodeList=48(886090,);" in text
    assert "DateTime=8192(132258398-132258753)" in text
    assert "DataType=13,19,40,10,23,22,6," in text
    assert "LackTime=0,3,0,0,0,0,0,0" in text
    assert f"pageid={PAGEID_BOARD_HISTORY}" in text


def test_build_board_timeline_query_defaults_to_today():
    today = datetime.date.today()
    bar_start = date_to_normal_timeline_bar(today)

    frame = build_board_timeline_query("886090")
    text = frame[12:].decode("gbk", errors="replace")

    assert f"DateTime=8192({bar_start}-{bar_start + 355})" in text


def test_build_board_list_query_shape():
    frame = build_board_list_query(["881101", "885480"])
    body = frame[12:]
    text = body.decode("gbk", errors="replace")
    assert "CodeList=48(881101,885480,);" in text
    assert f"pageid={PAGEID_BOARD_LIST}" in text
    assert "DataType=48,592890,10,6,66," in text
    # 2026-08-02 抓包：前缀 route=0x006C、查询 route=0x016C、seq=0x01C4、
    # 查询子帧无 history flag（字节 17=0x00）、LackTime 全 0。
    # 旧列表形态（0x0039/0x0139、无 history flag、LackTime 全 0）服务端不回复。
    assert body[11:13] == b"\x6c\x00"
    prefix_length = int.from_bytes(body[19:23], "little")
    query_offset = 23 + prefix_length
    assert body[query_offset + 10: query_offset + 12] == b"\x6c\x01"
    assert body[query_offset + 17] == 0x00
    assert body[query_offset + 4: query_offset + 6] == b"\xc4\x01"
    assert "LackTime=0,0,0,0,0,0,0,0" in text
    assert body.endswith(b"\r")


def test_build_board_list_query_l2_shape():
    frame = build_board_list_query(["881101", "885480"], level2=True)
    body = frame[12:]
    text = body.decode("gbk", errors="replace")
    assert "CodeList=48(881101,885480,);" in text
    assert f"pageid={PAGEID_BOARD_LIST_L2}" in text
    assert "DataType=" + ",".join(map(str, BOARD_QUOTE_DATATYPE_L2)) in text
    # 2026-08-02 抓包：L2 前缀 route=0x0052、查询 route=0x0152、seq=0x0068。
    assert body[11:13] == b"\x52\x00"
    prefix_length = int.from_bytes(body[19:23], "little")
    query_offset = 23 + prefix_length
    assert body[query_offset + 10: query_offset + 12] == b"\x52\x01"
    assert body[query_offset + 17] == 0x00
    assert body[query_offset + 4: query_offset + 6] == b"\x68\x00"
    assert "LackTime=0,0,0,0,0,0,0,0" in text


def test_build_board_constituents_query_groups_markets():
    frame = build_board_constituents_query(["600519", "000938", "920021"])
    body = frame[12:]
    text = body.decode("gbk", errors="replace")
    assert "17(600519,);" in text
    assert "33(000938,);" in text
    assert "151(920021,);" in text
    assert f"pageid={PAGEID_BOARD_TL}" in text
    assert "DataType=" + ",".join(map(str, BOARD_CONSTITUENT_DATATYPE)) in text
    # 2026-08-01 16:37 干净包：注册 route=0x44，查询 route=0x144。
    assert body[11:13] == b"\x44\x00"
    prefix_length = int.from_bytes(body[19:23], "little")
    query_offset = 23 + prefix_length
    assert body[query_offset + 10: query_offset + 12] == b"\x44\x01"
    assert body.endswith(b"\r")


def test_build_board_constituents_query_uses_level2_routes_and_datatypes():
    frame = build_board_constituents_query(
        ["600519", "000938", "920021"],
        level2=True,
    )
    body = frame[12:]
    text = body.decode("gbk", errors="replace")
    assert "pageid=6000" in text
    assert (
        "DataType=" + ",".join(map(str, BOARD_CONSTITUENT_DATATYPE_L2))
        in text
    )
    # 2026-08-01 16:40 干净包：两条市场连接均为 0x5c/0x15c。
    assert body[11:13] == b"\x5c\x00"
    prefix_length = int.from_bytes(body[19:23], "little")
    query_offset = 23 + prefix_length
    assert body[query_offset + 10: query_offset + 12] == b"\x5c\x01"
    assert body.endswith(b"\r")


def test_build_normal_board_constituent_sort_and_selection_shapes():
    universe = ["600519", "000938", "920021"]
    sort_frame = build_board_constituents_sort_query(
        universe,
        visible_codes=universe[:2],
        sort_begin=0,
        sort_count=2,
    )
    sort_body = sort_frame[12:]
    sort_text = sort_body.decode("gbk", errors="replace")
    assert "SortType=Sort" in sort_text
    assert "SortBegin=0" in sort_text
    assert "SortCount=2" in sort_text
    assert b"\x12\x00\x0f\x00\x44\x01" in sort_body
    assert sort_body.endswith(b"\r")

    selection_frame = build_board_constituents_selection_query(universe[:2])
    selection_body = selection_frame[12:]
    selection_text = selection_body.decode("gbk", errors="replace")
    assert "DataType=527527," in selection_text
    assert b"\x12\x00\x09\x00\x44\x01" in selection_body
    assert selection_body.endswith(b"\r")

    quote_frame = build_board_constituents_query(
        universe[:2],
        include_prefix=False,
    )
    quote_body = quote_frame[12:]
    assert quote_body[1:5] == b"\x00\x16\x00\x00"
    assert quote_body[9:13] == b"\x09\x00\x44\x01"
    assert quote_body.count(b"CodeList=") == 1
    assert quote_body.endswith(b"\r")


def test_build_board_constituents_preserves_explicit_market_22():
    frame = build_board_constituents_query(
        ["600745", "688270", "000938", "920012"],
        markets={
            "600745": "22",
            "688270": 22,
            "000938": "33",
            "920012": "-105",
        },
    )
    text = frame.decode("gbk", errors="replace")
    assert "22(600745,688270,);" in text
    assert "33(000938,);" in text
    assert "151(920012,);" in text


def test_build_board_auction_query_shape():
    frame = build_board_auction_query("886090", date="2026-07-23")
    text = frame[12:].decode("gbk", errors="replace")
    start = int(datetime.datetime(2026, 7, 23, 9, 15).timestamp())
    end = int(datetime.datetime(2026, 7, 23, 9, 25).timestamp())
    assert f"DateTime=7176({start}-{end})" in text
    assert "DataType=10,27,33,49," in text


def test_build_board_auction_query_defaults_to_today():
    today = datetime.date.today()
    start = int(datetime.datetime.combine(today, datetime.time(9, 15)).timestamp())
    end = int(datetime.datetime.combine(today, datetime.time(9, 25)).timestamp())

    frame = build_board_auction_query("886090")
    text = frame[12:].decode("gbk", errors="replace")

    assert f"DateTime=7176({start}-{end})" in text


def test_parse_board_quote_sample():
    path = _sample("_board_quote_0x130.bin")
    if not path.exists():
        pytest.skip("本机缺少板块行情 0x130 样本")
    records = parse_board_quote_response(path.read_bytes())
    assert len(records) == 17
    first = records[0]
    assert first["code"] == "881101"
    assert first["name"] == "种植业与林业"
    assert first["dt10"] > 0
    assert first["dt6"] > 0


def test_parse_board_constituents_sample():
    path = _sample("_board_constituents.bin")
    if not path.exists():
        pytest.skip("本机缺少板块成分股 0x64 样本")
    records = parse_board_constituents_response(path.read_bytes())
    assert len(records) == 21
    assert all(len(r.get("code", "")) == 6 for r in records)
    assert all("dt10" in r or "dt66" in r for r in records)


def test_parse_board_constituents_accepts_normal_account_table_flags(monkeypatch):
    calls = []

    def fake_rows(_body, *flags):
        calls.append(flags)
        return None

    monkeypatch.setattr(board_protocol, "_hd3_rows", fake_rows)
    assert board_protocol.parse_board_constituents_response(b"response") == []
    assert calls == [(0x64, 0x44, 0x50)]


def test_parse_board_constituents_scans_later_hd3_table(monkeypatch):
    body = b"prefix-hd3.1\x00other-table-hd3.1\x00constituents"

    def fake_rows(candidate, *flags):
        assert flags == (0x64, 0x44, 0x50)
        if not candidate.startswith(b"hd3.1\x00constituents"):
            return None
        return 0x64, 7, [(5, 0, 7)], b"", b"\x11600001"

    monkeypatch.setattr(board_protocol, "_hd3_rows", fake_rows)

    assert board_protocol.parse_board_constituents_response(body) == [
        {"code": "600001"}
    ]


def test_parse_board_timeline_sample():
    path = _sample("_board_timeline.bin")
    if not path.exists():
        pytest.skip("本机缺少板块分时 0x42 样本")
    records = parse_board_timeline_response(path.read_bytes())
    assert len(records) == 242
    assert records[0]["bar_index"] == records[0].get("bar_index")
    assert "dt10" in records[0]
    assert records[0]["minute_index"] == 0
    assert "date" not in records[0]  # 首行是基准价哨兵，不是 packed-date 游标
    assert records[1]["date"].isoformat() == "2026-02-03"


def test_parse_board_auction_0x32_fixture():
    """2026-08-02 抓包 0x32 竞价表（881101，2026-07-31 早盘集合竞价）。"""
    records = parse_board_auction_response(
        _fixture("auction_resp_0x32.bin").read_bytes()
    )
    assert len(records) == 21
    first, last = records[0], records[-1]
    assert first["time"].date().isoformat() == "2026-07-31"
    assert first["time"].time().isoformat() == "09:15:15"
    assert last["time"].time().isoformat() == "09:25:00"
    assert first["dt10"] > 0
    assert first["dt49"] > 0


def test_parse_board_daily_k_0x42_fixture():
    """2026-08-02 抓包 0x42 日K 表（881101，596 根）走 K 线解析器。

    服务端对 DateTime=16384 日K 查询也回 0x42 表（字段 [1,7,8,9,11,19,13]，
    dt1=YYYYMMDD），与分时字段集 [1,10,13,19,22,23,40] 不同；分时解析器
    应按字段集拒收，避免把日K 误当分时。
    """
    body = _fixture("daily_k_resp_0x42.bin").read_bytes()
    bars = parse_kline_hd3_response(body)
    assert len(bars) == 596
    assert bars[0]["time"].date().isoformat() == "2024-02-19"
    assert bars[0]["open"] == pytest.approx(1156.573, abs=0.001)
    assert bars[0]["close"] == pytest.approx(1161.679, abs=0.001)
    assert bars[-1]["time"].date().isoformat() == "2026-07-31"
    assert bars[-1]["close"] == pytest.approx(1984.555, abs=0.001)
    assert parse_board_timeline_response(body) == []


def test_parse_board_auction_sample():
    path = _sample("_board_auction.bin")
    if not path.exists():
        pytest.skip("本机缺少板块竞价 0x32 样本")
    records = parse_board_auction_response(path.read_bytes())
    assert len(records) >= 10
    assert "time" in records[0]
    assert "dt10" in records[0]
    assert "dt49" in records[0]
    assert records[0]["time"].date().isoformat() == "2026-07-31"
