"""系统板块 8901 协议离线回归（2026-08-01 抓包样本）。"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from thspypc.features.system_blocks_protocol import (  # noqa: E402
    BOARD_AUCTION_DATATYPE,
    BOARD_HISTORY_DATATYPE,
    BOARD_QUOTE_DATATYPE,
    PAGEID_BOARD_HISTORY,
    PAGEID_BOARD_LIST,
    PAGEID_BOARD_TL,
    build_board_auction_query,
    build_board_constituents_query,
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


def _sample(name: str) -> Path:
    return Path(__file__).resolve().parents[1] / "captures_live" / name


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


def test_build_board_list_query_shape():
    frame = build_board_list_query(["881101", "885480"])
    body = frame[12:]
    text = body.decode("gbk", errors="replace")
    assert "CodeList=48(881101,885480,);" in text
    assert f"pageid={PAGEID_BOARD_LIST}" in text
    assert "DataType=48,592890,10,6,66," in text


def test_build_board_constituents_query_groups_markets():
    frame = build_board_constituents_query(["600519", "000938", "920021"])
    text = frame[12:].decode("gbk", errors="replace")
    assert "17(600519,);" in text
    assert "33(000938,);" in text
    assert "151(920021,);" in text
    assert f"pageid={PAGEID_BOARD_TL}" in text


def test_build_board_auction_query_shape():
    frame = build_board_auction_query("886090", date="2026-07-23")
    text = frame[12:].decode("gbk", errors="replace")
    import datetime
    start = int(datetime.datetime(2026, 7, 23, 9, 15).timestamp())
    end = int(datetime.datetime(2026, 7, 23, 9, 25).timestamp())
    assert f"DateTime=7176({start}-{end})" in text
    assert "DataType=10,27,33,49," in text


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


def test_parse_board_timeline_sample():
    path = _sample("_board_timeline.bin")
    if not path.exists():
        pytest.skip("本机缺少板块分时 0x42 样本")
    records = parse_board_timeline_response(path.read_bytes())
    assert len(records) == 242
    assert records[0]["bar_index"] == records[0].get("bar_index")
    assert "dt10" in records[0]
    assert records[0]["minute_index"] == 0


def test_parse_board_auction_sample():
    path = _sample("_board_auction.bin")
    if not path.exists():
        pytest.skip("本机缺少板块竞价 0x32 样本")
    records = parse_board_auction_response(path.read_bytes())
    assert len(records) >= 10
    assert "time" in records[0]
    assert "dt10" in records[0]
    assert "dt49" in records[0]
