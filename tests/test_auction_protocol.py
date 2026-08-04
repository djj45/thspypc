"""Offline contracts for the extracted auction request protocol."""

import hashlib
import struct
from datetime import date

import pytest
import thspypc.protocol as protocol
from thspypc.features import auction_protocol


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def test_auction_builder_wire_contracts():
    # 2026-08-05 抓包对齐：L2 当日竞价 pageid 4214→1334；trade_date=None 现解析为
    # 最近交易日（显式时间戳，原 0-0 盘后超时）。测试用显式日期保证确定性。
    cases = [
        (
            auction_protocol.build_auction_query(
                "000938", market=33, trade_date=date(2026, 8, 4)
            ),
            158,
            "df7fcf8f129087dbb1decdc9f28335a30962e7a05ff956892f562db182155a3f",
        ),
        (
            auction_protocol.build_auction_query(
                "603118", market=17, trade_date=date(2026, 8, 4)
            ),
            158,
            "9c558f67311e22860d94938937531e3e1187e6e1d5a5472f6bf431be20c2c4a1",
        ),
        (
            auction_protocol.build_auction_query(
                "000938",
                market=33,
                trade_date=date(2026, 7, 24),
            ),
            158,
            "135cd3e29eace96eaac6d657660e6c597ac14f3117fba64a5a248a0f13b22236",
        ),
    ]

    for frame, expected_length, expected_hash in cases:
        assert len(frame) == expected_length
        assert _sha256(frame) == expected_hash


def test_auction_sentinels_remain_distinct_from_zero():
    assert auction_protocol._auction_value(0x80000000, 27) is None
    assert auction_protocol._auction_value(0xFFFFFFFF, 33) is None
    assert auction_protocol._auction_value(0, 27) == 0.0


def test_basic_auction_builders_match_current_and_history_shapes():
    current = auction_protocol.build_basic_auction_query(
        "000938",
        market=33,
        trade_date=date(2026, 7, 29),
    )
    history = auction_protocol.build_basic_auction_query(
        "603118",
        market=17,
        trade_date=date(2026, 5, 15),
        historical=True,
    )
    closing = auction_protocol.build_basic_auction_query(
        "603118",
        market=17,
        trade_date=date(2026, 7, 29),
        closing=True,
    )

    assert (len(current), _sha256(current)) == (
        157,
        "f0401389662eb94d55a717023b8aaec5"
        "a3b2f4c2d41d89abc9aa564e4a03ca93",
    )
    assert b"DateTime=6144(" in history
    assert b"pageid=9355" in history
    assert (len(closing), _sha256(closing)) == (
        155,
        "3c57adb3a09e7f41f8acf87c4bab8bc4"
        "9d62f48452cc50dc1f16a0ac271bd521",
    )


def test_index_auction_builder_and_json_parser():
    frame = auction_protocol.build_index_auction_query(
        "1A0001",
        market=16,
        seq=0x005A,
    )
    assert frame.startswith(b"\xfd\xfd\xfd\xfd")
    assert b"\x12\x00\x17\x00\x00\x01" in frame
    assert (
        b"T_URL=/quote/auction/USH/USHI_1A0001.dat\r\n"
        b"pageid=6240\r"
    ) in frame

    context = auction_protocol.build_index_auction_context_query(
        "1A0001",
        market=16,
        seq=0x0176,
    )
    close_frame = auction_protocol.build_index_auction_query(
        "1A0001",
        market=16,
        closing=True,
        seq=0x0177,
    )
    assert (len(context), _sha256(context)) == (
        147,
        "4d5f3a1e2603412fe6c4ea2cdfb598cf"
        "daba795bdc79aa2b75253f42c5d6d5ee",
    )
    assert (len(close_frame), _sha256(close_frame)) == (
        95,
        "602500726e7d1bf4eff6ab1aa318cdcc"
        "00fd6a8ea37ef3bb18fd0226f0b4a33a",
    )

    # The capture ends the JSON with NUL before the root object's final brace.
    body = (
        b'{"Auction":[{"markettime":"2026-08-04 09:25:00",'
        b'"newprice":3816.37,"leadprice":3829.089266,'
        b'"volume":404086720}]\x00'
    )
    records = auction_protocol.parse_index_auction_response(body)

    assert len(records) == 1
    assert records[0]["dt10"] == 3816.37
    assert records[0]["lead_price"] == 3829.089266
    assert records[0]["volume"] == 404086720
    assert records[0]["time"].isoformat(sep=" ") == "2026-08-04 09:25:00"

    numeric_time = auction_protocol.parse_index_auction_response(
        b'{"Auction":[{"markettime":1785806700,'
        b'"newprice":3816.37,"leadprice":3829.089266,'
        b'"volume":404086720}]}'
    )
    assert numeric_time[0]["time"].year == 2026

    closing = auction_protocol.build_index_auction_query(
        "399001",
        market=32,
        closing=True,
    )
    assert b"/quote/auction/USZ/USZI_CLOSE_399001.dat" in closing

    closing_records = auction_protocol.parse_index_auction_response(
        b'{"CloseAuction":[{"markettime":1785826632,'
        b'"newprice":13820.100098,"leadprice":13719.849663,'
        b'"volume":51439929}]}'
    )
    assert closing_records[0]["auction_type"] == "closing"
    assert closing_records[0]["lead_price"] == 13719.849663

    with pytest.raises(ValueError, match="1A0001"):
        auction_protocol.build_index_auction_query(
            "399002",
            market=32,
            closing=True,
        )


def test_closing_auction_parser_accepts_hd3_bitrle(monkeypatch):
    field_table = b"".join(
        bytes((datatype, fmt, 0, 4))
        for datatype, fmt in (
            (1, 0x30),
            (10, 0x70),
            (49, 0x70),
            (31, 0x70),
        )
    )
    shell = (
        b"\x16\x00\x01\x00\x11"
        + b"603118"
        + b"\x00" * 15
    )
    rows = b"".join(
        struct.pack(
            "<4I",
            int(
                __import__("datetime").datetime(
                    2026, 7, 29, 14, 57, second
                ).timestamp()
            ),
            0xC0052B70,
            0,
            0,
        )
        for second in (0, 3)
    )
    body = (
        b"hd3.1\x00"
        + struct.pack("<IHHH", 2, 0x0036, 16, 4)
        + field_table
        + shell
        + struct.pack(">I", 32)
    )
    monkeypatch.setattr(
        auction_protocol,
        "_decode_bitrle_0x13746d0",
        lambda _data, _size: b"\x00" * 32,
    )
    monkeypatch.setattr(
        auction_protocol,
        "_transpose_bitplane_0x1763410",
        lambda _data, _record_size, _record_count: rows,
    )

    records = auction_protocol.parse_closing_auction_response(body)

    assert len(records) == 2
    assert records[0]["dt10"] == 33.88


def test_closing_auction_parser_tolerates_hd1_trailing_truncation():
    """Level2 historical closing frames arrive as hd1.0 with the final
    record truncated by exactly one byte (verified on live captures for
    603118/600519/688981). The parser must keep every valid tick, including
    the closing point whose trailing field byte is missing, instead of
    discarding all records as it did before.
    """
    from datetime import datetime

    field_table = b"".join(
        bytes((datatype, fmt, 0, 4))
        for datatype, fmt in (
            (1, 0x30),
            (10, 0x70),
            (49, 0x70),
            (31, 0x71),
        )
    )
    shell = b"\x16\x00\x01\x00\x11" + b"603118" + b"\x00" * 15

    def _row(second: int, price_raw: int = 0xC0052B70) -> bytes:
        ts = int(datetime(2026, 7, 24, 14, 57, second).timestamp())
        return struct.pack("<4I", ts, price_raw, 0, 0)

    # Enough ticks that the data_start scan window reaches the records.
    rows = b"".join(_row(s) for s in (0, 3, 6, 9, 12))
    # Simulate the wire truncation: drop the last byte of the final record.
    truncated_rows = rows[:-1]
    body = (
        b"hd1.0\x00"
        + struct.pack("<IHHH", 5, 0x0036, 16, 4)
        + field_table
        + shell
        + truncated_rows
    )

    records = auction_protocol.parse_closing_auction_response(body)

    assert len(records) == 5
    assert records[0]["time"] == datetime(2026, 7, 24, 14, 57, 0)
    assert records[-1]["time"] == datetime(2026, 7, 24, 14, 57, 12)
    assert records[0]["dt10"] == 33.88


def test_closing_auction_parser_stops_at_timestamp_outside_window():
    """The declared record_count can exceed the real tick count by one
    (e.g. 688981 declares 62 but only 61 carry 14:57-15:00 timestamps).
    A trailing row whose timestamp falls outside the window must terminate
    decoding gracefully, preserving the valid records.
    """
    from datetime import datetime

    field_table = b"".join(
        bytes((datatype, fmt, 0, 4))
        for datatype, fmt in (
            (1, 0x30),
            (10, 0x70),
            (49, 0x70),
            (31, 0x71),
        )
    )
    shell = b"\x16\x00\x01\x00\x11" + b"603118" + b"\x00" * 15

    valid = b"".join(
        struct.pack(
            "<4I",
            int(datetime(2026, 7, 24, 14, 57, s).timestamp()),
            0xC0052B70, 0, 0,
        )
        for s in (0, 3, 6, 9, 12)
    )
    # A trailing row whose timestamp is NOT in the 14:57-15:00 window.
    out_of_window = struct.pack(
        "<4I",
        int(datetime(2026, 7, 24, 15, 0, 3).timestamp()),
        0, 0, 0,
    )
    rows = valid + out_of_window
    body = (
        b"hd1.0\x00"
        + struct.pack("<IHHH", 6, 0x0036, 16, 4)
        + field_table
        + shell
        + rows
    )

    records = auction_protocol.parse_closing_auction_response(body)

    assert len(records) == 5


def test_closing_auction_parser_handles_sz_9s_stride():
    """Shenzhen (深市) Level2 historical closing frames use the same hd1.0
    wire shape as Shanghai (verified on live captures for 000001/000938/300033)
    but tick at a 9-second cadence (≈20-21 points over 14:57-15:00) instead of
    Shanghai's 3-second cadence (≈61 points). The parser must decode them with
    no market-specific branch. Captured frames also carry the 1-byte trailing
    truncation seen on Shanghai.
    """
    from datetime import datetime, timedelta

    field_table = b"".join(
        bytes((datatype, fmt, 0, 4))
        for datatype, fmt in (
            (1, 0x30),
            (10, 0x70),
            (49, 0x70),
            (31, 0x71),
        )
    )
    shell = b"\x16\x00\x01\x00\x11" + b"000001" + b"\x00" * 15

    # 9-second stride: 14:57:00, 14:57:09, ... through 15:00:00.
    base_dt = datetime(2026, 3, 11, 14, 57, 0)
    offsets = tuple(range(0, 181, 9))
    rows = b"".join(
        struct.pack(
            "<4I",
            int((base_dt + timedelta(seconds=s)).timestamp()),
            0xC0052B70, 0, 0,
        )
        for s in offsets
    )
    # Mirror the live wire: final record truncated by one byte.
    truncated_rows = rows[:-1]
    body = (
        b"hd1.0\x00"
        + struct.pack("<IHHH", len(offsets), 0x0036, 16, 4)
        + field_table
        + shell
        + truncated_rows
    )

    records = auction_protocol.parse_closing_auction_response(body)

    assert len(records) == len(offsets)
    assert records[0]["time"] == base_dt
    assert records[-1]["time"] == datetime(2026, 3, 11, 15, 0, 0)


def test_level2_closing_builders_match_captured_sh_sz_requests():
    # 2026-08-05 抓包对齐：当日尾盘 pageid 4214→1334，hash 同步更新
    cases = [
        (
            auction_protocol.build_l2_closing_auction_query(
                "000938",
                market=33,
                trade_date=date(2026, 7, 24),
                seq=0x0121,
            ),
            "8f138ffbb562f7fcb3bbc71970857991"
            "f4883d2864d30490b44f61a75f534933",
        ),
        (
            auction_protocol.build_l2_closing_auction_query(
                "603118",
                market=17,
                trade_date=date(2026, 7, 24),
                seq=0x0155,
            ),
            "54406290fdbf6cff4fda94415fcd5e0b"
            "5ec7383332ee6d2ad00113325713cf8d",
        ),
    ]

    for frame, captured_body_hash in cases:
        assert len(frame) == 156
        assert _sha256(frame[12:]) == captured_body_hash
        assert b"pageid=1334" in frame
        assert b"DateTime=7424(" in frame
        assert b"DataType=10,49,287," in frame
        assert b"pageid=9354" not in frame
        assert b"pageid=9355" not in frame


def test_level2_historical_closing_matches_new_4417_capture():
    frame = auction_protocol.build_l2_closing_auction_query(
        "603118",
        market=17,
        trade_date=date(2026, 7, 24),
        historical=True,
        seq=0x00EF,
    )

    assert len(frame) == 156
    assert _sha256(frame[12:]) == (
        "252f426a2832d895dc2b980168bc5b83"
        "92f562429610b9b4425d7b8c6f739d4d"
    )
    assert b"pageid=4417" in frame
    assert b"pageid=4214" not in frame
    assert b"pageid=9355" not in frame


def test_level2_historical_opening_matches_new_4417_capture():
    frame = auction_protocol.build_l2_history_auction_query(
        "603118",
        market=17,
        trade_date=date(2026, 7, 24),
        seq=0x00F1,
    )

    assert len(frame) == 158
    assert _sha256(frame[12:]) == (
        "a94ced7281deb399dabb71fe69ff4014e"
        "d2fc022d610d1d88231137718d74920"
    )
    assert b"DateTime=6144(" in frame
    assert b"pageid=4417" in frame
    assert b"pageid=4214" not in frame


def test_protocol_reexports_auction_builder():
    assert protocol.build_auction_query is auction_protocol.build_auction_query
    assert protocol.AUCTION_DATATYPE is auction_protocol.AUCTION_DATATYPE
    assert (
        protocol._auction_ts_in_range
        is auction_protocol._auction_ts_in_range
    )
    assert (
        protocol._split_auction_state_rows
        is auction_protocol._split_auction_state_rows
    )
    assert (
        protocol._parse_auction_sh
        is auction_protocol._parse_auction_sh
    )
    assert (
        protocol.parse_auction_response
        is auction_protocol.parse_auction_response
    )
    assert (
        protocol.build_basic_auction_query
        is auction_protocol.build_basic_auction_query
    )
    assert (
        protocol.parse_closing_auction_response
        is auction_protocol.parse_closing_auction_response
    )
    assert (
        protocol.build_l2_closing_auction_query
        is auction_protocol.build_l2_closing_auction_query
    )
    assert (
        protocol.build_l2_history_auction_query
        is auction_protocol.build_l2_history_auction_query
    )
