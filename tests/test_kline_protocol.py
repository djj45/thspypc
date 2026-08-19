"""Offline contracts for the extracted K-line protocol module."""

import datetime
import hashlib

import thspypc.protocol as protocol
from thspypc.features import kline_protocol


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def test_kline_builder_wire_contracts():
    cases = [
        (
            kline_protocol.build_kline_query(
                "000089",
                market=33,
                period=kline_protocol.KLINE_PERIOD_DAY,
                count=335,
            ),
            159,
            "bf4a123e7fe249c70157a80eb43249fdce03b5d4e8db610e8807ccc853daa8ca",
        ),
        (
            kline_protocol.build_kline_query(
                "600000",
                market=17,
                period=kline_protocol.KLINE_PERIOD_WEEK,
                count=20,
            ),
            158,
            "819109907cb64f55a73cd4007e7c05a01b47dbf2535124f8ecbe8af7fc8fb552",
        ),
        (
            kline_protocol.build_kline_query(
                "000001",
                market=33,
                period=kline_protocol.KLINE_PERIOD_5MIN,
                count=48,
            ),
            158,
            "19dc57681f5c7f32a80ed01dacf0fda17ca309aeae258a71eb2cd8ff8ef2ee55",
        ),
    ]

    for frame, expected_length, expected_sha256 in cases:
        assert len(frame) == expected_length
        assert _sha256(frame) == expected_sha256


def test_kline_builder_anchor_and_new_periods():
    """翻页锚点 + 1分/季/年周期码（2026-08-03 抓包确认）。"""
    default = kline_protocol.build_kline_query(
        "000938",
        market=33,
        period=kline_protocol.KLINE_PERIOD_DAY,
        count=1938,
    )
    assert b"DateTime=16384(-1938-0)" in default

    paged = kline_protocol.build_kline_query(
        "000938",
        market=33,
        period=kline_protocol.KLINE_PERIOD_DAY,
        count=3103,
        anchor=20180727,
    )
    assert b"DateTime=16384(-3103-20180727)" in paged
    # 分钟K 锚点是 bar_index；周/月/季/年 route=0x014E
    minute = kline_protocol.build_kline_query(
        "000938",
        market=33,
        period=kline_protocol.KLINE_PERIOD_1MIN,
        count=1220,
        anchor=132639393,
    )
    assert b"DateTime=12288(-1220-132639393)" in minute
    assert kline_protocol.KLINE_PERIOD_1MIN == 0x3000
    assert kline_protocol.KLINE_PERIOD_QUARTER == 0x6003
    assert kline_protocol.KLINE_PERIOD_YEAR == 0x7001


def test_kline_time_helpers_cover_wire_encodings():
    assert kline_protocol._kline_decode_time(20260728) == datetime.datetime(
        2026, 7, 28
    )
    assert kline_protocol._kline_decode_time(0) == datetime.datetime.min
    assert kline_protocol._kline_dt1_is_bar_index(20260728) is False
    assert kline_protocol._kline_dt1_is_bar_index(132491944) is True
    assert kline_protocol._kline_dt1_is_bar_index(1784789709) is False


def test_kline_parser_rejects_non_kline_payloads():
    assert kline_protocol.parse_kline_hd1_response(b"") == []
    assert (
        kline_protocol.parse_kline_hd1_response(
            b"hd1.0\x00"
            b"\x01\x00\x00\x00"
            b"\x34\x12"
            b"\x04\x00"
            b"\x01\x00"
        )
        == []
    )
    assert kline_protocol.parse_kline_hd3_response(b"") == []
    assert (
        kline_protocol.parse_kline_hd3_response(
            b"hd3.1\x00"
            b"\x01\x00\x00\x00"
            b"\x34\x12"
            b"\x04\x00"
            b"\x01\x00"
        )
        == []
    )


def test_kline_hd1_parser_decodes_captured_688836_first_day_bar():
    """2026-08-19 新股首日只有一根时，L2 返回 hd1.0 而非 hd3.1。"""
    response = bytes.fromhex(
        "6864312e3000"  # hd1.0\0
        "0100000042001c000700"  # dc=1, flag=0x42, hs=28, fc=7
        "01300004"  # dt1: YYYYMMDD
        "07700004"  # dt7: open
        "08700004"  # dt8: high
        "09700004"  # dt9: low
        "0b700004"  # dt11: close
        "0d700004"  # dt13: volume
        "13700004"  # dt19: amount
        "16000100113638383833360000000000000000000100"  # 22B shell
        "d3273501"  # 20260819
        "e0c810b0"  # 1100.00
        "e0c810b0"  # 1100.00
        "50350cb0"  # 800.08
        "c8e40cb0"  # 845.00
        "4f828701"  # 25,657,935
        "ef626131"  # 23,159,535,000
    )

    assert kline_protocol.parse_kline_hd1_response(response) == [
        {
            "code": "688836",
            "time": datetime.datetime(2026, 8, 19),
            "open": 1100.0,
            "high": 1100.0,
            "low": 800.08,
            "close": 845.0,
            "volume": 25_657_935.0,
            "amount": 23_159_535_000.0,
        }
    ]


def test_protocol_reexports_kline_implementations():
    assert protocol.build_kline_query is kline_protocol.build_kline_query
    assert (
        protocol.parse_kline_hd1_response
        is kline_protocol.parse_kline_hd1_response
    )
    assert (
        protocol.parse_kline_hd3_response
        is kline_protocol.parse_kline_hd3_response
    )
    assert protocol.KLINE_DATATYPE is kline_protocol.KLINE_DATATYPE
    assert protocol.KLINE_PERIOD_DAY == kline_protocol.KLINE_PERIOD_DAY
    assert protocol.KLINE_PERIOD_WEEK == kline_protocol.KLINE_PERIOD_WEEK
    assert protocol.KLINE_PERIOD_MONTH == kline_protocol.KLINE_PERIOD_MONTH
    assert protocol.KLINE_PERIOD_1MIN == kline_protocol.KLINE_PERIOD_1MIN
    assert (
        protocol.KLINE_PERIOD_QUARTER
        == kline_protocol.KLINE_PERIOD_QUARTER
    )
    assert protocol.KLINE_PERIOD_YEAR == kline_protocol.KLINE_PERIOD_YEAR
