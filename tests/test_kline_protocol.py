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


def test_kline_time_helpers_cover_wire_encodings():
    assert kline_protocol._kline_decode_time(20260728) == datetime.datetime(
        2026, 7, 28
    )
    assert kline_protocol._kline_decode_time(0) == datetime.datetime.min
    assert kline_protocol._kline_dt1_is_bar_index(20260728) is False
    assert kline_protocol._kline_dt1_is_bar_index(132491944) is True
    assert kline_protocol._kline_dt1_is_bar_index(1784789709) is False


def test_kline_parser_rejects_non_kline_payloads():
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


def test_protocol_reexports_kline_implementations():
    assert protocol.build_kline_query is kline_protocol.build_kline_query
    assert (
        protocol.parse_kline_hd3_response
        is kline_protocol.parse_kline_hd3_response
    )
    assert protocol.KLINE_DATATYPE is kline_protocol.KLINE_DATATYPE
    assert protocol.KLINE_PERIOD_DAY == kline_protocol.KLINE_PERIOD_DAY
    assert protocol.KLINE_PERIOD_WEEK == kline_protocol.KLINE_PERIOD_WEEK
    assert protocol.KLINE_PERIOD_MONTH == kline_protocol.KLINE_PERIOD_MONTH
