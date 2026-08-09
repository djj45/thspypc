"""Offline contracts for the desktop DDE ranking protocol."""

import struct

import pytest

from thspypc.features import stock_list_protocol as protocol


def test_dde_builder_uses_captured_standard_route_and_page():
    request = protocol.build_dde_query(
        sort_by=592890,
        sort_dir="A",
        sort_begin=58,
        sort_count=58,
    )
    body = request[12:]

    assert struct.unpack_from("<H", body, 11)[0] == 0x0148
    assert b"CodeList=17();22();33();\r\n" in body
    assert b"SortBy=592890\r\nSortDir=A\r\n" in body
    assert b"SortBegin=58\r\nSortCount=58\r\n" in body
    assert b"pageid=10723\r" in body


def test_dde_builder_uses_captured_level2_route():
    request = protocol.build_dde_query(
        markets=(33,),
        level2=True,
    )
    body = request[12:]

    assert struct.unpack_from("<H", body, 11)[0] == 0x0149
    assert b"CodeList=33();\r\n" in body


@pytest.mark.parametrize("direction", ["", "X", "descending"])
def test_dde_builder_rejects_unknown_direction(direction):
    with pytest.raises(ValueError, match="sort_dir"):
        protocol.build_dde_query(sort_dir=direction)


def test_dde_parser_preserves_market_value_and_sort_context(monkeypatch):
    records = (
        bytes([17])
        + b"603459"
        + struct.pack("<I", 0xC0013547)
        + bytes([33])
        + b"000001"
        + struct.pack("<I", 0xFFFFFFFF)
    )
    fields = b"\x05\x20\x00\x07\xf8\x7b\x00\x04"
    hd31 = (
        b"hd3.1\x00"
        + struct.pack("<HHHHH", 2, 0x0100, 0, 11, 2)
        + fields
        + b"\x00" * 8
        + struct.pack(">I", 22)
    )
    body = (
        b"SortTotal=2\r\nSortBegin=0\r\nSortCount=2\r\n"
        b"SortDataCount=2\r\n" + hd31
    )
    monkeypatch.setattr(
        protocol,
        "_decode_bitrle_0x13746d0",
        lambda _data, size: b"x" * size,
    )
    monkeypatch.setattr(
        protocol,
        "_transpose_bitplane_0x1763410",
        lambda _data, _size, _count: records,
    )

    result = protocol.parse_dde_response(body, sort_by=592888)

    assert result["response_field"] == 248
    assert result["has_value_field"] is True
    assert result["rows"] == [
        {
            "code": "603459",
            "name": "",
            "market": 17,
            "value": pytest.approx(7.9175),
            "sort_by": 592888,
            "response_field": 248,
        },
        {
            "code": "000001",
            "name": "",
            "market": 33,
            "value": None,
            "sort_by": 592888,
            "response_field": 248,
        },
    ]


def test_dde_dt200_mapping_keeps_request_semantics():
    assert protocol.DDE_RESPONSE_FIELDS[199112] == 200
    assert protocol.DDE_RESPONSE_FIELDS[1968584] == 200

