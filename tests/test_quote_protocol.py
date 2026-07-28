"""Offline byte and parser contracts for quote protocols."""

import hashlib
import struct

import thspypc.protocol as protocol
from thspypc.features import quote_protocol


def _field(dt: int, fmt: int, width: int) -> bytes:
    return bytes((dt, fmt, 0, width))


def test_quote_builders_preserve_wire_bytes():
    list_frame = quote_protocol.build_list_quote_query(
        ["600000", "600519"],
        market=17,
    )
    depth_frame = quote_protocol.build_depth_quote_query(
        "000001",
        market=33,
    )

    assert len(list_frame) == 158
    assert hashlib.sha256(list_frame).hexdigest() == (
        "1613b27c45e317eee78db5349a198e233b0f8176e00d126d9a101495123adfe3"
    )
    assert len(depth_frame) == 272
    assert hashlib.sha256(depth_frame).hexdigest() == (
        "5b58c503eca5c386d8ccb7e87f69bbb119aa0c6e975cf39ab48061935e3f758f"
    )


def test_depth_parser_decodes_levels_and_limit_up_seal():
    fields = (
        _field(5, 0x20, 7)
        + _field(24, 0x70, 4)
        + _field(25, 0x70, 4)
        + _field(30, 0x70, 4)
        + _field(31, 0x70, 4)
    )
    row = (
        b"\x06"
        + b"002353"
        + struct.pack("<IIII", 135, 10, 136, 0)
    )
    header = struct.pack("<IHHH", 1, 0, len(row), 5)
    body = b"hd1.0\x00" + header + fields + row

    result = quote_protocol.parse_depth_quote_response(body)

    assert result["code"] == "002353"
    assert result["buy"][0] == {
        "level": "买一",
        "price": 135.0,
        "qty": 10.0,
        "amount": 1350.0,
    }
    assert result["sell"][0]["qty"] == 0.0
    assert result["seal_amount"] == 1350.0
    assert result["seal_type"] == "涨停"


def test_depth_parser_rejects_non_depth_hd1_frame():
    fields = _field(10, 0x70, 4)
    row = struct.pack("<I", 10)
    header = struct.pack("<IHHH", 1, 0, len(row), 1)

    assert (
        quote_protocol.parse_depth_quote_response(
            b"hd1.0\x00" + header + fields + row
        )
        == {}
    )


def test_protocol_reexports_quote_implementations():
    assert (
        protocol.build_list_quote_query
        is quote_protocol.build_list_quote_query
    )
    assert (
        protocol.build_depth_quote_query
        is quote_protocol.build_depth_quote_query
    )
    assert (
        protocol.parse_depth_quote_response
        is quote_protocol.parse_depth_quote_response
    )
    assert (
        protocol.LIST_QUOTE_DATATYPE_DEFAULT
        is quote_protocol.LIST_QUOTE_DATATYPE_DEFAULT
    )
    assert protocol.DEPTH_QUOTE_DATATYPE is quote_protocol.DEPTH_QUOTE_DATATYPE
