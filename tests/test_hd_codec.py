"""Offline contracts for the generic hd codec."""

import struct

import thspypc.protocol as protocol
from thspypc.codecs import hd


def _field(dt: int, fmt: int, width: int) -> bytes:
    return bytes((dt, fmt, 0, width))


def test_parse_hd1_response_decodes_code_numeric_and_raw_fields():
    fields = (
        _field(5, 0x00, 7)
        + _field(10, 0x70, 4)
        + _field(99, 0x00, 2)
    )
    row = b"\x06" + b"600000" + struct.pack("<I", 123) + b"\xaa\xbb"
    header = struct.pack("<IHHH", 1, 0, len(row), 3)
    body = b"prefix" + b"hd1.0\x00" + header + fields + row

    assert hd.parse_hd1_response(body) == [
        {
            "code": "600000",
            "dt10": 123.0,
            "dt99_raw": b"\xaa\xbb",
        }
    ]


def test_parse_hd_responses_reject_missing_or_incomplete_headers():
    assert hd.parse_hd1_response(b"") == []
    assert hd.parse_hd1_response(b"hd1.0\x00") == []
    assert hd.parse_hd3_response(b"") == []
    assert hd.parse_hd3_response(b"hd3.1\x00") == []


def test_protocol_reexports_hd_codec_implementations():
    assert protocol._parse_hd_field_table is hd._parse_hd_field_table
    assert protocol._parse_hd_records is hd._parse_hd_records
    assert protocol.parse_hd1_response is hd.parse_hd1_response
    assert protocol.parse_hd3_response is hd.parse_hd3_response
