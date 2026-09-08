"""Wire and parser contracts for stock-list ranking pages."""

import hashlib
import struct
from pathlib import Path

import pytest

import thspypc.protocol as protocol
from thspypc.features import stock_list_protocol
from thspypc.features.stock_list_protocol import (
    FULL_STOCK_LIST_MARKETS,
    build_full_stock_list_query,
    build_init_query,
    build_stock_list_query,
    parse_init_response,
    parse_stock_list_replay,
    parse_stock_list_response,
)


def _hd10_page(records, *, total=None, begin=0):
    rows = b"".join(
        b"\x00\x00\x00\x00"
        + bytes([market])
        + code.encode("ascii")
        for market, code in records
    )
    fields = b"\x05\x00\x00\x07\xc8\x00\x00\x04"
    hd10 = (
        b"hd1.0\x00"
        + struct.pack("<HHHHH", len(records), 0x0100, 0, 11, 2)
        + fields
        + rows
    )
    count = len(records)
    if total is None:
        total = count
    metadata = (
        f"SortTotal={total}\r\n"
        f"SortBegin={begin}\r\n"
        f"SortCount={count}\r\n"
        f"SortDataCount={count}\r\n"
    ).encode("ascii")
    return metadata + hd10


@pytest.mark.parametrize(
    ("kwargs", "expected_sha"),
    [
        (
            {},
            "624431fd537d380f26d787429f47268c623c930fe73881905fbae898c2471fb9",
        ),
        (
            {"sort_begin": 1361},
            "195e8cf799462445bbf6fb8fed328caf5b709167b05ccb940eeb7cbc574ca5e5",
        ),
        (
            {
                "sort_count": 20,
                "datatype": [48],
                "sort_by": 48,
                "sort_dir": "A",
                "seq": 9,
            },
            "c21230f41e4d1108be274144654e3e9796d88d2f73ac6180510a4dbafb012b42",
        ),
    ],
)
def test_stock_list_builder_wire_contract(kwargs, expected_sha):
    request = build_stock_list_query(**kwargs)

    assert hashlib.sha256(request).hexdigest() == expected_sha


@pytest.mark.parametrize(
    ("kwargs", "expected_sha"),
    [
        (
            # 2026-09-08 MarketDate 加 32(0) 后重算（北交所 151 数据下发开关，
            # 见 stock_list_protocol.INIT_MARKET_DATE 注释）。
            {},
            "8d455e940122584ef8ab3208156a05a05802b4aeca3a6b0ae838015f9b2de1e7",
        ),
        (
            {
                "config_ver": "20260728",
                "market_code": "16;32;",
                "c_modules": "MEQT;X",
                "seq": 7,
            },
            "f8f1e1e8da3e45935a070ae54aba1bb7cb5f3e7523c2e4757bb8753d1d2ad80a",
        ),
    ],
)
def test_init_builder_wire_contract(kwargs, expected_sha):
    request = build_init_query(**kwargs)

    assert hashlib.sha256(request).hexdigest() == expected_sha


def test_hd10_page_parser_preserves_market_and_metadata():
    body = _hd10_page(
        [(17, "600519"), (33, "000001")],
        total=5210,
        begin=59,
    )

    result = parse_stock_list_response(body)

    assert result["sort_total"] == 5210
    assert result["sort_begin"] == 59
    assert result["sort_count"] == 2
    assert result["sort_data_count"] == 2
    assert result["stocks"] == [
        {"code": "600519", "name": "", "market": 17},
        {"code": "000001", "name": "", "market": 33},
    ]


def test_captured_hd31_page_matches_known_codes():
    path = (
        Path(__file__).parents[1]
        / "captures_live"
        / "list_quote_fields_20260723_232604_resp_stream0.bin"
    )
    if not path.exists():
        pytest.skip("optional captured stock-list stream is unavailable")
    stream = path.read_bytes()
    body_size = int(stream[4:12], 16)
    body = stream[12 : 12 + body_size]

    result = parse_stock_list_response(body)

    assert result["sort_total"] == 5210
    assert result["sort_data_count"] == 59
    assert len(result["stocks"]) == 59
    assert [item["code"] for item in result["stocks"][:3]] == [
        "300062",
        "301587",
        "301292",
    ]


def test_captured_init_table_decodes_full_stock_list():
    path = (
        Path(__file__).parents[1]
        / "captures_live"
        / "list_quote_fields_20260723_203100_resp_stream0.bin"
    )
    if not path.exists():
        pytest.skip("optional captured init stock table is unavailable")
    stream = path.read_bytes()
    frame_offset = 38752
    body_size = int(stream[frame_offset + 4 : frame_offset + 12], 16)
    body = stream[
        frame_offset + 12 : frame_offset + 12 + body_size
    ]

    result = parse_init_response(body)

    assert result["hd31_frames"] == [
        {"pos": 222, "dc": 7479, "unk": 0x18, "hs": 71, "fc": 2}
    ]
    assert len(result["stocks"]) == 7479
    assert [item["code"] for item in result["stocks"][:3]] == [
        "1B0853",
        "1B0863",
        "600000",
    ]
    assert [item["code"] for item in result["stocks"][-3:]] == [
        "920982",
        "920985",
        "920992",
    ]


def test_full_stock_list_builder_is_the_verified_minimum_query():
    request = build_full_stock_list_query()

    assert len(request) == 146
    assert request.startswith(b"\xfd\xfd\xfd\xfd00000086\x09")
    assert b"DataType=[5],[55]\r\n" in request
    assert (
        b"CodeList="
        + b"".join(
            f"{market}();".encode("ascii")
            for market in FULL_STOCK_LIST_MARKETS
        )
        + b"\r\n"
    ) in request
    assert b"DateTime=0\r\npageid=5716\r\n" in request


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"\x00\x00\x00\x00",
        b"\x01\x00\x00\x00",
        b"\x01\x00\x00\x00\x05\x00\x00\x00abc",
        b"\x01\x00\x00\x00\x01\x00\x00\x00ab",
    ],
)
def test_replay_parser_rejects_invalid_container(data):
    with pytest.raises(ValueError, match="stock-list replay"):
        parse_stock_list_replay(data)


def test_protocol_facade_reexports_single_implementation():
    assert (
        protocol.build_full_stock_list_query
        is stock_list_protocol.build_full_stock_list_query
    )
    assert (
        protocol.build_stock_list_query
        is stock_list_protocol.build_stock_list_query
    )
    assert (
        protocol.parse_stock_list_response
        is stock_list_protocol.parse_stock_list_response
    )
    assert protocol.build_init_query is stock_list_protocol.build_init_query
    assert (
        protocol.parse_init_response
        is stock_list_protocol.parse_init_response
    )
