"""Wire and corpus contracts for the partial stock-name decoder."""

import hashlib
from pathlib import Path

import pytest

import thspypc.protocol as protocol
from thspypc.features import stock_name_protocol
from thspypc.features.stock_name_protocol import (
    build_upstockname_request,
    decode_name_frame,
)


@pytest.mark.parametrize(
    ("kwargs", "expected_sha"),
    [
        (
            {},
            "58d2726acf585f365c81f7d6bc030a4a725f49b8646f054796308270f11fbef9",
        ),
        (
            {
                "market": "UNX",
                "stock_name_ver": "20260728;1;",
                "pageid": 392,
                "instid": 7,
            },
            "e0aa06146829c9326ce0f11a22c9314fa814c3e01247270dc68bff07781e7eda",
        ),
    ],
)
def test_upstockname_builder_wire_contract(kwargs, expected_sha):
    request = build_upstockname_request(**kwargs)

    assert hashlib.sha256(request).hexdigest() == expected_sha


def test_text_and_nul_terminated_segment_names_are_decoded():
    body = (
        b"[name_96_96]\r\n"
        + "AUDUSD=澳元/美元|AUDUSD@0\r\n".encode("gbk")
        + b"[name_64_64\x00]\x00"
        + "850001=同花顺商品|alias@1\n".encode("gbk")
    )

    result = decode_name_frame(body)

    assert result["names"] == {
        "AUDUSD": "澳元/美元",
        "850001": "同花顺商品",
    }
    assert result["skipped"] == []
    assert [item[0] for item in result["segments"]] == [
        "96_96",
        "64_64",
    ]


def test_block_encoded_segment_is_reported_not_guessed():
    body = b"[name_16_16]\x00\xffbroken\x00payload"

    result = decode_name_frame(body)

    assert result["names"] == {}
    assert result["by_segment"] == {}
    assert result["skipped"] == ["16_16"]
    assert result["segments"] == [("16_16", 15, "block")]


def test_captured_text_stream_preserves_known_result():
    path = (
        Path(__file__).parents[1]
        / "captures_live"
        / "upstockname_stream37_server.bin"
    )
    if not path.exists():
        pytest.skip("optional captured stock-name text stream is unavailable")

    result = decode_name_frame(path.read_bytes())

    assert len(result["names"]) == 3510
    assert len(result["segments"]) == 22
    assert result["skipped"] == []
    assert "AUDUSD" in result["names"]
    assert result["segments"][0] == ("96_96", 21, "text")
    assert result["segments"][-1] == ("48_49", 47011, "text")


def test_captured_a_share_block_stream_stays_explicitly_skipped():
    path = (
        Path(__file__).parents[1]
        / "captures_live"
        / "upstockname_stream35_server.bin"
    )
    if not path.exists():
        pytest.skip("optional captured stock-name block stream is unavailable")

    result = decode_name_frame(path.read_bytes())

    assert result["names"] == {}
    assert result["skipped"] == ["16_16"]
    assert result["segments"] == [("16_16", 942899, "block")]


def test_protocol_facade_reexports_single_name_implementation():
    assert (
        protocol.build_upstockname_request
        is stock_name_protocol.build_upstockname_request
    )
    assert protocol.decode_name_frame is stock_name_protocol.decode_name_frame
