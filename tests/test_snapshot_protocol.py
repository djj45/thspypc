"""Offline wire contracts for Level2 snapshot registration."""

import hashlib
import struct
from pathlib import Path

import pytest

import thspypc.protocol as protocol
from thspypc.features import snapshot_protocol
from thspypc.codecs.quote_stream import (
    QuoteStreamNormalizer,
    normalize_stock_depth_push,
)


DEPTH_PUSH_FIXTURES = Path(__file__).parent / "fixtures" / "depth_push"


def _captured_depth_push(name: str) -> bytes:
    return bytes.fromhex(
        (DEPTH_PUSH_FIXTURES / name).read_text(encoding="ascii")
    )


@pytest.mark.parametrize(
    ("frame", "expected_length", "expected_hash"),
    [
        (
            snapshot_protocol.build_snapshot_subscribe("603118", 17),
            202,
            "d4077cc07ac8f357dfda9567e137bce7f847a420bc0df4cb74b588461f932fd2",
        ),
        (
            snapshot_protocol.build_snapshot_subscribe("000938", 33),
            202,
            "cec3fbeca04abff76c6e4744ec03db9a022fd0527af204361a128d7647f33469",
        ),
        (
            snapshot_protocol.build_snapshot_subscribe(
                "000938",
                33,
                seq=1,
                inner_seq=2,
                datatype=[10],
            ),
            186,
            "b57673f6e82469379c8be8c0da2bca5b5504c3f72091c2d866adbda75d60f31a",
        ),
    ],
)
def test_snapshot_builder_wire_contract(
    frame,
    expected_length,
    expected_hash,
):
    assert len(frame) == expected_length
    assert hashlib.sha256(frame).hexdigest() == expected_hash


def test_snapshot_builder_rejects_invalid_code():
    with pytest.raises(ValueError):
        snapshot_protocol.build_snapshot_subscribe("60A519")


@pytest.mark.parametrize(
    ("kwargs", "expected_length", "expected_hash"),
    [
        (
            {},
            155,
            "a92a2a558dfaf137c9a6d58be01f3cfd7e31d2742199e5fae1828ba321503d10",
        ),
        (
            {"markets": [16, 151]},
            100,
            "17e868e4dae980f63071473dd2c5c155216e901b78f0583f39de8abd1d1595dc",
        ),
        (
            {
                "markets": [17],
                "datatype": [5],
                "pageid": 4214,
                "seq": 2,
            },
            89,
            "5495ab1a295fa639b0f6613ef6caa57281268ad8bc44f506dc5f67235d06832b",
        ),
    ],
)
def test_market_snapshot_builder_wire_contract(
    kwargs,
    expected_length,
    expected_hash,
):
    frame = snapshot_protocol.build_market_snapshot_query(**kwargs)

    assert len(frame) == expected_length
    assert hashlib.sha256(frame).hexdigest() == expected_hash


def _snapshot_push(
    *,
    market_flag=0x11,
    code=b"603118",
    wire_subtype=0x7F,
    price_raw=0xC0057E40,  # ths_float → 36.00
    volume=300,
    direction=1,
    seq=36954662,
):
    """Build a synthetic 71B tick push frame matching 2026-08-07 capture layout."""
    body = bytearray(71)
    body[0] = 0x09
    body[1:4] = b"\x7b\xd0\x01"
    body[4] = wire_subtype
    body[28] = market_flag
    body[29:35] = code
    struct.pack_into("<I", body, 39, seq)
    struct.pack_into("<I", body, 47, price_raw)
    struct.pack_into("<H", body, 51, volume)
    body[55] = direction
    return bytes(body)


def test_snapshot_push_parser_contract():
    body = _snapshot_push()

    assert snapshot_protocol.is_snapshot_push(body)
    result = snapshot_protocol.parse_snapshot_push(body)
    assert result is not None
    assert result["code"] == "603118"
    assert result["market"] == "SH"
    assert result["price"] == 36.0
    assert result["volume"] == 300
    assert result["direction"] == 1
    assert result["seq"] == 36954662
    assert result["raw_len"] == 71


def test_snapshot_push_parser_preserves_sz_and_unknown_market_flags():
    sz = _snapshot_push(market_flag=0x21, code=b"000938")
    unknown = _snapshot_push(market_flag=0x31)

    assert snapshot_protocol.parse_snapshot_push(sz)["market"] == "SZ"
    assert snapshot_protocol.parse_snapshot_push(unknown)["market"] == "?0x31"


@pytest.mark.parametrize(
    "body",
    [
        _snapshot_push() + b"\x00",
        _snapshot_push(code=b"60A519"),
        _snapshot_push(wire_subtype=0x60),
        bytes(71),
    ],
)
def test_snapshot_push_parser_rejects_other_shapes(body):
    assert not snapshot_protocol.is_snapshot_push(body)
    assert snapshot_protocol.parse_snapshot_push(body) is None


def test_protocol_reexports_snapshot_builder_and_constants():
    assert (
        protocol.build_snapshot_subscribe
        is snapshot_protocol.build_snapshot_subscribe
    )
    assert protocol.SNAPSHOT_DATATYPE is snapshot_protocol.SNAPSHOT_DATATYPE
    assert protocol.SNAPSHOT_PAGEID == snapshot_protocol.SNAPSHOT_PAGEID
    assert (
        protocol.build_market_snapshot_query
        is snapshot_protocol.build_market_snapshot_query
    )
    assert (
        protocol.MARKET_SNAPSHOT_MARKETS
        is snapshot_protocol.MARKET_SNAPSHOT_MARKETS
    )
    assert protocol.parse_snapshot_push is snapshot_protocol.parse_snapshot_push
    assert protocol.is_snapshot_push is snapshot_protocol.is_snapshot_push
    assert (
        protocol.parse_auction_depth_push
        is snapshot_protocol.parse_auction_depth_push
    )
    assert (
        protocol.is_auction_depth_push
        is snapshot_protocol.is_auction_depth_push
    )
    assert (
        protocol.is_stock_depth_envelope
        is snapshot_protocol.is_stock_depth_envelope
    )


def _auction_depth_push(
    *,
    code_offset=45,
    market_flag=0x21,
    code=b"002428",
    auction_price_raw=0xC0107A5C,  # 107.99
    matched_volume=428_200,
    buy_unmatched=0,
    sell_unmatched=54_228,
):
    """Build the variable-offset 0x0f7f auction layout from the 08-10 pcap."""
    body = bytearray(code_offset + 130)
    body[0:5] = b"\x09\x7b\xd0\x0f\x7f"
    body[code_offset - 1] = market_flag
    body[code_offset : code_offset + 6] = code
    struct.pack_into("<I", body, code_offset + 6, 0xC00F4560)  # 100.08
    struct.pack_into("<I", body, code_offset + 10, auction_price_raw)
    # During the auction the ordinary current-price slot remains zero.
    struct.pack_into("<I", body, code_offset + 26, auction_price_raw)
    struct.pack_into("<I", body, code_offset + 30, matched_volume)
    struct.pack_into("<I", body, code_offset + 34, 0x80000000)
    struct.pack_into("<I", body, code_offset + 38, buy_unmatched)
    struct.pack_into("<I", body, code_offset + 50, auction_price_raw)
    struct.pack_into("<I", body, code_offset + 54, matched_volume)
    struct.pack_into("<I", body, code_offset + 58, 0x80000000)
    struct.pack_into("<I", body, code_offset + 62, sell_unmatched)
    imbalance = sell_unmatched or buy_unmatched
    if sell_unmatched:
        imbalance |= 0x08000000
    struct.pack_into("<I", body, code_offset + 126, imbalance)
    return bytes(body)


def test_auction_depth_push_parses_sell_dominant_three_row_book():
    body = _auction_depth_push()

    assert snapshot_protocol.is_depth_push(body)
    assert snapshot_protocol.is_auction_depth_push(body)
    result = snapshot_protocol.parse_depth_push(body)

    assert result == snapshot_protocol.parse_auction_depth_push(body)
    assert result["code"] == "002428"
    assert result["market"] == "SZ"
    assert result["phase"] == "auction"
    assert result["auction_price"] == 107.99
    assert result["matched_volume"] == 428_200
    assert result["buy_unmatched_volume"] == 0
    assert result["sell_unmatched_volume"] == 54_228
    assert result["imbalance_side"] == "sell"
    assert [(row["side"], row["level"]) for row in result["display_levels"]] == [
        ("sell", 1),
        ("sell", 2),
        ("buy", 1),
    ]
    assert result["display_levels"][1]["price"] is None


def test_depth_push_rejects_adjacent_wire_subtype():
    body = bytearray(_auction_depth_push())
    body[4] = 0x60

    assert not snapshot_protocol.is_depth_push(bytes(body))
    assert snapshot_protocol.parse_depth_push(bytes(body)) is None


def test_depth_push_rejects_unverified_compact_or_concatenated_layout():
    body = _continuous_depth_push() + bytes(16)

    assert snapshot_protocol.is_stock_depth_envelope(body)
    assert not snapshot_protocol.is_depth_push(body)
    assert snapshot_protocol.parse_depth_push(body) is None


def test_auction_depth_push_finds_shifted_buy_dominant_stock_block():
    body = _auction_depth_push(
        code_offset=213,
        auction_price_raw=0xC0107674,  # 107.89
        matched_volume=437_428,
        buy_unmatched=172,
        sell_unmatched=0,
    )

    result = snapshot_protocol.parse_depth_push(body)

    assert result is not None
    assert result["code_offset"] == 213
    assert result["auction_price"] == 107.89
    assert result["imbalance_side"] == "buy"
    assert result["imbalance_volume"] == 172
    assert [(row["side"], row["level"]) for row in result["display_levels"]] == [
        ("buy", 1),
        ("buy", 2),
        ("sell", 1),
    ]


def _continuous_depth_push():
    body = bytearray(550)
    body[0:5] = b"\x09\x7b\xd0\x0f\x7f"
    body[44] = 0x11
    body[45:51] = b"603118"
    for offset, raw in ((51, 9), (55, 10), (59, 12), (63, 8), (67, 11)):
        struct.pack_into("<I", body, offset, raw)

    pair_offsets = list(range(95, 143, 8))
    pair_offsets += list(range(147, 179, 8))
    pair_offsets += list(range(195, 267, 8))
    for index, offset in enumerate(pair_offsets):
        struct.pack_into("<I", body, offset, 100 + index)
        struct.pack_into("<I", body, offset + 4, 1_000 + index)
    return bytes(body)


def test_continuous_depth_push_keeps_existing_ten_level_layout():
    result = snapshot_protocol.parse_depth_push(_continuous_depth_push())

    assert result is not None
    assert result["phase"] == "continuous"
    assert result["code"] == "603118"
    assert result["price"] == 11.0
    assert len(result["bids"]) == 10
    assert len(result["asks"]) == 10
    assert result["bids"][0] == (100.0, 1_000)
    assert result["asks"][0] == (103.0, 1_003)


@pytest.mark.parametrize(
    ("name", "expected_len", "expected_hash"),
    [
        (
            "auction_sell_002428.hex",
            522,
            "842b292e125b3f22e406545dd8dc145d02553cf7ccf7b749c142db0191bdb41d",
        ),
        (
            "auction_buy_002428.hex",
            522,
            "0fcc5813fae748a557e9b22ed83202b587c635c460441767cfde98a503268941",
        ),
        (
            "continuous_000657.hex",
            550,
            "dc3fabfdfaf87dcb43c27c587459efe5952f5e4be16536f3b3a161d5c0bbd050",
        ),
    ],
)
def test_captured_depth_push_fixture_integrity(name, expected_len, expected_hash):
    body = _captured_depth_push(name)

    assert len(body) == expected_len
    assert hashlib.sha256(body).hexdigest() == expected_hash


@pytest.mark.parametrize(
    ("name", "side", "matched", "unmatched", "display_sides"),
    [
        (
            "auction_sell_002428.hex",
            "sell",
            353_400,
            47_428,
            ["sell", "sell", "buy"],
        ),
        (
            "auction_buy_002428.hex",
            "buy",
            437_428,
            172,
            ["buy", "buy", "sell"],
        ),
    ],
)
def test_captured_auction_depth_push_matches_super_book_oracle(
    name, side, matched, unmatched, display_sides
):
    result = snapshot_protocol.parse_depth_push(_captured_depth_push(name))

    assert result is not None
    assert result["code"] == "002428"
    assert result["phase"] == "auction"
    assert result["matched_volume"] == matched
    assert result["imbalance_side"] == side
    assert result["imbalance_volume"] == unmatched
    assert [row["side"] for row in result["display_levels"]] == display_sides


def test_captured_continuous_depth_push_has_exact_ten_levels():
    body = _captured_depth_push("continuous_000657.hex")

    assert snapshot_protocol.is_stock_depth_envelope(body)
    assert snapshot_protocol.is_depth_push(body)
    result = snapshot_protocol.parse_depth_push(body)

    assert result is not None
    assert result["code"] == "000657"
    assert result["market"] == "SZ"
    assert result["phase"] == "continuous"
    assert result["price"] == 69.05
    assert result["prev_close"] == 67.01
    assert len(result["bids"]) == 10
    assert len(result["asks"]) == 10
    assert result["bids"][0] == (69.05, 35_390)
    assert result["bids"][-1] == (68.96, 300)
    assert result["asks"][0] == (69.07, 700)
    assert result["asks"][-1] == (69.48, 200)


@pytest.mark.parametrize(
    ("name", "normalized_len", "normalized_hash", "codes"),
    [
        (
            "variable_c51_two_records.hex",
            2078,
            "4d076a07c842d54be29935fc522f498cf003793816a1b64199fab0a26fa45a4e",
            ["600000", "600012"],
        ),
        (
            "variable_c57_three_records.hex",
            2785,
            "812f5b27e076a10bffe036f2801c64ff8eb16ebce373c1d1f05a526cbe2f90cc",
            ["300308", "300322", "300394"],
        ),
    ],
)
def test_variable_depth_push_normalizes_to_native_hd1_output(
    name, normalized_len, normalized_hash, codes
):
    body = _captured_depth_push(name)

    normalized = normalize_stock_depth_push(body)
    assert normalized is not None
    assert len(normalized) == normalized_len
    assert hashlib.sha256(normalized).hexdigest() == normalized_hash

    records = snapshot_protocol.parse_depth_push_records(body)
    assert [record["code"] for record in records] == codes
    assert [record["batch_index"] for record in records] == list(range(len(codes)))
    assert {record["batch_size"] for record in records} == {len(codes)}
    assert {record["phase"] for record in records} == {"auction"}


def test_variable_depth_push_first_record_api_remains_backward_compatible():
    body = _captured_depth_push("variable_c51_two_records.hex")

    assert snapshot_protocol.is_depth_push(body)
    first = snapshot_protocol.parse_depth_push(body)
    assert first is not None
    assert first["code"] == "600000"
    assert first["batch_size"] == 2


def test_variable_depth_push_skips_kind5_context_block():
    body = bytearray(_captured_depth_push("variable_c51_two_records.hex"))
    baseline = normalize_stock_depth_push(bytes(body))
    assert baseline is not None

    # record_kind=1, extension_size=0 -> kind=5, size=3, payload="ctx".
    body[16] = 0x85
    body[17] = 0x83
    body[18:18] = b"ctx"

    assert normalize_stock_depth_push(bytes(body)) == baseline


def test_quote_stream_control_record_registers_native_field_table():
    def encode_varint(value: int) -> bytes:
        groups = [value & 0x7F]
        value >>= 7
        while value:
            groups.append(value & 0x7F)
            value >>= 7
        groups.reverse()
        groups[-1] |= 0x80
        return bytes(groups)

    stream_key = 0x12340011
    control = b"\x09{" + b"".join(
        encode_varint(value)
        for value in (0x4D, stream_key, 2, 0x1005, 7, 0x7006, 4)
    ) + b"}"
    normalizer = QuoteStreamNormalizer()

    assert normalizer.register_control(control)
    assert normalizer.schemas[stream_key] == bytes.fromhex(
        "0510000706700004"
    )
