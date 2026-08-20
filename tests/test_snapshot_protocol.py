"""Offline wire contracts for Level2 snapshot registration."""

import hashlib
import struct
from datetime import datetime
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


@pytest.mark.parametrize(
    ("fixture", "side", "placed", "cancelled", "price", "aux_id"),
    [
        (
            "auction_cancel_buy_002428.hex",
            "buy",
            datetime(2026, 8, 10, 9, 15, 2),
            datetime(2026, 8, 10, 9, 18, 57),
            110.09,
            216_579,
        ),
        (
            "auction_cancel_sell_002428.hex",
            "sell",
            datetime(2026, 8, 10, 9, 18, 0),
            datetime(2026, 8, 10, 9, 19, 3),
            90.07,
            291_607,
        ),
    ],
)
def test_captured_auction_cancel_push_contract(
    fixture,
    side,
    placed,
    cancelled,
    price,
    aux_id,
):
    body = _captured_depth_push(fixture)

    assert snapshot_protocol.is_order_cancel_push(body)
    assert snapshot_protocol.is_auction_cancel_push(body)
    assert not snapshot_protocol.is_snapshot_push(body)
    result = snapshot_protocol.parse_order_cancel_push(body)

    assert result is not None
    assert result["code"] == "002428"
    assert result["market"] == "SZ"
    assert result["event"] == "order_cancel"
    assert result["side"] == side
    assert result["side_raw"] == (0x08 if side == "buy" else 0x0C)
    assert result["placed_at"] == placed
    assert result["cancelled_at"] == cancelled
    assert result["lifetime_seconds"] == int(
        (cancelled - placed).total_seconds()
    )
    assert result["price"] == price
    assert result["volume"] == 100
    assert result["lots"] == 1
    assert result["aux_id"] == aux_id
    assert result["raw_len"] == 71

    legacy = snapshot_protocol.parse_auction_cancel_push(body)
    assert legacy is not None
    assert legacy["event"] == "auction_cancel"
    assert {**legacy, "event": "order_cancel"} == result


def test_realtime_trade_tick_matches_7169_replay_fields():
    body = _captured_depth_push("trade_tick_sell_603334.hex")

    assert snapshot_protocol.is_trade_tick_push(body)
    assert snapshot_protocol.is_snapshot_push(body)
    result = snapshot_protocol.parse_trade_tick_push(body)
    assert result == snapshot_protocol.parse_snapshot_push(body)
    assert result is not None
    assert result["event"] == "trade"
    assert result["wire_subtype"] == "0x60/0x04"
    assert result["code"] == "603334"
    assert result["market"] == "SH"
    assert result["time"] == datetime(2026, 8, 20, 13, 19, 22)
    assert result["timestamp"] == 1_787_203_162
    assert result["price"] == 34.86
    assert result["volume"] == 200
    assert result["direction"] == 5
    assert result["delegate_a"] == 11_868_730
    assert result["delegate_b"] == 11_857_651
    assert result["seq"] == 7_467
    assert result["previous_trade_no"] == 19_881_819
    assert result["trade_no"] == 19_881_819
    assert result["raw_len"] == 72


def test_trade_tick_canonical_api_keeps_legacy_0x7f_support():
    body = _snapshot_push()

    assert snapshot_protocol.is_trade_tick_push(body)
    result = snapshot_protocol.parse_trade_tick_push(body)
    assert result is not None
    assert result["wire_subtype"] == "0x7f"
    assert result["price"] == 36.0
    assert result["volume"] == 300


@pytest.mark.parametrize(
    ("name", "expected_len", "expected_hash"),
    [
        (
            "trade_batch_603334_174.hex",
            174,
            "76dadc2149f053b3bc77de7b371f2f59e9776094bc405b6594bf476db528d76d",
        ),
        (
            "trade_batch_603334_84.hex",
            84,
            "844f356db2a1df08169086b82c4651502e3c5efa16d4ec71baf5950520fdbd42",
        ),
    ],
)
def test_trade_batch_fixture_integrity(name, expected_len, expected_hash):
    body = _captured_depth_push(name)

    assert len(body) == expected_len
    assert hashlib.sha256(body).hexdigest() == expected_hash


def test_realtime_trade_tick_accepts_runtime_core_without_delimiter():
    """read_frame 按长度头返回 71B 核心（0x7d 是长度头之外的帧分隔符）。"""
    body = _captured_depth_push("trade_tick_sell_603334.hex")
    core = body[:-1]

    assert len(core) == 71
    assert snapshot_protocol.is_trade_tick_push(core)
    result = snapshot_protocol.parse_trade_tick_push(core)
    assert result is not None
    assert result["seq"] == 7_467
    assert result["previous_trade_no"] == 19_881_819
    assert result["trade_no"] == 19_881_819
    assert result["raw_len"] == 71
    # 两种形态产出一致的字段（除 raw_len）
    with_delimiter = snapshot_protocol.parse_trade_tick_push(body)
    core_view = {k: v for k, v in result.items() if k != "raw_len"}
    delimiter_view = {
        k: v for k, v in with_delimiter.items() if k != "raw_len"
    }
    assert core_view == delimiter_view


def test_trade_tick_batch_push_174_byte_contract():
    body = _captured_depth_push("trade_batch_603334_174.hex")

    assert snapshot_protocol.is_trade_tick_batch_push(body)
    # 批量帧不属于单笔形态；单笔识别器必须拒绝
    assert not snapshot_protocol.is_trade_tick_push(body)

    result = snapshot_protocol.parse_trade_tick_batch_push(body)
    assert result is not None
    assert result["code"] == "603334"
    assert result["market"] == "SH"
    assert result["event"] == "trade_batch"
    assert result["wire_subtype"] == "0x60/0x04-batch"
    assert result["count"] == 11
    assert result["seq_start"] == 7_469
    assert result["seq_end"] == 7_479
    assert result["seqs"] == list(range(7_469, 7_480))
    assert result["records_resolved"] is True
    assert len(result["records"]) == 11
    assert [row["volume"] for row in result["records"]] == [
        100, 200, 100, 200, 100, 100, 200, 200, 100, 200, 100,
    ]
    assert [row["delegate_b"] for row in result["records"]] == [
        11_869_653,
        11_869_654,
        11_869_655,
        11_869_656,
        11_869_657,
        11_869_660,
        11_869_668,
        11_869_669,
        11_869_670,
        11_869_671,
        11_869_676,
    ]
    assert result["records"][0] == {
        "code": "603334",
        "market": "SH",
        "event": "trade",
        "time": datetime(2026, 8, 20, 13, 19, 24),
        "timestamp": 1_787_203_164,
        "price": 34.85,
        "volume": 100,
        "direction": 1,
        "delegate_a": 11_868_045,
        "delegate_b": 11_869_653,
        "seq": 7_469,
        "previous_trade_no": 19_883_425,
        "trade_no": 19_883_425,
        "wire_subtype": "0x60/0x04-batch",
    }
    assert result["raw_len"] == 174


def test_trade_tick_batch_push_84_byte_contract():
    body = _captured_depth_push("trade_batch_603334_84.hex")

    result = snapshot_protocol.parse_trade_tick_batch_push(body)
    assert result is not None
    assert result["count"] == 2
    assert result["seq_start"] == 7_480
    assert result["seq_end"] == 7_481
    assert [
        (row["seq"], row["volume"], row["delegate_b"])
        for row in result["records"]
    ] == [
        (7_480, 100, 11_869_716),
        (7_481, 100, 11_869_717),
    ]


def test_trade_tick_batch_push_accepts_0x7d_delimiter_variant():
    for name in ("trade_batch_603334_174.hex", "trade_batch_603334_84.hex"):
        body = _captured_depth_push(name)

        variant = body + b"\x7d"
        assert snapshot_protocol.is_trade_tick_batch_push(variant)
        result = snapshot_protocol.parse_trade_tick_batch_push(variant)
        assert result is not None
        assert result["raw_len"] == len(body) + 1
        assert result["seqs"][0] == snapshot_protocol.parse_trade_tick_batch_push(
            body
        )["seqs"][0]


def test_trade_tick_batch_push_rejects_structural_damage():
    body = bytearray(_captured_depth_push("trade_batch_603334_174.hex"))

    # 破坏 count 回显
    damaged = bytearray(body)
    damaged[38] = 0x0A
    assert not snapshot_protocol.is_trade_tick_batch_push(bytes(damaged))
    assert snapshot_protocol.parse_trade_tick_batch_push(bytes(damaged)) is None

    # 破坏尾部 (n-1)×0x81 模式
    damaged = bytearray(body)
    damaged[-3] = 0x00
    assert not snapshot_protocol.is_trade_tick_batch_push(bytes(damaged))

    # 单笔帧不是批量
    single = _captured_depth_push("trade_tick_sell_603334.hex")
    assert not snapshot_protocol.is_trade_tick_batch_push(single)


def test_thspypc_exports_trade_tick_batch_api():
    import thspypc

    assert (
        thspypc.is_trade_tick_batch_push
        is snapshot_protocol.is_trade_tick_batch_push
    )
    assert (
        thspypc.parse_trade_tick_batch_push
        is snapshot_protocol.parse_trade_tick_batch_push
    )


def test_continuous_session_order_cancel_uses_phase_neutral_event():
    body = _captured_depth_push("order_cancel_sell_603334.hex")

    assert snapshot_protocol.is_order_cancel_push(body)
    result = snapshot_protocol.parse_order_cancel_push(body)

    assert result is not None
    assert result["code"] == "603334"
    assert result["market"] == "SH"
    assert result["event"] == "order_cancel"
    assert result["side"] == "sell"
    assert result["placed_at"] == datetime(2026, 8, 20, 13, 19, 12)
    assert result["cancelled_at"] == datetime(2026, 8, 20, 13, 19, 19)
    assert result["lifetime_seconds"] == 7
    assert result["price"] == 35.49
    assert result["volume"] == 500
    assert result["lots"] == 5
    assert result["seq"] == 3474
    assert result["cancel_id"] == 3474
    assert result["order_id"] == 11_860_871
    assert result["aux_id"] == result["order_id"]
    assert result["wire_subtype"] == "0x60/0x0c"


def test_order_cancel_accepts_live_core_without_capture_delimiter():
    captured = _captured_depth_push("order_cancel_sell_603334.hex")
    assert captured[-1] == 0x7D

    result = snapshot_protocol.parse_order_cancel_push(captured[:-1])

    assert result is not None
    assert result["cancel_id"] == 3474
    assert result["raw_len"] == 70


def test_order_cancel_batch_matches_7171_truth():
    body = _captured_depth_push("order_cancel_sell_batch_603334_87.hex")

    assert snapshot_protocol.is_order_cancel_batch_push(body)
    assert not snapshot_protocol.is_order_cancel_push(body)
    result = snapshot_protocol.parse_order_cancel_batch_push(body)

    assert result is not None
    assert result["event"] == "order_cancel_batch"
    assert result["side"] == "sell"
    assert result["count"] == 2
    assert (result["cancel_id_start"], result["cancel_id_end"]) == (3477, 3478)
    assert result["records_resolved"] is True
    assert snapshot_protocol.parse_order_cancel_records(body) == result["records"]
    assert [
        {
            "cancel_id": row["cancel_id"],
            "order_id": row["order_id"],
            "placed_timestamp": row["placed_timestamp"],
            "cancelled_timestamp": row["cancelled_timestamp"],
            "price_raw": row["price_raw"],
            "volume": row["volume"],
        }
        for row in result["records"]
    ] == [
        {
            "cancel_id": 3477,
            "order_id": 11_761_615,
            "placed_timestamp": 1_787_203_039,
            "cancelled_timestamp": 1_787_203_162,
            "price_raw": 2_952_825_506,
            "volume": 300,
        },
        {
            "cancel_id": 3478,
            "order_id": 11_839_106,
            "placed_timestamp": 1_787_203_127,
            "cancelled_timestamp": 1_787_203_162,
            "price_raw": 2_952_825_096,
            "volume": 500,
        },
    ]


@pytest.mark.parametrize(
    ("fixture", "side", "period", "price", "meta", "total", "entries"),
    [
        (
            "order_queue_buy_603334_75.hex",
            "buy",
            7173,
            34.85,
            189_200,
            3,
            [600, 100, 1000],
        ),
        (
            "order_queue_sell_603334_71.hex",
            "sell",
            7174,
            34.86,
            252_878,
            2,
            [900, 300],
        ),
    ],
)
def test_order_queue_push_matches_7173_7174_layout(
    fixture,
    side,
    period,
    price,
    meta,
    total,
    entries,
):
    body = _captured_depth_push(fixture)

    assert snapshot_protocol.is_order_queue_push(body)
    result = snapshot_protocol.parse_order_queue_push(body)

    assert result is not None
    assert result["code"] == "603334"
    assert result["market"] == "SH"
    assert result["event"] == "order_queue"
    assert result["side"] == side
    assert result["period"] == period
    assert result["price"] == price
    assert result["meta_value"] == meta
    assert result["total_order_count"] == total
    assert result["visible_count"] == len(entries)
    assert [row["shares"] for row in result["entries"]] == entries
    assert result["truncated"] is False


def test_order_queue_push_accepts_optional_capture_delimiter():
    body = _captured_depth_push("order_queue_buy_603334_75.hex")

    parsed = snapshot_protocol.parse_order_queue_push(body + b"\x7d")

    assert parsed is not None
    assert parsed["raw_len"] == len(body) + 1


def test_auction_cancel_push_rejects_mismatched_context_code():
    body = bytearray(
        _captured_depth_push("auction_cancel_buy_002428.hex")
    )
    body[29:35] = b"002429"

    assert not snapshot_protocol.is_order_cancel_push(bytes(body))
    assert snapshot_protocol.parse_order_cancel_push(bytes(body)) is None
    assert not snapshot_protocol.is_auction_cancel_push(bytes(body))
    assert snapshot_protocol.parse_auction_cancel_push(bytes(body)) is None


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
        protocol.parse_trade_tick_push
        is snapshot_protocol.parse_trade_tick_push
    )
    assert (
        protocol.is_trade_tick_push
        is snapshot_protocol.is_trade_tick_push
    )
    assert (
        protocol.parse_order_cancel_push
        is snapshot_protocol.parse_order_cancel_push
    )
    assert (
        protocol.is_order_cancel_push
        is snapshot_protocol.is_order_cancel_push
    )
    assert (
        protocol.parse_order_cancel_batch_push
        is snapshot_protocol.parse_order_cancel_batch_push
    )
    assert (
        protocol.is_order_cancel_batch_push
        is snapshot_protocol.is_order_cancel_batch_push
    )
    assert (
        protocol.parse_order_cancel_records
        is snapshot_protocol.parse_order_cancel_records
    )
    assert (
        protocol.parse_order_queue_push
        is snapshot_protocol.parse_order_queue_push
    )
    assert (
        protocol.is_order_queue_push
        is snapshot_protocol.is_order_queue_push
    )
    assert (
        protocol.parse_auction_cancel_push
        is snapshot_protocol.parse_auction_cancel_push
    )
    assert (
        protocol.is_auction_cancel_push
        is snapshot_protocol.is_auction_cancel_push
    )
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
        (
            "continuous_603334_614.hex",
            614,
            "a6d41a151bc6a1461f379a61968f7a92c3b914c29c272b8b2504005213cb2d6b",
        ),
        (
            "trade_tick_sell_603334.hex",
            72,
            "5384ba9137089ad9b4f2f9b2db49899344b564aa024794cb31958a261bd742e2",
        ),
        (
            "order_queue_buy_603334_75.hex",
            75,
            "d4f7cdb63e4e891487e11a740a17421750ecc7d537a43da0ca34d06aad6e0ba1",
        ),
        (
            "order_queue_sell_603334_71.hex",
            71,
            "2656bb7459f5d97162866c27faea9344ae3f2f515a1ee8c4f5c1038d36ff5627",
        ),
        (
            "order_cancel_sell_batch_603334_87.hex",
            87,
            "b2dac0b5a7578c85c4f30af1dc4d4ae330d79371541b676791e74e54d4219ada",
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


def test_captured_614b_continuous_depth_push_has_exact_ten_levels():
    body = _captured_depth_push("continuous_603334_614.hex")

    assert snapshot_protocol.is_stock_depth_envelope(body)
    assert snapshot_protocol.is_depth_push(body)
    result = snapshot_protocol.parse_depth_push(body)

    assert result is not None
    assert result["code"] == "603334"
    assert result["market"] == "SH"
    assert result["phase"] == "continuous"
    assert result["raw_len"] == 614
    assert result["code_offset"] == 61
    assert result["prev_close"] == 32.26
    assert result["open"] == 32.56
    assert result["high"] == 35.49
    assert result["low"] == 32.0
    assert result["price"] == 34.86
    assert len(result["bids"]) == 10
    assert len(result["asks"]) == 10
    assert result["bids"][0] == (34.8, 4_900)
    assert result["asks"][0] == (34.85, 100)


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
