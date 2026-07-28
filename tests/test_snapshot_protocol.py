"""Offline wire contracts for Level2 snapshot registration."""

import hashlib
import struct

import pytest

import thspypc.protocol as protocol
from thspypc.features import snapshot_protocol


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
    price=16220,
    volume=300,
    tick_seq=0x80,
):
    body = bytearray(71)
    body[0] = 0x09
    body[14] = 0x80
    body[28] = market_flag
    body[29:35] = code
    body[39] = tick_seq
    struct.pack_into("<H", body, 58, price)
    struct.pack_into("<H", body, 62, volume)
    body[70] = 0x7D
    return bytes(body)


def test_snapshot_push_parser_contract():
    body = _snapshot_push()

    assert snapshot_protocol.is_snapshot_push(body)
    assert snapshot_protocol.parse_snapshot_push(body) == {
        "code": "603118",
        "market": "SH",
        "price": 16.22,
        "volume": 300,
        "tick_seq": 0x80,
        "raw_len": 71,
    }


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
