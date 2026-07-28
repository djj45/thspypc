"""Offline contracts for the extracted auction request protocol."""

import hashlib
from datetime import date

import thspypc.protocol as protocol
from thspypc.features import auction_protocol


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def test_auction_builder_wire_contracts():
    cases = [
        (
            auction_protocol.build_auction_query("000938", market=33),
            140,
            "b80de83d83887458baa85aeeb00da9abf2423ea607000c285bc4e5b4169bb39f",
        ),
        (
            auction_protocol.build_auction_query("603118", market=17),
            140,
            "ea9107a0c80939cd661f5bf29b2b7ed5ec135748549c239e2a79a53c0d495550",
        ),
        (
            auction_protocol.build_auction_query(
                "000938",
                market=33,
                trade_date=date(2026, 7, 24),
            ),
            158,
            "e69869c9a35ae98986354b08ec71942c26ead54ea15a94b20756f6affd371ef0",
        ),
    ]

    for frame, expected_length, expected_hash in cases:
        assert len(frame) == expected_length
        assert _sha256(frame) == expected_hash


def test_auction_sentinels_remain_distinct_from_zero():
    assert auction_protocol._auction_value(0x80000000, 27) is None
    assert auction_protocol._auction_value(0xFFFFFFFF, 33) is None
    assert auction_protocol._auction_value(0, 27) == 0.0


def test_protocol_reexports_auction_builder():
    assert protocol.build_auction_query is auction_protocol.build_auction_query
    assert protocol.AUCTION_DATATYPE is auction_protocol.AUCTION_DATATYPE
    assert (
        protocol._auction_ts_in_range
        is auction_protocol._auction_ts_in_range
    )
    assert (
        protocol._split_auction_state_rows
        is auction_protocol._split_auction_state_rows
    )
    assert (
        protocol._parse_auction_sh
        is auction_protocol._parse_auction_sh
    )
    assert (
        protocol.parse_auction_response
        is auction_protocol.parse_auction_response
    )
