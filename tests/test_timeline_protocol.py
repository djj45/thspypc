"""Offline contracts for normal-account and Level2 timeline protocols."""

import hashlib
import struct
from pathlib import Path

import pytest
import thspypc.protocol as protocol
from thspypc.features import timeline_protocol


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def test_normal_account_timeline_builder_wire_contracts():
    shenzhen = timeline_protocol.build_timeline_query("000938", market=33)
    shanghai = timeline_protocol.build_timeline_query(
        "603118", market=17, seq=0x1234
    )

    assert len(shenzhen) == 359
    assert _sha256(shenzhen) == (
        "7c58ac0b8e6103924255f4aceda2782f"
        "0efe271f2fe4867d46b4509ae9eb9f77"
    )
    assert len(shanghai) == 359
    assert _sha256(shanghai) == (
        "20dad8b5fff206c0302e3489964beb6cc"
        "f2a1d3fac55bea08bd3d7ba527af737"
    )
    assert shanghai[12:] == timeline_protocol.build_timeline_query(
        "603118", market=17
    )[12:].replace(b"\x22\x11", b"\x34\x12", 1)


def test_level2_timeline_builder_wire_contracts():
    shenzhen = timeline_protocol.build_timeline_l2_query(
        "000938", market=33, extra_codelist="32(399002,);"
    )
    shanghai = timeline_protocol.build_timeline_l2_query(
        "603118", market=17, extra_codelist="16(1A0002,);"
    )

    assert len(shenzhen) == 255
    assert _sha256(shenzhen) == (
        "37ad377ea5ec8fddd842382d0e83919d"
        "ed4d2bb909f1ccabaeda516b9b6ef72d"
    )
    assert len(shanghai) == 255
    assert _sha256(shanghai) == (
        "548b05d9e123cce7e988b27c8a612c8"
        "9849648972981c56690d25268b410cb35"
    )


def test_level2_timeline_parser_selects_stock_half(monkeypatch):
    field_table = bytes((1, 0x30, 0, 4, 10, 0x70, 0, 4))
    shell = bytearray(44)
    shell[4] = 0x20
    shell[5:11] = b"399002"
    shell[22] = 0x21
    shell[23:29] = b"000938"
    header = b"hd3.1\x00" + struct.pack("<IHHH", 2, 0x00B4, 8, 2)
    body = header + field_table + bytes(shell) + struct.pack(">I", 16)
    rows = (
        struct.pack("<II", 132_477_534, 0)
        + struct.pack("<II", 132_477_535, 0xC0052B70)
    )

    monkeypatch.setattr(
        timeline_protocol,
        "_decode_bitrle_0x13746d0",
        lambda _data, _size: b"\x00" * 16,
    )
    monkeypatch.setattr(
        timeline_protocol,
        "_transpose_bitplane_0x1763410",
        lambda _data, _record_size, _record_count: rows,
    )

    assert timeline_protocol.parse_timeline_l2_response(body) == [
        {
            "code": "000938",
            "bar_index": 132_477_535,
            "dt10": 33.88,
        }
    ]


def test_index_timeline_parser_decodes_lead_change_and_price(monkeypatch):
    fields = (
        (1, 0x30),
        (10, 0x70),
        (40, 0x30),
    )
    field_table = b"".join(
        bytes((datatype, fmt, 0, 4)) for datatype, fmt in fields
    )
    shell = b"\x16\x00\x01\x00\x10" + b"1A0001" + b"\x00" * 15
    header = b"hd3.1\x00" + struct.pack("<IHHH", 2, 0x0086, 12, 3)
    body = header + field_table + shell + struct.pack(">I", 24)
    rows = (
        struct.pack("<III", 1, 0xA0000000 | 381_637, 51)
        + struct.pack("<III", 2, 0xA0000000 | 382_415, 150)
    )
    monkeypatch.setattr(
        timeline_protocol,
        "_decode_bitrle_0x13746d0",
        lambda _data, _size: b"\x00" * 24,
    )
    monkeypatch.setattr(
        timeline_protocol,
        "_transpose_bitplane_0x1763410",
        lambda _data, _record_size, _record_count: rows,
    )

    records = timeline_protocol.parse_index_timeline_response(body)
    timeline_protocol.enrich_index_lead_line(records, 3809.66)

    assert records == [
        {
            "code": "1A0001",
            "minute_index": 0,
            "bar_index": 1,
            "dt10": 3816.37,
            "dt40": 51,
            "lead_change_bp": 51,
            "lead_change_pct": 0.51,
            "prev_close": 3809.66,
            "lead_price": pytest.approx(3829.089266),
        },
        {
            "code": "1A0001",
            "minute_index": 1,
            "bar_index": 2,
            "dt10": 3824.15,
            "dt40": 150,
            "lead_change_bp": 150,
            "lead_change_pct": 1.5,
            "prev_close": 3809.66,
            "lead_price": pytest.approx(3866.8049),
        },
    ]


def test_normal_timeline_parser_accepts_shanghai_shell(monkeypatch):
    fields = timeline_protocol.TIMELINE_DATATYPE[:8]
    field_table = b"".join(
        bytes((datatype, 0x70, 0, 4)) for datatype in fields
    )
    shell = (
        b"\x16\x00\x01\x00\x11"
        + b"603118"
        + b"\x00" * 15
    )
    header = b"hd3.1\x00" + struct.pack(
        "<IHHH", 241, 0x0046, 32, 8
    )
    body = header + field_table + shell + struct.pack(">I", 241 * 32)
    row = [0] * 8
    row[4] = 0xC0052B70
    rows = b"".join(
        struct.pack("<8I", *row) for _ in range(241)
    )
    monkeypatch.setattr(
        timeline_protocol,
        "_decode_bitrle_0x13746d0",
        lambda _data, _size: b"\x00" * (241 * 32),
    )
    monkeypatch.setattr(
        timeline_protocol,
        "_transpose_bitplane_0x1763410",
        lambda _data, _record_size, _record_count: rows,
    )

    records = timeline_protocol.parse_timeline_response(body)

    assert len(records) == 241
    assert records[0]["code"] == "603118"
    assert records[0]["dt10"] == 33.88


def test_protocol_reexports_timeline_implementations():
    assert protocol.build_timeline_query is timeline_protocol.build_timeline_query
    assert (
        protocol.build_timeline_l2_query
        is timeline_protocol.build_timeline_l2_query
    )
    assert (
        protocol.parse_timeline_l2_response
        is timeline_protocol.parse_timeline_l2_response
    )
    assert (
        protocol.parse_timeline_response
        is timeline_protocol.parse_timeline_response
    )
    assert protocol.TIMELINE_DATATYPE is timeline_protocol.TIMELINE_DATATYPE
    assert (
        protocol.TIMELINE_L2_DATATYPE
        is timeline_protocol.TIMELINE_L2_DATATYPE
    )


def test_captured_level2_timeline_response():
    capture = (
        Path(__file__).resolve().parents[1]
        / "captures_live"
        / "hexin_timeline_resp_000938.bin"
    )
    if not capture.exists():
        pytest.skip("本机没有 Level2 分时响应语料")

    records = timeline_protocol.parse_timeline_l2_response(
        capture.read_bytes()
    )

    assert len(records) == 241
    assert records[0]["code"] == "000938"
    assert records[0]["bar_index"] == 132_629_086
