"""Contracts for the optional stable-ABI native compression codec."""
from __future__ import annotations

import pytest

from thspypc.codecs import compression


native = pytest.importorskip(
    "thspypc.codecs._compression_native",
    reason="optional native codec is not built",
)


def test_native_bitrle_matches_python_fallback_for_literal_stream(monkeypatch):
    stream = b"\x00\x00\x00\x04\x00abcd"
    expected = native.decode_bitrle(stream, 4)
    monkeypatch.setattr(compression, "_compression_native", None)

    assert expected == b"abcd"
    assert compression._decode_bitrle_0x13746d0(stream, 4) == expected


def test_native_transpose_matches_python_fallback_and_slice(monkeypatch):
    record_size = 7
    record_count = 17
    bitplane = bytes((index * 73 + 19) & 0xFF for index in range(119))
    complete = native.transpose(bitplane, record_size, record_count)
    selected = native.transpose(
        bitplane,
        record_size,
        record_count,
        row_start=9,
        row_count=7,
    )
    monkeypatch.setattr(compression, "_compression_native", None)

    assert complete == compression._transpose_bitplane_0x1763410(
        bitplane,
        record_size,
        record_count,
    )
    assert selected == complete[9 * record_size : 16 * record_size]


def test_native_transpose_preserves_negative_row_count_fallback_semantics():
    assert native.transpose(b"\xff", 1, 1, row_count=-1) == b""
