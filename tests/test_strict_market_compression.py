"""Compressed market tails must be backed by genuine input bytes."""

import struct

import pytest

from thspypc.codecs.compression import Incomplete8901Response, normalize_8901_response


def compressed_frame(expected_size, source):
    return b"\x0a" + struct.pack(">I", expected_size) + source


def test_strict_mode_keeps_plain_input_identity():
    body = b"\x00\x16already-normalized"
    assert normalize_8901_response(body, strict=True) is body


def test_strict_mode_rejects_missing_literal_and_keeps_trusted_prefix():
    body = compressed_frame(8, b"ABCD\x00E")
    assert normalize_8901_response(body) == b"ABCDE\x00\x00\x00"

    with pytest.raises(Incomplete8901Response) as raised:
        normalize_8901_response(body, strict=True)

    assert raised.value.normalized_prefix == b"ABCDE"
    assert raised.value.expected_size == 8


def test_strict_mode_accepts_real_zero_tail():
    body = compressed_frame(8, b"ABCD\x00E\x00\x00\x00")
    assert normalize_8901_response(body, strict=True) == b"ABCDE\x00\x00\x00"


def test_strict_mode_allows_unused_literal_after_odd_output_length():
    body = compressed_frame(5, b"ABCD\x00E")
    assert normalize_8901_response(body, strict=True) == b"ABCDE"


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        (b"ABCD\x0fEFGHIJKL", b"ABCDEFGHIJKLABCD"),
        (b"ABCD\x7dEF", b"ABCDEFABCDEFA"),
        (b"ABCD\x7fEF", b"ABCDEFABCDEFABCDE"),
    ],
)
def test_strict_mode_allows_unused_control_prefetch_after_proven_output(source, expected):
    # The last real control bit guarantees multiple reference bytes. The next
    # control is prefetched but becomes optional after those bytes are emitted.
    body = compressed_frame(len(expected), source)
    assert normalize_8901_response(body, strict=True) == expected
    assert normalize_8901_response(body) == expected


@pytest.mark.parametrize(
    ("source", "trusted_prefix"),
    [
        (b"ABCD\x0fEFGHIJKL", b"ABCDEFGHIJKLABCD"),
        (b"ABCD\x7dEF", b"ABCDEFABCDEFA"),
        (b"ABCD\x7fEF", b"ABCDEFABCDEFABCDE"),
    ],
)
def test_strict_mode_rejects_consuming_missing_control(source, trusted_prefix):
    expected_size = len(trusted_prefix) + 1
    body = compressed_frame(expected_size, source)

    with pytest.raises(Incomplete8901Response) as raised:
        normalize_8901_response(body, strict=True)

    assert raised.value.normalized_prefix == trusted_prefix
    assert raised.value.expected_size == expected_size
