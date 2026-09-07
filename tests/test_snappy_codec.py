"""纯 python snappy 解压器的字节级契约测试。

测试向量全部手工构造（不依赖 python-snappy），可选的 roundtrip 用例
在装有 python-snappy 时额外校验与参考实现一致。
"""
import pytest

from thspypc.codecs.snappy import snappy_decompress


def _varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _literal(payload: bytes) -> bytes:
    """构造一个 literal 元素（覆盖短/1字节扩展长度两种标签）。"""
    length = len(payload) - 1
    if length < 60:
        return bytes((length << 2,)) + payload
    assert length < 256  # 1 字节扩展长度足够测试用
    return bytes((60 << 2, length)) + payload


def _copy1(length: int, offset: int) -> bytes:
    assert 4 <= length <= 11 and offset < 2048
    tag = 0x01 | ((length - 4) << 2) | ((offset >> 8) << 5)
    return bytes((tag, offset & 0xFF))


def _copy2(length: int, offset: int) -> bytes:
    assert 1 <= length <= 64 and offset < 65536
    return bytes((0x02 | ((length - 1) << 2),)) + offset.to_bytes(2, "little")


def _stream(expected_len: int, elements: bytes) -> bytes:
    return _varint(expected_len) + elements


def test_literal_only_stream():
    payload = b"hq1.0\x00\x00\x00X" * 3
    data = _stream(len(payload), _literal(payload))
    assert snappy_decompress(data) == payload


def test_copy2_repeats_earlier_literal():
    head = b"ABCDEFGH"
    elements = _literal(head) + _copy2(8, 8)
    assert snappy_decompress(_stream(16, elements)) == head + head


def test_copy1_overlapping_behaves_like_rle():
    # 长度 8、偏移 1 的重叠拷贝 = 把最后 1 字节重复 8 次
    elements = _literal(b"Z") + _copy1(8, 1)
    assert snappy_decompress(_stream(9, elements)) == b"Z" * 9


def test_multi_byte_preamble_varint():
    # 200 需要 2 字节 varint（>=128），literal 用 1 字节扩展长度标签
    payload = b"x" * 200
    data = _varint(200) + _literal(payload)
    assert snappy_decompress(data) == payload


def test_length_mismatch_raises():
    elements = _literal(b"abc")
    with pytest.raises(ValueError):
        snappy_decompress(_stream(4, elements))  # 声明 4，实际 3


def test_zero_or_backward_offset_raises():
    # 偏移 0 非法；偏移大于已输出长度非法
    with pytest.raises(ValueError):
        snappy_decompress(_stream(4, _literal(b"ab") + _copy2(2, 0)))
    with pytest.raises(ValueError):
        snappy_decompress(_stream(6, _literal(b"ab") + _copy2(4, 99)))


def test_truncated_literal_raises():
    with pytest.raises(ValueError):
        snappy_decompress(_stream(5, _literal(b"ab")))  # literal 声明 5 只有 2


def test_roundtrip_against_reference_library():
    snappy = pytest.importorskip("snappy")
    payload = (
        b"\x09method=pushrealorder\nmarket=32\nziptype=snappy\n"
        b"!001309\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" * 8
    )
    compressed = snappy.compress(payload)
    assert snappy_decompress(compressed) == payload == snappy.uncompress(compressed)
