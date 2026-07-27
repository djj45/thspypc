import hashlib
import os
import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from thspypc.protocol import normalize_8901_response, parse_auction_response


def _compressed_frame(expected: int, stream: bytes) -> bytes:
    return b"\x0a" + struct.pack(">I", expected) + stream


def test_normalizer_leaves_plain_frames_unchanged():
    body = b"\x00\x16plain"

    assert normalize_8901_response(body) is body


def test_normalizer_decodes_literal_pairs():
    body = _compressed_frame(8, b"ABCD\x00EFGH")

    assert normalize_8901_response(body) == b"ABCDEFGH"


def test_normalizer_decodes_dictionary_reference():
    body = _compressed_frame(5, b"ABCD\xc0")

    assert normalize_8901_response(body) == b"ABCDA"


def test_normalizer_decodes_four_byte_dictionary_reference():
    body = _compressed_frame(8, b"ABCD\xf0")

    assert normalize_8901_response(body) == b"ABCDABCD"


def test_normalizer_rejects_invalid_declared_size():
    body = b"\x0a\x00\x00\x00\x00payload"

    try:
        normalize_8901_response(body)
    except ValueError as exc:
        assert "长度" in str(exc)
    else:
        raise AssertionError("invalid normalized size was accepted")


def test_captured_auction_frames_match_x86_oracle():
    capture_dir = Path(__file__).resolve().parents[1] / "captures_live"
    expected_hashes = {
        "auction_raw_603118_20260727_130841_r1.bin":
            "92369ff1df188da8f082b0b052f0cb2c2f7e63bc3216caa7185490776415f7b7",
        "auction_raw_603118_20260727_130843_r2.bin":
            "879e956a596f555848f479feca60ba18b3c7cf491dc98a147c95e40d5a522984",
        "auction_raw_603118_20260727_130846_r3.bin":
            "fcc279b0c7d45fa3f33081b82dc090d30207a723d6754aa5cfdb8c78cdad2a04",
        "auction_raw_603118_20260727_130848_r4.bin":
            "92369ff1df188da8f082b0b052f0cb2c2f7e63bc3216caa7185490776415f7b7",
        "auction_raw_603118_20260727_130850_r5.bin":
            "92369ff1df188da8f082b0b052f0cb2c2f7e63bc3216caa7185490776415f7b7",
    }
    paths = [capture_dir / name for name in expected_hashes]
    if not all(path.exists() for path in paths):
        pytest.skip("本机没有 603118 的五份原始竞价语料")

    for path in paths:
        normalized = normalize_8901_response(path.read_bytes())
        assert hashlib.sha256(normalized).hexdigest() == expected_hashes[path.name]
        records = parse_auction_response(path.read_bytes())
        assert len(records) == 200
        assert set(records[0]) == {"time", "dt10", "dt49", "dt27", "dt33"}


def test_older_captures_select_fixed_or_stateful_inner_parser():
    capture_dir = Path(__file__).resolve().parents[1] / "captures_live"
    fixed_path = capture_dir / "_sh_auction_resp_603118.bin"
    fallback_path = capture_dir / "_sh_auction_resp_600276.bin"
    if not fixed_path.exists() or not fallback_path.exists():
        pytest.skip("本机没有旧沪市竞价语料")

    fixed_records = parse_auction_response(fixed_path.read_bytes())
    assert len(fixed_records) == 201
    assert set(fixed_records[0]) == {"time", "dt10", "dt49", "dt27", "dt33"}

    stateful_records = parse_auction_response(fallback_path.read_bytes())
    assert len(stateful_records) == 159
    assert set(stateful_records[0]) == {"time", "dt10", "dt49", "dt27", "dt33"}
    assert stateful_records[12]["time"].strftime("%H:%M:%S") == "09:15:50"
    assert stateful_records[12]["dt10"] == 54.71
    assert stateful_records[15]["time"].strftime("%H:%M:%S") == "09:16:08"
    assert stateful_records[15]["dt33"] == 1100
    assert stateful_records[16]["time"].strftime("%H:%M:%S") == "09:16:14"
    assert stateful_records[16]["dt10"] == 54.51


def test_auction_sentinel_fields_return_none():
    """dt27/dt33 的「无值」哨兵（0x80000000/0xFFFFFFFF）应归一化为 None，
    与真实数值 0.0 区分；dt10/dt49 不受影响。

    实测六股语料（2026-07-27）：集合竞价撮合时被动方总被吃光，dt27 在大量
    tick 上为哨兵（该方向无未匹配委托）；dt33 后期多为哨兵。
    """
    capture_dir = Path(__file__).resolve().parents[1] / "captures_live"
    # 603118 定长帧：dt27 前 ~40 条是哨兵 0x80000000（文档 19.4 实测）
    paths = sorted((capture_dir).glob("auction_raw_603118_20260727_*.bin"))
    if not paths:
        pytest.skip("本机没有 603118 的 7-27 原始竞价语料")

    records = parse_auction_response(paths[0].read_bytes())
    assert len(records) == 200

    # dt27 应至少出现一个 None（哨兵），且 None 与 float 共存
    dt27_values = [r["dt27"] for r in records]
    assert any(v is None for v in dt27_values), "dt27 应有哨兵（None）"
    assert any(isinstance(v, float) for v in dt27_values), "dt27 应有真值（float）"

    # dt33 后期全哨兵（文档 19.5：9:17 后 dt33 多为 0x80000000）
    dt33_values = [r["dt33"] for r in records]
    assert any(v is None for v in dt33_values), "dt33 应有哨兵（None）"

    # dt10/dt49 六股实测从不带哨兵，必须全是 float
    assert all(isinstance(r["dt10"], float) for r in records)
    assert all(isinstance(r["dt49"], float) for r in records)
