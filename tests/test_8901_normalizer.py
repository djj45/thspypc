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

    dt27=买方未匹配量、dt33=卖方未匹配量。集合竞价撮合时被动方总被吃光，
    故每条 tick 恰好一侧为哨兵（None）；dt10/dt49 六股实测从不带哨兵。
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

    # dt33 同理（卖方未匹配量，也会出现哨兵）
    dt33_values = [r["dt33"] for r in records]
    assert any(v is None for v in dt33_values), "dt33 应有哨兵（None）"

    # dt10/dt49 六股实测从不带哨兵，必须全是 float
    assert all(isinstance(r["dt10"], float) for r in records)
    assert all(isinstance(r["dt49"], float) for r in records)


def test_auction_dt27_dt33_match_thsdk_buy2_sell2():
    """dt27≡thsdk buy2（买方未匹配），dt33≡thsdk sell2（卖方未匹配）。

    六股 × thsdk oracle 全量对照（2026-07-27）：约 99.5% 精确匹配，少量偏差
    是两通道 ±1~2 秒时间戳错位。本测试用 ±2 秒窗口对照，验证绝大多数 tick
    上 dt27=buy2、dt33=sell2 同时成立。
    """
    import bisect
    import json

    capture_dir = Path(__file__).resolve().parents[1] / "captures_live"
    code = "603118"
    raw_paths = sorted((capture_dir).glob(f"auction_raw_{code}_20260727_*.bin"))
    oracle_paths = sorted((capture_dir).glob(f"_thsdk_auction_USHA{code}_*.json"))
    if not raw_paths or not oracle_paths:
        pytest.skip("本机没有 603118 的 7-27 raw + thsdk oracle 语料")

    oracle = {}
    for row in json.loads(oracle_paths[-1].read_text(encoding="utf-8"))["data"]:
        values = list(row.values())
        oracle[int(values[0])] = (int(values[2]), int(values[3]))  # buy2, sell2
    oracle_ts = sorted(oracle)
    sentinel = 0x80000000

    records = parse_auction_response(raw_paths[0].read_bytes())
    matched = compared = 0
    for rec in records:
        t = rec.get("time")
        if t is None:
            continue
        ts = int(t.timestamp())
        idx = bisect.bisect_left(oracle_ts, ts)
        candidates = oracle_ts[max(0, idx - 1):idx + 2]
        if not candidates:
            continue
        nearest = min(candidates, key=lambda x: abs(x - ts))
        if abs(nearest - ts) > 2:
            continue
        buy2, sell2 = oracle[nearest]
        buy2 = 0 if buy2 == sentinel else buy2
        sell2 = 0 if sell2 == sentinel else sell2
        d27 = rec["dt27"] or 0
        d33 = rec["dt33"] or 0
        compared += 1
        if abs(d27 - buy2) < 1 and abs(d33 - sell2) < 1:
            matched += 1

    # 允许少量 ±1~2 秒错位；六股实测最差 603118 也 > 95% 匹配
    assert compared > 100, "对照样本不足"
    assert matched / compared > 0.95, f"dt27/dt33 与 buy2/sell2 匹配率过低: {matched}/{compared}"
