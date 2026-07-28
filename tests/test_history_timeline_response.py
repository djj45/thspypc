import os
import hashlib
import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from thspypc.protocol import (
    build_history_timeline_query,
    date_to_timeline_bar,
    parse_history_timeline_response,
    timeline_bar_to_date,
)
import thspypc.protocol as protocol
from thspypc.features import history_timeline_protocol


FRAME_MAGIC = b"\xfd\xfd\xfd\xfd"
BAR_OFFSETS = (
    list(range(0, 30))
    + list(range(34, 94))
    + list(range(98, 129))
    + list(range(227, 286))
    + list(range(290, 350))
    + [354]
)
STOCK_FIELDS = [
    1, 10, 13, 19, 22, 23, 54,
    201, 202, 203, 204, 207, 208, 209, 210,
    223, 224, 225, 226, 227, 228, 229, 230,
]


def _stock_history_frame(skip_offset: int | None = None) -> bytes:
    bar_start = 132_477_534
    table = bytearray()
    for dt in STOCK_FIELDS:
        table += bytes((dt, 0x30 if dt == 1 else 0x70, 0, 4))

    shell = b"\x16\x00\x01\x00\x21" + b"000938" + b"\x00" * 96
    rows = bytearray()
    for index, bar_offset in enumerate(BAR_OFFSETS):
        if bar_offset == skip_offset:
            continue
        raw = [bar_start + bar_offset, 0xC0052B70, 0x0053D748, 0x111C0D99]
        raw.extend([0] * (len(STOCK_FIELDS) - len(raw)))
        rows += b"".join(struct.pack("<I", value) for value in raw)
        # Reproduce the observed 89-92 byte physical rows.
        rows += b"\xa5" * (index % 4)

    header = (
        b"hd1.0\x00"
        + struct.pack("<IHHH", 0x040000F2, 0x0082, 92, 23)
    )
    return b"\x09plain-prefix" + header + bytes(table) + shell + bytes(rows)


def _split_frames(stream: bytes) -> list[bytes]:
    return [part[8:] for part in stream.split(FRAME_MAGIC) if len(part) >= 8]


def test_stock_history_uses_bar_anchors_instead_of_fixed_physical_rows():
    records = parse_history_timeline_response(
        _stock_history_frame(skip_offset=349),
        code="000938",
    )

    assert len(records) == 240
    assert records[0]["bar_index"] == 132_477_534
    assert records[-1]["bar_index"] == 132_477_888
    assert records[0]["dt10"] == 33.88
    assert records[0]["dt13"] == 5_494_600
    assert records[0]["dt19"] == 186_157_050
    assert set(records[0]) == {
        "bar_index", "dt10", "dt13", "dt19", "dt22", "dt23",
    }


def test_history_timeline_date_encoding_matches_thsdk_business_date():
    assert date_to_timeline_bar("2026-05-13") == 132_475_486
    assert date_to_timeline_bar("2026-05-14") == 132_477_534
    assert timeline_bar_to_date(132_477_534).date().isoformat() == "2026-05-14"


def test_protocol_reexports_history_timeline_implementations():
    assert (
        protocol.build_history_timeline_query
        is history_timeline_protocol.build_history_timeline_query
    )
    assert (
        protocol.parse_history_timeline_response
        is history_timeline_protocol.parse_history_timeline_response
    )
    assert (
        protocol.date_to_timeline_bar
        is history_timeline_protocol.date_to_timeline_bar
    )


def test_stock_history_query_matches_captured_three_part_request():
    frame = build_history_timeline_query(
        "000938",
        bar_start=132_477_534,
        market=33,
        seq=0x11DC,
    )
    body = frame[12:]

    assert len(body) == 373
    assert hashlib.sha256(body).hexdigest() == (
        "0dd56837d0fb2e8bc36ba50e2a93fd55"
        "be090fc9233153051fe4688c10784a25"
    )
    assert b"CodeList=32(399002,);33(000938,);" in body
    assert body.count(b"pageid=4417") == 3


def test_stock_history_query_groups_same_market_companion_codes():
    frame = build_history_timeline_query(
        "000938",
        date="2026-05-14",
        market=33,
        benchmark_market=33,
        benchmark_code="000001",
    )
    body = frame[12:]

    assert b"CodeList=33(000001,000938,);" in body
    assert b"CodeList=33(000001,);33(000938,);" not in body
    assert b"DateTime=8192(132477534-132477889)" in body


def test_stock_history_selects_requested_code():
    body = _stock_history_frame()

    assert len(parse_history_timeline_response(body, code="000938")) == 241
    assert parse_history_timeline_response(body, code="600519") == []


def test_captured_stock_history_matches_thsdk_core_oracle():
    capture = (
        Path(__file__).resolve().parents[1]
        / "captures_live"
        / "timeline_20260724_092405_resp_stream1.bin"
    )
    if not capture.exists():
        pytest.skip("本机没有历史分时重组响应语料")

    frames = _split_frames(capture.read_bytes())

    may13 = parse_history_timeline_response(frames[2], code="000938")
    assert len(may13) == 240
    assert (may13[0]["dt10"], may13[0]["dt13"], may13[0]["dt19"]) == (
        30.60, 1_115_400, 34_131_240,
    )
    assert (may13[-1]["dt10"], may13[-1]["dt13"], may13[-1]["dt19"]) == (
        32.91, 237_260_140, 7_568_339_900,
    )

    may14 = parse_history_timeline_response(frames[12], code="000938")
    assert len(may14) == 241
    assert (may14[0]["dt10"], may14[0]["dt13"], may14[0]["dt19"]) == (
        33.88, 5_494_600, 186_157_050,
    )
    assert (may14[-1]["dt10"], may14[-1]["dt13"], may14[-1]["dt19"]) == (
        32.14, 233_491_610, 7_610_279_300,
    )


def test_strong_state_omission_variant_is_rejected_not_misparsed():
    capture = (
        Path(__file__).resolve().parents[1]
        / "captures_live"
        / "timeline_20260724_091133_resp_stream2.bin"
    )
    if not capture.exists():
        pytest.skip("本机没有历史分时强状态省略语料")

    frames = _split_frames(capture.read_bytes())

    assert parse_history_timeline_response(frames[10], code="000938") == []


def test_companion_replacement_capture_identifies_000001():
    capture = (
        Path(__file__).resolve().parents[1]
        / "captures_live"
        / "history_companion_000001_000938_20260514_20260728_174530.bin"
    )
    if not capture.exists():
        pytest.skip("本机没有 000001 伴随代码替换实发语料")

    records = parse_history_timeline_response(
        capture.read_bytes(),
        code="000001",
    )

    # 这是强状态省略变体，只对可安全锚定的 225 点作断言。
    assert len(records) == 225
    assert records[0] == {
        "bar_index": 132_477_534,
        "dt10": 11.14,
        "dt13": 381_200,
        "dt19": 4_246_568,
        "dt22": 6_402_300,
        "dt23": 12_620_888,
    }
