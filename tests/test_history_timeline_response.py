import os
import hashlib
import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from thspypc.protocol import (
    build_history_timeline_query,
    build_normal_history_timeline_query,
    date_to_normal_timeline_bar,
    date_to_timeline_bar,
    normal_timeline_bar_to_date,
    parse_history_timeline_response,
    timeline_bar_to_date,
)
import thspypc.protocol as protocol
from thspypc.features import history_timeline_protocol
from thspypc.features.history_timeline_protocol import (
    history_timeline_request_codes,
)
from thspypc.codecs.compression import normalize_8901_response


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
        "bar_index", "dt10", "dt13", "dt19", "dt22", "dt23", "dt54",
        "dt201", "dt202", "dt203", "dt204",
        "dt207", "dt208", "dt209", "dt210",
        "dt223", "dt224", "dt225", "dt226", "dt227", "dt228", "dt229",
        "dt230",
    }


def test_history_timeline_date_encoding_matches_thsdk_business_date():
    assert date_to_timeline_bar("2026-05-13") == 132_475_486
    assert date_to_timeline_bar("2026-05-14") == 132_477_534
    assert timeline_bar_to_date(132_477_534).date().isoformat() == "2026-05-14"


def test_normal_history_date_encoding_matches_captured_cursor():
    assert date_to_normal_timeline_bar("2026-05-15") == 132_479_582
    assert date_to_normal_timeline_bar("2026-04-22") == 132_428_382
    assert normal_timeline_bar_to_date(
        132_479_582
    ).date().isoformat() == "2026-05-15"


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


def test_sh_stock_history_query_matches_captured_market_routes():
    # 抓包实测值 132629086 = packed-date(2026-07-24)。
    # 旧标签“07-27”是导航当天，实际请求的是按 ← 后的上一交易日 07-24。
    frame = build_history_timeline_query(
        "603118",
        date="2026-07-24",
        market=17,
        benchmark_market=16,
        benchmark_code="1A0002",
        seq=0x10EC,
    )
    body = frame[12:]

    assert len(body) == 373
    assert hashlib.sha256(body).hexdigest() == (
        "aeffeb5063ff9e583b67f20f3b6624b3"
        "395e048184bda1be69afb019d824898a"
    )
    assert body[11:13] == b"\x7c\x00"
    assert b"\x7c\x01" in body
    assert b"\x7c\x02" in body
    assert b"DateTime=8192(132629086-132629441)" in body


def test_normal_history_query_matches_captured_two_part_request():
    frame = build_normal_history_timeline_query(
        "603118",
        date="2026-05-15",
        market=17,
    )

    assert len(frame) == 283
    assert hashlib.sha256(frame).hexdigest() == (
        "df3e66be63fe07726ac1e9bf04fcb07e"
        "d6113e6ac27194b2c8830c092adb2646"
    )
    assert b"DateTime=8192(132479582-132479937)" in frame
    assert frame.count(b"pageid=9355") == 2


def test_normal_history_response_uses_basic_seven_fields():
    fields = [1, 10, 13, 19, 22, 23, 54]
    table = b"".join(
        bytes((datatype, 0x30 if datatype == 1 else 0x70, 0, 4))
        for datatype in fields
    )
    shell = b"\x16\x00\x01\x00\x11" + b"603118" + b"\x00" * 15
    bar_start = date_to_normal_timeline_bar("2026-05-15")
    rows = bytearray()
    for offset in BAR_OFFSETS:
        raw = [bar_start + offset, 0xC0052B70, 0, 0, 0, 0, 0]
        rows += struct.pack("<7I", *raw)
    body = (
        b"hd1.0\x00"
        + struct.pack("<IHHH", 0x040000F2, 0x0042, 28, 7)
        + table
        + shell
        + rows
    )

    records = parse_history_timeline_response(body, code="603118")

    assert len(records) == 241
    assert records[0]["bar_index"] == bar_start
    assert records[0]["dt10"] == 33.88
    assert set(records[0]) == {
        "bar_index", "dt10", "dt13", "dt19", "dt22", "dt23", "dt54"
    }


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


def test_history_request_codes_preserve_mixed_table_order():
    codes, benchmark_market, benchmark_code = (
        history_timeline_request_codes("000938", market=33)
    )

    assert codes == ("399002", "000938")
    assert benchmark_market == 32
    assert benchmark_code == "399002"


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
    assert len(may13) == 241
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


def _history_date_dump_cases():
    """扫描 captures_live 下 history_<code>_<yyyymmdd>_*.bin 样本。"""
    captures = (
        Path(__file__).resolve().parents[1]
        / "captures_live"
    )
    if not captures.is_dir():
        return []
    cases = []
    for path in sorted(captures.glob("history_*_20??????_*.bin")):
        name = path.stem  # history_000938_20260630_20260801_...
        parts = name.split("_")
        if len(parts) < 3:
            continue
        code = parts[1]
        date_part = parts[2]
        if not (code.isdigit() and len(code) == 6 and date_part.isdigit()):
            continue
        cases.append((code, date_part, path))
    return cases


@pytest.mark.parametrize(
    "code,date_part,path",
    _history_date_dump_cases(),
    ids=[f"{c}-{d}" for c, d, _ in _history_date_dump_cases()],
)
def test_captured_history_dump_dates_four_day_regression(code, date_part, path):
    """四日期离线回归：新抓的 06-30/07-23 样本放入 captures_live 即自动生效。"""
    if not path.exists():
        pytest.skip("本机缺少该历史分时抓包样本")

    data = path.read_bytes()
    if data.startswith(b"\x0a"):
        frames = [data]  # 裸压缩帧（单帧样本文件）
    else:
        frames = _split_frames(data)
    records = None
    for frame in frames:
        try:
            candidate = parse_history_timeline_response(frame, code=code)
        except Exception:
            continue
        if len(candidate) == 241:
            records = candidate
            break

    assert records is not None, f"{path.name}: 未从样本解出 241 点"
    assert records[0]["dt10"] is not None
    assert records[0]["dt13"] is not None
    assert records[0]["dt19"] is not None
    assert "dt54" in records[0]
    assert records[0]["bar_index"] is not None


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
    assert len(records) == 241
    assert records[0] == {
        "bar_index": 132_477_534,
        "dt10": 11.14,
        "dt13": 381_200,
        "dt19": 4_246_568,
        "dt22": 6_402_300,
        "dt23": 12_620_888,
        "dt54": 0.0,
        "dt201": 0.0,
        "dt202": 0.0,
        "dt203": 109_700.0,
        "dt204": 65_200.0,
        "dt207": 0.0,
        "dt208": 0.0,
        "dt209": 0.0,
        "dt210": 31_000.0,
        "dt223": 0.0,
        "dt224": 0.0,
        "dt225": 1_222_058.0,
        "dt226": 726_328.0,
        "dt227": 0.0,
        "dt228": 0.0,
        "dt229": 0.0,
        "dt230": 345_340.0,
    }


def test_companion_response_binds_unlabelled_target_table_by_request_order():
    capture = (
        Path(__file__).resolve().parents[1]
        / "captures_live"
        / "history_companion_000001_000938_20260514_20260728_174530.bin"
    )
    if not capture.exists():
        pytest.skip("本机没有 000001 伴随代码替换实发语料")

    records = parse_history_timeline_response(
        capture.read_bytes(),
        code="000938",
        requested_codes=("000001", "000938"),
    )

    assert len(records) == 241
    assert (
        records[0]["dt10"],
        records[0]["dt13"],
        records[0]["dt19"],
    ) == (33.88, 5_494_600, 186_157_050)
    assert (
        records[-1]["dt10"],
        records[-1]["dt13"],
        records[-1]["dt19"],
    ) == (32.14, 233_491_610, 7_610_279_300)


def test_companion_capture_normalizes_to_native_oracle_bytes():
    """Pinned against hexin.exe's own outer normalizer (DMP emulation).

    The Python port historically copied ``count - 1`` bytes per long match;
    the native loop copies ``count`` bytes.  That off-by-one lost bytes from
    record streams containing long matches, which misaligned the 0x0082 rows
    and was previously misdiagnosed as a "strong-state omission codec".
    """
    capture = (
        Path(__file__).resolve().parents[1]
        / "captures_live"
        / "history_companion_000001_000938_20260514_20260728_174530.bin"
    )
    if not capture.exists():
        pytest.skip("missing 000001 companion replacement capture")

    normalized = normalize_8901_response(capture.read_bytes())

    assert len(normalized) == 45_201
    assert hashlib.sha256(normalized).hexdigest() == (
        "7847044c900d52704465ec9dffc4f0d5"
        "8c12d1729d35b93e4b47e6c38a2c1c76"
    )
    offsets = [
        index
        for index in range(len(normalized))
        if normalized[index : index + 6] == b"hd1.0\x00"
    ]
    assert offsets == [0x8D, 0x5821, 0xAFB5, 0xB025]
