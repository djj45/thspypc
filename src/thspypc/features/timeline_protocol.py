"""Pure protocol operations for normal-account and Level2 intraday timelines."""
from __future__ import annotations

import logging
import struct
from datetime import datetime

from ..codecs.compression import (
    _decode_bitrle_0x13746d0,
    _transpose_bitplane_0x1763410,
    normalize_8901_response,
)
from ..codecs.framing import encode_frame
from ..codecs.hd import _parse_hd_field_table
from ..codecs.numeric import decode_ths_float


logger = logging.getLogger(__name__)

TIMELINE_PERIOD = 0x2000
TIMELINE_PAGEID = 9354
TIMELINE_L2_PAGEID = 4214

INDEX_TIMELINE_MARKETS = frozenset({16, 32, 144})
INDEX_TIMELINE_FLAGS = frozenset({0x003E, 0x0086, 0x009E})

TIMELINE_DATATYPE = [14, 13, 19, 54, 10, 23, 15, 22, 6, 45]
TIMELINE_COMPANION_DATATYPE = [
    13, 18, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35,
    122, 123, 124, 125, 150, 151, 152, 153, 154, 155, 156, 157,
]
TIMELINE_L2_DATATYPE = [
    1,
    16,
    229,
    14,
    207,
    15,
    228,
    13,
    227,
    19,
    40,
    226,
    54,
    18,
    204,
    39,
    225,
    10,
    203,
    210,
    38,
    224,
    23,
    202,
    209,
    223,
    230,
    15,
    22,
    201,
    208,
]


def is_index_timeline(code: str, market: int) -> bool:
    """Return whether a timeline request targets an index market."""
    return market in INDEX_TIMELINE_MARKETS


def enrich_index_lead_line(
    records: list[dict],
    prev_close: float | None = None,
) -> list[dict]:
    """Expose ``dt40`` as the index lead-line change and absolute price.

    Index timeline responses encode the yellow/lead line as signed basis
    points relative to the previous trading day's close.  Keep the original
    protocol field while adding stable, descriptive aliases.
    """
    for record in records:
        raw_change = record.get("dt40")
        if raw_change is None:
            continue
        change_bp = int(raw_change)
        record["lead_change_bp"] = change_bp
        record["lead_change_pct"] = change_bp / 100.0
        if prev_close is not None:
            record["prev_close"] = prev_close
            record["lead_price"] = prev_close * (
                1.0 + change_bp / 10_000.0
            )
    return records


def _decode_timeline_field(
    datatype: int,
    fmt: int,
    raw_value: int,
):
    if fmt in (0x70, 0x64):
        return decode_ths_float(raw_value)
    if datatype == 40:
        if raw_value == 0xFFFFFFFF:
            return None
        return struct.unpack("<i", struct.pack("<I", raw_value))[0]
    return raw_value


def parse_index_timeline_response(body: bytes) -> list[dict]:
    """Parse the 0x3e/0x86/0x9e index intraday BitRLE table."""
    if body.startswith(b"\x0a"):
        try:
            body = normalize_8901_response(body)
        except ValueError as exc:
            logger.debug("index timeline normalization failed: %s", exc)
            return []

    position = 0
    while True:
        marker = body.find(b"hd3.1\x00", position)
        if marker < 0:
            return []
        position = marker + 6
        base = marker + 6
        if len(body) < base + 10:
            continue

        record_count, flag, record_size, field_count = struct.unpack_from(
            "<IHHH", body, base
        )
        if (
            record_count == 0
            or flag not in INDEX_TIMELINE_FLAGS
            or record_size == 0
            or not 1 <= field_count <= 50
        ):
            continue

        fields = _parse_hd_field_table(body, base + 10, field_count)
        if (
            len(fields) != field_count
            or sum(width for _, _, width in fields) != record_size
            or not any(datatype == 10 for datatype, _, _ in fields)
            or not any(datatype == 40 for datatype, _, _ in fields)
        ):
            continue

        shell_offset = base + 10 + field_count * 4
        shell_size = 26
        bitrle_offset = shell_offset + shell_size
        if len(body) < bitrle_offset + 4:
            continue
        shell = body[shell_offset:bitrle_offset]
        if len(shell) != shell_size or shell[:4] != b"\x16\x00\x01\x00":
            continue
        code = shell[5:11].decode("ascii", errors="replace")

        expected_size = record_count * record_size
        if struct.unpack_from(">I", body, bitrle_offset)[0] != expected_size:
            continue
        bitplane = _decode_bitrle_0x13746d0(
            body[bitrle_offset:], expected_size
        )
        if len(bitplane) < expected_size:
            continue
        rows = _transpose_bitplane_0x1763410(
            bitplane, record_size, record_count
        )

        records: list[dict] = []
        for index in range(record_count):
            row = rows[index * record_size : (index + 1) * record_size]
            if len(row) != record_size:
                return []
            record: dict = {
                "code": code,
                "minute_index": index,
            }
            offset = 0
            for datatype, fmt, width in fields:
                chunk = row[offset : offset + width]
                offset += width
                if width != 4 or len(chunk) != 4:
                    record[f"dt{datatype}_raw"] = chunk
                    continue
                raw_value = struct.unpack("<I", chunk)[0]
                if datatype == 1:
                    record["bar_index"] = raw_value
                else:
                    record[f"dt{datatype}"] = _decode_timeline_field(
                        datatype,
                        fmt,
                        raw_value,
                    )
            records.append(record)
        return enrich_index_lead_line(records)


def build_timeline_query(
    code: str,
    market: int = 33,
    datatype: list[int] | None = None,
    pageid: int = TIMELINE_PAGEID,
    seq: int = 0x1122,
    companion_seq: int = 0x0125,
) -> bytes:
    """Build the two-part pageid=9354 request used by normal accounts."""
    if datatype is None:
        datatype = TIMELINE_DATATYPE
    datatype_text = ",".join(str(value) for value in datatype) + ","
    timeline_text = (
        f"CodeList={market}({code},);\r\nDataType={datatype_text}\r\n"
        f"DateTime={TIMELINE_PERIOD}(0-0)\r\n"
        f"LackTime=0,3,0,0,0,0,0,0\r\npageid={pageid}\r\n"
    ).encode("gbk")
    companion_datatype = ",".join(
        str(value) for value in TIMELINE_COMPANION_DATATYPE
    ) + ","
    companion_text = (
        f"CodeList={market}({code},);\r\n"
        f"DataType={companion_datatype}\r\n"
        "DateTime=0(0-0)\r\n"
        f"LackTime=0,0,0,0,0,0,0,0\r\npageid={pageid}\r\n"
    ).encode("gbk")

    def subframe(
        sequence: int,
        route: int,
        text: bytes,
        *,
        history_flag: bool,
    ) -> bytes:
        header = bytearray(22)
        header[0:4] = b"\x00\x16\x00\x00"
        struct.pack_into("<H", header, 4, sequence & 0xFFFF)
        header[6:10] = b"\x12\x00\x09\x00"
        struct.pack_into("<H", header, 10, route)
        if history_flag:
            header[17] = 0x20
        struct.pack_into("<I", header, 18, len(text))
        return bytes(header) + text

    body = (
        b"\x09"
        + subframe(
            seq,
            0x010A,
            timeline_text,
            history_flag=True,
        )
        + subframe(
            companion_seq,
            0x0100,
            companion_text,
            history_flag=False,
        )
    )
    return encode_frame(body)


def build_timeline_l2_query(
    code: str,
    market: int = 33,
    extra_codelist: str = "",
    datatype: list[int] | None = None,
    seq: int = 0x005B,
    pageid: int = TIMELINE_L2_PAGEID,
) -> bytes:
    """Build the Level2 timeline request.

    2026-08-05 抓包对齐：真实客户端 Level2 分时主体用 pageid=1334（走 L2 连接），
    DataType 仍含 L2 大单字段（dt223-230），响应仍为 flag=0x00B4 的 hd3.1 双码表，
    由 ``parse_timeline_l2_response`` 解析。

    Args:
        pageid: 默认 ``TIMELINE_L2_PAGEID``(4214) 保持向后兼容；真实客户端用 1334。
            两者 DataType 相同（含大单曲线），route/subtype/响应解析不变，仅 pageid 文本不同。
    """
    if datatype is None:
        datatype = TIMELINE_L2_DATATYPE
    datatype_text = ",".join(str(value) for value in datatype) + ","
    main_codelist = f"{market}({code},);"
    codelist = (
        extra_codelist + main_codelist
        if extra_codelist
        else main_codelist
    )
    text = (
        f"CodeList={codelist}\r\nDataType={datatype_text}\r\n"
        f"DateTime={TIMELINE_PERIOD}(0-0)\r\n"
        f"LackTime=0,3,0,0,20031231,2,0,0\r\n"
        f"pageid={pageid}\r\n"
    ).encode("gbk")

    header = bytearray(23)
    header[0] = 0x09
    header[1:5] = b"\x00\x16\x00\x00"
    struct.pack_into("<H", header, 5, (seq & 0xFF) | 0x1000)
    header[7:11] = b"\x12\x00\x09\x00"
    header[11:13] = b"\x02\x01"
    header[18] = 0x20
    struct.pack_into("<I", header, 19, len(text))
    return encode_frame(bytes(header) + text)


def parse_timeline_response(body: bytes) -> list[dict]:
    """Parse the normal-account ``pageid=9354`` intraday table.

    The MAIN servers return a single-instrument ``hd3.1`` BitRLE table.  The
    instrument shell uses either ``0x11`` or ``0x21`` depending on market, but
    both forms have the same 26-byte layout.
    """
    if body.startswith(b"\x0a"):
        try:
            body = normalize_8901_response(body)
        except ValueError as exc:
            logger.debug("normal timeline normalization failed: %s", exc)
            return []

    index_records = parse_index_timeline_response(body)
    if index_records:
        return index_records

    position = 0
    while True:
        marker = body.find(b"hd3.1\x00", position)
        if marker < 0:
            return []
        position = marker + 6
        base = marker + 6
        if len(body) < base + 10:
            continue

        record_count, flag, record_size, field_count = struct.unpack_from(
            "<IHHH", body, base
        )
        if (
            record_count != 241
            or flag not in (0x0042, 0x0046)
            or record_size == 0
            or not 1 <= field_count <= 50
        ):
            continue

        fields = _parse_hd_field_table(body, base + 10, field_count)
        if (
            len(fields) != field_count
            or sum(width for _, _, width in fields) != record_size
            or [field[0] for field in fields]
            != TIMELINE_DATATYPE[:8]
        ):
            continue

        shell_offset = base + 10 + field_count * 4
        shell_size = 26
        bitrle_offset = shell_offset + shell_size
        if len(body) < bitrle_offset + 4:
            continue
        shell = body[shell_offset:bitrle_offset]
        if (
            len(shell) != shell_size
            or shell[:4] != b"\x16\x00\x01\x00"
            or shell[4] not in (0x11, 0x21)
        ):
            continue
        code = shell[5:11].decode("ascii", errors="replace")

        expected_size = record_count * record_size
        if struct.unpack_from(">I", body, bitrle_offset)[0] != expected_size:
            continue
        bitplane = _decode_bitrle_0x13746d0(
            body[bitrle_offset:], expected_size
        )
        if len(bitplane) < expected_size:
            continue
        rows = _transpose_bitplane_0x1763410(
            bitplane, record_size, record_count
        )

        records: list[dict] = []
        for index in range(record_count):
            row = rows[
                index * record_size : (index + 1) * record_size
            ]
            if len(row) != record_size:
                return []
            record: dict = {"code": code, "minute_index": index}
            offset = 0
            for datatype, fmt, width in fields:
                chunk = row[offset : offset + width]
                offset += width
                if width != 4 or len(chunk) != 4:
                    record[f"dt{datatype}_raw"] = chunk
                    continue
                raw_value = struct.unpack("<I", chunk)[0]
                if datatype == 1:
                    try:
                        record["time"] = datetime.fromtimestamp(raw_value)
                    except (OSError, ValueError, OverflowError):
                        record["bar_index"] = raw_value
                elif fmt in (0x70, 0x64):
                    record[f"dt{datatype}"] = decode_ths_float(raw_value)
                else:
                    record[f"dt{datatype}_raw"] = chunk
            records.append(record)
        return records


def parse_timeline_l2_response(body: bytes) -> list[dict]:
    """Parse the dual-instrument hd3.1 response used by Level2 timelines."""
    if body.startswith(b"\x0a"):
        try:
            body = normalize_8901_response(body)
        except ValueError as exc:
            logger.debug("Level2 timeline normalization failed: %s", exc)
            return []

    index_records = parse_index_timeline_response(body)
    if index_records:
        return index_records

    pos = body.find(b"hd3.1\x00")
    if pos < 0:
        return []
    base = pos + 6
    if len(body) < base + 10:
        return []

    record_count = struct.unpack("<I", body[base : base + 4])[0]
    flag = struct.unpack("<H", body[base + 4 : base + 6])[0]
    record_size = struct.unpack("<H", body[base + 6 : base + 8])[0]
    field_count = struct.unpack("<H", body[base + 8 : base + 10])[0]
    if (
        record_count == 0
        or record_size == 0
        or field_count == 0
        or field_count > 50
        or flag != 0x00B4
    ):
        return []

    fields = _parse_hd_field_table(body, base + 10, field_count)
    shell_offset = base + 10 + field_count * 4
    if len(body) < shell_offset + 44:
        return []
    shell = body[shell_offset : shell_offset + 44]

    stock_code = ""
    for offset in range(22, 30):
        if shell[offset] in (0x11, 0x21):
            stock_code = (
                shell[offset + 1 : offset + 7]
                .split(b"\x00")[0]
                .decode("ascii", errors="replace")
            )
            break

    bitrle_offset = shell_offset + 44
    if len(body) < bitrle_offset + 4:
        return []
    expected_size = record_count * record_size
    bitrle_size = struct.unpack(
        ">I", body[bitrle_offset : bitrle_offset + 4]
    )[0]
    if bitrle_size != expected_size:
        logger.debug(
            "timeline_l2 BitRLE size mismatch: got=0x%x expect=0x%x",
            bitrle_size,
            expected_size,
        )
        return []

    bitplane = _decode_bitrle_0x13746d0(
        body[bitrle_offset:], expected_size
    )
    if len(bitplane) < expected_size:
        return []
    raw_records = _transpose_bitplane_0x1763410(
        bitplane, record_size, record_count
    )

    field_offsets: dict[int, tuple[int, int]] = {}
    offset = 0
    for datatype, _fmt, width in fields:
        field_offsets[datatype] = (offset, width)
        offset += width
    field_formats = {datatype: fmt for datatype, fmt, _ in fields}

    records: list[dict] = []
    for index in range(record_count // 2, record_count):
        row = raw_records[
            index * record_size : (index + 1) * record_size
        ]
        if len(row) < record_size:
            break
        record: dict = {"code": stock_code}
        for datatype, (value_offset, width) in field_offsets.items():
            chunk = row[value_offset : value_offset + width]
            if width != 4 or len(chunk) != 4:
                continue
            raw_value = struct.unpack("<I", chunk)[0]
            if datatype == 1:
                record["bar_index"] = raw_value
            else:
                record[f"dt{datatype}"] = _decode_timeline_field(
                    datatype,
                    field_formats.get(datatype, 0),
                    raw_value,
                )
        records.append(record)
    return records
