"""Pure protocol operations for normal-account and Level2 intraday timelines."""
from __future__ import annotations

import logging
import struct

from ..codecs.compression import (
    _decode_bitrle_0x13746d0,
    _transpose_bitplane_0x1763410,
)
from ..codecs.framing import encode_frame
from ..codecs.hd import _parse_hd_field_table
from ..codecs.numeric import decode_ths_float


logger = logging.getLogger(__name__)

TIMELINE_PERIOD = 0x2000
TIMELINE_PAGEID = 9354
TIMELINE_L2_PAGEID = 4214

TIMELINE_DATATYPE = [10, 13, 14, 15, 19, 22, 23, 54, 6, 45]
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


def build_timeline_query(
    code: str,
    market: int = 33,
    datatype: list[int] | None = None,
    pageid: int = TIMELINE_PAGEID,
    seq: int = 0x0025,
) -> bytes:
    """Build the pageid=9354 timeline request used by normal accounts."""
    if datatype is None:
        datatype = TIMELINE_DATATYPE
    datatype_text = ",".join(str(value) for value in datatype) + ","
    text = (
        f"CodeList={market}({code},);\r\nDataType={datatype_text}\r\n"
        f"DateTime={TIMELINE_PERIOD}(0-0)\r\n"
        f"LackTime=0,0,0,0,0,0,0,0\r\npageid={pageid}\r"
    ).encode("gbk")

    header = bytearray(23)
    header[0] = 0x09
    header[1:5] = b"\x00\x16\x00\x00"
    struct.pack_into("<H", header, 5, seq & 0xFFFF)
    header[7:11] = b"\x12\x00\x02\x00"
    struct.pack_into("<H", header, 11, 0x000A)
    struct.pack_into("<H", header, 19, len(text) + 1)
    return encode_frame(bytes(header) + text)


def build_timeline_l2_query(
    code: str,
    market: int = 33,
    extra_codelist: str = "",
    datatype: list[int] | None = None,
    seq: int = 0x005B,
) -> bytes:
    """Build the pageid=4214 timeline request used by Level2 accounts."""
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
        f"pageid={TIMELINE_L2_PAGEID}\r\n"
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


def parse_timeline_l2_response(body: bytes) -> list[dict]:
    """Parse the dual-instrument hd3.1 response used by Level2 timelines."""
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
            elif field_formats.get(datatype) in (0x70, 0x64):
                record[f"dt{datatype}"] = decode_ths_float(raw_value)
            else:
                record[f"dt{datatype}"] = raw_value
        records.append(record)
    return records
