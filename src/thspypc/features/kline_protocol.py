"""Pure request builder and response parser for K-line data."""
from __future__ import annotations

import datetime
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

KLINE_PERIOD_DAY = 0x4000
KLINE_PERIOD_WEEK = 0x5001
KLINE_PERIOD_MONTH = 0x6001
KLINE_PERIOD_QUARTER = 0x6003
KLINE_PERIOD_YEAR = 0x7001
KLINE_PERIOD_1MIN = 0x3000
KLINE_PERIOD_5MIN = 0x3005
KLINE_PERIOD_15MIN = 0x300F
KLINE_PERIOD_30MIN = 0x301E
KLINE_PERIOD_60MIN = 0x303C

KLINE_DATATYPE = [7, 8, 9, 11, 13, 19]

KLINE_DT_OPEN = 7
KLINE_DT_HIGH = 8
KLINE_DT_LOW = 9
KLINE_DT_CLOSE = 11
KLINE_DT_VOL = 13
KLINE_DT_AMT = 19


def build_kline_query(
    code: str,
    market: int = 33,
    period: int = KLINE_PERIOD_DAY,
    fuquan: str = "Q",
    count: int = 2146,
    anchor: int = 0,
    pageid: int = 9355,
    seq: int = 0x0025,
    route: int | None = None,
) -> bytes:
    """Build an 8901 K-line request frame.

    ``DateTime={period}(-{count}-{anchor})`` 语义（2026-08-03 抓包确认）：
    取 ``count`` 根、以 ``anchor`` 为终点，服务端返回 ``count+1`` 根（含终点，
    受上市日截断）。``anchor=0``=最新一根；日/周/月/季/年K 传 YYYYMMDD 日期；
    分钟K 传 bar_index。翻页时把 anchor 设为上一窗口最早一根即可继续回溯。

    Args:
        pageid: 普通账号走 9355（MAIN）；Level2 账号真实客户端走 1334（L2 连接），
            见 ``build_kline_l2_query``。
        route: 子帧路由。None=按 period 自动选（周月季年以上=0x014E，否则=0x0001），
            适合普通账号 9355；Level2 账号 1334 抓包用 0x0100。
    """
    datatype = ",".join(str(value) for value in KLINE_DATATYPE) + ","
    text = (
        f"ReqFuquan={fuquan}\r\nCodeList={market}({code},);\r\n"
        f"DataType={datatype}\r\nDateTime={period}(-{count}-{anchor})\r\n"
        f"LackTime=0,0,0,0,0,0,0,0\r\npageid={pageid}\r"
    ).encode("gbk")

    header = bytearray(23)
    header[0] = 0x09
    header[1:5] = b"\x00\x16\x00\x00"
    struct.pack_into("<H", header, 5, seq & 0xFFFF)
    header[7:11] = b"\x12\x00\x09\x00"
    if route is None:
        route = 0x014E if period >= 0x5000 else 0x0001
    struct.pack_into("<H", header, 11, route)
    header[17] = (
        0x01 if period >= 0x5000 else (0x05 if period < 0x4000 else 0x00)
    )
    header[18] = (period >> 8) & 0xFF
    struct.pack_into("<H", header, 19, len(text) + 1)
    return encode_frame(bytes(header) + text)


def build_kline_l2_query(
    code: str,
    market: int = 33,
    period: int = KLINE_PERIOD_DAY,
    fuquan: str = "Q",
    count: int = 2146,
    anchor: int = 0,
    seq: int = 0x0025,
) -> bytes:
    """Build the pageid=1334 K-line request used by Level2 accounts.

    2026-08-05 抓包（``kanpan_20260805_001523.pcap``）确认 Level2 账号的日K
    请求用 pageid=1334、route=0x0100，走 L2 连接（shlv2/szlv2），DataType 仍为
    基础 OHLCV（7,8,9,11,13,19），不含 L2 增强字段。响应仍是 hd3.1（flag
    0x0042/0x0046），由 ``parse_kline_hd3_response`` 解析（与普通账号同解析器）。

    普通账号仍用 ``build_kline_query``（pageid=9355, MAIN）。
    """
    return build_kline_query(
        code,
        market=market,
        period=period,
        fuquan=fuquan,
        count=count,
        anchor=anchor,
        pageid=1334,
        seq=seq,
        route=0x0100,
    )


def _kline_decode_time(tv: int) -> datetime.datetime:
    """Decode a packed YYYYMMDD value or a Unix timestamp."""
    if tv < 100_000_000:
        year, month_day = divmod(tv, 10000)
        month, day = divmod(month_day, 100)
        try:
            return datetime.datetime(year, month or 1, day or 1)
        except ValueError:
            return datetime.datetime.min
    try:
        return datetime.datetime.fromtimestamp(tv)
    except (OSError, ValueError, OverflowError):
        return datetime.datetime.min


def _kline_dt1_is_bar_index(tv: int) -> bool:
    """Return whether dt1 is an intraday bar index instead of a time value."""
    if tv < 100_000_000:
        return False
    try:
        decoded = datetime.datetime.fromtimestamp(tv)
    except (OSError, ValueError, OverflowError):
        return True
    return decoded.year < 1990


def parse_kline_hd3_response(body: bytes) -> list[dict]:
    """Parse the hd3.1 variant used by K-line responses."""
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
    ):
        return []
    if flag not in (0x0042, 0x0046):
        logger.debug("kline hd3.1 non-kline flag=0x%x", flag)
        return []

    fields = _parse_hd_field_table(body, base + 10, field_count)
    shell_offset = base + 10 + field_count * 4
    if len(body) < shell_offset + 26:
        return []
    shell = body[shell_offset : shell_offset + 26]
    code = (
        shell[5:11].decode("ascii", errors="replace")
        if shell[4] == 0x21
        else ""
    )

    bitrle_offset = shell_offset + 26
    if len(body) < bitrle_offset + 4:
        return []
    expected_size = record_count * record_size
    bitrle_size = struct.unpack(
        ">I", body[bitrle_offset : bitrle_offset + 4]
    )[0]
    if bitrle_size != expected_size:
        logger.debug(
            "kline hd3.1 BitRLE size mismatch: got=0x%x expect=0x%x "
            "(record_count*record_size=%d, flag=0x%x)",
            bitrle_size,
            expected_size,
            expected_size,
            flag,
        )
        return []

    bitplane = _decode_bitrle_0x13746d0(
        body[bitrle_offset:], expected_size
    )
    if len(bitplane) < expected_size:
        logger.debug(
            "kline hd3.1 BitRLE output too short: got=%d expect=%d",
            len(bitplane),
            expected_size,
        )
        return []
    raw_records = _transpose_bitplane_0x1763410(
        bitplane, record_size, record_count
    )

    field_offsets: dict[int, tuple[int, int]] = {}
    offset = 0
    for datatype, _fmt, width in fields:
        field_offsets[datatype] = (offset, width)
        offset += width

    time_is_bar_index = False
    if 1 in field_offsets and record_count > 0:
        time_offset, _ = field_offsets[1]
        first_row = raw_records[:record_size]
        first_time = first_row[time_offset : time_offset + 4]
        tv = struct.unpack("<I", first_time)[0] if len(first_time) == 4 else 0
        time_is_bar_index = _kline_dt1_is_bar_index(tv)

    field_formats = {datatype: fmt for datatype, fmt, _ in fields}
    records: list[dict] = []
    standard_fields = (
        ("open", KLINE_DT_OPEN),
        ("high", KLINE_DT_HIGH),
        ("low", KLINE_DT_LOW),
        ("close", KLINE_DT_CLOSE),
        ("volume", KLINE_DT_VOL),
        ("amount", KLINE_DT_AMT),
    )
    standard_datatypes = {
        1,
        KLINE_DT_OPEN,
        KLINE_DT_HIGH,
        KLINE_DT_LOW,
        KLINE_DT_CLOSE,
        KLINE_DT_VOL,
        KLINE_DT_AMT,
    }

    for index in range(record_count):
        row = raw_records[
            index * record_size : (index + 1) * record_size
        ]
        if len(row) < record_size:
            break
        record: dict = {"code": code}

        if 1 in field_offsets:
            time_offset, _ = field_offsets[1]
            raw_time = row[time_offset : time_offset + 4]
            tv = struct.unpack("<I", raw_time)[0] if len(raw_time) == 4 else 0
            if time_is_bar_index:
                record["time"] = None
                record["bar_index"] = tv
            else:
                record["time"] = _kline_decode_time(tv)

        for name, datatype in standard_fields:
            if datatype not in field_offsets:
                continue
            value_offset, width = field_offsets[datatype]
            chunk = row[value_offset : value_offset + width]
            if len(chunk) >= 4:
                value = struct.unpack("<I", chunk[:4])[0]
                record[name] = decode_ths_float(value)

        for datatype, (value_offset, width) in field_offsets.items():
            if datatype in standard_datatypes:
                continue
            chunk = row[value_offset : value_offset + width]
            if width != 4 or len(chunk) != 4:
                continue
            if field_formats.get(datatype) in (0x70, 0x64):
                value = struct.unpack("<I", chunk)[0]
                record[f"dt{datatype}"] = decode_ths_float(value)
            else:
                record[f"dt{datatype}_raw"] = chunk

        records.append(record)
    return records
