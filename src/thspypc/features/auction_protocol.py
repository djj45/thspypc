"""Pure request builder and shared field rules for call auctions."""
from __future__ import annotations

import json
import logging
import struct
from datetime import date as date_type
from datetime import datetime, time, timedelta

from ..codecs.compression import normalize_8901_response
from ..codecs.compression import (
    _decode_bitrle_0x13746d0,
    _transpose_bitplane_0x1763410,
)
from ..codecs.framing import encode_frame
from ..codecs.hd import _parse_hd_field_table
from ..codecs.numeric import decode_ths_float
from .timeline_protocol import TIMELINE_L2_PAGEID


logger = logging.getLogger(__name__)

AUCTION_PERIOD = 7176
AUCTION_DATATYPE = [10, 27, 33, 49]
BASIC_AUCTION_PAGEID = 9354
BASIC_HISTORY_AUCTION_PAGEID = 9355
BASIC_HISTORY_AUCTION_PERIOD = 6144
CLOSING_AUCTION_PERIOD = 7424
CLOSING_AUCTION_DATATYPE = [10, 49, 287]
L2_HISTORY_AUCTION_PAGEID = 4417
INDEX_AUCTION_PAGEID = 6240
INDEX_CLOSING_AUCTION_CODES = frozenset({"1A0001", "399001", "399006"})

_AUCTION_SENTINELS = frozenset({0x80000000, 0xFFFFFFFF})
_AUCTION_SENTINEL_FIELDS = frozenset({27, 33})


def _index_auction_path(code: str, market: int, closing: bool) -> str:
    if market == 16:
        directory, prefix = "USH", "USHI"
    elif market == 32:
        directory, prefix = "USZ", "USZI"
    else:
        raise ValueError(f"指数竞价暂不支持市场码: {market}")
    if closing and code not in INDEX_CLOSING_AUCTION_CODES:
        raise ValueError(
            "指数尾盘竞价仅支持 1A0001、399001、399006"
        )
    close_prefix = "CLOSE_" if closing else ""
    return (
        f"/quote/auction/{directory}/{prefix}_{close_prefix}{code}.dat"
    )


def _index_auction_subframe(
    text: bytes,
    *,
    seq: int,
    subtype: int,
    route: int,
    declared_length_delta: int = 0,
) -> bytes:
    header = bytearray(22)
    header[0:4] = b"\x00\x16\x00\x00"
    struct.pack_into("<H", header, 4, seq & 0xFFFF)
    struct.pack_into("<H", header, 6, 0x0012)
    struct.pack_into("<H", header, 8, subtype)
    struct.pack_into("<H", header, 10, route)
    struct.pack_into(
        "<I",
        header,
        18,
        len(text) + declared_length_delta,
    )
    return bytes(header) + text


def build_index_auction_context_query(
    code: str,
    market: int = 16,
    *,
    seq: int = 0x0176,
    pageid: int = INDEX_AUCTION_PAGEID,
) -> bytes:
    """Build the PC client's combined CodeList + opening URL context."""
    path = _index_auction_path(code, market, False)
    selection_route = 0x0007 if market == 16 else 0x0067
    selection_text = (
        f"CodeList={market}({code},);\r\npageid={pageid}\r\n"
    ).encode("gbk")
    opening_text = (
        f"T_URL={path}\r\npageid={pageid}\r"
    ).encode("gbk")
    body = (
        b"\x09"
        + _index_auction_subframe(
            selection_text,
            seq=0,
            subtype=0x0002,
            route=selection_route,
        )
        + _index_auction_subframe(
            opening_text,
            seq=seq,
            subtype=0x0017,
            route=0x0100,
            declared_length_delta=1,
        )
    )
    return encode_frame(body)


def build_index_auction_query(
    code: str,
    market: int = 16,
    *,
    closing: bool = False,
    seq: int = 0x005A,
    pageid: int = INDEX_AUCTION_PAGEID,
) -> bytes:
    """Build the index auction ``T_URL`` request captured on port 8901."""
    path = _index_auction_path(code, market, closing)
    text = (
        f"T_URL={path}\r\n"
        f"pageid={pageid}\r"
    ).encode("gbk")

    header = bytearray(23)
    header[0] = 0x09
    header[1:5] = b"\x00\x16\x00\x00"
    struct.pack_into("<H", header, 5, seq & 0xFFFF)
    header[7:11] = b"\x12\x00\x17\x00"
    struct.pack_into("<H", header, 11, 0x0100)
    struct.pack_into("<I", header, 19, len(text) + 1)
    return encode_frame(bytes(header) + text)


def parse_index_auction_response(body: bytes) -> list[dict]:
    """Parse index auction JSON and expose white/lead line aliases."""
    if body.startswith(b"\x0a"):
        try:
            body = normalize_8901_response(body)
        except ValueError as exc:
            logger.debug("index auction normalization failed: %s", exc)
            return []

    roots = ("Auction", "CloseAuction")
    matches = [
        (body.find(f'{{"{root}"'.encode("ascii")), root)
        for root in roots
    ]
    matches = [(offset, root) for offset, root in matches if offset >= 0]
    if not matches:
        return []
    start, root = min(matches)
    end = body.find(b"\x00", start)
    raw_json = body[start : end if end >= 0 else len(body)].rstrip()
    candidates = (raw_json, raw_json + b"}")
    payload = None
    for candidate in candidates:
        try:
            payload = json.loads(candidate.decode("utf-8"))
            break
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
    if not isinstance(payload, dict):
        return []
    rows = payload.get(root)
    if not isinstance(rows, list):
        return []

    records: list[dict] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        try:
            new_price = float(row["newprice"])
            lead_price = float(row["leadprice"])
        except (KeyError, TypeError, ValueError):
            continue
        market_time = row.get("markettime")
        record = dict(row)
        record["newprice"] = new_price
        record["leadprice"] = lead_price
        record["dt10"] = new_price
        record["lead_price"] = lead_price
        record["auction_type"] = (
            "closing" if root == "CloseAuction" else "opening"
        )
        if market_time:
            try:
                numeric_time = isinstance(
                    market_time,
                    (int, float),
                ) or str(market_time).isdigit()
                if numeric_time:
                    record["time"] = datetime.fromtimestamp(
                        int(market_time)
                    )
                else:
                    record["time"] = datetime.fromisoformat(
                        str(market_time)
                    )
            except (OSError, OverflowError, ValueError):
                pass
        volume = row.get("volume")
        if volume is not None:
            try:
                record["volume"] = int(volume)
            except (TypeError, ValueError):
                pass
        records.append(record)
    return records


def _auction_value(raw: int, datatype: int) -> float | None:
    """Decode auction values while preserving missing-order sentinels."""
    if (
        datatype in _AUCTION_SENTINEL_FIELDS
        and raw in _AUCTION_SENTINELS
    ):
        return None
    return decode_ths_float(raw)


def build_auction_query(
    code: str,
    market: int = 33,
    trade_date=None,
    datatype: list[int] | None = None,
    seq: int = 0x0079,
) -> bytes:
    """Build a Level2 call-auction request (period=7176, route=0x01FC).

    2026-08-05 抓包对齐：当日开盘竞价 pageid 改 1334（原 4214），route 0x01FC 不变。
    历史竞价仍走 ``build_l2_history_auction_query``（pageid=4417）。
    """
    if datatype is None:
        datatype = AUCTION_DATATYPE
    datatype_text = ",".join(str(value) for value in datatype) + ","

    # 2026-08-05 抓包对齐：trade_date=None → 最近交易日显式时间戳（原 0-0 盘后超时）
    value = resolve_trade_date(trade_date)
    start = datetime.combine(value, time(9, 15, 0))
    end = datetime.combine(value, time(9, 25, 0))
    datetime_args = f"{int(start.timestamp())}-{int(end.timestamp())}"

    text = (
        f"CodeList={market}({code},);\r\n"
        f"DataType={datatype_text}\r\n"
        f"DateTime={AUCTION_PERIOD}({datetime_args})\r\n"
        f"LackTime=0,0,0,0,0,0,0,0\r\n"
        f"pageid=1334\r\n"
    ).encode("gbk")

    header = bytearray(23)
    header[0] = 0x09
    header[1:5] = b"\x00\x16\x00\x00"
    struct.pack_into("<H", header, 5, (seq & 0xFF) | 0x0100)
    header[7:11] = b"\x12\x00\x09\x00"
    header[11:13] = b"\xfc\x01"
    header[15] = 0x40
    header[17] = 0x08
    header[18] = 0x1C
    struct.pack_into("<I", header, 19, len(text))
    return encode_frame(bytes(header) + text)


def _coerce_trade_date(value) -> date_type:
    if isinstance(value, str):
        return date_type.fromisoformat(value)
    if hasattr(value, "date") and callable(value.date):
        return value.date()
    return value


def resolve_trade_date(value=None) -> date_type:
    """Resolve a trade-date argument to a concrete date.

    ``None`` / 未传 → 最近已收盘的交易日（周末回退；收盘前 15:00 回退到前一交易日）。
    传 ``date``/``datetime``/ISO 字符串 → 原样返回（不强加交易日校验）。

    2026-08-05 抓包确认：同花顺客户端盘后查竞价/尾盘时，默认查的是**最近交易日**
    （8/4 周一）的时间戳，而非"今天"（8/5）。此前代码用 ``datetime.now().date()``
    导致盘后/周末请求当日竞价超时（当日无数据）。
    """
    if value is not None:
        return _coerce_trade_date(value)
    now = datetime.now()
    d = now.date()
    # 收盘前（15:00 前）且是工作日 → 当日竞价/尾盘可能尚未产生，回退到前一交易日
    if d.weekday() < 5 and now.time() < time(15, 0):
        return _trading_days_back(d, 1)
    # 周末或收盘后 → 回退到最近的工作日（不处理节假日，需调用方传显式日期）
    while d.weekday() >= 5:
        d = d - timedelta(days=1)
    return d


def _trading_days_back(from_date: date_type, n: int) -> date_type:
    """Go back n trading days (skipping weekends; holidays not handled)."""
    d = from_date
    count = 0
    while count < n:
        d = d - timedelta(days=1)
        if d.weekday() < 5:
            count += 1
    return d


def build_basic_auction_query(
    code: str,
    market: int = 33,
    trade_date=None,
    *,
    closing: bool = False,
    historical: bool = False,
    seq: int = 0x015A,
) -> bytes:
    """Build normal-account opening or closing auction requests on MAIN."""
    value = resolve_trade_date(trade_date)
    if closing:
        start_time, end_time = time(14, 57), time(15, 0)
        datatype = CLOSING_AUCTION_DATATYPE
        period = CLOSING_AUCTION_PERIOD
    else:
        start_time, end_time = time(9, 15), time(9, 25)
        datatype = AUCTION_DATATYPE
        period = (
            BASIC_HISTORY_AUCTION_PERIOD
            if historical
            else AUCTION_PERIOD
        )
    pageid = (
        BASIC_HISTORY_AUCTION_PAGEID
        if historical
        else BASIC_AUCTION_PAGEID
    )
    start = datetime.combine(value, start_time)
    end = datetime.combine(value, end_time)
    datatype_text = ",".join(str(item) for item in datatype) + ","
    text = (
        f"CodeList={market}({code},);\r\n"
        f"DataType={datatype_text}\r\n"
        f"DateTime={period}({int(start.timestamp())}-{int(end.timestamp())})\r\n"
        f"LackTime=0,0,0,0,0,0,0,0\r\n"
        f"pageid={pageid}\r"
    ).encode("gbk")

    header = bytearray(23)
    header[0] = 0x09
    header[1:5] = b"\x00\x16\x00\x00"
    struct.pack_into("<H", header, 5, seq & 0xFFFF)
    header[7:11] = b"\x12\x00\x09\x00"
    struct.pack_into("<H", header, 11, 0x0100)
    header[18] = (period >> 8) & 0xFF
    struct.pack_into("<I", header, 19, len(text) + 1)
    return encode_frame(bytes(header) + text)


def build_l2_closing_auction_query(
    code: str,
    market: int = 33,
    trade_date=None,
    *,
    historical: bool = False,
    seq: int = 0x0121,
) -> bytes:
    """Build current (1334) or historical (4417) Level2 closing auction.

    2026-08-05 抓包对齐：当日尾盘竞价 pageid 改 1334（原 4214），route 0x0100 不变；
    历史尾盘仍用 4417（抓包确认）。
    """
    value = resolve_trade_date(trade_date)
    start = datetime.combine(value, time(14, 57))
    end = datetime.combine(value, time(15, 0))
    datatype_text = ",".join(
        str(item) for item in CLOSING_AUCTION_DATATYPE
    ) + ","
    pageid = (
        L2_HISTORY_AUCTION_PAGEID
        if historical
        else 1334
    )
    text = (
        f"CodeList={market}({code},);\r\n"
        f"DataType={datatype_text}\r\n"
        f"DateTime={CLOSING_AUCTION_PERIOD}("
        f"{int(start.timestamp())}-{int(end.timestamp())})\r\n"
        "LackTime=0,0,0,0,0,0,0,0\r\n"
        f"pageid={pageid}\r\n"
    ).encode("gbk")

    header = bytearray(23)
    header[0] = 0x09
    header[1:5] = b"\x00\x16\x00\x00"
    struct.pack_into("<H", header, 5, seq & 0xFFFF)
    header[7:11] = b"\x12\x00\x09\x00"
    struct.pack_into("<H", header, 11, 0x0100)
    header[18] = (CLOSING_AUCTION_PERIOD >> 8) & 0xFF
    struct.pack_into("<I", header, 19, len(text))
    return encode_frame(bytes(header) + text)


def build_l2_history_auction_query(
    code: str,
    market: int = 33,
    trade_date=None,
    *,
    seq: int = 0x0123,
) -> bytes:
    """Build the captured pageid=4417 historical opening-auction request."""
    value = resolve_trade_date(trade_date)
    start = datetime.combine(value, time(9, 15))
    end = datetime.combine(value, time(9, 25))
    datatype_text = ",".join(
        str(item) for item in AUCTION_DATATYPE
    ) + ","
    text = (
        f"CodeList={market}({code},);\r\n"
        f"DataType={datatype_text}\r\n"
        f"DateTime={BASIC_HISTORY_AUCTION_PERIOD}("
        f"{int(start.timestamp())}-{int(end.timestamp())})\r\n"
        "LackTime=0,0,0,0,0,0,0,0\r\n"
        f"pageid={L2_HISTORY_AUCTION_PAGEID}\r\n"
    ).encode("gbk")

    header = bytearray(23)
    header[0] = 0x09
    header[1:5] = b"\x00\x16\x00\x00"
    struct.pack_into("<H", header, 5, seq & 0xFFFF)
    header[7:11] = b"\x12\x00\x09\x00"
    struct.pack_into("<H", header, 11, 0x0100)
    header[18] = (BASIC_HISTORY_AUCTION_PERIOD >> 8) & 0xFF
    struct.pack_into("<I", header, 19, len(text))
    return encode_frame(bytes(header) + text)


def _closing_ts_in_range(timestamp: int) -> bool:
    try:
        value = datetime.fromtimestamp(timestamp)
    except (OSError, ValueError, OverflowError):
        return False
    seconds = value.hour * 3600 + value.minute * 60 + value.second
    return 14 * 3600 + 57 * 60 <= seconds <= 15 * 3600


def _decode_closing_rows(
    rows: bytes,
    fields: list[tuple[int, int, int]],
    record_size: int,
    record_count: int,
) -> list[dict]:
    records: list[dict] = []
    for index in range(record_count):
        row = rows[index * record_size : (index + 1) * record_size]
        if len(row) < record_size:
            # Level2 historical closing frames are persistently truncated by
            # one byte at the tail (verified across 603118/600519/688981:
            # every frame's declared record region overruns the frame end by
            # exactly 1 byte on the final record's last field). Only the very
            # last declared record is affected; its leading timestamp/price/
            # amount fields are intact, so pad it and keep the closing tick
            # rather than dropping the 15:00:00 point. A mid-stream shortfall
            # would indicate real corruption, so stop there.
            if index == record_count - 1 and len(row) >= 4:
                row = row + b"\x00" * (record_size - len(row))
            else:
                break
        if len(row) > record_size:
            row = row[:record_size]
        record: dict = {}
        offset = 0
        valid = True
        for datatype, fmt, width in fields:
            chunk = row[offset : offset + width]
            offset += width
            if width != 4 or len(chunk) != 4:
                record[f"dt{datatype}_raw"] = chunk
                continue
            raw_value = struct.unpack("<I", chunk)[0]
            if datatype == 1:
                if not _closing_ts_in_range(raw_value):
                    # The declared record_count may include a trailing
                    # non-data row (e.g. 688981 declares 62 but only 61 carry
                    # valid 14:57-15:00 timestamps). Stop at the first row
                    # whose timestamp falls outside the window and return what
                    # we have, instead of throwing everything away.
                    valid = False
                    break
                record["time"] = datetime.fromtimestamp(raw_value)
            elif fmt in (0x70, 0x64):
                record[f"dt{datatype}"] = decode_ths_float(raw_value)
            else:
                record[f"dt{datatype}_raw"] = chunk
        if not valid:
            break
        records.append(record)
    return records


def parse_closing_auction_response(body: bytes) -> list[dict]:
    """Parse MAIN or Level2 14:57-15:00 companion tables."""
    if body.startswith(b"\x0a"):
        try:
            body = normalize_8901_response(body)
        except ValueError:
            return []

    for marker_name in (b"hd1.0", b"hd3.1"):
        position = 0
        while True:
            marker = body.find(marker_name, position)
            if marker < 0:
                break
            position = marker + 6
            base = marker + 6
            if len(body) < base + 10:
                continue
            raw_count, flag, record_size, field_count = struct.unpack_from(
                "<IHHH", body, base
            )
            if (
                flag != 0x0036
                or record_size != 16
                or field_count != 4
            ):
                continue
            record_count = raw_count & 0xFFFF
            fields = _parse_hd_field_table(
                body, base + 10, field_count
            )
            if (
                len(fields) != field_count
                or sum(width for _, _, width in fields) != record_size
                or [field[0] for field in fields]
                != [1, 10, 49, 31]
            ):
                continue
            shell_offset = base + 10 + field_count * 4

            if marker_name == b"hd3.1":
                bitrle_offset = shell_offset + 26
                expected_size = record_count * record_size
                if (
                    len(body) < bitrle_offset + 4
                    or struct.unpack_from(
                        ">I", body, bitrle_offset
                    )[0]
                    != expected_size
                ):
                    continue
                bitplane = _decode_bitrle_0x13746d0(
                    body[bitrle_offset:], expected_size
                )
                rows = _transpose_bitplane_0x1763410(
                    bitplane, record_size, record_count
                )
                records = _decode_closing_rows(
                    rows, fields, record_size, record_count
                )
                if records:
                    return records
                continue

            scan_end = min(
                len(body) - record_size * 2,
                shell_offset + 256,
            )
            for data_start in range(shell_offset, max(shell_offset, scan_end)):
                if data_start + record_size * 2 > len(body):
                    break
                first = struct.unpack_from("<I", body, data_start)[0]
                second = struct.unpack_from(
                    "<I", body, data_start + record_size
                )[0]
                if (
                    _closing_ts_in_range(first)
                    and _closing_ts_in_range(second)
                    and 0 < second - first <= 180
                ):
                    rows = body[
                        data_start :
                        data_start + record_count * record_size
                    ]
                    records = _decode_closing_rows(
                        rows, fields, record_size, record_count
                    )
                    if records:
                        return records
    return []


def _auction_ts_in_range(timestamp: int) -> bool:
    """Return whether a local timestamp is in the 09:15-09:25 auction."""
    try:
        value = datetime.fromtimestamp(timestamp)
    except (OSError, ValueError, OverflowError):
        return False
    seconds = value.hour * 3600 + value.minute * 60 + value.second
    return 9 * 3600 + 15 * 60 <= seconds <= 9 * 3600 + 25 * 60


def _split_auction_state_rows(
    body: bytes,
    data_start: int,
    record_count: int,
    record_size: int,
) -> list[bytes]:
    """Recover fixed rows after omitted state bytes shift later records."""
    if (
        record_count < 1
        or record_size < 4
        or data_start + 4 > len(body)
    ):
        return []

    first_timestamp = struct.unpack_from("<I", body, data_start)[0]
    try:
        first_time = datetime.fromtimestamp(first_timestamp)
    except (OSError, ValueError, OverflowError):
        return []
    if not _auction_ts_in_range(first_timestamp):
        return []

    anchors = [data_start]
    previous_timestamp = first_timestamp
    for _ in range(1, record_count):
        expected = anchors[-1] + record_size
        candidates: list[tuple[int, int, int]] = []
        search_start = max(data_start, expected - 4)
        search_end = min(len(body) - 4, expected + 4)
        for offset in range(search_start, search_end + 1):
            timestamp = struct.unpack_from("<I", body, offset)[0]
            try:
                value = datetime.fromtimestamp(timestamp)
            except (OSError, ValueError, OverflowError):
                continue
            if (
                value.date() == first_time.date()
                and _auction_ts_in_range(timestamp)
                and 0 < timestamp - previous_timestamp <= 180
            ):
                candidates.append(
                    (abs(offset - expected), offset, timestamp)
                )
        if not candidates:
            return []
        _, offset, previous_timestamp = min(candidates)
        anchors.append(offset)

    data_end = min(
        len(body), data_start + record_count * record_size
    )
    rows: list[bytes] = []
    for index, offset in enumerate(anchors):
        end = (
            anchors[index + 1]
            if index + 1 < len(anchors)
            else data_end
        )
        row = body[offset:end]
        if not record_size - 4 <= len(row) <= record_size + 4:
            return []
        if len(row) < record_size:
            row += b"\x00" * (record_size - len(row))
        elif any(value not in (0x00, 0x80) for value in row[record_size:]):
            return []
        rows.append(row[:record_size])
    return rows


def _split_auction_history_segment(
    body: bytes,
    base: int,
    record_size: int,
    field_count: int,
) -> list[dict]:
    """Extract the auction rows from a combined historical intraday frame."""
    fields = _parse_hd_field_table(body, base + 10, field_count)
    if (
        len(fields) != field_count
        or sum(width for _, _, width in fields) != record_size
    ):
        return []
    records_offset = base + 10 + field_count * 4
    data_start = -1
    scan_end = min(
        records_offset + record_size * 3,
        len(body) - record_size * 2,
    )
    for offset in range(records_offset, scan_end):
        value = struct.unpack("<I", body[offset : offset + 4])[0]
        if 1_700_000_000 < value < 1_800_000_000:
            next_value = struct.unpack(
                "<I",
                body[
                    offset + record_size : offset + record_size + 4
                ],
            )[0]
            third_value = struct.unpack(
                "<I",
                body[
                    offset + record_size * 2 :
                    offset + record_size * 2 + 4
                ],
            )[0]
            if (
                1 <= next_value - value <= 10
                and 1 <= third_value - next_value <= 10
            ):
                data_start = offset
                break
    if data_start < 0:
        return []

    records: list[dict] = []
    offset = data_start
    while offset + record_size <= len(body):
        raw_timestamp = struct.unpack(
            "<I", body[offset : offset + 4]
        )[0]
        if (
            not 1_700_000_000 < raw_timestamp < 1_800_000_000
            or not _auction_ts_in_range(raw_timestamp)
        ):
            break
        row = body[offset : offset + record_size]
        record: dict = {}
        field_offset = 0
        for datatype, _fmt, width in fields:
            chunk = row[field_offset : field_offset + width]
            field_offset += width
            if len(chunk) < width:
                return []
            if width != 4:
                record[f"dt{datatype}_raw"] = chunk
            else:
                raw_value = struct.unpack("<I", chunk)[0]
                if datatype == 1:
                    try:
                        record["time"] = datetime.fromtimestamp(raw_value)
                    except (OSError, ValueError, OverflowError):
                        return []
                else:
                    record[f"dt{datatype}"] = _auction_value(
                        raw_value, datatype
                    )
        records.append(record)
        offset += record_size
    return records


def _parse_auction_sh(body: bytes) -> list[dict]:
    """Heuristically recover time and price from legacy Shanghai frames."""
    records: list[dict] = []
    ts_candidates: dict[int, int] = {}
    time_markers = (0x62, 0x66)

    # Prefer the adjacent timestamp form because captures have validated its
    # offsets. Inserted-control candidates only fill timestamps still missing.
    for index in range(len(body) - 3):
        for marker in time_markers:
            if marker not in body[index + 2:index + 4]:
                continue
            timestamp = (
                (0x6A << 24)
                | (marker << 16)
                | (body[index + 1] << 8)
                | body[index]
            ) & 0xFFFFFFFF
            if _auction_ts_in_range(timestamp):
                ts_candidates.setdefault(timestamp, index)

    for index in range(len(body) - 4):
        marker = body[index + 3]
        if marker not in time_markers:
            continue
        timestamp = (
            (0x6A << 24)
            | (marker << 16)
            | (body[index + 2] << 8)
            | body[index]
        ) & 0xFFFFFFFF
        if not _auction_ts_in_range(timestamp):
            continue
        ts_candidates.setdefault(timestamp, index)

    if len(ts_candidates) < 3:
        return records

    residue_counts: dict[int, int] = {}
    for timestamp in ts_candidates:
        residue = timestamp % 3
        residue_counts[residue] = residue_counts.get(residue, 0) + 1
    cadence_residue = max(residue_counts, key=residue_counts.get)
    timestamp_offsets = {
        timestamp: offset
        for timestamp, offset in ts_candidates.items()
        if timestamp % 3 == cadence_residue
    }
    if len(timestamp_offsets) < 3:
        return records

    tick_candidates: list[tuple[int, list[float]]] = []
    for timestamp in sorted(timestamp_offsets):
        offset = timestamp_offsets[timestamp]
        row = body[offset + 4:offset + 32]
        marker_offset = -1
        for index in range(min(len(row), 6)):
            if row[index] == 0xB0:
                marker_offset = index
                break

        candidates: list[float] = []
        if marker_offset >= 0:
            if len(row) >= 2:
                value = struct.unpack("<H", row[0:2])[0] / 1000.0
                if 1.0 <= value <= 2000.0:
                    candidates.append(value)
            if marker_offset >= 2:
                value = struct.unpack(
                    "<H", row[marker_offset - 2:marker_offset]
                )[0] / 1000.0
                if 1.0 <= value <= 2000.0:
                    candidates.append(value)
        tick_candidates.append((timestamp, candidates))

    seed_candidates: list[float] = []
    for _, candidates in tick_candidates:
        if candidates:
            seed_candidates.extend(candidates)
        if len(seed_candidates) >= 10:
            break

    base_price: float | None = None
    if seed_candidates:
        best_count = 0
        for anchor in seed_candidates:
            lower, upper = anchor * 0.8, anchor * 1.2
            count = sum(
                1 for candidate in seed_candidates
                if lower <= candidate <= upper
            )
            if count > best_count:
                best_count = count
                base_price = anchor

    previous_price = base_price
    for timestamp, candidates in tick_candidates:
        price: float | None = None
        if candidates:
            if previous_price is not None:
                close = [
                    candidate
                    for candidate in candidates
                    if abs(candidate - previous_price) / previous_price < 0.2
                ]
                if close:
                    close.sort(
                        key=lambda candidate: abs(
                            candidate - previous_price
                        )
                    )
                    price = close[0]
            else:
                price = candidates[0]
        if price is not None:
            previous_price = price
        elif previous_price is not None:
            price = previous_price
        try:
            value = datetime.fromtimestamp(timestamp)
        except (OSError, ValueError, OverflowError):
            value = None
        records.append({"time": value, "dt10": price})
    return records


def parse_auction_response(body: bytes) -> list[dict]:
    """Parse fixed, state-packed, historical, and legacy auction frames."""
    original_body = body
    if body.startswith(b"\x0a"):
        try:
            body = normalize_8901_response(body)
        except ValueError as exc:
            logger.debug(
                "集合竞价 0x0a 外层正规化失败，回退原始扫描: %s",
                exc,
            )

    position = 0
    records: list[dict] = []
    while True:
        marker = body.find(b"hd1.0", position)
        if marker < 0:
            break
        position = marker + 6
        base = marker + 6
        if len(body) < base + 10:
            continue

        record_count = struct.unpack("<I", body[base:base + 4])[0]
        flag = struct.unpack("<H", body[base + 4:base + 6])[0]
        record_size = struct.unpack("<H", body[base + 6:base + 8])[0]
        field_count = struct.unpack("<H", body[base + 8:base + 10])[0]
        if flag != 0x003A or record_size == 0 or field_count == 0:
            continue

        if record_count > 1000:
            history_records = _split_auction_history_segment(
                body,
                base,
                record_size,
                field_count,
            )
            if history_records:
                return history_records
            continue
        if record_count == 0:
            continue

        fields = _parse_hd_field_table(
            body,
            base + 10,
            field_count,
        )
        records_offset = base + 10 + field_count * 4
        if len(body) < records_offset + record_count * record_size:
            continue

        data_start = -1
        scan_end = min(
            records_offset + record_size * 3,
            len(body) - record_size * 2,
        )
        for offset in range(records_offset, scan_end):
            value = struct.unpack("<I", body[offset:offset + 4])[0]
            if 1_700_000_000 < value < 1_800_000_000:
                next_value = struct.unpack(
                    "<I",
                    body[
                        offset + record_size:
                        offset + record_size + 4
                    ],
                )[0]
                third_value = struct.unpack(
                    "<I",
                    body[
                        offset + record_size * 2:
                        offset + record_size * 2 + 4
                    ],
                )[0]
                if (
                    1 <= next_value - value <= 10
                    and 1 <= third_value - next_value <= 10
                ):
                    data_start = offset
                    break
        if data_start < 0:
            continue

        frame_records: list[dict] = []
        frame_valid = True
        for index in range(record_count):
            row = body[
                data_start + index * record_size:
                data_start + (index + 1) * record_size
            ]
            if len(row) < record_size:
                frame_valid = False
                break
            record: dict = {}
            field_offset = 0
            for datatype, _fmt, width in fields:
                chunk = row[field_offset:field_offset + width]
                field_offset += width
                if len(chunk) < width:
                    break
                if width != 4:
                    record[f"dt{datatype}_raw"] = chunk
                    continue
                raw_value = struct.unpack("<I", chunk)[0]
                if datatype == 1:
                    if 1_700_000_000 < raw_value < 1_800_000_000:
                        try:
                            record["time"] = datetime.fromtimestamp(
                                raw_value
                            )
                        except (OSError, ValueError, OverflowError):
                            record["time"] = None
                            record["ts"] = raw_value
                    else:
                        record["ts"] = raw_value
                        frame_valid = False
                else:
                    record[f"dt{datatype}"] = _auction_value(
                        raw_value,
                        datatype,
                    )
            frame_records.append(record)
        if frame_valid and len(frame_records) == record_count:
            return frame_records

        state_rows = (
            _split_auction_state_rows(
                body,
                data_start,
                record_count,
                record_size,
            )
            if (
                len(fields) == field_count
                and sum(width for _, _, width in fields) == record_size
            )
            else []
        )
        if state_rows:
            state_records: list[dict] = []
            state_valid = True
            for row in state_rows:
                record: dict = {}
                field_offset = 0
                for datatype, _fmt, width in fields:
                    chunk = row[field_offset:field_offset + width]
                    field_offset += width
                    if len(chunk) < width:
                        state_valid = False
                        break
                    if width != 4:
                        record[f"dt{datatype}_raw"] = chunk
                        continue
                    raw_value = struct.unpack("<I", chunk)[0]
                    if datatype == 1:
                        if not 1_700_000_000 < raw_value < 1_800_000_000:
                            state_valid = False
                            break
                        try:
                            record["time"] = datetime.fromtimestamp(
                                raw_value
                            )
                        except (OSError, ValueError, OverflowError):
                            state_valid = False
                            break
                    else:
                        record[f"dt{datatype}"] = _auction_value(
                            raw_value,
                            datatype,
                        )
                state_records.append(record)
            if state_valid and len(state_records) == record_count:
                return state_records
        logger.debug(
            "集合竞价 hd1.0 记录区不是完整定长行流（dc=%d），回退原始扫描",
            record_count,
        )

    if not records:
        sh_records = _parse_auction_sh(original_body)
        if sh_records:
            return sh_records
    return records
