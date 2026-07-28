"""Pure request builder and shared field rules for call auctions."""
from __future__ import annotations

import logging
import struct
from datetime import datetime, time

from ..codecs.compression import normalize_8901_response
from ..codecs.framing import encode_frame
from ..codecs.hd import _parse_hd_field_table
from ..codecs.numeric import decode_ths_float
from .timeline_protocol import TIMELINE_L2_PAGEID


logger = logging.getLogger(__name__)

AUCTION_PERIOD = 7176
AUCTION_DATATYPE = [10, 27, 33, 49]

_AUCTION_SENTINELS = frozenset({0x80000000, 0xFFFFFFFF})
_AUCTION_SENTINEL_FIELDS = frozenset({27, 33})


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
    """Build a pageid=4214, period=7176 call-auction request."""
    if datatype is None:
        datatype = AUCTION_DATATYPE
    datatype_text = ",".join(str(value) for value in datatype) + ","

    if trade_date is None:
        datetime_args = "0-0"
    else:
        value = (
            trade_date.date()
            if hasattr(trade_date, "date") and callable(trade_date.date)
            else trade_date
        )
        start = datetime.combine(value, time(9, 15, 0))
        end = datetime.combine(value, time(9, 25, 0))
        datetime_args = f"{int(start.timestamp())}-{int(end.timestamp())}"

    text = (
        f"CodeList={market}({code},);\r\n"
        f"DataType={datatype_text}\r\n"
        f"DateTime={AUCTION_PERIOD}({datetime_args})\r\n"
        f"LackTime=0,0,0,0,0,0,0,0\r\n"
        f"pageid={TIMELINE_L2_PAGEID}\r\n"
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
