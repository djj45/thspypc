"""Normalizer for ``0x7b`` variable-length quote-stream records.

The implementation is a direct Python port of hexin's ``cc9000`` stock
branch and its ``cdc420`` row-delta normalizer.  A ``0x4d`` control record
registers field descriptors; a ``0x50`` data record carries one or more rows
using presence masks and per-field deltas.  The normal form is the ordinary
fixed-row ``hd1.0`` layout used by the other codecs.
"""
from __future__ import annotations

import struct


# Stock market 0x11/0x21, data type 0xffff.  These 162 descriptors are the
# exact table registered by the 2026-08-10 0x4d control frame.  A descriptor
# is ``dt:u8, fmt:u8, reserved:u8, width:u8``.
_STOCK_DEPTH_FIELD_TABLE = bytes.fromhex(
    "0510000737200028067000040770000408700004097000040a70000411700004"
    "0d70000413700004127000040c3000040e7000040f7000041870000419700004"
    "1a7000041b7000041c7000041d7000041e7000041f7000042070000421700004"
    "2270000423700004317000042d70000450700004967000049770000498700004"
    "997000049a7000049b7000049c7000049d7000045b7000045170000430700004"
    "4570000446700004e9700004ea700004827000047f1000083670000455200014"
    "1f7100042671000427710004287100044a7000044b7000048d70000466700004"
    "6770000468700004697000046a7000046b7000046c7000046d7000046e700004"
    "6f70000470700004717000047270000473700004747000047570000476700004"
    "7770000478700004797000047a7000047b7000047c7000047d700004c9700004"
    "ca700004cb700004cc700004cd700004ce700004cf700004d0700004d1700004"
    "d2700004d3700004d4700004d5700004d6700004d7700004d8700004d9700004"
    "da700004db700004dc700004dd700004de700004df700004e0700004e1700004"
    "e2700004e3700004e4700004e5700004e6700004e7700004e870000403710004"
    "047100040571000406710004fa700004fb700004fc700004fd70000453100004e"
    "d700004ee70000483700004b570000484700004b670000485700004b77000048"
    "6700004b870000487700004b970000488700004ba70000489700004bb7000048"
    "a700004bc7000048b700004bd7000048c700004be70000408710004097100040"
    "a7100040c7100040d7100040e710004c3700004c4700004c5700004c6700004"
    "bf700004c0700004c1700004c270000420710004227100042371000424710004"
    "297100042a710004"
)
_STOCK_DEPTH_FIELD_COUNT = 162
_STOCK_DEPTH_ROW_SIZE = 707


class QuoteStreamDecodeError(ValueError):
    """Raised when a quote-stream record is malformed or unsupported."""


def _read_varint(data: bytes | bytearray, offset: int, *, signed: bool = False) -> tuple[int, int]:
    """Read THS's big-endian 7-bit integer (high bit marks the final byte)."""
    value = 0
    first = 0
    for index in range(5):
        if offset >= len(data):
            raise QuoteStreamDecodeError("truncated quote-stream varint")
        raw = data[offset]
        offset += 1
        part = raw & 0x7F
        if index == 0:
            first = part
            if signed and first & 0x40:
                value = -1
        value = (value << 7) | part
        if raw & 0x80:
            return value, offset
    raise QuoteStreamDecodeError("quote-stream varint exceeds five bytes")


def _field_descriptors(table: bytes) -> list[tuple[int, int, int]]:
    return [
        (
            struct.unpack_from("<H", table, offset)[0],
            table[offset + 1] & 0x70,
            table[offset + 3],
        )
        for offset in range(0, len(table), 4)
    ]


def _decode_row_delta(
    header: bytes,
    payload: bytes,
    record_count: int,
    row_size: int,
    table: bytes,
) -> bytes:
    """Port of native ``cdc420``: expand masks and row/field deltas."""
    section_size, cursor = _read_varint(payload, 0, signed=True)
    if section_size <= 0:
        raise QuoteStreamDecodeError("invalid row-delta section size")
    section_end = cursor + section_size
    if section_end > len(payload):
        raise QuoteStreamDecodeError("truncated row-delta section")

    field_count = len(table) // 4
    mask_size = (field_count + 7) // 8
    masks = bytearray(record_count * mask_size)

    if record_count == 1:
        if cursor + mask_size > section_end:
            raise QuoteStreamDecodeError("truncated row presence mask")
        masks[:] = payload[cursor : cursor + mask_size]
        cursor += mask_size
    else:
        for group_offset in range(0, mask_size, 4):
            width = min(4, mask_size - group_offset)
            previous = 0
            value_mask = (1 << (width * 8)) - 1
            for record_index in range(record_count):
                if record_index == 0:
                    if cursor + width > section_end:
                        raise QuoteStreamDecodeError("truncated first row presence mask")
                    value = int.from_bytes(payload[cursor : cursor + width], "little")
                    cursor += width
                else:
                    delta, cursor = _read_varint(payload, cursor, signed=True)
                    value = (previous + delta) & value_mask
                start = record_index * mask_size + group_offset
                masks[start : start + width] = value.to_bytes(width, "little")
                previous = value

    rows = bytearray(b"\xff" * (record_count * row_size))
    field_offset = 0
    for field_index, (_descriptor, format_flags, width) in enumerate(
        _field_descriptors(table)
    ):
        previous_offset: int | None = None
        for record_index in range(record_count):
            present = masks[record_index * mask_size + field_index // 8] & (
                1 << (field_index % 8)
            )
            destination = record_index * row_size + field_offset
            if not present:
                continue

            if previous_offset is not None and format_flags in (0x30, 0x70):
                delta, cursor = _read_varint(payload, cursor, signed=True)
                previous = int.from_bytes(
                    rows[previous_offset : previous_offset + width], "little"
                )
                value_mask = (1 << (width * 8)) - 1
                rows[destination : destination + width] = (
                    (previous + delta) & value_mask
                ).to_bytes(width, "little")
            elif previous_offset is not None and format_flags == 0x10:
                changed, cursor = _read_varint(payload, cursor)
                if changed > width:
                    raise QuoteStreamDecodeError("invalid prefix-delta width")
                unchanged = width - changed
                rows[destination : destination + unchanged] = rows[
                    previous_offset : previous_offset + unchanged
                ]
                if cursor + changed > section_end:
                    raise QuoteStreamDecodeError("truncated prefix-delta value")
                rows[
                    destination + unchanged : destination + width
                ] = payload[cursor : cursor + changed]
                cursor += changed
            else:
                if cursor + width > section_end:
                    raise QuoteStreamDecodeError("truncated row field")
                rows[destination : destination + width] = payload[
                    cursor : cursor + width
                ]
                cursor += width
            previous_offset = destination
        field_offset += width

    if field_offset != row_size:
        raise QuoteStreamDecodeError(
            f"field widths total {field_offset}, expected row size {row_size}"
        )
    if cursor > section_end:
        raise QuoteStreamDecodeError("row decoder consumed past section boundary")
    return header + rows


def normalize_stock_depth_push(
    body: bytes,
    *,
    field_table: bytes | None = None,
) -> bytes | None:
    """Normalize a stock ``09 7b ...`` push to fixed-row ``hd1.0`` bytes.

    The current stock stream uses the built-in 162-field schema registered by
    its preceding ``0x4d`` control record.  Unsupported selector/schema
    variants return ``None`` rather than being guessed from code offsets.
    """
    encoded = body[1:] if body[:2] == b"\x09\x7b" else body
    if not encoded or encoded[0] != 0x7B:
        return None
    try:
        cursor = 1
        command, cursor = _read_varint(encoded, cursor)
        if command != 0x50:
            return None
        stream_key, cursor = _read_varint(encoded, cursor)
        market = stream_key & 0xFF
        data_type = stream_key >> 16
        if market not in (0x11, 0x21) or data_type != 0xFFFF:
            return None

        _timestamp, cursor = _read_varint(encoded, cursor)
        variant, cursor = _read_varint(encoded, cursor)
        _flags, cursor = _read_varint(encoded, cursor)
        _market_class, cursor = _read_varint(encoded, cursor)
        record_kind, cursor = _read_varint(encoded, cursor)
        extension_size, cursor = _read_varint(encoded, cursor)
        if record_kind == 5:
            if cursor + extension_size > len(encoded):
                return None
            cursor += extension_size

        # A zero selector byte means "use the complete registered schema".
        # Non-zero bitsets select descriptor groups and need registry state.
        if cursor >= len(encoded) or encoded[cursor] != 0x80:
            return None
        cursor += 1
        schema_payload_size, cursor = _read_varint(encoded, cursor)
        if schema_payload_size:
            # The built-in stock stream does not need a per-frame descriptor
            # payload.  Reject it until its selected-schema form is supplied.
            return None
        record_count, cursor = _read_varint(encoded, cursor)
        if record_count <= 0 or record_count > 10_000:
            return None

        table = field_table or _STOCK_DEPTH_FIELD_TABLE
        if not table or len(table) % 4:
            return None
        field_count = len(table) // 4
        row_size = sum(table[offset + 3] for offset in range(0, len(table), 4))
        if row_size <= 0:
            return None
        header_size = 16 + len(table)
        header = (
            b"hd1.0\x00"
            + struct.pack(
                "<IHHH", record_count, header_size, row_size, field_count
            )
            + table
        )
        payload = encoded[cursor:]
        if variant >= 0x33:
            return _decode_row_delta(
                header, payload, record_count, row_size, table
            )

        expected = record_count * row_size
        if len(payload) < expected:
            return None
        return header + payload[:expected]
    except (OverflowError, QuoteStreamDecodeError, struct.error):
        return None


class QuoteStreamNormalizer:
    """Stateful ``0x4d`` schema registry plus ``0x50`` data normalizer.

    The built-in stock schema keeps individual push parsing backward
    compatible.  Feeding control records first also makes schema refreshes
    take effect without changing production code.
    """

    def __init__(self) -> None:
        self.schemas: dict[int, bytes] = {
            0xFFFF0011: _STOCK_DEPTH_FIELD_TABLE,
            0xFFFF0021: _STOCK_DEPTH_FIELD_TABLE,
        }

    def register_control(self, body: bytes) -> bool:
        """Register one native ``0x4d`` field-descriptor control record."""
        encoded = body[1:] if body[:2] == b"\x09\x7b" else body
        if not encoded or encoded[0] != 0x7B:
            return False
        try:
            cursor = 1
            command, cursor = _read_varint(encoded, cursor)
            if command != 0x4D:
                return False
            stream_key, cursor = _read_varint(encoded, cursor)
            field_count, cursor = _read_varint(encoded, cursor)
            if field_count <= 0 or field_count > 0x3FFF:
                return False
            table = bytearray()
            for _ in range(field_count):
                descriptor, cursor = _read_varint(encoded, cursor)
                width, cursor = _read_varint(encoded, cursor)
                if descriptor > 0xFFFF or width > 0xFF:
                    return False
                table += struct.pack("<HBB", descriptor, 0, width)
            self.schemas[stream_key] = bytes(table)
            return True
        except (OverflowError, QuoteStreamDecodeError, struct.error):
            return False

    def feed(self, body: bytes) -> bytes | None:
        """Consume a control/data record and return normalized data if any."""
        encoded = body[1:] if body[:2] == b"\x09\x7b" else body
        if not encoded or encoded[0] != 0x7B:
            return None
        try:
            command, cursor = _read_varint(encoded, 1)
            if command == 0x4D:
                self.register_control(body)
                return None
            if command != 0x50:
                return None
            stream_key, _cursor = _read_varint(encoded, cursor)
        except QuoteStreamDecodeError:
            return None
        table = self.schemas.get(stream_key)
        if table is None:
            return None
        return normalize_stock_depth_push(body, field_table=table)


__all__ = [
    "QuoteStreamDecodeError",
    "QuoteStreamNormalizer",
    "normalize_stock_depth_push",
]
