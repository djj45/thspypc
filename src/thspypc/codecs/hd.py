"""Generic hd1.0 and hd3.1 field-table response codecs."""
from __future__ import annotations

import logging
import struct

from .compression import (
    _decode_bitrle_0x13746d0,
    _transpose_bitplane_0x1763410,
)
from .numeric import decode_ths_float


logger = logging.getLogger(__name__)


def _parse_hd_field_table(
    buf: bytes,
    off: int,
    fc: int,
) -> list[tuple[int, int, int]]:
    """解析 hd1.0/hd3.1 字段表，返回 ``(dt, fmt, width)``。"""
    fields = []
    for i in range(fc):
        entry = buf[off + i * 4 : off + (i + 1) * 4]
        if len(entry) < 4:
            break
        fields.append((entry[0], entry[1], entry[3]))
    return fields


def _parse_hd_records(
    recs: bytes,
    fields: list[tuple[int, int, int]],
    hs: int,
    dc: int,
) -> list[dict]:
    """按字段表切分行主序记录区。

    代码字段 dt5 使用历史兼容键 ``code``；数值字段 fmt=0x70/0x64 使用 THS
    定点浮点解码，未知字段保留为 ``dt<N>_raw``。
    """
    records = []
    for record_index in range(dc):
        row = recs[record_index * hs : (record_index + 1) * hs]
        if len(row) < hs:
            break
        record: dict = {}
        offset = 0
        for dt, fmt, width in fields:
            chunk = row[offset : offset + width]
            offset += width
            if len(chunk) < width:
                break
            if dt == 5:
                code = (
                    chunk[1 : 1 + 6]
                    .split(b"\x00")[0]
                    .decode("ascii", errors="replace")
                )
                record["code"] = code
            elif fmt in (0x70, 0x64):
                if width == 4:
                    record[f"dt{dt}"] = decode_ths_float(
                        struct.unpack("<I", chunk)[0]
                    )
                elif width == 8:
                    value_a = struct.unpack("<I", chunk[:4])[0]
                    value_b = struct.unpack("<I", chunk[4:8])[0]
                    record[f"dt{dt}_a"] = decode_ths_float(value_a)
                    record[f"dt{dt}_b"] = decode_ths_float(value_b)
                else:
                    record[f"dt{dt}_raw"] = chunk
            else:
                record[f"dt{dt}_raw"] = chunk
        records.append(record)
    return records


def parse_hd1_response(body: bytes) -> list[dict]:
    """解析 hd1.0 明文响应（少量股票通常使用此格式）。

    结构：
        hd1.0\\0 + dc(LE32) + reserved(LE16) + hs(LE16) + fc(LE16)
        + 字段表(fc×4B) + 行主序记录区(dc×hs)
    """
    pos = body.find(b"hd1.0")
    if pos < 0:
        return []
    base = pos + 6
    if len(body) < base + 10:
        return []
    dc = struct.unpack("<I", body[base : base + 4])[0]
    hs = struct.unpack("<H", body[base + 6 : base + 8])[0]
    fc = struct.unpack("<H", body[base + 8 : base + 10])[0]
    if dc == 0 or hs == 0:
        return []
    fields = _parse_hd_field_table(body, base + 10, fc)
    records_offset = base + 10 + fc * 4
    records = body[records_offset : records_offset + dc * hs]
    return _parse_hd_records(records, fields, hs, dc)


def parse_hd3_response(body: bytes) -> list[dict]:
    """解析标准 BitRLE hd3.1 批量响应。

    其他 hd3.1 业务变体由各自 feature parser 处理。
    """
    pos = body.find(b"hd3.1\x00")
    if pos < 0:
        return []
    base = pos + 6
    if len(body) < base + 10:
        return []
    dc = struct.unpack("<I", body[base : base + 4])[0]
    variant = struct.unpack("<H", body[base + 4 : base + 6])[0]
    hs = struct.unpack("<H", body[base + 6 : base + 8])[0]
    fc = struct.unpack("<H", body[base + 8 : base + 10])[0]
    if dc == 0 or hs == 0:
        return []
    fields = _parse_hd_field_table(body, base + 10, fc)
    expected_size = dc * hs
    bitrle_offset = base + 10 + fc * 4 + 4
    if len(body) < bitrle_offset + 4:
        return []
    bitrle_size = struct.unpack(
        ">I",
        body[bitrle_offset : bitrle_offset + 4],
    )[0]
    if bitrle_size != expected_size:
        logger.debug(
            "hd3.1 非 BitRLE 变体(unk=0x%x, 头=0x%x), 跳过",
            variant,
            bitrle_size,
        )
        return []
    bitplane = _decode_bitrle_0x13746d0(
        body[bitrle_offset:],
        expected_size,
    )
    records = _transpose_bitplane_0x1763410(bitplane, hs, dc)
    return _parse_hd_records(records, fields, hs, dc)
