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

    代码字段 dt5 使用历史兼容键 ``code``；数值字段 fmt=0x70/0x79/0x7B 使用
    THS 定点浮点解码（0x79/0x7B 见 hd3.1 0xc4 变体，2026-08-18 抓包+
    DDE API 交叉验证与 0x70 同编码），未知字段保留为 ``dt<N>_raw``。
    重复 dt（如 0xc4 表的两个 dt200）第二个起键名加 ``#2`` 后缀。
    """
    records = []
    for record_index in range(dc):
        row = recs[record_index * hs : (record_index + 1) * hs]
        if len(row) < hs:
            break
        record: dict = {}
        seen: dict[int, int] = {}
        offset = 0
        for dt, fmt, width in fields:
            chunk = row[offset : offset + width]
            offset += width
            if len(chunk) < width:
                break
            if dt == 5 and width >= 7 and chunk[1:7].isdigit():
                code = (
                    chunk[1 : 1 + 6]
                    .split(b"\x00")[0]
                    .decode("ascii", errors="replace")
                )
                record["code"] = code
            elif fmt in (0x70, 0x79, 0x7B, 0x64):
                seen[dt] = seen.get(dt, 0) + 1
                key = f"dt{dt}" if seen[dt] == 1 else f"dt{dt}#{seen[dt]}"
                if width == 4:
                    record[key] = decode_ths_float(
                        struct.unpack("<I", chunk)[0]
                    )
                elif width == 8:
                    value_a = struct.unpack("<I", chunk[:4])[0]
                    value_b = struct.unpack("<I", chunk[4:8])[0]
                    record[f"{key}_a"] = decode_ths_float(value_a)
                    record[f"{key}_b"] = decode_ths_float(value_b)
                else:
                    record[f"{key}_raw"] = chunk
            else:
                seen[dt] = seen.get(dt, 0) + 1
                key = f"dt{dt}" if seen[dt] == 1 else f"dt{dt}#{seen[dt]}"
                record[f"{key}_raw"] = chunk
        records.append(record)
    return records


def parse_hd1_response(body: bytes) -> list[dict]:
    """解析 hd1.0 明文响应（少量股票通常使用此格式）。

    结构：
        hd1.0\\0 + dc(LE32) + reserved(LE16) + hs(LE16) + fc(LE16)
        + 字段表(fc×4B) + 行主序记录区(dc×hs)

    0xc4 金额表小批量变体（2026-08-18 活网确认）：dc 高 8 位=0x01、
    reserved=0x00C4，字段表后是 60 字节前导，随后**未压缩**行主序记录
    （大批量同表走 hd3.1 魔法数 + BitRLE，见 parse_hd3_response）。
    """
    pos = body.find(b"hd1.0")
    if pos < 0:
        return []
    base = pos + 6
    if len(body) < base + 10:
        return []
    dc_raw = struct.unpack("<I", body[base : base + 4])[0]
    hs = struct.unpack("<H", body[base + 6 : base + 8])[0]
    fc = struct.unpack("<H", body[base + 8 : base + 10])[0]
    dc = dc_raw & 0x00FFFFFF
    if dc == 0 or hs == 0:
        return []
    fields = _parse_hd_field_table(body, base + 10, fc)
    records_offset = base + 10 + fc * 4
    if dc_raw & 0xFF000000:
        records_offset += 60
        records = body[records_offset : records_offset + dc * hs]
        # 服务器偶发末记录末字节落在帧外（2026-08-18 实测 2 行帧缺 1 字节，
        # 与十档盘口同型）：补零展开，末字段是无关的日期哨兵，不受影响。
        if 0 < len(records) < dc * hs:
            records = records.ljust(dc * hs, b"\x00")
    else:
        records = body[records_offset : records_offset + dc * hs]
    return _parse_hd_records(records, fields, hs, dc)


def parse_hd3_response(body: bytes) -> list[dict]:
    """解析标准 BitRLE hd3.1 批量响应（含 0xc4/0xb2 金额表变体）。

    其他 hd3.1 业务变体由各自 feature parser 处理。

    变体布局（2026-08-18 抓包逆向，captures_live/c4/）：
    - 标准表：dc 低 24 位为行数，字段表后直接跟 BitRLE 流
      （BE32 明文长度 + 位流）。
    - 0xc4/0xb2 金额表（pageid=1334 请求 DataType 含 592890/592888 时响应）：
      dc 高 8 位为 0x01 标志，字段表后是 64 字节前导（内含压缩长度等元数据，
      偏移 0x3c 处 LE32=位流字节数），BitRLE 流从前导之后开始。字段 fmt
      0x79/0x7B 与 0x70 同为 THS 定点浮点（dt250=主力净额元、dt248=DDE
      主力亿，与 /api/dde_rank 活网交叉验证）。
    """
    pos = body.find(b"hd3.1\x00")
    if pos < 0:
        return []
    base = pos + 6
    if len(body) < base + 10:
        return []
    dc_raw = struct.unpack("<I", body[base : base + 4])[0]
    variant = struct.unpack("<H", body[base + 4 : base + 6])[0]
    hs = struct.unpack("<H", body[base + 6 : base + 8])[0]
    fc = struct.unpack("<H", body[base + 8 : base + 10])[0]
    dc = dc_raw & 0x00FFFFFF
    if dc == 0 or hs == 0:
        return []
    fields = _parse_hd_field_table(body, base + 10, fc)
    expected_size = dc * hs
    data_offset = base + 10 + fc * 4 + 4
    if dc_raw & 0xFF000000:
        # 0xc4/0xb2 金额表变体：前导扩为 64 字节（BE32 明文长度在 0x40 处）
        data_offset += 60
    bitplane = _decode_bitrle_0x13746d0(
        body[data_offset:],
        expected_size,
    )
    if len(bitplane) != expected_size:
        logger.debug(
            "hd3.1 变体(unk=0x%x, dc=0x%x) BitRLE 长度不符: %d != %d",
            variant,
            dc_raw,
            len(bitplane),
            expected_size,
        )
        return []
    records = _transpose_bitplane_0x1763410(bitplane, hs, dc)
    return _parse_hd_records(records, fields, hs, dc)
