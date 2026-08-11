"""Stock-list ranking request and response protocol."""
from __future__ import annotations

import logging
import re
import struct

from ..codecs.compression import (
    _decode_bitrle_0x13746d0,
    _transpose_bitplane_0x1763410,
    normalize_8901_response,
)
from ..codecs.framing import encode_frame
from ..codecs.hd import _parse_hd_field_table, parse_hd3_response
from ..codecs.numeric import decode_ths_float


logger = logging.getLogger(__name__)

STOCK_LIST_MARKETS = [(17, "沪"), (22, "深"), (151, "北交所")]
STOCK_LIST_DATATYPE = [199112]
FULL_STOCK_LIST_MARKETS = (
    16,
    17,
    19,
    20,
    144,
    145,
    146,
    147,
    150,
    151,
)

SORT_BY_VALUES = {
    "涨幅": {"sort_by": 199112, "verified": True, "response_dt": 200},
    "涨速": {"sort_by": 48, "verified": True},
    "换手率": {"sort_by": 1968584, "verified": True},
    "量比": {"sort_by": 1771976, "verified": True},
    "主力净流入": {"sort_by": 592890, "verified": True},
    "竞价金额": {"sort_by": 68758, "verified": True, "response_dt": 150},
    "竞价涨幅": {"sort_by": 68762, "verified": True},
    # 2026-08-11 抓包+活网确认(pageid=1334,与涨幅榜同通道):
    # 全市场 2899 只股票按封单额降序,SortTotal=2899/2655(沪深/含北交所)。
    # 不是客户端查所有盘口本地排,而是服务端排序后返回代码列表。
    # response_dt=44 经 verify_sort_values_online.py 活网验证(首条 3.43 亿,
    # 量级符合涨停封单)。
    "封单额": {"sort_by": 265260, "verified": True, "response_dt": 44},
}

DDE_PAGEID = 10723
DDE_STANDARD_ROUTE = 0x0148
DDE_LEVEL2_ROUTE = 0x0149
DDE_STANDARD_MARKETS = (17, 22, 33)
DDE_LEVEL2_MARKETS = (
    (17, 22),
    (33,),
)
# DDE responses use compact one-byte field ids.  dt200 is overloaded, so the
# originating SortBy must remain part of the public result.
DDE_RESPONSE_FIELDS = {
    592888: 248,
    592889: 249,
    592890: 250,
    199112: 200,
    19: 19,
    48: 48,
    1968584: 200,
}

INIT_C_MODULES = "MEQT"
# 16=沪市 144=科创/北证指数
# 151(北交所个股)不加到 init MarketCode——部分 main.123ths.com IP 拒绝含 151 的 init，
# 且北交所分时在 main.123ths.com 上不需要 init 里声明 151 即可请求 pageid=10443/11695。
INIT_MARKET_CODE = "16;144;"
INIT_STOCK_LINKS = [
    "Stock_176_H_QC",
    "Stock_176_H_QP",
    "Stock_16_A_SO",
    "Stock_16_F_SO",
    "Stock_16_B_SO",
    "Stock_16_Z_SO",
    "Stock_32_A_SO",
    "Stock_32_B_SO",
    "Stock_32_F_SO",
    "Stock_32_Z_SO",
    "Stock_68_C_DO",
    "Stock_69_C_ZO",
    "Stock_64_C_SO",
    "Stock_64_C_DO",
    "Stock_64_C_ZO",
    "Stock_144_P_SC",
    "Stock_144_Y_SC",
    "Stock_16_X_IO",
    "Stock_176_H_BULL",
    "Stock_176_H_BEAR",
    "Stock_88_H_QC",
    "Stock_88_H_QP",
    "Stock_88_H_BULL",
    "Stock_88_H_BEAR",
    "Stock_UGFF_F_O",
    "Stock_32_X_IO",
    "Stock_64_F_OS",
    "Stock_112_H_HF",
    "Stock_64_F_DL",
]

_BLOCK = b"\x02"
_SECTION = b"\x01"
_RECORD = b"\x0e"
_KEY = b"\x05"
_ROUND_TRIP = b"\x12"


def build_stock_list_query(
    markets: list[int] | tuple[int, ...] = (17, 22, 151),
    sort_begin: int = 0,
    sort_count: int = 59,
    datatype: list[int] | None = None,
    sort_by: int = 199112,
    sort_dir: str = "D",
    pageid: int = 1334,
    seq: int = 0x0025,
    route: int = 0x0156,
) -> bytes:
    """Build a DataType=199112 sorted stock-list page request."""
    if datatype is None:
        datatype = STOCK_LIST_DATATYPE
    codelist = "".join(f"{market}();" for market in markets)
    datatype_text = ",".join(str(value) for value in datatype) + ","
    text = (
        f"CodeList={codelist}\r\nDataType={datatype_text}\r\n"
        f"SortType=Sort\r\nSortBy={sort_by}\r\n"
        f"SortDir={sort_dir}\r\nSortAppend=YC\r\n"
        f"SortBegin={sort_begin}\r\nSortCount={sort_count}\r\n"
        f"FuncPeriod=0\r\nDateTime=0(0-0)\r\n"
        f"LackTime=0,0,0,0,0,0,0,0\r\npageid={pageid}\r"
    ).encode("gbk")

    header = bytearray(23)
    header[0] = 0x09
    header[1:5] = b"\x00\x16\x00\x00"
    struct.pack_into("<H", header, 5, seq & 0xFFFF)
    header[7:11] = b"\x12\x00\x0f\x00"
    struct.pack_into("<H", header, 11, route & 0xFFFF)
    struct.pack_into("<H", header, 19, len(text) + 1)
    return encode_frame(bytes(header) + text)


def build_dde_query(
    *,
    markets: tuple[int, ...] = DDE_STANDARD_MARKETS,
    sort_by: int = 592888,
    sort_dir: str = "D",
    sort_begin: int = 0,
    sort_count: int = 58,
    level2: bool = False,
    seq: int = 0x0025,
) -> bytes:
    """Build the ranking request used by the desktop DDE page."""
    direction = sort_dir.upper()
    if direction not in {"A", "D"}:
        raise ValueError("sort_dir must be 'A' or 'D'")
    if sort_begin < 0 or sort_count <= 0:
        raise ValueError("DDE pagination values must be positive")
    route = DDE_LEVEL2_ROUTE if level2 else DDE_STANDARD_ROUTE
    return build_stock_list_query(
        markets=markets,
        sort_begin=sort_begin,
        sort_count=sort_count,
        datatype=[sort_by],
        sort_by=sort_by,
        sort_dir=direction,
        pageid=DDE_PAGEID,
        seq=seq,
        route=route,
    )


def build_full_stock_list_query(
    markets: tuple[int, ...] = FULL_STOCK_LIST_MARKETS,
    *,
    seq: int = 1,
    route: int = 0x0100,
    pageid: int = 5716,
) -> bytes:
    """Build the minimum verified full code/name table query."""
    if not markets:
        raise ValueError("full stock list requires at least one market")
    codelist = "".join(f"{market}();" for market in markets)
    text = (
        "DataType=[5],[55]\r\n"
        f"CodeList={codelist}\r\n"
        "DateTime=0\r\n"
        f"pageid={pageid}\r\n"
    ).encode("gbk")

    header = bytearray(22)
    header[0:4] = b"\x00\x16\x00\x00"
    struct.pack_into("<H", header, 4, seq & 0xFFFF)
    header[6:10] = b"\x12\x00\x09\x00"
    struct.pack_into("<H", header, 10, route & 0xFFFF)
    struct.pack_into("<I", header, 18, len(text))
    return encode_frame(b"\x09" + bytes(header) + text)


def parse_stock_list_response(body: bytes) -> dict:
    """Parse pagination metadata and stock codes from one response body."""
    text = body.decode("gbk", errors="replace")
    result = {
        "sort_total": 0,
        "sort_begin": 0,
        "sort_count": 0,
        "sort_data_count": 0,
        "stocks": [],
    }
    for key, field in (
        ("sort_total", "SortTotal"),
        ("sort_begin", "SortBegin"),
        ("sort_count", "SortCount"),
        ("sort_data_count", "SortDataCount"),
    ):
        match = re.search(
            rf"(?:^|[^0-9A-Za-z_-]){field}=(\d+)",
            text,
        )
        if match:
            result[key] = int(match.group(1))

    stocks = _parse_stock_list_hd31_variant(body)
    if not stocks:
        stocks = _parse_stock_list_hd10_variant(body)
    result["stocks"] = stocks
    return result


def parse_dde_response(body: bytes, *, sort_by: int = 592888) -> dict:
    """Parse one DDE ranking page while preserving its numeric sort value."""
    result = parse_stock_list_response(body)
    records = _parse_stock_list_hd31_records(body)
    response_field = DDE_RESPONSE_FIELDS.get(sort_by, sort_by & 0xFF)
    value_key = f"dt{response_field}"
    rows = []
    for record in records:
        code = record.get("code", "")
        if not code:
            continue
        rows.append(
            {
                "code": code,
                "name": "",
                "market": record.get("market", 0),
                "value": record.get(value_key),
                "sort_by": sort_by,
                "response_field": response_field,
            }
        )
    result["rows"] = rows
    result["response_field"] = response_field
    result["has_value_field"] = any(
        value_key in record for record in records
    )
    return result


def build_init_query(
    config_ver: str = "0",
    market_code: str = INIT_MARKET_CODE,
    c_modules: str = INIT_C_MODULES,
    seq: int = 0,
) -> bytes:
    """Build the startup init request used by the captured replay."""
    stock_link_parts = [
        _BLOCK
        + b"ConfigInfo"
        + _SECTION
        + _ROUND_TRIP
        + _RECORD
        + b"ConfigVer"
        + _KEY
        + config_ver.encode("gbk")
        + _ROUND_TRIP
        + _RECORD
    ]
    for stock_link in INIT_STOCK_LINKS:
        stock_link_parts.append(
            _BLOCK
            + stock_link.encode("gbk")
            + _SECTION
            + _ROUND_TRIP
            + _RECORD
            + b"ConfigVer"
            + _KEY
            + config_ver.encode("gbk")
            + _ROUND_TRIP
            + _RECORD
        )
    stock_link_version = b"".join(stock_link_parts)
    text = (
        "C-Language=2052\r\n"
        "C-Version=E029.60.20.0031\r\n"
        "C-Config=同花顺方案\r\n"
        f"C-Modules={c_modules}\r\n"
        "C-UACS=20120716#0#\r\n"
        f"MarketCode={market_code}\r\n"
        "MarketDate=16(0);144(0);\r\n"
    ).encode("gbk") + b"StockLinkVer=" + stock_link_version

    header = bytearray(23)
    header[0] = 0x09
    header[1:5] = b"\x00\x16\x00\x00"
    struct.pack_into("<H", header, 5, seq & 0xFFFF)
    header[7:11] = b"\x12\x00\x01\x00"
    header[11:13] = b"\x00\x00"
    header[13:15] = b"\x00\x20"
    struct.pack_into("<H", header, 19, len(text) + 1)
    return encode_frame(bytes(header) + text)


def parse_init_response(body: bytes) -> dict:
    """Parse server metadata and the largest standard unk=0x18 hd3.1 table."""
    result = {"stocks": [], "server_info": {}, "hd31_frames": []}
    # 服务器配置帧可能套 cmd=0x0a 外层压缩（2026-08-07 盘后抓包 fr178 实测：
    # 107KB 压缩帧解压后才含 S-OS/S-Version/S-Name 文本），必须先解压再解析，
    # 否则 server_info 恒空 → MAIN init 被误判失败。
    if body.startswith(b"\x0a"):
        try:
            body = normalize_8901_response(body)
        except ValueError as exc:
            logger.debug("init response 0x0a 解压失败，按原样解析: %s", exc)
    text = body.decode("gbk", errors="replace")
    for key in (
        "S-OS",
        "S-Version",
        "S-Name",
        "S-Time",
        "S-ClientIP",
        "S-WebPort",
    ):
        match = re.search(rf"{key}=([^\r\n]+)", text)
        if match:
            result["server_info"][key] = match.group(1).strip()

    best_records: list[dict] = []
    for match in re.finditer(rb"hd3\.1\x00", body):
        marker = match.start()
        base = marker + 6
        if base + 10 > len(body):
            continue
        record_count = struct.unpack_from("<I", body, base)[0]
        variant = struct.unpack_from("<H", body, base + 4)[0]
        record_size = struct.unpack_from("<H", body, base + 6)[0]
        field_count = struct.unpack_from("<H", body, base + 8)[0]
        if record_count == 0 or record_count > 100000 or record_size == 0:
            continue
        result["hd31_frames"].append(
            {
                "pos": marker,
                "dc": record_count,
                "unk": variant,
                "hs": record_size,
                "fc": field_count,
            }
        )
        if variant != 0x18:
            continue
        records = parse_hd3_response(body[marker:])
        if len(records) > len(best_records):
            best_records = [
                {
                    "code": record.get("code", ""),
                    "name": "",
                    "market": _dt5_market(record),
                }
                for record in records
                if record.get("code")
            ]

    result["stocks"] = best_records
    return result


def _dt5_market(_record: dict) -> int:
    """Preserve the legacy placeholder for hidden dt5 market bytes."""
    return 0


def parse_stock_list_replay(data: bytes) -> tuple[bytes, ...]:
    """Decode the length-prefixed captured request-segment resource."""
    if len(data) < 4:
        raise ValueError("stock-list replay header is truncated")
    segment_count = int.from_bytes(data[:4], "little")
    if not 1 <= segment_count <= 64:
        raise ValueError(
            f"invalid stock-list replay segment count: {segment_count}"
        )

    offset = 4
    segments = []
    for _ in range(segment_count):
        if offset + 4 > len(data):
            raise ValueError("stock-list replay length table is truncated")
        size = int.from_bytes(data[offset : offset + 4], "little")
        offset += 4
        if size == 0 or offset + size > len(data):
            raise ValueError("stock-list replay segment is truncated")
        segments.append(data[offset : offset + size])
        offset += size
    if offset != len(data):
        raise ValueError("stock-list replay contains trailing bytes")
    return tuple(segments)


def _parse_stock_list_hd31_records(body: bytes) -> list[dict]:
    """Decode all fields in the 16-bit-count hd3.1 stock-list variant."""
    marker = body.find(b"hd3.1\x00")
    if marker < 0:
        return []
    base = marker + 6
    if len(body) < base + 10:
        return []

    record_count = struct.unpack_from("<H", body, base)[0]
    flag = struct.unpack_from("<H", body, base + 2)[0]
    record_size = struct.unpack_from("<H", body, base + 6)[0]
    field_count = struct.unpack_from("<H", body, base + 8)[0]
    if (
        flag != 0x0100
        or record_count == 0
        or record_size == 0
        or field_count == 0
    ):
        return []

    fields = _parse_hd_field_table(body, base + 10, field_count)
    bitrle_offset = base + 10 + field_count * 4 + 8
    if len(body) < bitrle_offset + 4:
        return []
    expected_size = record_count * record_size
    declared_size = struct.unpack_from(">I", body, bitrle_offset)[0]
    if declared_size != expected_size:
        logger.debug(
            "stock-list BitRLE size mismatch: got=%d expected=%d",
            declared_size,
            expected_size,
        )
        return []

    bitplane = _decode_bitrle_0x13746d0(
        body[bitrle_offset:],
        expected_size,
    )
    if len(bitplane) < expected_size:
        return []
    records = _transpose_bitplane_0x1763410(
        bitplane,
        record_size,
        record_count,
    )

    decoded = []
    for index in range(record_count):
        row = records[
            index * record_size : (index + 1) * record_size
        ]
        if len(row) < record_size:
            break
        record: dict = {}
        offset = 0
        for datatype, field_format, width in fields:
            chunk = row[offset : offset + width]
            offset += width
            if len(chunk) < width:
                break
            if datatype == 5 and width >= 7:
                code_bytes = chunk[1:7]
                if all(48 <= value <= 57 for value in code_bytes):
                    record["code"] = code_bytes.decode("ascii")
                    record["market"] = chunk[0]
                continue
            if width == 4:
                raw_value = struct.unpack("<I", chunk)[0]
                record[f"dt{datatype}_raw"] = raw_value
                record[f"dt{datatype}"] = (
                    None
                    if raw_value == 0xFFFFFFFF
                    else decode_ths_float(raw_value)
                )
            else:
                record[f"dt{datatype}_raw"] = chunk
            record[f"dt{datatype}_format"] = field_format
        if record.get("code"):
            decoded.append(record)
    return decoded


def _parse_stock_list_hd31_variant(body: bytes) -> list[dict]:
    """Parse stock identities from the 16-bit-count hd3.1 variant.

    保留底层 record 的全部 ``dt<N>`` 字段值(排序值、行情字段等),不只 code/name。
    调用方只取 ``code`` 时不受影响(多余字段被忽略)。想丢弃数值字段只留身份,
    用 :func:`strip_to_identity`。
    """
    out = []
    for record in _parse_stock_list_hd31_records(body):
        item = {
            "code": record["code"],
            "name": "",
            "market": record.get("market", 0),
        }
        # 保留 dt<N>(数值)和 dt<N>_format(字段格式),丢弃 _raw(中间态)。
        for key, value in record.items():
            if key.startswith("dt") and not key.endswith("_raw"):
                item[key] = value
        out.append(item)
    return out


def strip_to_identity(stocks: list[dict]) -> list[dict]:
    """把带 dt 字段的 ranked 结果裁成只剩 code/name/market。"""
    return [
        {"code": s.get("code", ""), "name": s.get("name", ""), "market": s.get("market", 0)}
        for s in stocks
    ]


def _parse_stock_list_hd10_variant(body: bytes) -> list[dict]:
    """Parse the row-major hd1.0 stock-list variant."""
    marker = body.find(b"hd1.0")
    if marker < 0:
        return []
    base = marker + 6
    if len(body) < base + 10:
        return []

    record_count = struct.unpack_from("<H", body, base)[0]
    flag = struct.unpack_from("<H", body, base + 2)[0]
    record_size = struct.unpack_from("<H", body, base + 6)[0]
    field_count = struct.unpack_from("<H", body, base + 8)[0]
    if (
        flag != 0x0100
        or record_count == 0
        or record_size < 11
        or field_count == 0
    ):
        return []

    records_offset = base + 10 + field_count * 4
    stocks = []
    for index in range(record_count):
        row = body[
            records_offset + index * record_size :
            records_offset + (index + 1) * record_size
        ]
        if len(row) < record_size:
            break
        code_bytes = row[5:11]
        if len(code_bytes) != 6 or not all(
            48 <= value <= 57 for value in code_bytes
        ):
            continue
        stocks.append(
            {
                "code": code_bytes.decode("ascii"),
                "name": "",
                "market": row[4],
            }
        )
    return stocks


__all__ = [
    "DDE_LEVEL2_MARKETS",
    "DDE_LEVEL2_ROUTE",
    "DDE_PAGEID",
    "DDE_RESPONSE_FIELDS",
    "DDE_STANDARD_MARKETS",
    "DDE_STANDARD_ROUTE",
    "FULL_STOCK_LIST_MARKETS",
    "INIT_C_MODULES",
    "INIT_MARKET_CODE",
    "INIT_STOCK_LINKS",
    "SORT_BY_VALUES",
    "STOCK_LIST_DATATYPE",
    "STOCK_LIST_MARKETS",
    "build_init_query",
    "build_dde_query",
    "build_full_stock_list_query",
    "build_stock_list_query",
    "parse_init_response",
    "parse_dde_response",
    "parse_stock_list_replay",
    "parse_stock_list_response",
]
