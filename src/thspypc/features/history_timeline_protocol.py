"""Pure builder and parser for historical intraday timelines."""
from __future__ import annotations

import logging
import re
import struct
from collections.abc import Sequence
from datetime import date as date_type
from datetime import datetime

from ..codecs.compression import (
    _decode_bitrle_0x13746d0,
    _transpose_bitplane_0x1763410,
    normalize_8901_response,
)
from ..codecs.framing import encode_frame
from ..codecs.numeric import decode_ths_float
from .timeline_protocol import TIMELINE_PERIOD


logger = logging.getLogger(__name__)

HISTORY_TIMELINE_PAGEID = 4417
NORMAL_HISTORY_TIMELINE_PAGEID = 9355
# 北交所（BSE）专用 pageid（2026-08-06 抓包确认）
# 个股（920xxx 等，market=151）当日分时走 pageid=10443，DataType 含 dt14/dt15（买卖力量）
BEIJING_TIMELINE_PAGEID = 10443
BEIJING_TIMELINE_DATATYPE = [14, 13, 19, 54, 10, 23, 15, 22]
# 北证50 指数（899050，market=144）当日分时走 pageid=11695，DataType 无 dt14/dt15（无买卖力量）
BEIJING_INDEX_TIMELINE_PAGEID = 11695
BEIJING_INDEX_TIMELINE_DATATYPE = [272, 207, 42, 271, 228, 13, 41, 227, 19, 40, 10, 224, 23, 202, 223, 22, 201, 208]
HISTORY_TIMELINE_DATATYPE = [
    229,
    207,
    228,
    13,
    227,
    19,
    226,
    54,
    204,
    225,
    10,
    203,
    210,
    224,
    23,
    202,
    209,
    223,
    230,
    22,
    201,
    208,
    6,
    1110,
    407,
    1111,
]
NORMAL_HISTORY_TIMELINE_DATATYPE = [
    207,
    13,
    19,
    54,
    204,
    10,
    203,
    210,
    23,
    202,
    209,
    22,
    201,
    208,
    6,
    1110,
    407,
    1111,
    14,
    15,
]
INDEX_HISTORY_TIMELINE_PAGEID = 77
INDEX_HISTORY_TIMELINE_DATATYPE = [13, 19, 40, 10, 23, 22, 6]
# 北证50 指数（899050）历史分时 pageid=5703（2026-08-07 盘后抓包确认，
# 与沪/深指数历史分时的 77 不同；DataType 相同 = [13,19,40,10,23,22,6]）
BEIJING_INDEX_HISTORY_PAGEID = 5703
HISTORY_TIMELINE_BAR_SPAN = 355

TIMELINE_BAR_EPOCH_ORDINAL = 675064
TIMELINE_BAR_DAYS_SCALE = 2048
TIMELINE_INTRADAY_BAR = 606

_HISTORY_TIMELINE_BAR_OFFSETS = tuple(
    list(range(0, 30))
    + list(range(34, 94))
    + list(range(98, 129))
    + list(range(227, 286))
    + list(range(290, 350))
    + [354]
)
_HISTORY_TIMELINE_MIN_ANCHORED_ROWS = 200
# 普通账号（0x0042）稀疏历史分时响应实测只有 185-202 行/日
# （2026-06-30/07-23 抓包），合并多张表后按 120 行判定。
_HISTORY_TIMELINE_NORMAL_MIN_ROWS = 120
# 稀疏响应单张表可能只含几十行（普通账号 9355 会把一天拆成多张 0x42 表），
# 先按 ≥10 行收集，合并后再用 _HISTORY_TIMELINE_MIN_ANCHORED_ROWS 判定。
_HISTORY_TIMELINE_MIN_TABLE_ROWS = 10


def _date_to_ordinal(value) -> int:
    """Convert date-like input to an ordinal."""
    if isinstance(value, str):
        compact = value.replace("-", "").replace("/", "")
        value = date_type(
            int(compact[:4]),
            int(compact[4:6]),
            int(compact[6:8]),
        )
    return value.toordinal()


def date_to_timeline_bar(value) -> int:
    """Convert a trading date to the historical timeline's first bar index.

    本函数保留 ordinal 游标（竞价 4417 上下文预热用，测试钉死
    ordinal(下一交易日) 语义）。**历史分时请求本身用 packed-date 游标**，
    :func:`build_history_timeline_query` 内部显式调用
    :func:`date_to_normal_timeline_bar`。

    2026-08-01 抓包证据：07-23 的 4417/9355 请求都是 ``132627038``
    （= packed(07-23)；ordinal 会解成 07-26），响应行 241 点与该日期逐值一致。
    """
    ordinal = (
        value.toordinal()
        if hasattr(value, "toordinal") and not isinstance(value, int)
        else _date_to_ordinal(value)
    )
    return (
        (ordinal - TIMELINE_BAR_EPOCH_ORDINAL) * TIMELINE_BAR_DAYS_SCALE
        + TIMELINE_INTRADAY_BAR
    )


def timeline_bar_to_date(bar_start: int) -> datetime:
    """Convert a historical timeline bar index back to its calendar date."""
    days = (
        bar_start - TIMELINE_INTRADAY_BAR
    ) // TIMELINE_BAR_DAYS_SCALE
    return datetime.fromordinal(days + TIMELINE_BAR_EPOCH_ORDINAL)


def date_to_normal_timeline_bar(value) -> int:
    """Encode a date using the normal-account packed-date cursor.

    2026-08-01 抓包确认 L2（4417）与普通（9355）**历史分时**都用本
    packed-date 游标（``build_history_timeline_query`` 内部调用本函数）；
    旧文档“4417 历史分时用 ordinal 游标”作废。ordinal 仅保留给竞价 4417
    上下文预热（见 :func:`date_to_timeline_bar`）。
    """
    if isinstance(value, str):
        compact = value.replace("-", "").replace("/", "")
        value = date_type(
            int(compact[:4]),
            int(compact[4:6]),
            int(compact[6:8]),
        )
    packed_date = (
        ((value.year - 1900) << 9)
        | (value.month << 5)
        | value.day
    )
    return (
        packed_date * TIMELINE_BAR_DAYS_SCALE
        + TIMELINE_INTRADAY_BAR
    )


def normal_timeline_bar_to_date(bar_start: int) -> datetime:
    """Decode a normal-account packed-date timeline cursor."""
    packed_date = (
        bar_start - TIMELINE_INTRADAY_BAR
    ) // TIMELINE_BAR_DAYS_SCALE
    year = 1900 + (packed_date >> 9)
    month = (packed_date >> 5) & 0x0F
    day = packed_date & 0x1F
    return datetime(year, month, day)


def _subframe_header(
    subtype: int,
    route: int,
    sequence: int,
    text_length: int,
    history_flag: bool = False,
) -> bytes:
    header = bytearray(22)
    header[0:4] = b"\x00\x16\x00\x00"
    struct.pack_into("<H", header, 4, sequence & 0xFFFF)
    header[6:10] = b"\x12\x00" + struct.pack("<H", subtype)
    struct.pack_into("<H", header, 10, route)
    if history_flag:
        header[17] = 0x20
    struct.pack_into("<I", header, 18, text_length)
    return bytes(header)


def _history_timeline_route_base(market: int) -> int:
    """Return the market-specific nested route used by page 4417."""
    if market in (16, 17):
        return 0x007C
    return 0x0058


def build_history_timeline_query(
    code: str,
    bar_start: int | None = None,
    market: int = 33,
    datatype: list[int] | None = None,
    pageid: int = HISTORY_TIMELINE_PAGEID,
    seq: int = 0x0025,
    inner_seq: int = 0x0000,
    dt_prev_off: int = -61,
    date=None,
    benchmark_market: int | None = None,
    benchmark_code: str | None = None,
) -> bytes:
    """Build the nested pageid=4417 historical timeline request."""
    if date is not None:
        bar_start = date_to_normal_timeline_bar(date)
    if bar_start is None:
        raise ValueError("必须传 bar_start 或 date 之一")
    if datatype is None:
        datatype = HISTORY_TIMELINE_DATATYPE
    datatype_text = ",".join(str(value) for value in datatype) + ","
    bar_end = bar_start + HISTORY_TIMELINE_BAR_SPAN
    route_base = _history_timeline_route_base(market)

    request_codes, benchmark_market, benchmark_code = (
        history_timeline_request_codes(
            code,
            market=market,
            benchmark_market=benchmark_market,
            benchmark_code=benchmark_code,
        )
    )

    target_list = f"{market}({code},);"
    benchmark_list = (
        f"{benchmark_market}({benchmark_code},);"
        if benchmark_market is not None and benchmark_code is not None
        else ""
    )
    if benchmark_list and benchmark_market == market:
        query_list = (
            f"{market}({','.join(request_codes)},);"
        )
    else:
        query_list = benchmark_list + target_list

    full_text = (
        f"CodeList={query_list}\r\nDataType={datatype_text}\r\n"
        f"DateTime={TIMELINE_PERIOD}({bar_start}-{bar_end})\r\n"
        f"DTPrevOff={dt_prev_off}\r\n"
        f"LackTime=0,3,0,0,0,0,0,0\r\npageid={pageid}\r\n"
    ).encode("gbk")
    target_text = (
        f"CodeList={target_list}\r\npageid={pageid}\r\n"
    ).encode("gbk")
    tail_text = (
        f"CodeList={benchmark_list or target_list}\r\npageid={pageid}\r\n"
    ).encode("gbk")

    full_frame = (
        _subframe_header(
            0x0009,
            0x0100 | route_base,
            seq,
            len(full_text),
            history_flag=True,
        )
        + full_text
    )
    tail_frame = (
        _subframe_header(
            0x0002,
            0x0200 | route_base,
            inner_seq,
            len(tail_text),
        )
        + tail_text
    )
    if benchmark_list:
        prefix_frame = (
            _subframe_header(
                0x0002,
                route_base,
                inner_seq,
                len(target_text),
            )
            + target_text
        )
        body = b"\x09" + prefix_frame + full_frame + tail_frame
    else:
        body = b"\x09" + full_frame + tail_frame
    return encode_frame(body)


def build_normal_history_timeline_query(
    code: str,
    bar_start: int | None = None,
    market: int = 33,
    datatype: list[int] | None = None,
    pageid: int = NORMAL_HISTORY_TIMELINE_PAGEID,
    seq: int = 0x1156,
    inner_seq: int = 0,
    dt_prev_off: int = -367,
    date=None,
    *,
    today: bool = False,
) -> bytes:
    """Build the two-part MAIN request used by normal accounts.

    ``today=True`` 时构造**当日分时**请求（``DateTime=8192(0-0)``，无需 bar_start）。
    2026-08-06 抓包确认：同花顺普通账号当日分时走 pageid=9355 + 同一 DataType
    （与历史分时完全一致），只是 DateTime 用 8192(0-0) 而非 packed-date 游标。
    旧代码用的 pageid=9354 已废弃（服务端不响应）。
    """
    if today:
        bar_start = None  # 当日模式不需要 packed-date 游标
    else:
        if date is not None:
            bar_start = date_to_normal_timeline_bar(date)
        if bar_start is None:
            raise ValueError("必须传 bar_start 或 date 之一（或 today=True）")
    if datatype is None:
        datatype = NORMAL_HISTORY_TIMELINE_DATATYPE

    target_list = f"{market}({code},);"
    datatype_text = ",".join(str(value) for value in datatype) + ","
    if today:
        datetime_arg = "0-0"
    else:
        datetime_arg = f"{bar_start}-{bar_start + HISTORY_TIMELINE_BAR_SPAN}"
    prefix_text = (
        f"CodeList={target_list}\r\npageid={pageid}\r\n"
    ).encode("gbk")
    # hexin declares one byte more than it sends and terminates the last line
    # with CR only.  Preserve that wire contract for MAIN compatibility.
    query_text = (
        f"CodeList={target_list}\r\nDataType={datatype_text}\r\n"
        f"DateTime={TIMELINE_PERIOD}({datetime_arg})\r\n"
        f"DTPrevOff={dt_prev_off}\r\n"
        f"LackTime=0,3,0,0,0,0,0,0\r\npageid={pageid}\r"
    ).encode("gbk")

    prefix = (
        _subframe_header(
            0x0002,
            0x006C,
            inner_seq,
            len(prefix_text),
        )
        + prefix_text
    )
    query = (
        _subframe_header(
            0x0009,
            0x016C,
            seq,
            len(query_text) + 1,
            history_flag=True,
        )
        + query_text
    )
    return encode_frame(b"\x09" + prefix + query)


def build_index_history_timeline_query(
    code: str,
    bar_start: int | None = None,
    market: int = 16,
    datatype: list[int] | None = None,
    pageid: int = INDEX_HISTORY_TIMELINE_PAGEID,
    seq: int = 0x005B,
    date=None,
) -> bytes:
    """Build the captured pageid=77 index historical-timeline request."""
    if market == 144 and code.startswith("899"):
        # 北证50 指数历史分时走 pageid=5703（2026-08-07 盘后抓包）
        pageid = BEIJING_INDEX_HISTORY_PAGEID
    if date is not None:
        bar_start = date_to_normal_timeline_bar(date)
    if bar_start is None:
        raise ValueError("必须传 bar_start 或 date 之一")
    if datatype is None:
        datatype = INDEX_HISTORY_TIMELINE_DATATYPE

    datatype_text = ",".join(str(value) for value in datatype) + ","
    bar_end = bar_start + HISTORY_TIMELINE_BAR_SPAN
    text = (
        f"CodeList={market}({code},);\r\n"
        f"DataType={datatype_text}\r\n"
        f"DateTime={TIMELINE_PERIOD}({bar_start}-{bar_end})\r\n"
        "LackTime=0,3,0,0,0,0,0,0\r\n"
        f"pageid={pageid}\r\n"
    ).encode("gbk")

    header = bytearray(23)
    header[0] = 0x09
    header[1:5] = b"\x00\x16\x00\x00"
    struct.pack_into("<H", header, 5, seq & 0xFFFF)
    header[7:11] = b"\x12\x00\x09\x00"
    struct.pack_into("<H", header, 11, 0x0100)
    header[18] = 0x20
    struct.pack_into("<I", header, 19, len(text))
    return encode_frame(bytes(header) + text)


def history_timeline_request_codes(
    code: str,
    *,
    market: int,
    benchmark_market: int | None = None,
    benchmark_code: str | None = None,
) -> tuple[tuple[str, ...], int | None, str | None]:
    """Resolve the exact CodeList order used by a historical request.

    The response can omit the ASCII code from later tables.  Keeping this
    ordering in one pure helper lets the response parser bind such tables
    without assuming that the first table is always the requested security.
    """
    is_stock = code.isdigit() and not code.startswith("399")
    if (
        benchmark_market is None
        and benchmark_code is None
        and is_stock
        and market == 33
    ):
        benchmark_market, benchmark_code = 32, "399002"
    if (benchmark_market is None) != (benchmark_code is None):
        raise ValueError("benchmark_market 和 benchmark_code 必须同时提供")
    if benchmark_code is None:
        return (code,), None, None
    return (
        (benchmark_code, code),
        benchmark_market,
        benchmark_code,
    )


def _history_timeline_table_code(
    body: bytes,
    search_start: int,
    search_end: int,
) -> str | None:
    """Return an explicit six-digit instrument label from a table shell."""
    match = re.search(
        rb"(?<![0-9])([0-9]{6})(?![0-9])",
        body[search_start:min(search_end, search_start + 160)],
    )
    return match.group(1).decode("ascii") if match is not None else None


def _history_timeline_first_row(
    body: bytes,
    search_start: int,
    search_end: int,
    record_size: int,
    code: str | None,
) -> int:
    """Find the first bar after a selected instrument shell."""
    if code:
        code_offset = body.find(
            code.encode("ascii"), search_start, search_end
        )
        if code_offset < 0:
            return -1
        search_start = code_offset + len(code)
        search_end = min(search_end, search_start + 512)

    stop = max(search_start, search_end - record_size - 8)
    for offset in range(search_start, stop):
        bar = struct.unpack_from("<I", body, offset)[0]
        if (
            not 100_000_000 < bar < 200_000_000
            or bar % TIMELINE_BAR_DAYS_SCALE != TIMELINE_INTRADAY_BAR
        ):
            continue
        next_bar = struct.pack("<I", bar + 1)
        if any(
            body[candidate : candidate + 4] == next_bar
            for candidate in range(
                offset + max(4, record_size - 4),
                offset + record_size + 5,
            )
        ):
            return offset
    return -1


def _history_timeline_row_anchors(
    body: bytes,
    first_row: int,
    block_end: int,
    record_size: int,
) -> list[tuple[int, int]]:
    """Recover physical rows using their on-wire bar-index anchors.

    The normal-account (0x0042) sparse responses store row segments out of
    chronological order inside one decompressed body, so each expected bar
    is searched across the whole table block rather than only forward from
    the previously anchored row.
    """
    first_bar = struct.unpack_from("<I", body, first_row)[0]
    rows = [(first_row, first_bar)]
    search_start = first_row + max(4, record_size - 4)
    for delta in _HISTORY_TIMELINE_BAR_OFFSETS[1:]:
        expected_bar = first_bar + delta
        offset = body.find(
            struct.pack("<I", expected_bar),
            search_start,
            block_end,
        )
        if offset < 0 or offset + record_size > block_end:
            continue
        rows.append((offset, expected_bar))
    return rows


def _decode_history_timeline_rows(
    body: bytes,
    rows: list[tuple[int, int]],
    fields: list[tuple[int, int, int, int]],
    record_size: int,
) -> list[dict]:
    records: list[dict] = []
    for row_offset, bar_index in rows:
        if row_offset + record_size > len(body):
            break
        record: dict = {}
        field_offset = row_offset
        for datatype, fmt, _flags, width in fields:
            chunk = body[field_offset : field_offset + width]
            field_offset += width
            if len(chunk) < width:
                return []
            if width != 4:
                record[f"dt{datatype}_raw"] = chunk
            elif datatype == 1:
                record["bar_index"] = bar_index
            else:
                raw_value = struct.unpack("<I", chunk)[0]
                if datatype == 40 and fmt not in (0x70, 0x64):
                    record[f"dt{datatype}"] = (
                        None
                        if raw_value == 0xFFFFFFFF
                        else struct.unpack("<i", chunk)[0]
                    )
                else:
                    record[f"dt{datatype}"] = decode_ths_float(raw_value)
        records.append(record)
    return records


def parse_history_timeline_response(
    body: bytes,
    code: str | None = None,
    requested_codes: Sequence[str] | None = None,
) -> list[dict]:
    """Parse safely anchored records from a historical timeline response.

    ``requested_codes`` must follow the request ``CodeList`` order.  It is
    used only when a mixed response omits a later table's ASCII code label;
    an explicit on-wire label always takes precedence.
    """
    if body.startswith(b"\x0a"):
        try:
            body = normalize_8901_response(body)
        except ValueError as exc:
            logger.debug(
                "history timeline outer normalization failed: %s", exc
            )
            return []

    # code 单独传入时（如字母代码 1A0001/1B0680，显式壳标签正则匹配不到），
    # 把它作为请求代码序，保证 assigned_code 能对上。
    requested = (
        tuple(requested_codes)
        if requested_codes
        else ((code,) if code else ())
    )
    table_index = 0
    pos = 0
    candidates: list[
        tuple[
            tuple[tuple[int, int, int, int], ...],
            list[tuple[int, int]],
            bool,
        ]
    ] = []
    # 北证50 指数历史分时（hd3.1 BitRLE）解码产物：
    # (解码后行 buffer, [(row_offset, bar_index)], 字段表)
    bitrle_buffers: list[
        tuple[bytes, list[tuple[int, int]], tuple[tuple[int, int, int, int], ...]]
    ] = []
    while True:
        p1 = body.find(b"hd1.0", pos)
        p3 = body.find(b"hd3.1", pos)
        # 北证50 指数历史分时响应是 hd3.1 标记（2026-08-07 盘后抓包），
        # 其余指数/个股是 hd1.0；表头布局一致，统一按最近标记扫描。
        if p1 < 0 and p3 < 0:
            break
        if p1 < 0:
            marker = p3
        elif p3 < 0 or p1 < p3:
            marker = p1
        else:
            marker = p3
        pos = marker + 6
        base = marker + 6
        if base + 10 > len(body):
            continue

        record_count = struct.unpack("<I", body[base : base + 4])[0]
        flag = struct.unpack("<H", body[base + 4 : base + 6])[0]
        record_size = struct.unpack("<H", body[base + 6 : base + 8])[0]
        field_count = struct.unpack("<H", body[base + 8 : base + 10])[0]
        normal_table = (
            flag == 0x0042
            and record_size == 28
            and field_count == 7
        )
        level2_table = (
            flag in (0x007E, 0x0082)
            and record_size in (88, 92)
            and field_count in (22, 23)
        )
        if (
            (record_count >> 16) != 0x0400
            or (record_count & 0xFFFF) == 0
            or not (normal_table or level2_table)
        ):
            continue

        next_p1 = body.find(b"hd1.0", pos)
        next_p3 = body.find(b"hd3.1", pos)
        if next_p1 < 0:
            next_marker = next_p3
        elif next_p3 < 0:
            next_marker = next_p1
        else:
            next_marker = min(next_p1, next_p3)
        block_end = next_marker if next_marker >= 0 else len(body)
        if flag in (0x0042, 0x007E, 0x0082):
            # 0x0082 与 0x007E/0x0042 一样有内联字段表（fc×4B，紧跟 header），
            # 之后是壳段（含 ASCII 代码标签）和记录数据。早期代码误以为 0x0082
            # 没有内联字段表面硬编码 6 字段，实测字段表就在 base+10。
            field_table = base + 10
            raw_table = body[
                field_table : field_table + field_count * 4
            ]
            if len(raw_table) < field_count * 4:
                continue
            fields = [
                (
                    raw_table[index * 4],
                    raw_table[index * 4 + 1],
                    raw_table[index * 4 + 2],
                    raw_table[index * 4 + 3],
                )
                for index in range(field_count)
            ]
            if (
                not any(field[0] == 10 for field in fields)
                or sum(field[3] for field in fields) != record_size
            ):
                continue
            search_start = field_table + field_count * 4
        else:
            # Only the table shapes above are supported; a different flag is
            # not a historical timeline stock/index table.
            continue

        explicit_code = _history_timeline_table_code(
            body,
            search_start,
            block_end,
        )
        assigned_code = (
            requested[table_index]
            if table_index < len(requested)
            else explicit_code
        )
        table_index += 1
        # 显式壳标签优先；缺失时才用请求代码序（2026-08-07 修正：
        # 混合响应里基准表 explicit="399002" 不能用 assigned 兜底而误收）。
        label = explicit_code if explicit_code is not None else assigned_code
        if code is not None and code != label:
            continue

        marker_kind = body[marker : marker + 5]
        if (
            marker_kind == b"hd3.1"
            and flag == 0x0042
            and record_size == 28
            and field_count == 7
        ):
            # 北证50 指数历史分时（899050，pageid=5703）响应是 hd3.1 BitRLE 表
            # （2026-08-07 盘后抓包）：壳 26B（16 00 01 00 + 0x90 + 6 位代码 +
            # 填充），随后 BE u32 expected_size = count × hs，再是 BitRLE 位流。
            shell_off = base + 10 + field_count * 4
            if shell_off + 30 <= block_end:
                shell = body[shell_off : shell_off + 26]
                bitrle_off = shell_off + 26
                count = record_count & 0xFFFF
                expected = count * record_size
                if (
                    shell[:4] == b"\x16\x00\x01\x00"
                    and struct.unpack_from(">I", body, bitrle_off)[0] == expected
                ):
                    bitplane = _decode_bitrle_0x13746d0(
                        body[bitrle_off:],
                        expected,
                    )
                    if len(bitplane) >= expected:
                        rows_bytes = _transpose_bitplane_0x1763410(
                            bitplane,
                            record_size,
                            count,
                        )
                        if len(rows_bytes) >= expected:
                            buffer = bytes(rows_bytes)
                            # 北证50 历史分时响应 241 个有效点、bar 有固定缺口
                            # （2026-08-07 抓包实测），不要求连续，只保留合法 bar 行。
                            valid_rows = [
                                (i * record_size, bar)
                                for i in range(count)
                                if 100_000_000
                                <= (
                                    bar := struct.unpack_from(
                                        "<I", buffer, i * record_size
                                    )[0]
                                )
                                <= 200_000_000
                            ]
                            if len(valid_rows) >= _HISTORY_TIMELINE_MIN_TABLE_ROWS:
                                bitrle_buffers.append((
                                    buffer,
                                    valid_rows,
                                    tuple(fields),
                                ))
                                continue

        first_row = _history_timeline_first_row(
            body,
            search_start,
            block_end,
            record_size,
            explicit_code,
        )
        if first_row < 0:
            continue
        rows = _history_timeline_row_anchors(
            body, first_row, block_end, record_size
        )
        if len(rows) < _HISTORY_TIMELINE_MIN_TABLE_ROWS:
            continue
        candidates.append((tuple(fields), rows, level2_table))

    if not candidates:
        if not bitrle_buffers:
            return []
        # 899050 历史分时只有 BitRLE 表；按 bar_index 排序后从解码 buffer 解码。
        buffer, rows, fields = bitrle_buffers[0]
        merged: dict[int, tuple[int, tuple]] = {
            bar: (row_offset, fields)
            for row_offset, bar in rows
        }
        ordered = sorted(merged.items())
        rows_out = [(offset, bar) for bar, (offset, _f) in ordered]
        if len(rows_out) < _HISTORY_TIMELINE_NORMAL_MIN_ROWS:
            return []
        return _decode_history_timeline_rows(
            buffer,
            rows_out,
            fields,
            record_size,
        )

    # 稀疏响应会把同一代码/同一日期的行拆到多张 0x42 表里（行段乱序），
    # 合并后再统一解码；不同形状（普通 vs Level2）的表不合并。
    merged: dict[int, tuple[int, tuple]] = {}
    any_level2 = False
    for fields, rows, is_level2 in candidates:
        any_level2 = any_level2 or is_level2
        for row_offset, bar_index in rows:
            merged.setdefault(bar_index, (row_offset, fields))
    min_rows = (
        _HISTORY_TIMELINE_MIN_ANCHORED_ROWS
        if any_level2
        else _HISTORY_TIMELINE_NORMAL_MIN_ROWS
    )
    if len(merged) < min_rows:
        return []

    ordered = sorted(merged.items())
    fields, first_offset = ordered[0][1][1], ordered[0][1][0]
    rows_out = [(offset, bar_index) for bar_index, (offset, _f) in ordered]
    return _decode_history_timeline_rows(body, rows_out, fields, record_size)


# ── 北交所（BSE）当日分时请求 ──
# 2026-08-06 抓包确认：
# - 个股（920xxx，market=151）走 pageid=10443，双子帧 0x09
#   SUB1 route=0x014a hist=0x20（分时主体，DataType 含 14/15）
#   SUB2 route=0x0100 hist=0x00（五档伴随，DataType=13,18,24,...,157）
# - 北证50 指数（899050，market=144）走 pageid=11695，双子帧 0x09
#   SUB1 route=0x003e hist=0x00（前缀 CodeList+pageid）
#   SUB2 route=0x013e hist=0x20（分时主体，DataType 无 14/15）
# 响应均为 hd3.1 BitRLE 表（flag=0x0046 个股 / 0x006e 指数），走
# parse_index_timeline_response 解码。

BEIJING_TIMELINE_COMPANION_DATATYPE = [
    13, 18, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35,
    122, 123, 124, 125, 150, 151, 152, 153, 154, 155, 156, 157,
]


def build_beijing_timeline_query(
    code: str,
    market: int = 151,
    datatype: list[int] | None = None,
    pageid: int = BEIJING_TIMELINE_PAGEID,
    seq: int = 0x1181,
    companion_seq: int = 0x0184,
) -> bytes:
    """构建北交所个股（market=151）当日分时请求（pageid=10443）。

    双子帧结构（0x09 前缀）：
      SUB1 route=0x014a hist=0x20 — 分时主体（DataType 含 14/15 买卖力量）
      SUB2 route=0x0100 hist=0x00 — 五档伴随（DataType=TIMELINE_COMPANION）
    """
    if datatype is None:
        datatype = BEIJING_TIMELINE_DATATYPE
    target = f"{market}({code},);"
    dt_text = ",".join(str(v) for v in datatype) + ","
    query_text = (
        f"CodeList={target}\r\nDataType={dt_text}\r\n"
        f"DateTime={TIMELINE_PERIOD}(0-0)\r\n"
        f"LackTime=0,3,0,0,0,0,0,0\r\npageid={pageid}\r"
    ).encode("gbk")
    companion_dt = ",".join(str(v) for v in BEIJING_TIMELINE_COMPANION_DATATYPE) + ","
    companion_text = (
        f"CodeList={target}\r\nDataType={companion_dt}\r\n"
        f"DateTime=0(0-0)\r\n"
        f"LackTime=0,0,0,0,0,0,0,0\r\npageid={pageid}\r"
    ).encode("gbk")
    sub1 = _subframe_header(0x0009, 0x014A, seq, len(query_text), history_flag=True) + query_text
    sub2 = _subframe_header(0x0009, 0x0100, companion_seq, len(companion_text), history_flag=False) + companion_text
    return encode_frame(b"\x09" + sub1 + sub2)


def build_beijing_index_timeline_query(
    code: str,
    market: int = 144,
    datatype: list[int] | None = None,
    pageid: int = BEIJING_INDEX_TIMELINE_PAGEID,
    seq: int = 0x10B8,
    prefix_seq: int = 0x0000,
) -> bytes:
    """构建北证50 指数（899050，market=144）当日分时请求（pageid=11695）。

    双子帧结构（0x09 前缀）：
      SUB1 route=0x003e hist=0x00 — 前缀（CodeList+pageid）
      SUB2 route=0x013e hist=0x20 — 分时主体（DataType 无 14/15，北证50 无买卖力量）
    """
    if datatype is None:
        datatype = BEIJING_INDEX_TIMELINE_DATATYPE
    target = f"{market}({code},);"
    prefix_text = (
        f"CodeList={target}\r\npageid={pageid}\r\n"
    ).encode("gbk")
    dt_text = ",".join(str(v) for v in datatype) + ","
    query_text = (
        f"CodeList={target}\r\nDataType={dt_text}\r\n"
        f"DateTime={TIMELINE_PERIOD}(0-0)\r\n"
        f"LackTime=0,3,0,0,0,0,0,0\r\npageid={pageid}\r"
    ).encode("gbk")
    sub1 = _subframe_header(0x0002, 0x003E, prefix_seq, len(prefix_text), history_flag=False) + prefix_text
    sub2 = _subframe_header(0x0009, 0x013E, seq, len(query_text), history_flag=True) + query_text
    return encode_frame(b"\x09" + sub1 + sub2)
