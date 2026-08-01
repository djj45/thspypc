"""同花顺 PC 系统板块 8901 协议（2026-08-01 抓包逆向）。

板块指数统一挂在 **market=48** 下（881xxx 行业 / 885xxx、886xxx 概念指数）。
账号差异只体现在 pageid：

- Level2 账号：5716/1341（板块列表+当日分时）、6000（成分股+当日分时）、
  6002（板块历史分时/K线/竞价）
- 普通账号：392（板块列表）、4180（成分股+当日分时）、4181（历史分时/K线/竞价）

响应表型（hd3.1 + BitRLE 位面）：

- 0x130 rec=344：板块行情列表（dt5=代码 16B、dt55=名称 20B GBK、
  dt6/7/8/9/10/13/19…）
- 0x64 rec=95：成分股行情（dt5=代码 7B + dt215…dt66 等 21 字段）
- 0x42 rec=28 [1,10,13,19,22,23,40]：板块指数分时（dt1=packed bar 游标，
  242 点/日）
- 0x32 rec=12 [1,10,49]：板块集合竞价（dt1=unix 秒）

本模块只做纯函数 builder/parser，连接编排在 services/system_blocks.py。
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

from .history_timeline_protocol import (
    _subframe_header,
    date_to_normal_timeline_bar,
    normal_timeline_bar_to_date,
)
from .kline_protocol import (
    _decode_bitrle_0x13746d0,
    _parse_hd_field_table,
    _transpose_bitplane_0x1763410,
)
from ..codecs.numeric import decode_ths_float
from ..codecs.framing import encode_frame

# 板块指数统一市场码
BOARD_MARKET = 48

# Level2 账号 pageid
PAGEID_BOARD_LIST_L2 = 5716
PAGEID_BOARD_TL_L2 = 6000
PAGEID_BOARD_HISTORY_L2 = 6002
# 普通账号 pageid
PAGEID_BOARD_LIST = 392
PAGEID_BOARD_TL = 4180
PAGEID_BOARD_HISTORY = 4181

# 抓包实测的请求参数
BOARD_QUOTE_DATATYPE = [48, 592890, 10, 6, 66]          # 板块列表（普通 392）
BOARD_QUOTE_DATATYPE_L2 = [271, 13, 3252, 48, 19, 3251, 90, 592890, 3250,
                           39, 10, 275, 38, 3541450, 68285, 6, 45, 66]
BOARD_TL_DATATYPE = [13, 19, 10, 23, 22, 1110]          # 当日分时
BOARD_HISTORY_DATATYPE = [13, 19, 40, 10, 23, 22, 6]    # 历史分时
BOARD_AUCTION_DATATYPE = [10, 27, 33, 49]               # 集合竞价

# 子帧路由（抓包实测值，会话内固定）
_ROUTES = {
    PAGEID_BOARD_LIST: 0x0039,
    PAGEID_BOARD_LIST_L2: 0x0052,
    PAGEID_BOARD_TL: 0x0041,
    PAGEID_BOARD_TL_L2: 0x0014,
    PAGEID_BOARD_HISTORY: 0x0021,
    PAGEID_BOARD_HISTORY_L2: 0x0012,
}

TIMELINE_PERIOD = 8192
AUCTION_PERIOD = 7176
KLINE_DAY_PERIOD = 16384


def _route_for(pageid: int) -> int:
    return _ROUTES.get(pageid, 0x0021)


def _datatype_text(datatype: list[int]) -> str:
    return ",".join(str(d) for d in datatype) + ","


def build_board_query(
    code: str,
    *,
    pageid: int,
    datatype: list[int],
    period: int = 0,
    args: str = "0-0",
    market: int = BOARD_MARKET,
    lack_time: str = "0,3,0,0,0,0,0,0",
    seq: int = 0x1156,
    inner_seq: int = 0,
) -> bytes:
    """构造板块指数查询（双子帧：前缀 + 查询），对齐 2026-08-01 抓包形态。"""
    route = _route_for(pageid)
    prefix_text = f"CodeList={market}({code},);\r\npageid={pageid}\r\n"
    query_text = (
        f"CodeList={market}({code},);\r\n"
        f"DataType={_datatype_text(datatype)}\r\n"
        f"DateTime={period}({args})\r\n"
        f"LackTime={lack_time}\r\npageid={pageid}\r"
    ).encode("gbk")
    prefix = (
        _subframe_header(0x0002, route, inner_seq, len(prefix_text))
        + prefix_text.encode("gbk")
    )
    query = (
        _subframe_header(
            0x0009,
            0x0100 | route,
            seq,
            len(query_text) + 1,
            history_flag=True,
        )
        + query_text
    )
    return encode_frame(b"\x09" + prefix + query)


def build_board_list_query(
    codes: list[str],
    *,
    level2: bool = False,
    datatype: list[int] | None = None,
) -> bytes:
    """构造板块列表/行情请求（一次携带全部板块指数代码）。"""
    pageid = PAGEID_BOARD_LIST_L2 if level2 else PAGEID_BOARD_LIST
    if datatype is None:
        datatype = BOARD_QUOTE_DATATYPE_L2 if level2 else BOARD_QUOTE_DATATYPE
    return build_board_query(
        ",".join(codes),
        pageid=pageid,
        datatype=datatype,
        period=0,
        args="0-0",
    )


def build_board_timeline_query(
    code: str,
    *,
    level2: bool = False,
    date=None,
    bar_start: int | None = None,
) -> bytes:
    """板块指数当日/历史分时。date 传入时按 packed-date 编码历史游标。"""
    pageid = (
        PAGEID_BOARD_HISTORY_L2
        if level2
        else PAGEID_BOARD_HISTORY
    )
    if bar_start is None:
        bar_start = date_to_normal_timeline_bar(date)
    return build_board_query(
        code,
        pageid=pageid,
        datatype=BOARD_HISTORY_DATATYPE,
        period=TIMELINE_PERIOD,
        args=f"{bar_start}-{bar_start + 355}",
    )


def build_board_auction_query(
    code: str,
    *,
    level2: bool = False,
    date=None,
    start_ts: int | None = None,
    end_ts: int | None = None,
) -> bytes:
    """板块指数集合竞价（period=7176，unix 秒区间）。"""
    pageid = (
        PAGEID_BOARD_HISTORY_L2
        if level2
        else PAGEID_BOARD_HISTORY
    )
    if start_ts is None:
        import datetime
        value = date
        if isinstance(value, str):
            value = datetime.date.fromisoformat(value)
        start_ts = int(
            datetime.datetime.combine(value, datetime.time(9, 15)).timestamp()
        )
        end_ts = int(
            datetime.datetime.combine(value, datetime.time(9, 25)).timestamp()
        )
    return build_board_query(
        code,
        pageid=pageid,
        datatype=BOARD_AUCTION_DATATYPE,
        period=AUCTION_PERIOD,
        args=f"{start_ts}-{end_ts}",
    )


def build_board_constituents_query(
    codes: list[str],
    *,
    level2: bool = False,
    datatype: list[int] | None = None,
) -> bytes:
    """构造板块成分股行情请求（按各自市场码分组）。"""
    pageid = PAGEID_BOARD_TL_L2 if level2 else PAGEID_BOARD_TL
    if datatype is None:
        datatype = [7, 13, 48, 19, 226, 225, 10, 224, 9, 223, 8, 6, 45, 66, 1111]
    route = _route_for(pageid)
    groups: dict[str, list[str]] = {}
    for code in codes:
        mkt = "17" if code.startswith(("6", "9")) else "33"
        if code.startswith(("4", "8", "9")) and len(code) == 6 and code[:3] in ("920", "430", "830", "831", "832", "833", "834", "835", "836", "837", "838", "839", "870", "871", "872", "873"):
            mkt = "151"
        groups.setdefault(mkt, []).append(code)
    code_list = "".join(
        f"{mkt}({','.join(codes) + ','});" for mkt, codes in groups.items()
    )
    query_text = (
        f"CodeList={code_list}\r\n"
        f"DataType={_datatype_text(datatype)}\r\n"
        f"DateTime=0(0-0)\r\n"
        "LackTime=0,0,0,0,0,0,0,0\r\n"
        f"pageid={pageid}\r"
    ).encode("gbk")
    query = (
        _subframe_header(
            0x0009,
            0x0100 | route,
            0x1156,
            len(query_text) + 1,
            history_flag=True,
        )
        + query_text
    )
    return encode_frame(b"\x09" + query)


# ── 响应解析 ──


def _normalize(body: bytes) -> bytes:
    if body.startswith(b"\x0a"):
        from ..codecs.compression import normalize_8901_response
        return normalize_8901_response(body)
    return body


def _hd3_rows(
    body: bytes,
    *allowed_flags: int,
) -> tuple[int, int, list[tuple[int, int, int]], bytes, list[bytes]] | None:
    """定位 hd3.1 表并 BitRLE 还原行字节。

    返回 (flag, record_size, fields, code, rows) 或 None。
    抓包发现字段表后还有 4 字节前缀，随后才是 4 字节大端 BitRLE 长度。
    """
    norm = _normalize(body)
    pos = norm.find(b"hd3.1\x00")
    if pos < 0 or pos + 16 > len(norm):
        return None
    rc, flag, rec_size, fc = struct.unpack("<IHHH", norm[pos + 6: pos + 16])
    if allowed_flags and flag not in allowed_flags:
        return None
    if fc == 0 or fc > 80 or rec_size == 0:
        return None
    fields = _parse_hd_field_table(norm, pos + 16, fc)
    if sum(f[2] for f in fields) != rec_size:
        return None
    ft_end = pos + 16 + fc * 4
    rows = None
    # 0x130/0x64 无 shell（字段表后 +4 即 BitRLE 长度）；
    # 0x42/0x32 有 26B shell（与 K线 hd3.1 一致）。
    for bo in (ft_end + 4, ft_end + 26):
        if len(norm) < bo + 4:
            continue
        size = struct.unpack(">I", norm[bo: bo + 4])[0]
        if not 0 < size <= 2_000_000 or size % rec_size:
            continue
        try:
            bitplane = _decode_bitrle_0x13746d0(norm[bo:], size)
        except Exception:
            continue
        if len(bitplane) < size:
            continue
        rows = _transpose_bitplane_0x1763410(
            bitplane, rec_size, size // rec_size
        )
        break
    if rows is None:
        return None
    # shell 里的代码标签（若有）
    shell = norm[pos + 16 + fc * 4: pos + 16 + fc * 4 + 26]
    code = (
        shell[5:11].decode("ascii", errors="replace")
        if len(shell) >= 11 and shell[4] in (0x11, 0x21)
        else ""
    )
    return flag, rec_size, fields, code, rows


def _decode_row(row: bytes, fields: list[tuple[int, int, int]]) -> dict:
    record: dict = {}
    offset = 0
    for datatype, fmt, width in fields:
        chunk = row[offset: offset + width]
        offset += width
        if len(chunk) < width:
            break
        if datatype == 5:
            code_bytes = chunk.rstrip(b"\x00")
            # 首字节是市场/类型标记：0x130 为 '0'（"0881101"），
            # 0x64 为 0x11（0x11+"600288"）。去掉后余 6 位数字码。
            if len(code_bytes) >= 7 and code_bytes[1:].isdigit():
                code_bytes = code_bytes[1:]
            record.setdefault(
                "code", code_bytes.decode("ascii", errors="replace")
            )
        elif datatype == 55:
            record.setdefault(
                "name",
                chunk.rstrip(b"\x00\xff").decode("gbk", errors="replace"),
            )
        elif fmt in (0x70, 0x64) and width == 4:
            record.setdefault(
                f"dt{datatype}",
                decode_ths_float(struct.unpack("<I", chunk)[0]),
            )
        elif datatype == 1 and width == 4:
            record.setdefault("bar_index", struct.unpack("<I", chunk)[0])
        else:
            record.setdefault(f"dt{datatype}_raw", chunk)
    return record


def parse_board_quote_response(body: bytes) -> list[dict]:
    """解析板块行情列表（hd3.1 0x130，344B/行）。"""
    parsed = _hd3_rows(body, 0x130)
    if parsed is None:
        return []
    _flag, rec_size, fields, _code, rows = parsed
    records = []
    for index in range(len(rows) // rec_size):
        row = rows[index * rec_size: (index + 1) * rec_size]
        records.append(_decode_row(row, fields))
    return records


def parse_board_constituents_response(body: bytes) -> list[dict]:
    """解析板块成分股行情（hd3.1 0x64，95B/行）。"""
    parsed = _hd3_rows(body, 0x64)
    if parsed is None:
        return []
    _flag, rec_size, fields, _code, rows = parsed
    records = []
    for index in range(len(rows) // rec_size):
        row = rows[index * rec_size: (index + 1) * rec_size]
        records.append(_decode_row(row, fields))
    return records


def parse_board_timeline_response(body: bytes) -> list[dict]:
    """解析板块指数分时（hd3.1 0x42，7 字段，242 点/日）。

    dt1 是 packed-date bar 游标（与股票历史分时一致），这里附上
    ``date`` 与 ``minute_index``。
    """
    parsed = _hd3_rows(body, 0x42)
    if parsed is None:
        return []
    _flag, rec_size, fields, code, rows = parsed
    records = []
    for index in range(len(rows) // rec_size):
        row = rows[index * rec_size: (index + 1) * rec_size]
        record = _decode_row(row, fields)
        bar = record.get("bar_index")
        if bar is not None:
            try:
                record["date"] = normal_timeline_bar_to_date(bar).date()
            except Exception:
                pass
            record["minute_index"] = index
        if code:
            record["code"] = code
        records.append(record)
    return records


def parse_board_auction_response(body: bytes) -> list[dict]:
    """解析板块指数集合竞价（hd3.1 0x32，12B/行：unix 秒 + dt10 + dt49）。"""
    parsed = _hd3_rows(body, 0x32)
    if parsed is None:
        return []
    _flag, rec_size, fields, code, rows = parsed
    records = []
    for index in range(len(rows) // rec_size):
        row = rows[index * rec_size: (index + 1) * rec_size]
        record = _decode_row(row, fields)
        ts = record.pop("bar_index", None)
        if ts is not None:
            import datetime
            try:
                record["time"] = datetime.datetime.fromtimestamp(ts)
            except (OSError, ValueError, OverflowError):
                record["ts"] = ts
        if code:
            record["code"] = code
        records.append(record)
    return records


__all__ = [
    "BOARD_MARKET",
    "PAGEID_BOARD_LIST",
    "PAGEID_BOARD_LIST_L2",
    "PAGEID_BOARD_TL",
    "PAGEID_BOARD_TL_L2",
    "PAGEID_BOARD_HISTORY",
    "PAGEID_BOARD_HISTORY_L2",
    "BOARD_QUOTE_DATATYPE",
    "BOARD_QUOTE_DATATYPE_L2",
    "BOARD_TL_DATATYPE",
    "BOARD_HISTORY_DATATYPE",
    "BOARD_AUCTION_DATATYPE",
    "build_board_query",
    "build_board_list_query",
    "build_board_timeline_query",
    "build_board_auction_query",
    "build_board_constituents_query",
    "parse_board_quote_response",
    "parse_board_constituents_response",
    "parse_board_timeline_response",
    "parse_board_auction_response",
]
