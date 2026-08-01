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
from .stock_list_protocol import (
    INIT_C_MODULES,
    INIT_STOCK_LINKS,
)

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

# 板块专用通道（fu4.123ths.com）引导常量，2026-08-01 双账号抓包字节级确认。
# fu4 市场组：96;128;88;216;48（板块指数挂在 market=48），subreal 注册通道
# 为 URS/UCT/UNX/UCX/UME（普通账号另加 usotc 的 UNS/UHI）。
BOARD_MARKET_CODES_L2 = "96;128;88;216;48;"
BOARD_MARKET_CODES_NORMAL = "96;88;128;216;48;"
BOARD_MARKET_DATE_L2 = (
    "96(1552184517);128(-590752822);88(-2011602689);"
    "216(1181895559);48(-209152183);"
)
BOARD_MARKET_DATE_NORMAL = (
    "96(1552184517);88(-2011602689);128(-590752822);"
    "216(1181895559);48(-209152183);"
)
BOARD_SUBREAL_CHANNELS = ("URS", "UCT", "UNX", "UCX", "UME")
BOARD_SUBREAL_CHANNELS_NORMAL = BOARD_SUBREAL_CHANNELS + ("UNS", "UHI")

# 板块通道 [5],[55] 分类表查询的 CodeList 基础市场码（抓包实测）
BOARD_CLASSIFY_MARKETS_L2 = (
    97, 98, 99, 100, 101, 88, 89, 90, 91, 48, 49, 217, 218, 219, 129, 130,
)
BOARD_CLASSIFY_MARKETS_NORMAL = (88, 89, 90, 91)

# qureal-init 的 instid 基址（抓包 L2/普通账号各自连续 0x10000 递增）
_L2_INIT_INSTID = (0xE0000, 0xF0000)
_NORMAL_INIT_INSTID = (0x290000, 0x2A0000)
_INIT_MARKETS = ("URS", "UCT", "UNX", "UCX", "UME")
_TIMEMAA = {
    "URS": "678198351",
    "UCT": "84957561",
    "UNX": "575995559",
    "UCX": "-125053799",
    "UME": "1633299046",
}


def _board_pageid(level2: bool) -> int:
    return PAGEID_BOARD_LIST_L2 if level2 else PAGEID_BOARD_LIST


def _board_stocklink_ver(config_ver: str = "0") -> str:
    """板块通道的 StockLinkVer 文本（^b/^B/^r/^n/^e 标记，抓包字节确认）。

    注意：与 MAIN init 的二进制 \x02/\x01/\x12/\x0e 编码不同——板块通道
    （fu4）的 init/qureal-init/qustocklink 帧用纯文本版本串。
    """
    parts = [f"^bConfigInfo^B^r^nConfigVer^e{config_ver}^r^n"]
    for name in INIT_STOCK_LINKS:
        parts.append(f"^b{name}^B^r^nConfigVer^e{config_ver}^r^n")
    return "".join(parts)


def _board_subframe(
    subtype: int,
    text: bytes,
    flags: bytes = b"\x01\x00",
    *,
    length_plus_one: bool = False,
) -> bytes:
    """构造板块通道双子帧子帧（22 字节头 + 文本，抓包字节级复刻）。

    ``flags`` 两个字节：pageid 注册子帧（subtype 0x0002）抓包为 ``01 00``，
    StockNameVer 子帧（subtype 0x001C）为 ``00 00``。抓包实测长度字段：
    pageid 注册 = ``len(text)``；StockNameVer/分类表/init = ``len(text)+1``
    （与 ``build_init_query`` 的 +1 约定一致）。
    """
    length = len(text) + (1 if length_plus_one else 0)
    return (
        b"\x00\x16\x00\x00"
        b"\x00\x00"
        b"\x12\x00"
        + struct.pack("<H", subtype)
        + flags
        + b"\x00" * 6
        + struct.pack("<I", length)
        + text
    )


def build_board_subreal_registration(
    level2: bool,
    repeat: int = 1,
) -> list[bytes]:
    """构造板块通道 subreal 注册帧（URS/UCT/UNX/UCX/UME，普通账号加 UNS/UHI）。

    pageid 与账号对应：Level2=5716，普通=392（抓包确认；MAIN 连接上重放这些
    帧服务器只回 CodeListSize=0，板块通道必须走 fu4 专用服务器）。
    帧文本以 ``\\n`` 结尾（抓包字节一致），发送时**不要在帧间追加额外换行**。
    """
    pageid = _board_pageid(level2)
    channels = (
        BOARD_SUBREAL_CHANNELS_NORMAL
        if not level2
        else BOARD_SUBREAL_CHANNELS
    )
    prefix = {
        "URS": "URSI",
        "UCT": "UCTF",
        "UNX": "UNXF",
        "UCX": "UCXF",
        "UME": "UMEF",
        "UNS": "UNSF",
        "UHI": "UHIF",
    }
    frames: list[bytes] = []
    for _ in range(max(1, repeat)):
        for channel in channels:
            text = (
                f"instid=2147483647\nmethod=subreal\nmarket={channel}\n"
                f"period=0\naction=change\nclass={prefix[channel]}\n"
                f"codelist= \npageid={pageid}"
            ).encode("gbk")
            frames.append(b"\x09" + text)
    return frames


def build_board_pageid_register(
    level2: bool,
    repeats: int = 3,
) -> bytes:
    """构造板块通道 pageid 注册帧（sub=0x0002，文本 ``\\r\\npageid=N\\r\\n``）。

    抓包 L2 为 3 个相同子帧（111B），普通账号为单个子帧；子帧路由 rt=0x0001
    （与推送连接的 0x0401 不同）。发送时帧间不要追加额外换行。
    """
    pageid = _board_pageid(level2)
    text = f"\r\npageid={pageid}\r\n".encode("gbk")
    sub = _board_subframe(0x0002, text)
    return b"\x09" + sub * repeats


def build_board_market_init(
    level2: bool,
    *,
    config_ver: str = "0",
    c_modules: str = INIT_C_MODULES,
    seq: int = 0,
) -> bytes:
    """构造板块通道 MarketCode 初始化帧（激活 market=48 板块指数的会话状态）。

    与 MAIN ``build_init_query`` 同构（subtype 0x0001），差异仅在：
    MarketCode=96;128;88;216;48;（L2）/ 96;88;128;216;48;（普通）、MarketDate
    填充、StockLinkVer 以 ``config_ver`` 生成、文本尾追加 ``\\r\\npageid=N\\r``。
    """
    pageid = _board_pageid(level2)
    market_code = (
        BOARD_MARKET_CODES_L2 if level2 else BOARD_MARKET_CODES_NORMAL
    )
    market_date = (
        BOARD_MARKET_DATE_L2 if level2 else BOARD_MARKET_DATE_NORMAL
    )
    text = (
        "C-Language=2052\r\n"
        "C-Version=E029.60.20.0031\r\n"
        "C-Config=同花顺方案\r\n"
        f"C-Modules={c_modules}\r\n"
        "C-UACS=20120716#208#\r\n"
        f"MarketCode={market_code}\r\n"
        f"MarketDate={market_date}\r\n"
    ).encode("gbk") + (
        "StockLinkVer=" + _board_stocklink_ver(config_ver)
    ).encode("gbk")
    text += f"\r\npageid={pageid}\r".encode("gbk")

    header = bytearray(23)
    header[0] = 0x09
    header[1:5] = b"\x00\x16\x00\x00"
    struct.pack_into("<H", header, 5, seq & 0xFFFF)
    header[7:11] = b"\x12\x00\x01\x00"
    header[11:13] = b"\x00\x00"
    header[13:15] = b"\x00\x20"
    struct.pack_into("<H", header, 19, len(text) + 1)
    return bytes(header) + text


def build_board_qureal_init(
    level2: bool,
    *,
    stocklink_ver: str | None = None,
) -> list[bytes]:
    """构造板块通道 qureal-init 帧（每市场 init + qustocklink 各一，共 10 帧）。

    抓包确认：Login 后紧跟 ``instid=0xE0000``（L2）/``0x290000``（普通）起始的
    method=init（market/timemaa/StockLinkVer）+ method=qustocklink 配对帧；
    服务器逐帧回 ``rettype=ini``。``stocklink_ver`` 传客户端本地版本串，
    缺省用空版本（服务器侧视为无缓存、下发全量配置）。
    """
    if stocklink_ver is None:
        stocklink_ver = _board_stocklink_ver("0")
    frames: list[bytes] = []
    base_init, base_link = (
        _L2_INIT_INSTID if level2 else _NORMAL_INIT_INSTID
    )
    for index, market in enumerate(_INIT_MARKETS):
        init_text = (
            f"instid={base_init + index * 0x20000}\n"
            f"market={market}\n"
            f"timemaa={_TIMEMAA[market]}\n"
            "c-version=E029.60.20.0031\n"
            "c-config=同花顺方案\n"
            "method=init\n"
            "c-modules=MEQT\n"
            f"StockLinkVer={stocklink_ver}"
        ).encode("gbk")
        frames.append(b"\x09" + init_text)
        link_text = (
            f"instid={base_link + index * 0x20000}\n"
            "method=qustocklink\n"
            "c-version=E029.60.20.0031\n"
            f"stocklinkver={stocklink_ver}"
        ).encode("gbk")
        frames.append(b"\x09" + link_text)
    return frames


def build_board_classification_query(
    level2: bool,
    *,
    seq: int = 1,
    route: int = 0x0100,
) -> bytes:
    """构造板块通道 ``DataType=[5],[55]`` 分类表查询（激活板块名称表）。"""
    markets = (
        BOARD_CLASSIFY_MARKETS_L2 if level2 else BOARD_CLASSIFY_MARKETS_NORMAL
    )
    codelist = "".join(f"{market}();" for market in markets)
    text = (
        "DataType=[5],[55]\r\n"
        f"CodeList={codelist}\r\n"
        "DateTime=0\r\n"
        f"pageid={_board_pageid(level2)}\r"
    ).encode("gbk")
    header = bytearray(22)
    header[0:4] = b"\x00\x16\x00\x00"
    struct.pack_into("<H", header, 4, seq & 0xFFFF)
    header[6:10] = b"\x12\x00\x09\x00"
    struct.pack_into("<H", header, 10, route & 0xFFFF)
    struct.pack_into("<I", header, 18, len(text) + 1)
    return b"\x09" + bytes(header) + text


def build_board_stockname_query(
    level2: bool,
    *,
    stock_name_ver: str = ";;",
) -> bytes:
    """构造板块通道 StockNameVer 请求。

    Level2：双子帧（pageid 注册 + subtype 0x001c），文本
    ``MarketCode=96;128;88;216;48;`` + ``StockNameVer=<vers>;;``。
    普通账号：``method=upstockname``（instid=65536，StockNameVer=;;）。
    """
    pageid = _board_pageid(level2)
    if not level2:
        # 普通账号：method=upstockname（抓包 88B：instid=65536，无尾随换行）
        body = (
            "instid=65536\n"
            "method=upstockname\n"
            "market=URS\n"
            f"StockNameVer={stock_name_ver}\n"
            "prototype=kvproto\n"
            f"pageid={pageid}"
        ).encode("gbk")
        return b"\x09" + body
    register_text = f"\r\npageid={pageid}\r\n".encode("gbk")
    register_sub = _board_subframe(0x0002, register_text)
    name_text = (
        f"MarketCode={BOARD_MARKET_CODES_L2}\r\n"
        f"StockNameVer={stock_name_ver};;\r\n"
        f"pageid={pageid}\r"
    ).encode("gbk")
    name_sub = _board_subframe(0x001C, name_text, flags=b"\x00\x00")
    return b"\x09" + register_sub + name_sub


def build_board_bootstrap(
    level2: bool,
    *,
    stocklink_ver: str | None = None,
    stock_name_ver: str = ";;",
) -> list[bytes]:
    """板块通道完整引导序列（除 login 外）：subreal→pageid→MKT_INIT→
    qureal-init×10→分类表→StockNameVer。发送时帧间不要追加额外换行。"""
    frames: list[bytes] = []
    frames.extend(build_board_subreal_registration(level2, repeat=3))
    frames.append(build_board_pageid_register(level2))
    frames.append(build_board_market_init(level2))
    frames.extend(build_board_qureal_init(level2, stocklink_ver=stocklink_ver))
    frames.append(build_board_classification_query(level2))
    frames.append(build_board_stockname_query(level2, stock_name_ver=stock_name_ver))
    return frames


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
