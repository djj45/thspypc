"""同花顺 PC 系统板块 8901 协议（2026-08-01 抓包逆向）。

板块指数统一挂在 **market=48** 下（881xxx 行业 / 885xxx、886xxx 概念指数）。
账号差异只体现在 pageid：

- Level2 账号：5716/1341（板块列表+当日分时）、6000（成分股+当日分时）、
  6002（板块历史分时/K线/竞价）
- 普通账号：392（板块列表）、4180（成分股+当日分时）、4181（历史分时/K线/竞价）

响应表型（hd3.1 + BitRLE 位面）：

- 0x130 rec=344：板块行情列表（dt5=代码 16B、dt55=名称 20B GBK、
  dt6/7/8/9/10/13/19…；2026-08-02 抓包起服务端对列表查询改回紧凑表
  0x20/0x1c/0x22，0x130 仅作兼容保留）
- 0x64 rec=95：成分股行情（dt5=代码 7B + dt215…dt66 等 21 字段）
- 0x42 rec=28 [1,10,13,19,22,23,40]：板块指数分时（dt1=packed bar 游标，
  242 点/日）
- 0x32 rec=12 [1,10,49]：板块集合竞价（dt1=unix 秒）

本模块只做纯函数 builder/parser，连接编排在 services/system_blocks.py。
"""
from __future__ import annotations

import json
import os
import struct
from dataclasses import dataclass
from pathlib import Path

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
    parse_stock_list_response,
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

# ── 热点板块（94 页面，pageid=12480，2026-08-07 双账号抓包确认）──
# 与板块列表（392/5716）共用同一批 fu4 板块通道连接，仅组件实例号不同：
# 普通账号与 392 旧路由 0x0039/0x0139 相邻（0x003A/0x013A 板块、0x003B/0x013B
# 成分股），L2 与 5716 路由 0x0052/0x0152 相邻（0x0053/0x0153、0x0054/0x0154）。
PAGEID_BOARD_HOT = 12480
HOT_BOARD_ROUTE_NORMAL = 0x003A
HOT_BOARD_ROUTE_L2 = 0x0053
HOT_STOCK_ROUTE_NORMAL = 0x003B
HOT_STOCK_ROUTE_L2 = 0x0054
# 热点板块列表 Datatype（双账号抓包：板块指数全字段表；普通账号同样能取到
# 271/3252 等增强字段，无需像 392 那样回退基础集）
HOT_BOARD_DATATYPE = [
    271, 13, 3252, 48, 19, 3251, 90, 3250, 39, 10, 275, 38, 6, 45, 66,
]
# 板块表头各列的 SortBy 值（2026-08-07 排序抓包确认：点击表头即发
# subtype=0x000f Sort 请求，SortBy=<该列字段>；响应为 method=sort + dt5/dt15 表）
HOT_SORT_BY_CHG = 199112        # 涨幅（进入页面默认）
HOT_SORT_BY_SPEED_1M = 527527   # 1分钟涨速（dt167）
HOT_SORT_BY_SPEED_4M = 48       # 4分钟涨速（dt48）
HOT_SORT_BY_MAIN_INFLOW = 592890  # 主力净流入（dt250）
HOT_SORT_BY_LIMIT_UP = 271      # 涨停数
HOT_SORT_BY_UP_COUNT = 38       # 涨家数
HOT_SORT_BY_DOWN_COUNT = 39     # 跌家数
# 热点板块详情表（0x40/72B）字段含义（885927 CRO概念 2026-08-07 实测确认）
HOT_DETAIL_LIMIT_UP_DT = 15     # 涨停数
HOT_DETAIL_UP_COUNT_DT = 38     # 涨家数
HOT_DETAIL_DOWN_COUNT_DT = 39   # 跌家数
HOT_DETAIL_SPEED_4M_DT = 48     # 4分钟涨速

# 抓包实测的请求参数
BOARD_QUOTE_DATATYPE = [48, 592890, 10, 6, 66]          # 板块列表（普通 392）
BOARD_QUOTE_DATATYPE_L2 = [271, 13, 3252, 48, 19, 3251, 90, 592890, 3250,
                           39, 10, 275, 38, 3541450, 68285, 6, 45, 66]
# 2026-08-02 抓包：板块指数**全量**行情请求（DataType=527527、
# DateTime=8192(-2-0)）。普通账号（pageid=392）查询子帧 route 0x016C、
# seq 0x01C6；L2（pageid=5716）route 0x0152、seq 0x006A。响应为 hd3.1
# 紧凑表 0x20/0x1c/0x22（单表 513 行），与 0x130 名称行情表不同。
BOARD_FULL_QUOTE_DATATYPE = [527527]
BOARD_FULL_QUOTE_PERIOD = 8192
BOARD_FULL_QUOTE_ARGS = "-2-0"
BOARD_FULL_QUOTE_ROUTE_NORMAL = 0x006C
BOARD_FULL_QUOTE_ROUTE_L2 = 0x0052
BOARD_FULL_QUOTE_SEQ_NORMAL = 0x01C6
BOARD_FULL_QUOTE_SEQ_L2 = 0x006A
# 普通账号基准表 0x20；L2 账号为 0x40/72B（dt6/dt10/dt13/dt19/dt48 等）。
# 0x1c/11B 是单字段小表（普通 dt250 主力；L2 另有 dt178/179/180/189/202），
# 0x22/15B 是 1分钟涨速（513×3 行），0x130 是名称行情表（兼容）。
BOARD_FULL_QUOTE_FLAGS = (0x20, 0x40, 0x1C, 0x22, 0x130)
# 全量响应小表的 BitRLE 长度头偏移（相对字段表尾）与 0x20 不同（2026-08-02
# 抓包）：0x1c/11B（dt5+dt250 主力金额）在 +8；0x22/15B（dt5+dt1+dt167
# 1分钟涨速，1539 行=513×3）在 +10。
_BOARD_FULL_BITRLE_OFFSET = {(0x1C, 11): 8, (0x22, 15): 10}
# 板块行情字段的无数据哨兵（2026-08-02 抓包：新板块 886112 的 4分钟涨速
# dt48=0xFFFFFFFF、主力金额 dt250=0x80000000；同花顺 UI 显示“-”）。
_BOARD_SENTINEL_U32 = (0xFFFFFFFF, 0x80000000)
BOARD_TL_DATATYPE = [13, 19, 10, 23, 22, 1110]          # 当日分时
BOARD_HISTORY_DATATYPE = [13, 19, 40, 10, 23, 22, 6]    # 历史分时
BOARD_AUCTION_DATATYPE = [10, 27, 33, 49]               # 集合竞价
BOARD_CONSTITUENT_DATATYPE = [
    7, 13, 48, 19, 226, 225, 10, 224, 9, 223, 8, 6, 45, 66, 1111,
]
BOARD_CONSTITUENT_DATATYPE_L2 = [
    215, 222, 221, 13, 220, 48, 19, 219, 18, 218,
    10, 217, 9, 216, 8, 6, 45, 66, 407, 1111,
]
BOARD_CONSTITUENT_CONTEXT_DATATYPE_L2 = [
    272, 271, 13, 19, 40, 54, 39, 10, 38, 6, 1110, 1111, 380,
]

# 子帧路由（抓包实测值，会话内固定）。
# 2026-08-02 抓包：板块列表查询（pageid=392）前缀/查询子帧路由已从
# 0x0039/0x0139 改为 0x006C/0x016C（与 527527 全量请求同族）。生产侧与
# 最新抓包一致使用新路由；2026-08-03 交易日同环境受控复验（双账号，仅改
# route 字节）显示旧 0x0039/0x0139 仍返回相同紧凑表（响应回显请求 route），
# “旧路由静默”未复现，非交易日行为未验证。L2（pageid=5716）保持
# 0x0052/0x0152。
_ROUTES = {
    PAGEID_BOARD_LIST: 0x006C,
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
# 成分股独立连接的 MKT_INIT 市场集（2026-08-01 抓包字节级确认）：普通账号
# （thsuser，整市场 16;32;144）、L2 沪（thsuser，16;144）、L2 深（__manual，32）。
# 误用板块指数的 96;88;128;216;48 时，服务器对 socket 上的 subreal 注册全部回
# errorcode=-1，业务查询只回空 Sort 响应。
BOARD_CONSTITUENT_MARKET_CODES = {
    ("sh", False): "16;32;144;",
    ("sh", True): "16;144;",
    ("sz", True): "32;",
}
BOARD_CONSTITUENT_MARKET_DATE = {
    ("sh", False): "16(-1738516266);32(-1050958608);144(-924138670);",
    ("sh", True): "16(-1738516266);144(-924138670);",
    ("sz", True): "32(-1050958608);",
}
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


def load_local_board_stocklink_ver(
    hexin_dir: str | None = None,
) -> str | None:
    """从真实客户端 ``StockLink.ini`` 读取逐 section 的 ConfigVer。

    fu4 对 ``ConfigVer=0`` 的行为与 MAIN 不同：既有探针记录到错误响应后 FIN。
    因此板块通道优先复用本机客户端的完整版本声明，而不是伪造全零版本。
    找不到文件或缺少任一核心 section 时返回 ``None``，由调用方决定是否回退。
    """
    candidates: list[Path] = []
    configured = hexin_dir or os.environ.get("THS_HEXIN_DIR")
    if configured:
        candidates.append(Path(configured))
    candidates.extend(Path(path) for path in (
        r"D:\同花顺软件\同花顺",
        r"C:\new_hxzq_hd",
        r"C:\hexin",
        r"C:\同花顺软件\同花顺",
        r"D:\同花顺\同花顺",
    ))

    stocklink_path = next(
        (
            root / "system" / "同花顺方案" / "StockLink.ini"
            for root in candidates
            if (root / "system" / "同花顺方案" / "StockLink.ini").is_file()
        ),
        None,
    )
    if stocklink_path is None:
        return None
    try:
        text = stocklink_path.read_text(encoding="gbk", errors="replace")
    except OSError:
        return None

    wanted = {"ConfigInfo", *INIT_STOCK_LINKS}
    versions: dict[str, str] = {}
    section = ""
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            continue
        if section in wanted and line.startswith("ConfigVer="):
            value = line.split("=", 1)[1].strip()
            if value:
                versions[section] = value

    if any(name not in versions for name in wanted):
        return None
    parts = [
        f"^bConfigInfo^B^r^nConfigVer^e{versions['ConfigInfo']}^r^n"
    ]
    for name in INIT_STOCK_LINKS:
        parts.append(
            f"^b{name}^B^r^nConfigVer^e{versions[name]}^r^n"
        )
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
    body 文本本身不补换行；发送层仍须在每个完整 FD 帧后追加 ``0x0a`` 分隔符。
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
        "UNS": "UNSI",
        "UHI": "UHII",
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
    """构造板块通道 pageid 注册帧（sub=0x0002）。

    抓包 L2 为 3 个相同子帧（111B），普通账号为单个子帧；子帧路由 rt=0x0001
    （与推送连接的 0x0401 不同）。最后一个子帧文本以 ``\\r`` 结束，但长度字段
    仍按包含终止 ``\\n`` 计算；前面的子帧为完整 ``\\r\\n``。这正是抓包 body
    比朴素拼接少 1B 的原因。完整 FD 帧后仍由发送层追加 ``0x0a`` 分隔符。
    """
    pageid = _board_pageid(level2)
    repeats = max(1, repeats)
    complete_text = f"\r\npageid={pageid}\r\n".encode("gbk")
    final_text = complete_text[:-1]
    complete = _board_subframe(0x0002, complete_text)
    final = _board_subframe(0x0002, final_text, length_plus_one=True)
    return b"\x09" + complete * (repeats - 1) + final


def build_board_market_init(
    level2: bool,
    *,
    config_ver: str = "0",
    stocklink_ver: str | None = None,
    c_modules: str = INIT_C_MODULES,
    seq: int = 0,
    market_code: str | None = None,
    market_date: str | None = None,
) -> bytes:
    """构造板块通道 MarketCode 初始化帧（激活 market=48 板块指数的会话状态）。

    与 MAIN ``build_init_query`` 同构（subtype 0x0001），差异仅在：
    MarketCode=96;128;88;216;48;（L2）/ 96;88;128;216;48;（普通）、MarketDate
    填充、StockLinkVer 以 ``config_ver`` 生成、文本尾追加 ``\\r\\npageid=N\\r``。
    """
    pageid = _board_pageid(level2)
    if market_code is None:
        market_code = (
            BOARD_MARKET_CODES_L2 if level2 else BOARD_MARKET_CODES_NORMAL
        )
    if market_date is None:
        market_date = (
            BOARD_MARKET_DATE_L2 if level2 else BOARD_MARKET_DATE_NORMAL
        )
    if stocklink_ver is None:
        stocklink_ver = _board_stocklink_ver(config_ver)
    text = (
        "C-Language=2052\r\n"
        "C-Version=E029.60.20.0031\r\n"
        "C-Config=同花顺方案\r\n"
        f"C-Modules={c_modules}\r\n"
        "C-UACS=20120716#208#\r\n"
        f"MarketCode={market_code}\r\n"
        f"MarketDate={market_date}\r\n"
    ).encode("gbk") + ("StockLinkVer=" + stocklink_ver).encode("gbk")
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
    """兼容接口：返回按抓包顺序展开的板块通道核心引导帧。

    真客户端并非在 login 后一次性突发所有帧，而是分三阶段发送；连接代码应使用
    :func:`build_board_bootstrap_stages` 保留阶段边界。分类表和 StockNameVer 是
    页面加载后的数据请求，不是激活板块行情通道的前置条件，因此不混入核心引导。
    """
    del stock_name_ver  # 旧签名兼容；核心引导不需要名称表请求
    return [
        frame
        for stage in build_board_bootstrap_stages(
            level2,
            stocklink_ver=stocklink_ver,
        )
        for frame in stage
    ]


def build_board_bootstrap_stages(
    level2: bool,
    *,
    stocklink_ver: str | None = None,
) -> tuple[list[bytes], list[bytes], list[bytes]]:
    """构造抓包中的三阶段板块通道核心引导。

    2026-08-01 双账号 pcap 的共同结构为：

    1. subreal 注册三轮 + pageid 注册；
    2. （普通账号额外一轮 subreal + pageid）MarketCode init + qureal-init；
    3. 收到/等待 init 响应后，再注册三轮 subreal + pageid。

    阶段之间存在真实等待（login 后约 0.45s、init 前后约 0.2--0.6s）。因此把
    三阶段合并为一个 ``sendall`` 不能视为与客户端时序等价。
    """
    initial = build_board_subreal_registration(level2, repeat=3)
    initial.append(build_board_pageid_register(level2))

    initialize: list[bytes] = []
    if not level2:
        initialize.extend(build_board_subreal_registration(False))
        initialize.append(build_board_pageid_register(False, repeats=1))
    initialize.append(
        build_board_market_init(level2, stocklink_ver=stocklink_ver)
    )
    initialize.extend(
        build_board_qureal_init(level2, stocklink_ver=stocklink_ver)
    )

    reregister: list[bytes] = []
    if level2:
        for _ in range(3):
            reregister.extend(build_board_subreal_registration(True))
            reregister.append(build_board_pageid_register(True, repeats=1))
    else:
        # 普通账号抓包：第一轮后单独注册一次 pageid，后两轮合并注册两次。
        reregister.extend(build_board_subreal_registration(False))
        reregister.append(build_board_pageid_register(False, repeats=1))
        reregister.extend(build_board_subreal_registration(False, repeat=2))
        reregister.append(build_board_pageid_register(False, repeats=2))

    return initial, initialize, reregister


def build_board_constituent_bootstrap_stages(
    level2: bool,
    side: str,
    *,
    stocklink_ver: str | None = None,
) -> tuple[list[bytes], list[bytes], list[bytes]]:
    """Build the role-specific fu4 bootstrap used by constituent sockets.

    Constituent sockets must be initialised with the **stock** market set, not
    the board-index set: normal (thsuser) uses ``16;32;144;``, L2 沪
    (thsuser) uses ``16;144;`` and L2 深 (__manual) uses ``32;``.  Using the
    board ``96;88;128;216;48;`` set makes fu4 reject every subreal
    registration with ``errorcode=-1`` and the constituent business query then
    returns an empty Sort response.  Constituent streams never send the
    qureal-init pairs used by the board-index channel.
    """
    if side not in ("sh", "sz"):
        raise ValueError("constituent side must be 'sh' or 'sz'")
    if not level2 and side != "sh":
        raise ValueError(
            "normal accounts use one standard constituent socket"
        )
    key = (side, level2)
    market_init = build_board_market_init(
        level2,
        market_code=BOARD_CONSTITUENT_MARKET_CODES[key],
        market_date=BOARD_CONSTITUENT_MARKET_DATE[key],
        stocklink_ver=stocklink_ver,
    )
    if level2:
        # L2 抓包（stream 0/1）：subreal 注册组在前，MKT_INIT 在后，随后再补
        # 一轮 subreal + pageid；成分股连接不发 qureal-init。
        return (
            build_board_subreal_registration(True, repeat=3),
            [market_init],
            build_board_subreal_registration(True)
            + [build_board_pageid_register(True, repeats=1)],
        )
    return (
        [market_init],
        build_board_subreal_registration(False, repeat=2)
        + [build_board_pageid_register(False, repeats=1)],
        build_board_subreal_registration(False)
        + [build_board_pageid_register(False, repeats=1)],
    )


def _route_for(pageid: int) -> int:
    return _ROUTES.get(pageid, 0x0021)


def _datatype_text(datatype: list[int]) -> str:
    return ",".join(str(d) for d in datatype) + ","


def _constituent_market(code: str) -> str:
    """返回板块 CodeList 使用的股票市场码。"""
    if code.startswith(("4", "8", "9")):
        return "151"
    if code.startswith("6"):
        return "17"
    return "33"


def _constituent_codelist(
    codes: list[str],
    markets: dict[str, int | str] | None = None,
) -> str:
    groups: dict[str, list[str]] = {}
    for code in codes:
        market = str(markets.get(code, "")) if markets else ""
        if market in ("-105", "144"):
            market = "151"
        if market not in ("17", "22", "33", "151"):
            market = _constituent_market(code)
        groups.setdefault(market, []).append(code)
    # 客户端常见顺序为沪/深/北；顺序本身不改变查询语义，但固定下来便于回归。
    return "".join(
        f"{market}({','.join(groups[market])},);"
        for market in ("17", "22", "33", "151")
        if market in groups
    )


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
    history_flag: bool = True,
    query_codes: str | None = None,
    route_base: int | None = None,
) -> bytes:
    """构造板块指数查询（双子帧：前缀 + 查询），对齐 2026-08-01 抓包形态。

    ``history_flag`` 控制查询子帧字节 17（0x20）：分时/竞价沿用抓包默认开启，
    板块列表查询（0x130/紧凑表）2026-08-02 起不带该标记。
    ``query_codes`` 提供时查询子帧 CodeList 使用它（真实客户端在查询里携带
    完整 universe，前缀只注册当前可见页）。
    ``route_base`` 覆盖组件路由（页面实例号）。缺省按 ``pageid`` 查
    ``_ROUTES``；热点板块（12480）等页面用相邻实例号，须显式传入
    （普通 0x003A、Level2 0x0053，见 :func:`build_board_hot_query`）。
    """
    route = _route_for(pageid) if route_base is None else route_base
    prefix_text = f"CodeList={market}({code},);\r\npageid={pageid}\r\n"
    if query_codes is None:
        query_codes = code
    query_text = (
        f"CodeList={market}({query_codes},);\r\n"
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
            history_flag=history_flag,
        )
        + query_text
    )
    return encode_frame(b"\x09" + prefix + query)


def build_board_list_query(
    codes: list[str],
    *,
    level2: bool = False,
    datatype: list[int] | None = None,
    universe_codes: list[str] | None = None,
) -> bytes:
    """构造板块列表/行情请求（一次携带全部板块指数代码）。

    2026-08-02 抓包（普通账号 pageid=392）：
    - 前缀子帧 route=0x006C、查询子帧 route=0x016C、seq=0x01C4；
      L2（pageid=5716）为 0x0052/0x0152、seq=0x0068。
    - 查询子帧不带 history flag（字节 17=0x00），``LackTime`` 全 0。
    - 前缀 CodeList 是当前可见页 ``codes``，查询 CodeList 是完整
      ``universe_codes``（缺省与 ``codes`` 相同）。

    2026-08-03 交易日同环境受控复验（双账号，同一板块连接上仅把 route 字节
    改回 0x0039/0x0139，其余字节不变）：旧路由仍返回与当前路由相同的
    0x20/0x1c/0x22 紧凑表（513 行，响应回显请求 route），“旧路由静默”在
    当前环境不成立；08-02 跨机重放无数据更可能来自重放连接缺引导/会话身份，
    非交易日行为未验证。08-01 同路由另有 history flag + LackTime=0,3,… 的
    527527 请求，不能混为同一形态。旧抓包中的 0x130 是板块详情相关板块组件
    的周期推送，解析器仅作兼容保留。
    """
    pageid = PAGEID_BOARD_LIST_L2 if level2 else PAGEID_BOARD_LIST
    if datatype is None:
        datatype = BOARD_QUOTE_DATATYPE_L2 if level2 else BOARD_QUOTE_DATATYPE
    query_codes = (
        ",".join(universe_codes) if universe_codes is not None else None
    )
    return build_board_query(
        ",".join(codes),
        pageid=pageid,
        datatype=datatype,
        period=0,
        args="0-0",
        lack_time="0,0,0,0,0,0,0,0",
        seq=0x0068 if level2 else 0x01C4,
        history_flag=False,
        query_codes=query_codes,
    )


_BOARD_CODES_PATH = Path(__file__).with_name("board_codes.json")


def load_board_full_codes() -> tuple[str, ...]:
    """返回 2026-08-02 抓包确认的板块指数全量代码表（market=48，513 个）。

    包含 881xxx 行业、882xxx、885xxx/886xxx 概念指数；由
    ``board_codes.json`` 固化（来源：普通账号 2026-08-02 全量请求样本），
    后续可改为从板块分类表（[5],[55]）响应动态刷新。
    """
    data = json.loads(_BOARD_CODES_PATH.read_text(encoding="utf-8"))
    return tuple(data["codes"])


def build_board_full_list_query(
    codes: list[str],
    *,
    level2: bool = False,
) -> bytes:
    """构造板块指数全量行情请求（单查询子帧，逐字节对齐 2026-08-02 抓包）。

    请求文本：``CodeList=48(<全部代码>); DataType=527527,
    DateTime=8192(-2-0)``。普通账号 pageid=392、route 0x016C、seq 0x01C6；
    L2 pageid=5716、route 0x0152、seq 0x006A。响应解析见
    :func:`parse_board_full_quote_response`。
    """
    pageid = PAGEID_BOARD_LIST_L2 if level2 else PAGEID_BOARD_LIST
    route = (
        BOARD_FULL_QUOTE_ROUTE_L2
        if level2
        else BOARD_FULL_QUOTE_ROUTE_NORMAL
    )
    seq = BOARD_FULL_QUOTE_SEQ_L2 if level2 else BOARD_FULL_QUOTE_SEQ_NORMAL
    query_text = (
        f"CodeList={BOARD_MARKET}({','.join(codes)},);\r\n"
        f"DataType={_datatype_text(BOARD_FULL_QUOTE_DATATYPE)}\r\n"
        f"DateTime={BOARD_FULL_QUOTE_PERIOD}({BOARD_FULL_QUOTE_ARGS})\r\n"
        "LackTime=0,3,0,0,0,0,0,0\r\n"
        f"pageid={pageid}\r\n"
    ).encode("gbk")
    body = (
        b"\x09"
        + _subframe_header(
            0x0009,
            0x0100 | route,
            seq,
            len(query_text),
            history_flag=True,
        )
        + query_text
    )
    return encode_frame(body)


def build_board_hot_query(
    codes: list[str],
    *,
    level2: bool = False,
    datatype: list[int] | None = None,
    period: int = 0,
    args: str = "0-0",
    lack_time: str = "0,0,0,0,0,0,0,0",
    seq: int | None = None,
    query_codes: list[str] | None = None,
    history_flag: bool = False,
) -> bytes:
    """构造热点板块（94 页面）查询，pageid=12480。

    2026-08-07 双账号抓包确认：热点板块与板块列表（392/5716）共用同一批
    fu4 板块通道连接，请求形态为同构双子帧（前缀 CodeList + 查询
    DataType/DateTime/LackTime/pageid），仅组件路由不同——普通账号
    ``HOT_BOARD_ROUTE_NORMAL``(0x003A/0x013A)，Level2
    ``HOT_BOARD_ROUTE_L2``(0x0053/0x0153)。响应为标准 hd3.1 表
    （普通账号明文 / Level2 走 0x0a 外层压缩），现有板块解析器可直接复用。

    Args:
        codes: 板块指数代码（market=48，如 886099/881101）。
        level2: Level2 账号（默认走普通账号路由）。
        datatype: 查询字段集，缺省 ``HOT_BOARD_DATATYPE``（全字段表）。
        period/args: DateTime 游标（0(0-0) 当日；8192(-2-0) 全量等）。
        lack_time: LackTime 文本。
        seq: 查询子帧序号（会话内实例号，服务端不严格校验）。
        query_codes: 查询子帧携带的完整 universe（缺省与 ``codes`` 相同）。
        history_flag: 查询子帧是否带 0x20 标记（列表查询不带）。
    """
    if not codes:
        raise ValueError("hot board query requires at least one board code")
    pageid = PAGEID_BOARD_HOT
    if datatype is None:
        datatype = HOT_BOARD_DATATYPE
    route_base = HOT_BOARD_ROUTE_L2 if level2 else HOT_BOARD_ROUTE_NORMAL
    if seq is None:
        seq = 0x114A if level2 else 0x1182
    query_codes_text = (
        ",".join(query_codes) if query_codes is not None else ",".join(codes)
    )
    return build_board_query(
        ",".join(codes),
        pageid=pageid,
        datatype=datatype,
        period=period,
        args=args,
        lack_time=lack_time,
        seq=seq,
        history_flag=history_flag,
        query_codes=query_codes_text,
        route_base=route_base,
    )


def build_board_hot_sort_query(
    universe_codes: list[str],
    *,
    visible_codes: list[str] | None = None,
    sort_by: int = HOT_SORT_BY_CHG,
    sort_dir: str = "D",
    sort_begin: int = 0,
    sort_count: int = 26,
    level2: bool = False,
    seq: int | None = None,
) -> bytes:
    """构造热点板块（94 页面）表头排序请求（subtype=0x000f）。

    2026-08-07 排序抓包（kanpan_20260807_231038.pcap）：点击板块表头即发
    ``SortType=Sort`` + ``SortBy=<该列字段>`` + ``SortDir=D/A`` +
    ``SortAppend=YC`` + ``SortBegin/SortCount`` 分页 + ``FuncPeriod=0``。
    SortBy 取值见 ``HOT_SORT_BY_*``（199112 涨幅 / 527527 1分钟涨速 /
    592890 主力净流入 / 271 涨停数 / 38 涨家数 / 39 跌家数 / 48 4分钟涨速）。

    ``universe_codes`` 是全部板块代码；``visible_codes`` 是当前页展示代码
    （用于前置 CodeList 注册）。响应为 ``method=sort`` 文本 + hd3.1 表
    （dt5 代码 + dt15 排序值，``sortcount=26``），由
    :func:`parse_board_hot_sort_response` 解析。
    """
    if not universe_codes:
        raise ValueError("hot board sort requires a code universe")
    if visible_codes is None:
        visible_codes = universe_codes[sort_begin: sort_begin + sort_count]
    if not visible_codes:
        visible_codes = universe_codes[:sort_count]
    pageid = PAGEID_BOARD_HOT
    route_base = HOT_BOARD_ROUTE_L2 if level2 else HOT_BOARD_ROUTE_NORMAL
    if seq is None:
        seq = 0x114A if level2 else 0x1182
    visible_list = f"{BOARD_MARKET}({','.join(visible_codes)},);"
    universe_list = f"{BOARD_MARKET}({','.join(universe_codes)},);"
    prefix_text = (
        f"CodeList={visible_list}\r\npageid={pageid}\r\n"
    ).encode("gbk")
    query_text = (
        f"CodeList={universe_list}\r\n"
        f"DataType={sort_by},\r\n"
        "SortType=Sort\r\n"
        f"SortBy={sort_by}\r\nSortDir={sort_dir}\r\n"
        "SortAppend=YC\r\n"
        f"SortBegin={sort_begin}\r\nSortCount={sort_count}\r\n"
        "FuncPeriod=0\r\nDateTime=0(0-0)\r\n"
        "LackTime=0,0,0,0,0,0,0,0\r\n"
        f"pageid={pageid}\r"
    ).encode("gbk")
    prefix = (
        _subframe_header(0x0002, route_base, 0, len(prefix_text))
        + prefix_text
    )
    query = (
        _subframe_header(
            0x000F, 0x0100 | route_base, seq, len(query_text) + 1
        )
        + query_text
    )
    return encode_frame(b"\x09" + prefix + query)


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
        import datetime
        value = date if date is not None else datetime.date.today()
        bar_start = date_to_normal_timeline_bar(value)
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
        value = date if date is not None else datetime.date.today()
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
    seq: int | None = None,
    include_prefix: bool = True,
    route_base: int | None = None,
    markets: dict[str, int | str] | None = None,
    visible_codes: list[str] | None = None,
    context_market: int | None = None,
) -> bytes:
    """构造板块成分股可见页行情请求。

    2026-08-01 16:37/16:40 冷启动干净包确认：普通账号 pageid=4180，
    最新组件路由为 0x44/0x144；Level2 pageid=6000，两条市场连接均为
    0x5c/0x15c。路由是页面组件实例号，因此保留 ``route_base`` 注入点。

    Level2 的前缀 CodeList 是可见子集，最终查询才携带该市场的完整板块
    universe；沪/深首个事务还分别与 1A0002/399002 上下文打包。上层不得再按
    21 股把最终查询切块。
    """
    if not codes:
        raise ValueError("board constituents requires at least one stock code")
    pageid = PAGEID_BOARD_TL_L2 if level2 else PAGEID_BOARD_TL
    if datatype is None:
        datatype = (
            BOARD_CONSTITUENT_DATATYPE_L2
            if level2
            else BOARD_CONSTITUENT_DATATYPE
        )
    if route_base is None:
        # Component routes are client-side page-instance identifiers.  The
        # clean 2026-08-01 captures used the same base on both L2 market
        # sockets, while an earlier page layout allocated different values.
        route_base = 0x005C if level2 else 0x0044
    prefix_route, query_route = route_base, 0x0100 | route_base
    if seq is None:
        seq = 0x114A if level2 else 0x1182
    code_list = _constituent_codelist(codes, markets)
    visible_list = _constituent_codelist(
        visible_codes if visible_codes is not None else codes,
        markets,
    )
    prefix_text = (
        f"CodeList={visible_list}\r\npageid={pageid}\r\n"
    ).encode("gbk")
    query_text = (
        f"CodeList={code_list}\r\n"
        f"DataType={_datatype_text(datatype)}\r\n"
        f"DateTime=0(0-0)\r\n"
        "LackTime=0,0,0,0,0,0,0,0\r\n"
        f"pageid={pageid}\r"
    ).encode("gbk")
    prefix = (
        _subframe_header(0x0002, prefix_route, 0, len(prefix_text))
        + prefix_text
    )
    query = (
        _subframe_header(
            0x0009,
            query_route,
            seq,
            len(query_text) + 1,
        )
        + query_text
    )
    context = b""
    if level2 and context_market is not None:
        if context_market == 16:
            context_code = "1A0002"
        elif context_market == 32:
            context_code = "399002"
        else:
            raise ValueError("L2 constituent context market must be 16 or 32")
        context_list = f"{context_market}({context_code},);"
        context_query_text = (
            f"CodeList={context_list}\r\n"
            f"DataType={_datatype_text(BOARD_CONSTITUENT_CONTEXT_DATATYPE_L2)}\r\n"
            "DateTime=8192(0-0)\r\n"
            "LackTime=0,3,0,0,0,0,0,0\r\n"
            f"pageid={pageid}\r\n"
        ).encode("gbk")
        context_prefix_text = (
            f"CodeList={context_list}\r\npageid={pageid}\r\n"
        ).encode("gbk")
        context = (
            _subframe_header(
                0x0009,
                0x0157,
                seq - 11,
                len(context_query_text),
                history_flag=True,
            )
            + context_query_text
            + _subframe_header(
                0x0002, 0x0257, 0, len(context_prefix_text)
            )
            + context_prefix_text
        )
    return encode_frame(
        b"\x09" + context + (prefix if include_prefix else b"") + query
    )


def build_board_constituents_page_transition(level2: bool) -> bytes:
    """Close the list-page component before entering the constituent page."""
    pageid = PAGEID_BOARD_LIST_L2 if level2 else PAGEID_BOARD_LIST
    text = f"\r\npageid={pageid}\r".encode("gbk")
    return encode_frame(
        b"\x09" + _subframe_header(0x0002, 0x0401, 0, len(text) + 1) + text
    )


def build_board_constituents_sort_query(
    universe_codes: list[str],
    *,
    visible_codes: list[str] | None = None,
    sort_begin: int = 0,
    sort_count: int = 22,
    sort_by: int = 199112,
    sort_dir: str = "D",
    seq: int = 0x117C,
    route_base: int = 0x0044,
    markets: dict[str, int | str] | None = None,
) -> bytes:
    """构造普通账号 4180 成分股排序/选页请求（subtype=0x0f）。

    ``universe_codes`` 是板块全部成分；``visible_codes`` 是当前页客户端准备
    展示的代码，用于前置 CodeList 注册。服务器返回排序页的股票代码，随后客户端
    再用 527527 和完整字段请求获取该页行情。
    """
    if not universe_codes:
        raise ValueError("board constituent sort requires a code universe")
    if visible_codes is None:
        visible_codes = universe_codes[sort_begin: sort_begin + sort_count]
    if not visible_codes:
        visible_codes = universe_codes[:sort_count]
    pageid = PAGEID_BOARD_TL
    visible_list = _constituent_codelist(visible_codes, markets)
    universe_list = _constituent_codelist(universe_codes, markets)
    prefix_text = (
        f"CodeList={visible_list}\r\npageid={pageid}\r\n"
    ).encode("gbk")
    query_text = (
        f"CodeList={universe_list}\r\n"
        f"DataType={sort_by},\r\n"
        "SortType=Sort\r\n"
        f"SortBy={sort_by}\r\nSortDir={sort_dir}\r\n"
        "SortAppend=YC\r\n"
        f"SortBegin={sort_begin}\r\nSortCount={sort_count}\r\n"
        "FuncPeriod=0\r\nDateTime=0(0-0)\r\n"
        "LackTime=0,0,0,0,0,0,0,0\r\n"
        f"pageid={pageid}\r"
    ).encode("gbk")
    prefix = (
        _subframe_header(0x0002, route_base, 0, len(prefix_text))
        + prefix_text
    )
    query = (
        _subframe_header(
            0x000F, 0x0100 | route_base, seq, len(query_text) + 1
        )
        + query_text
    )
    return encode_frame(b"\x09" + prefix + query)


def build_board_constituents_selection_query(
    codes: list[str],
    *,
    seq: int = 0x1180,
    route_base: int = 0x0044,
    markets: dict[str, int | str] | None = None,
) -> bytes:
    """构造普通账号排序页后的 527527 选择确认请求。"""
    if not codes:
        raise ValueError("board constituent selection requires stock codes")
    pageid = PAGEID_BOARD_TL
    code_list = _constituent_codelist(codes, markets)
    prefix_text = (
        f"CodeList={code_list}\r\npageid={pageid}\r\n"
    ).encode("gbk")
    query_text = (
        f"CodeList={code_list}\r\n"
        "DataType=527527,\r\n"
        "DateTime=0(0-0)\r\n"
        "LackTime=0,0,0,0,0,0,0,0\r\n"
        f"pageid={pageid}\r"
    ).encode("gbk")
    prefix = (
        _subframe_header(0x0002, route_base, 0, len(prefix_text))
        + prefix_text
    )
    query = (
        _subframe_header(
            0x0009, 0x0100 | route_base, seq, len(query_text) + 1
        )
        + query_text
    )
    return encode_frame(b"\x09" + prefix + query)


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
    # 0x42/0x32 固定有 26B shell（与 K线 hd3.1 一致）。旧实现两个 offset
    # 都试，shell 内的随机 4 字节偶尔会碰巧像合法 size，导致整表错位解码。
    # 2026-08-02 全量行情小表另有固定偏移（见 _BOARD_FULL_BITRLE_OFFSET）。
    override = _BOARD_FULL_BITRLE_OFFSET.get((flag, rec_size))
    if override is not None:
        offsets = (ft_end + override,)
    elif flag in (0x42, 0x32):
        offsets = (ft_end + 26,)
    else:
        offsets = (ft_end + 4,)
    for bo in offsets:
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
            # 兼容 0x20 全量表末行代码域尾字节被服务端 padding 污染：
            # 只要前 7 字节（市场标记 + 6 位数字码）合法，就只取前 7 字节。
            prefix = code_bytes[:7]
            if len(prefix) >= 7 and prefix[1:].isdigit():
                code_bytes = prefix
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
        elif fmt in (0x70, 0x64, 0x7B, 0x7C) and width == 4:
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


def parse_board_hot_detail_response(body: bytes) -> list[dict]:
    """解析热点板块（94 页面）详情表（hd3.1 0x40，72B/行）。

    2026-08-07 普通账号抓包（kanpan_20260807_231038.pcap 帧949）：热点板块
    详情请求（pageid=12480，DataType=271,...）的响应帧含多个 hd3.1 表，
    其中 0x40/72B 是详情表，字段：dt5(16B 代码)、dt6 昨收、dt10 最新、
    dt13、dt19、dt38 涨家数、dt39 跌家数、dt90、dt15 涨停数、dt19(16B)、
    dt48 4分钟涨速、dt45。

    885927 CRO概念 实测对照（UI）：涨幅 +8.05% = dt10/dt6-1；涨停数 8 =
    dt15；涨家数 73 = dt38；跌家数 3 = dt39；4分钟涨速 -0.00% = dt48。

    Returns:
        list[dict]，每条含 ``code``/``pre_close``/``price``/``chg_pct``/
        ``limit_up``/``up_count``/``down_count``/``speed_4m``。
    """
    norm = _normalize(body)
    positions = [
        pos for pos in range(len(norm))
        if norm.startswith(b"hd3.1\x00", pos)
    ]
    candidates = (
        [norm] if len(positions) <= 1 else [norm[pos:] for pos in positions]
    )
    records = []
    seen_codes: set[str] = set()
    for candidate in candidates:
        parsed = _hd3_rows(candidate, 0x40)
        if parsed is None:
            continue
        _flag, rec_size, fields, _code, rows = parsed
        for index in range(len(rows) // rec_size):
            row = rows[index * rec_size: (index + 1) * rec_size]
            rec = _decode_row(row, fields)
            code = str(rec.get("code", ""))
            if not code or code in seen_codes:
                continue
            seen_codes.add(code)
            dt6 = rec.get("dt6")
            dt10 = rec.get("dt10")
            chg = None
            if dt6 and dt10:
                chg = (dt10 / dt6 - 1) * 100

            def _field(dt: int):
                # 涨停/涨家/跌家是整数编码的 THS float（fmt=0x48/0x49），
                # _decode_row 只留 raw；这里统一按 u32 → THS float 解码。
                raw = _row_field_raw(row, fields, dt)
                return (
                    decode_ths_float(raw)
                    if raw is not None and raw not in _BOARD_SENTINEL_U32
                    else None
                )

            record = {
                "code": code,
                "pre_close": dt6,
                "price": dt10,
                "chg_pct": chg,
                "limit_up": _field(HOT_DETAIL_LIMIT_UP_DT),
                "up_count": _field(HOT_DETAIL_UP_COUNT_DT),
                "down_count": _field(HOT_DETAIL_DOWN_COUNT_DT),
                "speed_4m": rec.get(f"dt{HOT_DETAIL_SPEED_4M_DT}"),
            }
            for key, value in rec.items():
                record.setdefault(key, value)
            records.append(record)
    return records


def parse_board_hot_sort_response(body: bytes) -> list[dict]:
    """解析热点板块表头排序响应（method=sort + hd3.1 dt5 + dt<SortBy> 表）。

    2026-08-07 排序抓包确认：排序请求（subtype=0x000f，SortBy=<列>）的
    响应为 ``instid=...\\nmethod=sort\\norderlist=\\nrettype=hdfile\\n
    indexname=199112:ZHANGDIEFU;...\\nsortbegin=0\\nsortcalcprogress=1\\
    sortcount=26\\nsorttotal=...`` 文本 + hd3.1 表（dt5 代码 + **dt<SortBy>**
    排序字段值）。**SortBy 值即响应第二个字段的 dt 编号**：

    - ``199112`` → dt200 涨跌幅（ZHANGDIEFU）
    - ``527527`` → dt167 1分钟涨速（onerise）
    - ``592890`` → dt250 主力净流入（bigtrademoneynow）
    - ``271`` → dt15 涨停数；``38`` → dt38 涨家数；``39`` → dt39 跌家数

    返回记录含 ``code`` 与 ``value``（排序字段的 THS float 解码值，单位与
    语义随 SortBy 变化：涨跌幅/涨速为百分比数，主力为元，涨停/涨跌家为个数）。
    """
    parsed = _hd3_rows(body, 0x1C)
    if parsed is None:
        return []
    _flag, rec_size, fields, _code, rows = parsed
    records = []
    for index in range(len(rows) // rec_size):
        row = rows[index * rec_size: (index + 1) * rec_size]
        rec = _decode_row(row, fields)
        record = {"code": rec.get("code")}
        for d, _fmt, width in fields:
            if d == 5:
                continue
            raw = _row_field_raw(row, fields, d)
            if raw is not None and raw not in _BOARD_SENTINEL_U32:
                record["value"] = decode_ths_float(raw)
                record[f"dt{d}"] = decode_ths_float(raw)
            elif width == 4:
                record["value"] = None
                record[f"dt{d}"] = None
        records.append(record)
    return records


def _row_field_raw(
    row: bytes,
    fields: list[tuple[int, int, int]],
    datatype: int,
) -> int | None:
    """返回行内指定 datatype 的 4 字节原始 u32（用于哨兵判定）。"""
    offset = 0
    for d, _fmt, width in fields:
        if d == datatype and width == 4 and offset + 4 <= len(row):
            return struct.unpack("<I", row[offset:offset + 4])[0]
        offset += width
    return None


def parse_board_full_quote_response(body: bytes) -> list[dict]:
    """解析板块指数全量行情响应（2026-08-02 抓包确认的三表合并）。

    一个响应周期含多帧/多表（DataType=527527）：

    - ``0x20`` 28B：dt5 代码 + dt6 昨收 + dt10 最新 + dt48 4分钟涨速（513 行）
    - ``0x1c`` 24B：dt5 + dt10 + dt48（0x20 子集，兼容）
    - ``0x1c`` 11B：dt5(7B) + dt250 主力净流入金额（513 行）
    - ``0x22`` 15B：dt5(7B) + dt1 bar + dt167 1分钟涨速（513×3 行，每组取
      bar 最大的一行）

    涨幅由客户端按 ``(dt10/dt6-1)`` 计算；``0xFFFFFFFF`` 哨兵在
    ``chg_pct/speed_4m/speed_1m/main_inflow`` 友好字段里映射为 ``None``
    （同花顺 UI 显示“-”），原始 ``dt*`` 键仍保留 THS float 解码值。
    """
    norm = _normalize(body)
    positions = [
        pos for pos in range(len(norm))
        if norm.startswith(b"hd3.1\x00", pos)
    ]
    candidates = [norm] if len(positions) <= 1 else [norm[pos:] for pos in positions]
    merged: dict[str, dict] = {}

    def merge(record: dict) -> None:
        code = str(record.get("code", ""))
        if not code:
            return
        target = merged.setdefault(code, {"code": code})
        for key, value in record.items():
            if key != "code":
                target.setdefault(key, value)

    for candidate in candidates:
        for flag in BOARD_FULL_QUOTE_FLAGS:
            parsed = _hd3_rows(candidate, flag)
            if parsed is None:
                continue
            _flag, rec_size, fields, _code, rows = parsed
            n = len(rows) // rec_size
            if flag == 0x22:
                # 每板块 3 行（dt1 三个相邻 bar），1分钟涨速取 bar 最大的一行
                group: dict[str, list[dict]] = {}
                for index in range(n):
                    row = rows[index * rec_size: (index + 1) * rec_size]
                    rec = _decode_row(row, fields)
                    code = str(rec.get("code", ""))
                    if code:
                        group.setdefault(code, []).append(rec)
                for code, recs in group.items():
                    best = max(
                        recs,
                        key=lambda r: r.get("bar_index", 0) or 0,
                    )
                    merge(best)
                continue
            for index in range(n):
                row = rows[index * rec_size: (index + 1) * rec_size]
                rec = _decode_row(row, fields)
                for dt in (6, 10, 48, 167, 250):
                    raw = _row_field_raw(row, fields, dt)
                    if raw is not None:
                        rec[f"dt{dt}_raw"] = raw
                merge(rec)

    records = []
    for code, rec in merged.items():
        dt6 = rec.get("dt6")
        dt10 = rec.get("dt10")
        dt6_raw = rec.get("dt6_raw")
        chg = None
        if (
            dt6 is not None
            and dt10 is not None
            and dt6_raw not in _BOARD_SENTINEL_U32
            and dt6
        ):
            chg = (dt10 / dt6 - 1) * 100
        row = {
            "code": code,
            "name": rec.get("name"),
            "pre_close": dt6,
            "price": dt10,
            "chg_pct": chg,
            "speed_4m": (
                None
                if rec.get("dt48_raw") in _BOARD_SENTINEL_U32
                else rec.get("dt48")
            ),
            "speed_1m": (
                None
                if rec.get("dt167_raw") in _BOARD_SENTINEL_U32
                else rec.get("dt167")
            ),
            "main_inflow": (
                None
                if rec.get("dt250_raw") in _BOARD_SENTINEL_U32
                else rec.get("dt250")
            ),
        }
        for key, value in rec.items():
            row.setdefault(key, value)
        records.append(row)
    return records


def parse_board_constituents_response(body: bytes) -> list[dict]:
    """解析双账号板块成分股行情。

    Level2 返回 0x64/95B；普通账号按字段集合返回 0x44/59B 或 0x50/71B。
    三种表都含 dt5 股票代码，因此可以统一逐行解码。
    """
    norm = _normalize(body)
    positions = [
        pos for pos in range(len(norm))
        if norm.startswith(b"hd3.1\x00", pos)
    ]
    candidates = [norm] if len(positions) <= 1 else [norm[pos:] for pos in positions]
    records = []
    seen_codes: set[str] = set()
    for candidate in candidates:
        parsed = _hd3_rows(candidate, 0x64, 0x44, 0x50)
        if parsed is None:
            continue
        _flag, rec_size, fields, _code, rows = parsed
        for index in range(len(rows) // rec_size):
            row = rows[index * rec_size: (index + 1) * rec_size]
            record = _decode_row(row, fields)
            code = str(record.get("code", ""))
            if code and code in seen_codes:
                continue
            if code:
                seen_codes.add(code)
            records.append(record)
    return records


def parse_board_constituents_selection_response(body: bytes) -> list[dict]:
    """解析普通账号 4180 排序/527527 响应中的代码页。"""
    return parse_stock_list_response(body).get("stocks", [])


def parse_board_timeline_response(body: bytes) -> list[dict]:
    """解析板块指数分时（hd3.1 0x42，7 字段，242 点/日）。

    dt1 是 packed-date bar 游标（与股票历史分时一致），这里附上
    ``date`` 与 ``minute_index``。

    2026-08-02 抓包发现服务端对日K 查询（DateTime=16384）也回 0x42 表
    （字段 [1,7,8,9,11,19,13]，dt1=YYYYMMDD，596 根/次），因此必须按
    字段集区分：非分时字段集（[1,10,13,19,22,23,40]）返回空，避免把
    日K 误当分时。
    """
    parsed = _hd3_rows(body, 0x42)
    if parsed is None:
        return []
    _flag, rec_size, fields, code, rows = parsed
    if {dt for dt, _fmt, _width in fields} != {1, 10, 13, 19, 22, 23, 40}:
        return []
    records = []
    for index in range(len(rows) // rec_size):
        row = rows[index * rec_size: (index + 1) * rec_size]
        record = _decode_row(row, fields)
        bar = record.get("bar_index")
        if bar is not None:
            try:
                parsed_date = normal_timeline_bar_to_date(bar).date()
                # 0x42 首行可能是基准价/前收哨兵，dt1 不是 packed-date 游标；
                # 不应把它渲染成 3967 年之类的伪日期。
                if 1990 <= parsed_date.year <= 2100:
                    record["date"] = parsed_date
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
    "BOARD_CONSTITUENT_DATATYPE",
    "BOARD_CONSTITUENT_DATATYPE_L2",
    "BOARD_CONSTITUENT_CONTEXT_DATATYPE_L2",
    "BOARD_CONSTITUENT_MARKET_CODES",
    "BOARD_CONSTITUENT_MARKET_DATE",
    "build_board_query",
    "build_board_list_query",
    "build_board_timeline_query",
    "build_board_auction_query",
    "build_board_constituents_query",
    "build_board_constituents_page_transition",
    "build_board_constituent_bootstrap_stages",
    "build_board_constituents_sort_query",
    "build_board_constituents_selection_query",
    "parse_board_quote_response",
    "parse_board_constituents_response",
    "parse_board_constituents_selection_response",
    "parse_board_timeline_response",
    "parse_board_auction_response",
]
