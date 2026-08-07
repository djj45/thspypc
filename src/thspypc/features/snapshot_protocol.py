"""Pure Level2 snapshot-subscription request protocol."""
from __future__ import annotations

import struct

from ..codecs.framing import encode_frame
from ..codecs.numeric import decode_ths_float


SNAPSHOT_PAGEID = 4214
SNAPSHOT_PAGEID_SUB = 5716
SNAPSHOT_SUBTYPE = b"\x12\x00\x02\x00"
SNAPSHOT_DATATYPE = [10, 24, 30, 69, 70, 127]
MARKET_SNAPSHOT_MARKETS = [
    16,
    17,
    18,
    19,
    20,
    22,
    144,
    145,
    146,
    147,
    150,
    151,
]
MARKET_SNAPSHOT_DATATYPE = [5, 55]


def build_market_snapshot_query(
    markets: list[int] | tuple[int, ...] | None = None,
    datatype: list[int] | None = None,
    pageid: int = 5716,
    seq: int = 0x0001,
) -> bytes:
    """Build the MAIN-channel query for a whole-market HFD1 snapshot."""
    if markets is None:
        markets = MARKET_SNAPSHOT_MARKETS
    if datatype is None:
        datatype = MARKET_SNAPSHOT_DATATYPE

    codelist = "".join(f"{market}();" for market in markets)
    datatype_text = ",".join(f"[{value}]" for value in datatype)
    text = (
        f"DataType={datatype_text}\r\n"
        f"CodeList={codelist}\r\n"
        f"DateTime=0\r\n"
        f"pageid={pageid}\r"
    ).encode("gbk")

    header = bytearray(23)
    header[0] = 0x09
    header[1:5] = b"\x00\x16\x00\x00"
    struct.pack_into("<H", header, 5, seq & 0xFFFF)
    header[7:11] = b"\x12\x00\x09\x00"
    header[11:13] = b"\x00\x01"
    struct.pack_into("<H", header, 19, len(text) + 1)
    return encode_frame(bytes(header) + text)


def build_snapshot_subscribe(
    code: str,
    market: int = 17,
    pageid: int = SNAPSHOT_PAGEID,
    seq: int = 0x0086,
    datatype: list[int] | None = None,
    inner_seq: int = 0x0071,
) -> bytes:
    """Build the nested pageid=4214 registration and initial query."""
    if not code or not code.isdigit():
        raise ValueError(f"code 必须为纯数字: {code!r}")
    if datatype is None:
        datatype = SNAPSHOT_DATATYPE

    outer_text = (
        f"CodeList={market}({code},);\r\npageid={pageid}\r\n"
    ).encode("gbk")
    datatype_text = ",".join(str(value) for value in datatype) + ","
    inner_text = (
        f"CodeList={market}({code},);\r\n"
        f"DataType={datatype_text}\r\n"
        f"DateTime=0(0-0)\r\n"
        f"LackTime=0,0,0,0,0,0,0,0\r\n"
        f"pageid={pageid}\r\n"
    ).encode("gbk")

    inner_header = bytearray(22)
    inner_header[0:4] = b"\x00\x16\x00\x00"
    struct.pack_into("<H", inner_header, 4, inner_seq & 0xFFFF)
    inner_header[6:10] = b"\x12\x00\x09\x00"
    inner_header[10:12] = b"\x00\x01"
    struct.pack_into("<I", inner_header, 18, len(inner_text))
    inner_frame = bytes(inner_header) + inner_text

    header = bytearray(23)
    header[0] = 0x09
    header[1:5] = b"\x00\x16\x00\x00"
    struct.pack_into("<H", header, 5, seq & 0xFFFF)
    header[7:11] = SNAPSHOT_SUBTYPE
    header[11:13] = b"\x02\x00"
    struct.pack_into("<I", header, 19, len(outer_text))
    return encode_frame(bytes(header) + outer_text + inner_frame)


def parse_snapshot_push(body: bytes) -> dict | None:
    """Parse the 71-byte Level2 tick-by-tick push frame.

    2026-08-07 盘中抓包破译（002384 东山精密 ~197 元对照确认）::

        [0]     0x09            帧类型标记
        [1-4]   09 7b d0 01     魔数（推送帧头）
        [28]    市场标记         0x11=沪 0x21=深
        [29-34] ASCII 代码       6 位股票代码
        [39-42] u32 LE           序号（递增）
        [47-50] ths_float        **成交价格**
        [51-52] u16 LE           **成交量（股）**
        [55]    1/5              **方向**（1=主动买 5=主动卖）
        [59-62] u32 LE           被动方序号

    帧间隔平均 0.11 秒（真逐笔），非定时快照。
    """
    if not is_snapshot_push(body):
        return None

    code = body[29:35].decode("ascii")
    market_flag = body[28]
    market = (
        "SH"
        if market_flag == 0x11
        else "SZ"
        if market_flag == 0x21
        else f"?{market_flag:#x}"
    )
    return {
        "code": code,
        "market": market,
        "price": decode_ths_float(struct.unpack("<I", body[47:51])[0]),
        "volume": struct.unpack("<H", body[51:53])[0],
        "direction": body[55],
        "seq": struct.unpack("<I", body[39:43])[0],
        "raw_len": len(body),
    }


def is_snapshot_push(body: bytes) -> bool:
    """Return whether ``body`` matches the 71-byte tick push shape."""
    return (
        len(body) == 71
        and body[0] == 0x09
        and body[1:4] == b"\x7b\xd0\x01"
        and all(0x30 <= value <= 0x39 for value in body[29:35])
    )


# ── 549B 十档盘口推送（2026-08-07 盘中破译）──
# magic = 09 7b d0 0f，含完整十档买卖价量。
# 布局（相对帧起点）：
#   [1:5]   magic 7b d0 0f 7f
#   [28]    市场标记 0x21=深 0x11=沪
#   [29:35] ASCII 代码
#   [51:67] 昨收/开盘/最高/最低/现价 (5×4B ths_float)
#   [67:95] 成交量/额等
#   [95:143] 买1买2买3 卖1卖2卖3 (6对×8B: 4B ths_float价 + 4B u32量)
#   [143:147] 4B 间隔
#   [147:179] 买4 卖4 买5 卖5 (4对×8B)
#   [179:195] 16B 间隔块
#   [195:267] 买6-买10 卖6-卖10 (10对×8B)
_DEPTH_PUSH_MAGIC = b"\x7b\xd0\x0f"


def is_depth_push(body: bytes) -> bool:
    """Return whether ``body`` matches the ~549B ten-level depth push shape."""
    return (
        len(body) >= 300
        and body[0] == 0x09
        and body[1:4] == _DEPTH_PUSH_MAGIC
        and all(0x30 <= value <= 0x39 for value in body[45:51])
    )


def parse_depth_push(body: bytes) -> dict | None:
    """Parse the ~549B ten-level depth push frame.

    2026-08-07 盘中破译（002384 东山精密 ~200 元对照确认）。
    含完整十档买卖价量 + 昨收/开盘/最高/最低/现价。
    """
    if not is_depth_push(body):
        return None

    code = body[45:51].decode("ascii")
    market_flag = body[44]
    market = (
        "SH" if market_flag == 0x11
        else "SZ" if market_flag == 0x21
        else f"?{market_flag:#x}"
    )

    def _f(off):
        return decode_ths_float(struct.unpack("<I", body[off:off + 4])[0])

    def _u32(off):
        return struct.unpack("<I", body[off:off + 4])[0]

    # 十档：价量对，4B gap 后再继续
    def _pair(off):
        return round(_f(off), 3), _u32(off + 4)

    # 前 3 档买卖 (6对 @95-142)
    pairs = []
    off = 95
    for _ in range(6):
        pairs.append(_pair(off))
        off += 8
    off += 4  # 4B 间隔 @143
    # 买4 卖4 买5 卖5 (4对 @147-178)
    for _ in range(4):
        pairs.append(_pair(off))
        off += 8
    off += 16  # 16B 间隔块 @179-194
    # 买6-买10 卖6-卖10 (10对 @195-266)
    for _ in range(10):
        if off + 8 > len(body):
            break
        pairs.append(_pair(off))
        off += 8

    return {
        "code": code,
        "market": market,
        "price": _f(67),       # 现价
        "prev_close": _f(51),  # 昨收
        "open": _f(55),        # 开盘
        "high": _f(59),        # 最高
        "low": _f(63),         # 最低
        # 十档：买1-买5 价/量, 卖1-卖5 价/量, 买6-买10, 卖6-卖10
        # pairs 顺序: 买1买2买3卖1卖2卖3 买4卖4买5卖5 买6卖6买7卖7买8卖8买9卖9买10卖10
        "bids": [pairs[i] for i in [0, 1, 2, 6, 8, 10, 12, 14, 16, 18] if i < len(pairs)],
        "asks": [pairs[i] for i in [3, 4, 5, 7, 9, 11, 13, 15, 17, 19] if i < len(pairs)],
        "raw_len": len(body),
    }


__all__ = [
    "MARKET_SNAPSHOT_DATATYPE",
    "MARKET_SNAPSHOT_MARKETS",
    "SNAPSHOT_DATATYPE",
    "SNAPSHOT_PAGEID",
    "SNAPSHOT_PAGEID_SUB",
    "SNAPSHOT_SUBTYPE",
    "build_market_snapshot_query",
    "build_snapshot_subscribe",
    "is_snapshot_push",
    "parse_snapshot_push",
    "is_depth_push",
    "parse_depth_push",
]
