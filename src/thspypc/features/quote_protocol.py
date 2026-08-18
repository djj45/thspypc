"""Pure request and response protocol for list quotes and five-level depth."""
from __future__ import annotations

import struct

from ..codecs.framing import encode_frame
from ..codecs.numeric import decode_ths_float
from ..models import DepthLevel, DepthQuote


LIST_QUOTE_DATATYPE_DEFAULT = [7, 49, 13, 48, 10, 17, 6, 66, 1111]


def build_list_quote_query(
    codes: list[str],
    market: int = 17,
    datatype: list[int] | None = None,
    pageid: int = 1335,
    seq: int = 0x0025,
) -> bytes:
    """构造 8901 端口个股列表行情请求帧。"""
    if datatype is None:
        datatype = LIST_QUOTE_DATATYPE_DEFAULT
    codes_str = ",".join(codes) + ("," if codes else "")
    market_str = f"{market}({codes_str})"
    datatype_text = ",".join(str(value) for value in datatype) + ","
    text = (
        f"CodeList={market_str};\r\nDataType={datatype_text}\r\n"
        f"DateTime=0(0-0)\r\nLackTime=0,0,0,0,0,0,0,0\r\n"
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


DEPTH_QUOTE_DATATYPE = [
    13,
    18,
    24,
    25,
    26,
    27,
    28,
    29,
    30,
    31,
    32,
    33,
    34,
    35,
    122,
    123,
    124,
    125,
    150,
    151,
    152,
    153,
    154,
    155,
    156,
    157,
]

# 买/卖十档价量字段对（2026-07-28 L2 抓包确认；一~五档旧已知，六~十档
# dt102-121）。解析时按响应字段表实际出现情况输出，五档响应自然只有五档。
BUY_LEVEL_FIELDS = [
    ("买一", 24, 25),
    ("买二", 26, 27),
    ("买三", 28, 29),
    ("买四", 150, 151),
    ("买五", 154, 155),
    ("买六", 102, 103),
    ("买七", 106, 107),
    ("买八", 110, 111),
    ("买九", 114, 115),
    ("买十", 118, 119),
]

SELL_LEVEL_FIELDS = [
    ("卖一", 30, 31),
    ("卖二", 32, 33),
    ("卖三", 34, 35),
    ("卖四", 152, 153),
    ("卖五", 156, 157),
    ("卖六", 104, 105),
    ("卖七", 108, 109),
    ("卖八", 112, 113),
    ("卖九", 116, 117),
    ("卖十", 120, 121),
]

# 十档请求在五档 DataType 基础上追加六~十档价量字段，顺序对齐 2026-07-28
# 抓包：24-35 → 102-121 → 122-125 → 150-157（与五档常量顺序不同）
DEPTH_QUOTE_DATATYPE_10 = (
    DEPTH_QUOTE_DATATYPE[:14]
    + list(range(102, 122))
    + DEPTH_QUOTE_DATATYPE[14:]
)


def build_depth_quote_query(
    code: str,
    market: int = 33,
    datatype: list[int] | None = None,
    pageid: int = 1333,
    seq: int = 0x0000,
    inner_seq: int = 0x0163,
    ten_levels: bool = False,
) -> bytes:
    """构造个股盘口嵌套请求帧（默认五档；``ten_levels=True`` 追加六~十档字段）。"""
    if datatype is None:
        datatype = DEPTH_QUOTE_DATATYPE_10 if ten_levels else DEPTH_QUOTE_DATATYPE
    market_text = f"{market}({code},)"
    datatype_text = ",".join(str(value) for value in datatype) + ","

    outer_text = (
        f"CodeList={market_text};\r\npageid={pageid}\r\n"
    ).encode("gbk")
    inner_text = (
        f"CodeList={market_text};\r\nDataType={datatype_text}\r\n"
        f"DateTime=0(0-0)\r\nLackTime=0,0,0,0,0,0,0,0\r\n"
        f"pageid={pageid}\r"
    ).encode("gbk")

    inner_header = bytearray(22)
    inner_header[0:4] = b"\x00\x16\x00\x00"
    struct.pack_into("<H", inner_header, 4, inner_seq & 0xFFFF)
    inner_header[6:10] = b"\x12\x00\x09\x00"
    inner_header[10:12] = b"\x00\x01"
    struct.pack_into("<H", inner_header, 18, len(inner_text) + 1)
    inner_frame = bytes(inner_header) + inner_text

    outer_header = bytearray(23)
    outer_header[0] = 0x09
    outer_header[1:5] = b"\x00\x16\x00\x00"
    struct.pack_into("<H", outer_header, 5, seq & 0xFFFF)
    outer_header[7:11] = b"\x12\x00\x02\x00"
    outer_header[11:13] = b"\x1c\x00"
    struct.pack_into("<H", outer_header, 19, len(outer_text))
    body = bytes(outer_header) + outer_text + inner_frame
    return encode_frame(body)


def build_depth_ten_query(
    code: str,
    market: int = 33,
    pageid: int = 4214,
    seq: int = 0x00CB,
    datatype: list[int] | None = None,
) -> bytes:
    """构造 Level2 十档盘口查询（单子帧 pageid=4214，2026-07-28 抓包真值）。

    十档仅 Level2 账号可用，且必须在**对应市场的 L2 连接**（沪 shlv2 / 深
    szlv2）上发送；在 MAIN 连接上即使带完整 DataType（含 dt102-121）也只回
    0xFFFFFFFF 哨兵（深层档位为空）。抓包原始帧
    ``tests/fixtures/depth10/req_000938_4214_ten.bin`` 与本函数输出逐字节一致。
    """
    if datatype is None:
        datatype = DEPTH_QUOTE_DATATYPE_10
    text = (
        f"CodeList={market}({code},);\r\n"
        f"DataType={','.join(str(value) for value in datatype)},\r\n"
        f"DateTime=0(0-0)\r\n"
        f"LackTime=0,0,0,0,0,0,0,0\r\n"
        f"pageid={pageid}\r\n"
    ).encode("gbk")
    header = bytearray(23)
    header[0] = 0x09
    header[1:5] = b"\x00\x16\x00\x00"
    struct.pack_into("<H", header, 5, seq & 0xFFFF)
    header[7:11] = b"\x12\x00\x09\x00"
    header[11:13] = b"\x00\x01"
    struct.pack_into("<I", header, 19, len(text))
    return encode_frame(bytes(header) + text)


def parse_depth_quote_response(body: bytes) -> DepthQuote:
    """解析个股盘口响应（五档/十档自适应）并计算涨跌停封单额。"""
    pos = body.find(b"hd1.0")
    if pos < 0:
        return {}
    base = pos + 6
    if base + 10 > len(body):
        return {}
    data_count = struct.unpack("<I", body[base : base + 4])[0]
    row_size = struct.unpack("<H", body[base + 6 : base + 8])[0]
    field_count = struct.unpack("<H", body[base + 8 : base + 10])[0]
    if not (
        0 < data_count < 100
        and 0 < row_size < 500
        and 0 < field_count < 64
    ):
        return {}

    field_table_offset = base + 10
    field_table = body[
        field_table_offset : field_table_offset + field_count * 4
    ]
    if len(field_table) < field_count * 4:
        return {}
    fields = [
        (
            field_table[index * 4],
            field_table[index * 4 + 1],
            field_table[index * 4 + 3],
        )
        for index in range(field_count)
    ]
    if not any(dt == 24 for dt, _, _ in fields):
        return {}

    record_offset = field_table_offset + field_count * 4
    record: dict = {}
    for dt, fmt, width in fields:
        chunk = body[record_offset : record_offset + width]
        record_offset += width
        if len(chunk) < width:
            # 服务端偶发：记录区比 hs 少 1 字节，且末字段是 0xFFFFFFFF 哨兵
            # 时截掉最后一个字节（活网 600519 十档实测）。只对纯 0xff 前缀
            # 补齐哨兵，避免中断整行解析；其他截断仍按原逻辑放弃。
            if chunk == b"\xff" * len(chunk):
                chunk = chunk + b"\xff" * (width - len(chunk))
            else:
                break
        if dt == 5 and fmt == 0x20:
            record["code"] = (
                chunk[1 : 1 + 6]
                .split(b"\x00")[0]
                .decode("ascii", errors="replace")
            )
        elif width == 4:
            record[f"dt{dt}"] = decode_ths_float(
                struct.unpack("<I", chunk)[0]
            )

    def build_levels(level_fields) -> list[DepthLevel]:
        levels: list[DepthLevel] = []
        for level, price_key, quantity_key in level_fields:
            price = record.get(f"dt{price_key}")
            quantity = record.get(f"dt{quantity_key}")
            if price is not None and quantity is not None:
                levels.append(
                    {
                        "level": level,
                        "price": price,
                        "qty": quantity,
                        "amount": price * quantity if price else 0.0,
                    }
                )
        return levels

    buy = build_levels(BUY_LEVEL_FIELDS)
    sell = build_levels(SELL_LEVEL_FIELDS)

    buy_one_quantity = record.get("dt25", 0)
    sell_one_quantity = record.get("dt31", 0)
    seal_amount = 0.0
    seal_type = None
    if (
        sell_one_quantity == 0
        and buy_one_quantity > 0
        and "dt24" in record
    ):
        seal_amount = record["dt24"] * record["dt25"]
        seal_type = "涨停"
    elif (
        buy_one_quantity == 0
        and sell_one_quantity > 0
        and "dt30" in record
    ):
        seal_amount = record["dt30"] * record["dt31"]
        seal_type = "跌停"

    return {
        "code": record.get("code", ""),
        "buy": buy,
        "sell": sell,
        "seal_amount": seal_amount,
        "seal_type": seal_type,
        "fields": {
            key: value
            for key, value in record.items()
            if key.startswith("dt")
        },
    }


# 统一列表字段请求：dt5 代码 dt6 昨收 dt7 今开 dt10 最新 dt17 竞价量
# dt19 成交额 dt48 4分钟涨速 dt66 涨幅。竞价/涨幅列由本地派生计算
# （竞价金额 = dt17×dt7，涨幅 = (dt10-dt6)/dt6），与 list_quotes 既有
# 口径一致（dt66 盘外恒 0，不可直接用）。
STOCK_QUOTE_FIELDS_DATATYPE = [5, 6, 7, 10, 17, 19, 48, 66]

# 0xc4 金额表请求字段集（2026-08-18 同花顺客户端抓包原文顺序，
# captures_live/stocklist_page_20260818_185944.pcapng，pageid=1334）。
# 响应为 hd3.1 变体 0xc4（大批量 BitRLE+64B 前导）或 hd1.0 同款小批量
# 明文（60B 前导），字段 fmt 0x79/0x7B 与 0x70 同为 THS 定点浮点。
# 已活网验证的响应字段：dt250=主力净额(元)、dt248=DDE 主力(亿，
# 与 /api/dde_rank 逐码一致)、dt202=总市值(元)、dt13=成交量(股)。
# ⚠ 单代码请求服务器不应答，调用方须保证每批 ≥2 个代码。
MONEY_QUOTE_DATATYPE = [
    7, 49, 13, 461256, 70, 27, 127, 48, 12, 69, 33,
    1968584, 2942, 592890, 25, 10, 17, 24, 31, 9,
    3541450, 592888, 2947, 30, 8, 6, 45, 66, 1111,
]


def derive_list_quote_fields(record: dict) -> dict:
    """把 list_quotes 原始 dt 字段派生成统一列表行。

    Args:
        record: ``list_quotes`` 返回的单条记录（含 ``dt6/dt7/dt10/dt17/
            dt19/dt48``，0xc4 金额表记录额外可含 ``dt250/dt248/dt202``）。

    Returns:
        ``{code, price, chg_pct, auction_chg_pct, auction_amount, amount,
        speed_4m, main_inflow, dde_main, market_cap}``；昨收为 0/缺失
        （停牌等）时派生列为 ``None``。成交额优先 dt19，缺失时用
        dt13(成交量股)×dt10 本地计算（0xc4 表无 dt19）。
    """

    def pct(new, base) -> float | None:
        if new is None or not base:
            return None
        return round((new - base) / base * 100, 2)

    dt6 = record.get("dt6")
    dt7 = record.get("dt7")
    dt10 = record.get("dt10")
    dt13 = record.get("dt13")
    dt17 = record.get("dt17")
    amount = record.get("dt19")
    if amount is None and dt13 is not None and dt10 is not None:
        amount = dt13 * dt10
    return {
        "code": record.get("code", ""),
        "price": dt10,
        "chg_pct": pct(dt10, dt6),
        "auction_chg_pct": pct(dt7, dt6),
        "auction_amount": (
            dt17 * dt7 if dt17 is not None and dt7 is not None else None
        ),
        "amount": amount,
        "speed_4m": record.get("dt48"),
        "main_inflow": record.get("dt250"),
        "dde_main": record.get("dt248"),
        "market_cap": record.get("dt202"),
    }
