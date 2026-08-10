"""Pure Level2 snapshot-subscription request protocol."""
from __future__ import annotations

import struct
from datetime import datetime

from ..codecs.framing import encode_frame
from ..codecs.numeric import decode_ths_float
from ..codecs.quote_stream import normalize_stock_depth_push


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
        and body[1:5] == b"\x7b\xd0\x01\x7f"
        and all(0x30 <= value <= 0x39 for value in body[29:35])
    )


_AUCTION_CANCEL_SIDES = {0x08: "buy", 0x0C: "sell"}


def is_auction_cancel_push(body: bytes) -> bool:
    """Return whether ``body`` is a 71-byte opening-auction cancel push.

    The ``0x60`` subtype is distinct from the ``0x7f`` trade-tick subtype.
    Its two embedded code markers must agree; this prevents an adjacent or
    truncated 71-byte payload from being accepted accidentally.
    """
    return (
        len(body) == 71
        and body[0:5] == b"\x09\x7b\xd0\x01\x60"
        and body[5] in _AUCTION_CANCEL_SIDES
        and body[28] in (0x11, 0x21)
        and body[43] == body[28]
        and body[29:35] == body[44:50]
        and body[29:35].isdigit()
        and body[-1] == 0x7D
    )


def parse_auction_cancel_push(body: bytes) -> dict | None:
    """Parse one 71-byte opening-auction order-cancellation event.

    Verified against the PC client's order/cancel view for ``002428`` on
    2026-08-10.  The UI's ``买撤``/``卖撤`` rows map to marker ``0x08``/
    ``0x0c`` respectively.  The UI suffix beside the cancel side is exactly
    ``cancelled_at - placed_at`` (for example ``30s`` or ``4m``).

    ``volume`` is expressed in shares, matching the rest of the public quote
    parsers; ``lots`` exposes the PC view's 100-share 手 unit.
    """
    if not is_auction_cancel_push(body):
        return None

    market_flag = body[43]
    placed_timestamp = struct.unpack_from("<I", body, 50)[0]
    cancelled_timestamp = struct.unpack_from("<I", body, 54)[0]
    volume = struct.unpack_from("<I", body, 62)[0]
    side_raw = body[5]
    return {
        "code": body[44:50].decode("ascii"),
        "market": "SH" if market_flag == 0x11 else "SZ",
        "event": "auction_cancel",
        "side": _AUCTION_CANCEL_SIDES[side_raw],
        "side_raw": side_raw,
        "placed_at": datetime.fromtimestamp(placed_timestamp),
        "cancelled_at": datetime.fromtimestamp(cancelled_timestamp),
        "placed_timestamp": placed_timestamp,
        "cancelled_timestamp": cancelled_timestamp,
        "lifetime_seconds": cancelled_timestamp - placed_timestamp,
        "price": decode_ths_float(struct.unpack_from("<I", body, 58)[0]),
        "volume": volume,
        "lots": volume / 100,
        # The PC view used for side/price/volume truth does not display this
        # value.  Preserve it without over-claiming its exact order-ID role.
        "aux_id": struct.unpack_from("<I", body, 66)[0],
        "seq": struct.unpack_from("<I", body, 39)[0],
        "raw_len": len(body),
    }


# ── 550B 十档盘口推送（2026-08-07 盘中破译）──
# magic = 09 7b d0 0f，含完整十档买卖价量。
# 布局（相对帧起点）：
#   [1:5]   magic 7b d0 0f 7f
#   [44]    市场标记 0x21=深 0x11=沪
#   [45:51] ASCII 代码
#   [51:67] 昨收/开盘/最高/最低/现价 (5×4B ths_float)
#   [67:95] 成交量/额等
#   [95:143] 买1买2买3 卖1卖2卖3 (6对×8B: 4B ths_float价 + 4B u32量)
#   [143:147] 4B 间隔
#   [147:179] 买4 卖4 买5 卖5 (4对×8B)
#   [179:195] 16B 间隔块
#   [195:267] 买6-买10 卖6-卖10 (10对×8B)
_DEPTH_PUSH_MAGIC = b"\x7b\xd0\x0f\x7f"
_DEPTH_PUSH_MARKETS = {0x11: "SH", 0x21: "SZ"}
_AUCTION_IMBALANCE_SELL = 0x08000000
_AUCTION_IMBALANCE_MASK = 0x07FFFFFF
# A complete continuous-book record ends 505 bytes after the first code byte:
# code at 45 in a 550B frame, or at 213 in a 718B prefixed frame.
_CONTINUOUS_DEPTH_RECORD_END = 505


def _find_depth_code(body: bytes) -> tuple[int, int, str] | None:
    """Locate ``market marker + six digit code`` inside a 0x0f push.

    The 2026-08-10 opening-auction capture showed that a push body may prepend
    status text or another compact record.  The stock block therefore starts
    at a variable offset even though fields relative to its code are stable.
    """
    for market_pos in range(5, max(5, len(body) - 6)):
        market_flag = body[market_pos]
        if market_flag not in _DEPTH_PUSH_MARKETS:
            continue
        code_raw = body[market_pos + 1 : market_pos + 7]
        if len(code_raw) != 6 or not all(0x30 <= value <= 0x39 for value in code_raw):
            continue
        return market_pos, market_pos + 1, code_raw.decode("ascii")
    return None


def _depth_float(body: bytes, offset: int) -> float:
    return decode_ths_float(struct.unpack_from("<I", body, offset)[0])


def _depth_u32(body: bytes, offset: int) -> int:
    return struct.unpack_from("<I", body, offset)[0]


def _is_auction_depth_block(body: bytes, code_pos: int) -> bool:
    """Recognize the three-row virtual-book layout used before 09:25."""
    if code_pos + 130 > len(body):
        return False
    auction_price = _depth_float(body, code_pos + 10)
    current_price = _depth_float(body, code_pos + 22)
    bid_price = _depth_float(body, code_pos + 26)
    ask_price = _depth_float(body, code_pos + 50)
    bid_matched = _depth_u32(body, code_pos + 30)
    ask_matched = _depth_u32(body, code_pos + 54)
    return (
        auction_price > 0
        and current_price == 0
        and bid_price == auction_price
        and ask_price == auction_price
        and bid_matched == ask_matched
    )


def _is_continuous_depth_block(body: bytes, code_pos: int) -> bool:
    """Recognize a complete continuous-auction ten-level record.

    Some 0x0f7f envelopes contain compact or concatenated records.  Merely
    finding a stock code is not enough: applying the ten-level offsets to
    those variants produced impossible prices in the 2026-08-10 capture.
    """
    if len(body) != code_pos + _CONTINUOUS_DEPTH_RECORD_END:
        return False
    shift = code_pos - 45
    prev_close = _depth_float(body, shift + 51)
    current_price = _depth_float(body, shift + 67)
    bid1_price = _depth_float(body, shift + 95)
    ask1_price = _depth_float(body, shift + 119)
    return (
        prev_close > 0
        and current_price > 0
        and bid1_price > 0
        and ask1_price > 0
    )


def is_stock_depth_envelope(body: bytes) -> bool:
    """Return whether a 0x0f7f envelope contains a stock-code marker.

    This is broader than :func:`is_depth_push`: unknown compact layouts are
    stock depth envelopes but are deliberately not accepted by the production
    parser until their record structure has been verified.
    """
    return bool(
        len(body) >= 5
        and body[0] == 0x09
        and body[1:5] == _DEPTH_PUSH_MAGIC
        and _find_depth_code(body)
    )


def is_auction_depth_push(body: bytes) -> bool:
    """Return whether ``body`` contains an opening-auction virtual book.

    The book has one matched row on each side plus an optional unmatched row
    on the dominant side.  It is not a truncated continuous-auction order
    book, even though it shares the ``09 7b d0 0f 7f`` envelope.
    """
    if not is_stock_depth_envelope(body):
        return False
    located = _find_depth_code(body)
    return bool(located and _is_auction_depth_block(body, located[1]))


def parse_auction_depth_push(body: bytes) -> dict | None:
    """Parse the variable-offset three-row opening-auction push.

    ``buy_unmatched_volume`` and ``sell_unmatched_volume`` correspond to the
    Level2 7176 oracle's dt27/dt33.  Their price slot is an absent-value
    sentinel, so ``display_levels`` uses ``price=None`` for the second row.
    The row order mirrors the PC client: dominant-side level 1/2 followed by
    the opposite-side level 1.
    """
    if not is_auction_depth_push(body):
        return None
    located = _find_depth_code(body)
    if located is None:
        return None
    market_pos, code_pos, code = located
    market = _DEPTH_PUSH_MARKETS[body[market_pos]]

    auction_price = round(_depth_float(body, code_pos + 10), 3)
    matched_volume = _depth_u32(body, code_pos + 30)
    buy_unmatched = _depth_u32(body, code_pos + 38)
    sell_unmatched = _depth_u32(body, code_pos + 62)
    direction_raw = _depth_u32(body, code_pos + 126)
    encoded_volume = direction_raw & _AUCTION_IMBALANCE_MASK
    encoded_side = "sell" if direction_raw & _AUCTION_IMBALANCE_SELL else "buy"

    # The explicit buy2/sell2 slots are authoritative.  The packed direction
    # word is a fallback for compact variants and a useful consistency field.
    if encoded_volume:
        if encoded_side == "sell" and not sell_unmatched:
            sell_unmatched = encoded_volume
        elif encoded_side == "buy" and not buy_unmatched:
            buy_unmatched = encoded_volume

    if sell_unmatched:
        imbalance_side = "sell"
        imbalance_volume = sell_unmatched
    elif buy_unmatched:
        imbalance_side = "buy"
        imbalance_volume = buy_unmatched
    else:
        imbalance_side = None
        imbalance_volume = 0

    bid1 = {
        "side": "buy",
        "level": 1,
        "price": auction_price,
        "volume": matched_volume,
        "kind": "matched",
    }
    ask1 = {
        "side": "sell",
        "level": 1,
        "price": auction_price,
        "volume": matched_volume,
        "kind": "matched",
    }
    buy2 = {
        "side": "buy",
        "level": 2,
        "price": None,
        "volume": buy_unmatched,
        "kind": "unmatched",
    }
    sell2 = {
        "side": "sell",
        "level": 2,
        "price": None,
        "volume": sell_unmatched,
        "kind": "unmatched",
    }
    if imbalance_side == "sell":
        display_levels = [ask1, sell2, bid1]
    elif imbalance_side == "buy":
        display_levels = [bid1, buy2, ask1]
    else:
        display_levels = [bid1, ask1]

    bids = [(auction_price, matched_volume)]
    asks = [(auction_price, matched_volume)]
    if buy_unmatched:
        bids.append((0.0, buy_unmatched))
    if sell_unmatched:
        asks.append((0.0, sell_unmatched))

    return {
        "code": code,
        "market": market,
        "phase": "auction",
        "price": auction_price,
        "auction_price": auction_price,
        "prev_close": round(_depth_float(body, code_pos + 6), 3),
        "open": 0.0,
        "high": 0.0,
        "low": 0.0,
        "volume": matched_volume,
        "matched_volume": matched_volume,
        "buy_unmatched_volume": buy_unmatched,
        "sell_unmatched_volume": sell_unmatched,
        "imbalance_side": imbalance_side,
        "imbalance_volume": imbalance_volume,
        "imbalance_raw": direction_raw,
        "bids": bids,
        "asks": asks,
        "display_levels": display_levels,
        "raw_len": len(body),
        "code_offset": code_pos,
    }


def is_depth_push(body: bytes) -> bool:
    """Return whether ``body`` contains a verified auction or ten-level book."""
    if normalize_stock_depth_push(body) is not None:
        return True
    if not is_stock_depth_envelope(body):
        return False
    located = _find_depth_code(body)
    if located is None:
        return False
    code_pos = located[1]
    return _is_auction_depth_block(body, code_pos) or _is_continuous_depth_block(
        body, code_pos
    )


def _parse_normalized_depth_records(body: bytes) -> list[dict]:
    """Parse every fixed 707-byte row produced by the native-style normalizer."""
    normalized = normalize_stock_depth_push(body)
    if normalized is None:
        return []
    marker = normalized.find(b"hd1.0\x00")
    if marker < 0 or len(normalized) < marker + 16:
        return []
    base = marker + 6
    record_count = struct.unpack_from("<I", normalized, base)[0]
    row_size = struct.unpack_from("<H", normalized, base + 6)[0]
    field_count = struct.unpack_from("<H", normalized, base + 8)[0]
    records_offset = base + 10 + field_count * 4
    if row_size != 707 or records_offset + record_count * row_size > len(normalized):
        return []

    parsed: list[dict] = []
    pair_offsets = [
        *range(95, 143, 8),
        *range(155, 187, 8),
        *range(279, 359, 8),
    ]
    for record_index in range(record_count):
        start = records_offset + record_index * row_size
        row = normalized[start : start + row_size]
        market_flag = row[0]
        code_raw = row[1:7]
        if market_flag not in _DEPTH_PUSH_MARKETS or not code_raw.isdigit():
            continue
        code = code_raw.decode("ascii")
        market = _DEPTH_PUSH_MARKETS[market_flag]

        current_price = _depth_float(row, 63)
        bid_price = _depth_float(row, 95)
        ask_price = _depth_float(row, 119)
        auction_price = current_price or bid_price
        bid_matched = _depth_u32(row, 99)
        ask_matched = _depth_u32(row, 123)
        if (
            auction_price > 0
            and all(_depth_float(row, offset) == 0 for offset in (51, 55, 59))
            and bid_price == auction_price
            and ask_price == auction_price
            and bid_matched == ask_matched
        ):
            buy_unmatched = _depth_u32(row, 107)
            sell_unmatched = _depth_u32(row, 131)
            if buy_unmatched in (0x80000000, 0xFFFFFFFF):
                buy_unmatched = 0
            if sell_unmatched in (0x80000000, 0xFFFFFFFF):
                sell_unmatched = 0
            direction_raw = (
                (_AUCTION_IMBALANCE_SELL | sell_unmatched)
                if sell_unmatched
                else buy_unmatched
            )
            encoded_volume = direction_raw & _AUCTION_IMBALANCE_MASK
            encoded_side = (
                "sell" if direction_raw & _AUCTION_IMBALANCE_SELL else "buy"
            )
            if encoded_volume:
                if encoded_side == "sell" and not sell_unmatched:
                    sell_unmatched = encoded_volume
                elif encoded_side == "buy" and not buy_unmatched:
                    buy_unmatched = encoded_volume
            imbalance_side = (
                "sell" if sell_unmatched else "buy" if buy_unmatched else None
            )
            imbalance_volume = sell_unmatched or buy_unmatched
            price = round(auction_price, 3)
            bid1 = {
                "side": "buy", "level": 1, "price": price,
                "volume": bid_matched, "kind": "matched",
            }
            ask1 = {
                "side": "sell", "level": 1, "price": price,
                "volume": bid_matched, "kind": "matched",
            }
            buy2 = {
                "side": "buy", "level": 2, "price": None,
                "volume": buy_unmatched, "kind": "unmatched",
            }
            sell2 = {
                "side": "sell", "level": 2, "price": None,
                "volume": sell_unmatched, "kind": "unmatched",
            }
            display_levels = (
                [ask1, sell2, bid1]
                if imbalance_side == "sell"
                else [bid1, buy2, ask1]
                if imbalance_side == "buy"
                else [bid1, ask1]
            )
            bids = [(price, bid_matched)]
            asks = [(price, bid_matched)]
            if buy_unmatched:
                bids.append((0.0, buy_unmatched))
            if sell_unmatched:
                asks.append((0.0, sell_unmatched))
            result = {
                "code": code,
                "market": market,
                "phase": "auction",
                "price": price,
                "auction_price": price,
                "prev_close": round(_depth_float(row, 47), 3),
                "open": 0.0,
                "high": 0.0,
                "low": 0.0,
                "volume": bid_matched,
                "matched_volume": bid_matched,
                "buy_unmatched_volume": buy_unmatched,
                "sell_unmatched_volume": sell_unmatched,
                "imbalance_side": imbalance_side,
                "imbalance_volume": imbalance_volume,
                "imbalance_raw": direction_raw,
                "bids": bids,
                "asks": asks,
                "display_levels": display_levels,
            }
        else:
            pairs = [
                (round(_depth_float(row, offset), 3), _depth_u32(row, offset + 4))
                for offset in pair_offsets
            ]
            result = {
                "code": code,
                "market": market,
                "phase": "continuous",
                "price": current_price,
                "prev_close": _depth_float(row, 47),
                "open": _depth_float(row, 51),
                "high": _depth_float(row, 55),
                "low": _depth_float(row, 59),
                "bids": [pairs[index] for index in [0, 1, 2, 6, 8, 10, 12, 14, 16, 18]],
                "asks": [pairs[index] for index in [3, 4, 5, 7, 9, 11, 13, 15, 17, 19]],
            }
        result.update(
            {
                "raw_len": len(body),
                "code_offset": None,
                "batch_index": record_index,
                "batch_size": record_count,
                "normalized": True,
            }
        )
        parsed.append(result)
    return parsed


def parse_depth_push_records(body: bytes) -> list[dict]:
    """Parse all stock records carried by one depth-push envelope."""
    records = _parse_normalized_depth_records(body)
    if records:
        return records
    parsed = parse_depth_push(body)
    return [parsed] if parsed is not None else []


def parse_depth_push(body: bytes) -> dict | None:
    """Parse a verified auction book or complete ten-level depth push.

    2026-08-07 盘中破译（002384 东山精密 ~200 元对照确认）。
    含完整十档买卖价量 + 昨收/开盘/最高/最低/现价。
    """
    normalized_records = _parse_normalized_depth_records(body)
    if normalized_records:
        return normalized_records[0]

    if not is_depth_push(body):
        return None

    auction = parse_auction_depth_push(body)
    if auction is not None:
        return auction

    located = _find_depth_code(body)
    if located is None:
        return None
    market_pos, code_pos, code = located
    market = _DEPTH_PUSH_MARKETS[body[market_pos]]
    shift = code_pos - 45
    if len(body) < shift + 267:
        return None

    def _f(off):
        return _depth_float(body, shift + off)

    def _u32(off):
        return _depth_u32(body, shift + off)

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
        "phase": "continuous",
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
        "code_offset": code_pos,
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
    "is_auction_cancel_push",
    "is_snapshot_push",
    "parse_auction_cancel_push",
    "parse_snapshot_push",
    "is_stock_depth_envelope",
    "is_auction_depth_push",
    "parse_auction_depth_push",
    "is_depth_push",
    "parse_depth_push",
    "parse_depth_push_records",
]
