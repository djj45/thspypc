"""超级盘口 / 逐笔成交回放协议（period=7169，沪深通用）。

2026-08-05 盘后破译（见 docs/handoffs/HANDOFF_KANPAN_CAPTURE_20260805.md §H.8 + §J.6bis）。
7169 是同花顺「超级盘口 / 逐笔成交」面板按时间区间拖动时请求的逐笔成交回放协议，
返回该区间内每一笔撮合的时间、价、量、主动方向、买卖委托号。

关键发现：沪市（``hd\\x8d1.0`` 变体）和深市（标准 ``hd1.0``）**经 normalize_8901_response
正规化后结构完全一致**——标准 ``hd1.0`` + 行主序定长 32B/记录 + 8 字段。沪市所谓「变长」
只是外层 ``cmd=0x0a`` 压缩（与集合竞价 7176 同根因），HANDOFF_SUPERORDER §9-§16 的
x32dbg 逆向工作作废。

沪深唯一差异在 dt12/dt74/dt18 三个委托号字段的语义（见模块 docstring 末尾的差异表），
价/量/方向/时间戳/逐笔序号五字段沪深一致。解析层统一输出 ``delegate_a``/``delegate_b``，
语义解释见下方注释，不在解析器内做猜测性标注。

沪深 dt12/dt74/dt18 语义差异（解析器不区分，留给调用方按 market 判断）：

| 字段 | 深市（000938 实测）| 沪市（603118 实测）|
|---|---|---|
| delegate_a (dt12) | 卖方委托号 | 主动方委托号（dir=1/5 都随每笔变化）|
| delegate_b (dt74) | 买方委托号 | 被动方挂单号（多笔成交共用）|
| trade_no (dt18) | 成交号（≈主动方委托号+小偏移）| 独立成交序号（量级与委托号差千万）|

深市铁证：dir=1 时 trade_no≈delegate_b（5817/5817=100%），
         dir=5 时 trade_no≈delegate_a（4183/4183=100%）。
沪市铁证：dir=1 块里 delegate_b 恒定、delegate_a 变（22675 相邻对）。
"""
from __future__ import annotations

import logging
import struct
from datetime import datetime

from ..codecs.compression import Incomplete8901Response, normalize_8901_response
from ..codecs.framing import encode_frame
from ..codecs.hd import _parse_hd_field_table
from ..codecs.numeric import decode_ths_float

logger = logging.getLogger(__name__)

# ── 协议常量（2026-08-05 抓包确认）──

SUPERORDER_PERIOD = 7169
SUPERORDER_L2_PAGEID = 4214          # 逐笔面板入口
SUPERORDER_SUPER_PAGEID = 4260       # 超级盘口入口（两通道响应同构，§J.6）

# 请求 DataType=10,12,13（抓包确认；响应返回 8 个 dt 字段，dt 号与 DataType 不对应）
SUPERORDER_DATATYPE = [10, 12, 13]

# 响应帧：normalize 后是标准 hd1.0，flag=0x0046，行主序定长（非 BitRLE/位平面转置）
SUPERORDER_FLAG = 0x0046
SUPERORDER_RECORD_SIZE = 32
SUPERORDER_FIELD_COUNT = 8

# 合法 unix 时间戳区间（用于定位记录起点 + 过滤截断帧尾部噪声）
# 1.78e9 ≈ 2026-08-05，覆盖近期 A 股交易时段；放宽到 ±5e7 容纳跨年/历史回看
_TS_LO = 1_700_000_000   # 2023-11
_TS_HI = 1_900_000_000   # 2030-03

# 逐笔序号合理性上限（A 股单票一天逐笔 <1 亿，超此必为帧边界错位的垃圾字节）
_SEQ_MAX = 100_000_000

# ── 4096 盘口快照回放（超级盘口分时曲线，2026-08-06 抓包破译）──
# 走 4260 通道，DateTime=4096(0-0) 返回全天每 3 秒一个完整盘口快照。
# 响应是标准 hd1.0 行主序（flag=0x00FE，非 BitRLE），rc≈4927, hs=216, fc=54。
SNAPSHOT_REPLAY_PERIOD = 4096
SNAPSHOT_REPLAY_PAGEID = 4260
SNAPSHOT_REPLAY_FLAG = 0x00FE
# 4417 盘后/历史通道（2026-08-07 盘后抓包确认）：同花顺客户端超级盘口在盘后/历史
# 走 pageid=4417 + period=4096，响应是 flag=0x009E hs=120 fc=30 的定长行主序表
# （dt1=unix 秒、dt10=最新价），与盘中 4260@4096 的 0x00FE/216/54 布局不同。
SNAPSHOT_REPLAY_HIST_PAGEID = 4417
SNAPSHOT_REPLAY_HIST_FLAG = 0x009E
SNAPSHOT_REPLAY_HIST_RECORD_SIZE = 120
SNAPSHOT_REPLAY_HIST_FIELD_COUNT = 30
# 指数历史超级盘口（2026-08-07 盘后抓包）：pageid=77 + period=4096，
# 响应是 hd1.0 flag=0x0046 hs=32 fc=8 行主序，字段 [dt1,dt10,dt13,dt19,dt49,dt18,dt123,dt125]。
# 与 7169 逐笔同 flag/hs/fc，但字段表不同（7169 是 dt1/dt56/dt10/...），靠 dt10@4 区分。
SNAPSHOT_REPLAY_INDEX_FLAG = 0x0046
SNAPSHOT_REPLAY_INDEX_RECORD_SIZE = 32
SNAPSHOT_REPLAY_INDEX_FIELD_COUNT = 8
# 指数历史超级盘口 pageid（2026-08-07 盘后抓包：1A0001/1B0680/399001/399006
# 均走 pageid=77 + period=4096；北证50 无历史超级盘口）
SNAPSHOT_REPLAY_INDEX_PAGEID = 77
# 4417@4096 请求 DataType（2026-08-07 盘后抓包 fr1986 字节级确认）
SNAPSHOT_REPLAY_HIST_DATATYPE = [
    7, 10, 12, 13, 18, 19, 20, 21,
    25, 26, 27, 28, 29, 31, 32, 33, 34, 35,
    49, 75, 123, 125,
    150, 151, 152, 153, 154, 155, 156, 157,
    6, 66, 1110,
]
# 请求 DataType：十档价量（dt24-35 + dt102-125）+ dt10/13/19/49/74/75 + 扩展
SNAPSHOT_REPLAY_DATATYPE = [
    10, 12, 13, 14, 18, 19, 20, 21,
    25, 26, 27, 28, 29, 31, 32, 33, 34, 35,
    49, 74, 75,
    102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121,
    122, 123, 124, 125, 150, 151, 152, 153, 154, 155, 156, 157,
    6, 45, 407, 619, 1110,
]
SNAPSHOT_REPLAY_COMPANION_DATATYPE = [7, 10, 2419, 2420, 6, 45, 402, 619]
_SNAPSHOT_REPLAY_ROUTE = 0x0158

# 买一/卖一委托队列（Level2 超级盘口）。7173=买一，7174=卖一；请求只取
# DataType=10。历史日仍发 -1-0，但必须先在同一条连接上用 4096 建立 4417
# 上下文；目前只确认服务端保留最近一个交易日。
ORDER_QUEUE_BUY_PERIOD = 7173
ORDER_QUEUE_SELL_PERIOD = 7174
ORDER_QUEUE_DATATYPE = [10]
ORDER_QUEUE_PAGEID = 4214
ORDER_QUEUE_HIST_PAGEID = 4417
ORDER_QUEUE_FLAG = 0x002A
ORDER_QUEUE_RECORD_SIZE = 4
ORDER_QUEUE_FIELD_COUNT = 1

# 看盘页“挂单/撤单”全量明细（2026-08-10 客户端抓包 + UI 真值对齐）。
# 7175 返回所有挂单；7170/7171 分别返回买撤/卖撤，并通过 dt37 回连
# 7175 的 dt1 原委托号。撤单存续秒数 = dt82 - dt56。
ORDER_DETAIL_PERIOD = 7175
BUY_CANCEL_PERIOD = 7170
SELL_CANCEL_PERIOD = 7171
ORDER_DETAIL_DATATYPE = [10, 12, 13]
CANCEL_DETAIL_DATATYPE = [13, 20, 37, 82]
ORDER_DETAIL_FLAG = 0x003A
ORDER_DETAIL_RECORD_SIZE = 20
ORDER_DETAIL_FIELD_COUNT = 5
CANCEL_DETAIL_FLAG = 0x0042
CANCEL_DETAIL_RECORD_SIZE = 31
CANCEL_DETAIL_FIELD_COUNT = 7

_ORDER_DETAIL_FIELDS = (
    (1, 0x30, 4),
    (56, 0x30, 4),
    (10, 0x70, 4),
    (13, 0x70, 4),
    (12, 0x30, 4),
)
_CANCEL_DETAIL_FIELDS = (
    (1, 0x30, 4),
    (5, 0x10, 7),
    (56, 0x30, 4),
    (82, 0x30, 4),
    (20, 0x70, 4),
    (13, 0x70, 4),
    (37, 0x30, 4),
)
_SUPERORDER_FIELDS = (
    (1, 0x30, 4),
    (56, 0x30, 4),
    (10, 0x70, 4),
    (13, 0x70, 4),
    (12, 0x30, 4),
    (74, 0x30, 4),
    (75, 0x30, 4),
    (18, 0x70, 4),
)

# 外层请求路由标记（2026-08-05 抓包确认，0x02FC = 小端 fc 02；区别于 auction 的 0x01FC）
_SUPERORDER_ROUTE = b"\xfc\x02"


def build_order_queue_query(
    code: str,
    market: int = 33,
    *,
    side: str = "buy",
    pageid: int = ORDER_QUEUE_PAGEID,
    seq: int = 0,
    inner_seq: int = 0x09A0,
) -> bytes:
    """构造买一/卖一委托队列请求（7173/7174，Level2 专属）。

    ``side="buy"`` 使用 7173，``side="sell"`` 使用 7174。历史日期不能写入
    本请求；调用方须先在同一连接请求 4417@4096 建立日期上下文，再以
    ``pageid=4417`` 发本请求。
    """
    if side not in ("buy", "sell"):
        raise ValueError("side 必须是 'buy' 或 'sell'")
    if not code or not code.isascii() or not code.isalnum():
        raise ValueError(f"非法证券代码: {code!r}")
    if pageid not in (ORDER_QUEUE_PAGEID, 4260, ORDER_QUEUE_HIST_PAGEID):
        raise ValueError(f"不支持的委托队列 pageid: {pageid}")

    period = (
        ORDER_QUEUE_BUY_PERIOD
        if side == "buy"
        else ORDER_QUEUE_SELL_PERIOD
    )
    target = f"{market}({code},);"
    outer_text = (
        f"CodeList={target}\r\npageid={pageid}\r\n"
    ).encode("gbk")
    inner_text = (
        f"CodeList={target}\r\n"
        "DataType=10,\r\n"
        f"DateTime={period}(-1-0)\r\n"
        "LackTime=0,0,0,0,0,0,0,0\r\n"
        f"pageid={pageid}\r\n"
    ).encode("gbk")

    # 抓包形态：帧级 cmd=0x09；outer route=0x02fc，只携带 CodeList/pageid；
    # inner route=0x01fc，携带 DataType/DateTime/LackTime。
    outer_header = bytearray(23)
    outer_header[0] = 0x09
    outer_header[1:5] = b"\x00\x16\x00\x00"
    struct.pack_into("<H", outer_header, 5, seq & 0xFFFF)
    outer_header[7:11] = b"\x12\x00\x02\x00"
    outer_header[11:13] = b"\xfc\x02"
    struct.pack_into("<I", outer_header, 19, len(outer_text))

    inner_header = bytearray(22)
    inner_header[0:4] = b"\x00\x16\x00\x00"
    struct.pack_into("<H", inner_header, 4, inner_seq & 0xFFFF)
    inner_header[6:10] = b"\x12\x00\x09\x00"
    inner_header[10:12] = b"\xfc\x01"
    inner_header[12:14] = b"\x00\x00"
    inner_header[14:16] = b"\x40\x00"
    inner_header[16:18] = b"\x05\x1c"
    struct.pack_into("<I", inner_header, 18, len(inner_text))
    return encode_frame(
        bytes(outer_header)
        + outer_text
        + bytes(inner_header)
        + inner_text
    )


def parse_order_queue_response(
    body: bytes,
    *,
    side: str,
) -> dict | None:
    """解析 7173/7174 委托队列响应；ACK/空队列返回 ``None``。

    ``entries`` 只包含客户端展示窗口中的委托（通常最多 50 笔），不等于该价位
    全部委托。``total_order_count`` 是该价位总笔数；``meta_value`` 是响应壳中的
    原始辅助值（与 4096 的 dt123/dt125 对齐），暂不赋予“总量”语义。
    """
    if side not in ("buy", "sell"):
        raise ValueError("side 必须是 'buy' 或 'sell'")
    if body.startswith(b"\x0a"):
        try:
            body = normalize_8901_response(body)
        except ValueError as exc:
            logger.debug("order queue normalization failed: %s", exc)
            return None

    pos = 0
    while True:
        marker = body.find(b"hd1.0", pos)
        if marker < 0:
            return None
        pos = marker + 6
        base = marker + 6
        if base + 14 > len(body):
            continue
        record_count, flag, record_size, field_count = struct.unpack_from(
            "<IHHH", body, base
        )
        if (
            flag != ORDER_QUEUE_FLAG
            or record_size != ORDER_QUEUE_RECORD_SIZE
            or field_count != ORDER_QUEUE_FIELD_COUNT
        ):
            continue
        field_off = base + 10
        if field_off + 4 > len(body):
            continue
        dt, fmt, _flags, width = body[field_off : field_off + 4]
        if (dt, fmt, width) != (56, 0x30, 4):
            continue

        # 壳长不是稳定常量，用市场字节 + 证券代码定位。0x11=沪，0x21=深。
        shell_start = field_off + 4
        shell_end = min(shell_start + 120, len(body) - 42)
        code_pos = None
        for candidate in range(shell_start, max(shell_start, shell_end) + 1):
            if body[candidate] not in (0x11, 0x21):
                continue
            label = body[candidate + 1 : candidate + 7]
            if len(label) == 6 and all(
                48 <= value <= 57 or 65 <= value <= 90
                for value in label
            ):
                code_pos = candidate
                break
        if code_pos is None or code_pos + 42 > len(body):
            continue

        ts = struct.unpack_from("<I", body, code_pos + 18)[0]
        price_raw = struct.unpack_from("<I", body, code_pos + 22)[0]
        meta_value = struct.unpack_from("<I", body, code_pos + 26)[0]
        display_limit = body[code_pos + 32]
        subtype = body[code_pos + 33]
        total_order_count = struct.unpack_from("<H", body, code_pos + 34)[0]
        marker_value = struct.unpack_from("<H", body, code_pos + 38)[0]
        if subtype != 16 or marker_value != 0x0101:
            continue

        data_off = code_pos + 42
        next_table = body.find(b"hd1.0", data_off)
        data_end = next_table if next_table >= 0 else len(body)
        available = max(0, (data_end - data_off) // 4)
        visible_count = min(display_limit, available)
        entries = []
        for index in range(visible_count):
            raw = struct.unpack_from("<I", body, data_off + index * 4)[0]
            shares = raw & 0x07FFFFFF
            entries.append({
                "index": index + 1,
                "raw": raw,
                "shares": shares,
                "hands": (shares + 50) // 100,
                "is_major": bool(raw & 0x08000000),
            })
        major_entries = [entry for entry in entries if entry["is_major"]]
        major_shares = sum(entry["shares"] for entry in major_entries)
        try:
            time_value = datetime.fromtimestamp(ts)
        except (OSError, ValueError, OverflowError):
            time_value = None
        code = body[code_pos + 1 : code_pos + 7].decode("ascii")
        return {
            "code": code,
            "market_marker": body[code_pos],
            "side": side,
            "period": (
                ORDER_QUEUE_BUY_PERIOD
                if side == "buy"
                else ORDER_QUEUE_SELL_PERIOD
            ),
            "time": time_value,
            "ts": ts,
            "price": round(decode_ths_float(price_raw), 3),
            "price_raw": price_raw,
            "meta_value": meta_value,
            "display_limit": display_limit,
            "total_order_count": total_order_count,
            "visible_count": len(entries),
            "truncated": total_order_count > len(entries),
            "entries": entries,
            "visible_major_order_count": len(major_entries),
            "visible_major_shares": major_shares,
            "visible_major_hands": major_shares / 100.0,
            "record_count": record_count,
        }


def build_order_detail_query(
    code: str,
    market: int = 33,
    start_ts: int = -29,
    end_ts: int = 0,
    *,
    period: int = ORDER_DETAIL_PERIOD,
    pageid: int = ORDER_QUEUE_PAGEID,
    seq: int | None = None,
) -> bytes:
    """Build a full order/cancel detail query from the PC 4214 panel.

    ``period=7175`` returns all submitted orders. ``7170`` and ``7171``
    return buy-side and sell-side cancellations. Negative ranges request the
    newest rows (for example ``-29-0``); absolute Unix ranges retrieve a
    complete interval.
    """
    if period not in (
        ORDER_DETAIL_PERIOD,
        BUY_CANCEL_PERIOD,
        SELL_CANCEL_PERIOD,
    ):
        raise ValueError(f"unsupported order detail period: {period}")
    if not code or not code.isascii() or not code.isalnum():
        raise ValueError(f"非法证券代码: {code!r}")
    if pageid != ORDER_QUEUE_PAGEID:
        raise ValueError("挂单/撤单全量明细目前仅确认 pageid=4214")

    target = f"{market}({code},);"
    datatype = (
        ORDER_DETAIL_DATATYPE
        if period == ORDER_DETAIL_PERIOD
        else CANCEL_DETAIL_DATATYPE
    )
    datatype_text = ",".join(str(value) for value in datatype) + ","
    detail_text = (
        f"CodeList={target}\r\n"
        f"DataType={datatype_text}\r\n"
        f"DateTime={period}({start_ts}-{end_ts})\r\n"
        "LackTime=0,0,0,0,0,0,0,0\r\n"
        f"pageid={pageid}\r\n"
    ).encode("gbk")

    if period in (BUY_CANCEL_PERIOD, SELL_CANCEL_PERIOD):
        # 7170/7171 are direct 0x01fc query frames. Byte 16 selects the
        # cancel side: 0x02=buy cancel, 0x03=sell cancel.
        if seq is None:
            seq = 0x00B5 if period == BUY_CANCEL_PERIOD else 0x00B7
        header = bytearray(23)
        header[0] = 0x09
        header[1:5] = b"\x00\x16\x00\x00"
        struct.pack_into("<H", header, 5, seq & 0xFFFF)
        header[7:11] = b"\x12\x00\x09\x00"
        header[11:13] = b"\xfc\x01"
        header[13:16] = b"\x00\x00\x40"
        header[16:19] = (
            b"\x00\x02\x1c"
            if period == BUY_CANCEL_PERIOD
            else b"\x00\x03\x1c"
        )
        struct.pack_into("<I", header, 19, len(detail_text))
        return encode_frame(bytes(header) + detail_text)

    # 7175 uses the captured three-level 0x02fc -> 0x02e1 -> 0x01fc form.
    outer_text = f"CodeList={target}\r\npageid={pageid}\r\n".encode("gbk")
    middle_text = outer_text

    inner_header = bytearray(22)
    inner_header[0:4] = b"\x00\x16\x00\x00"
    inner_seq = 0x00B3 if seq is None else seq
    struct.pack_into("<H", inner_header, 4, inner_seq & 0xFFFF)
    inner_header[6:10] = b"\x12\x00\x09\x00"
    inner_header[10:12] = b"\xfc\x01"
    inner_header[12:16] = b"\x00\x00\x40\x00"
    inner_header[16:18] = b"\x07\x1c"
    struct.pack_into("<I", inner_header, 18, len(detail_text))

    middle_header = bytearray(22)
    middle_header[0:4] = b"\x00\x16\x00\x00"
    middle_header[6:10] = b"\x12\x00\x02\x00"
    middle_header[10:12] = b"\xe1\x02"
    struct.pack_into("<I", middle_header, 18, len(middle_text))

    outer_header = bytearray(23)
    outer_header[0] = 0x09
    outer_header[1:5] = b"\x00\x16\x00\x00"
    outer_header[7:11] = b"\x12\x00\x02\x00"
    outer_header[11:13] = b"\xfc\x02"
    struct.pack_into("<I", outer_header, 19, len(outer_text))
    return encode_frame(
        bytes(outer_header)
        + outer_text
        + bytes(middle_header)
        + middle_text
        + bytes(inner_header)
        + detail_text
    )


def _order_detail_table(
    body: bytes,
    *,
    period: int,
) -> tuple[bytes, int, int, str] | None:
    """Return ``(body, data_offset, row_count, shell_code)`` for one table."""
    if body.startswith(b"\x0a"):
        try:
            body = normalize_8901_response(body, strict=True)
        except Incomplete8901Response as exc:
            body = exc.normalized_prefix
        except ValueError as exc:
            logger.debug("order detail normalization failed: %s", exc)
            return None

    expected = (
        (
            ORDER_DETAIL_FLAG,
            ORDER_DETAIL_RECORD_SIZE,
            ORDER_DETAIL_FIELD_COUNT,
            _ORDER_DETAIL_FIELDS,
        )
        if period == ORDER_DETAIL_PERIOD
        else (
            CANCEL_DETAIL_FLAG,
            CANCEL_DETAIL_RECORD_SIZE,
            CANCEL_DETAIL_FIELD_COUNT,
            _CANCEL_DETAIL_FIELDS,
        )
    )
    flag_expected, size_expected, count_expected, fields_expected = expected
    position = 0
    while True:
        marker = body.find(b"hd1.0\x00", position)
        if marker < 0:
            return None
        position = marker + 6
        base = marker + 6
        if base + 10 > len(body):
            continue
        row_count, flag, row_size, field_count = struct.unpack_from(
            "<IHHH", body, base
        )
        if (
            flag != flag_expected
            or row_size != size_expected
            or field_count != count_expected
            or row_count > 2_000_000
        ):
            continue
        fields = tuple(_parse_hd_field_table(body, base + 10, field_count))
        if fields != fields_expected:
            continue
        shell_start = base + 10 + field_count * 4
        next_table = body.find(b"hd1.0\x00", shell_start)
        table_end = next_table if next_table >= 0 else len(body)
        shell_end = min(shell_start + 120, table_end - 18)
        for code_pos in range(shell_start, shell_end + 1):
            if body[code_pos] not in (0x11, 0x21):
                continue
            raw_code = body[code_pos + 1 : code_pos + 7]
            if len(raw_code) != 6 or not raw_code.isalnum():
                continue
            # These three tables use a 22-byte shell whose market marker is
            # four bytes into the shell, so records start marker+18.
            data_offset = code_pos + 18
            available_bytes = table_end - data_offset
            expected_bytes = row_count * row_size
            if available_bytes < expected_bytes:
                # Only complete rows from actual source bytes can be trusted.
                row_count = max(0, available_bytes // row_size)
            return body, data_offset, row_count, raw_code.decode("ascii")


def parse_order_detail_response(
    body: bytes,
    *,
    period: int,
) -> list[dict]:
    """Parse 7175 orders or 7170/7171 cancellation detail rows."""
    if period not in (
        ORDER_DETAIL_PERIOD,
        BUY_CANCEL_PERIOD,
        SELL_CANCEL_PERIOD,
    ):
        raise ValueError(f"unsupported order detail period: {period}")
    located = _order_detail_table(body, period=period)
    if located is None:
        return []
    normalized, data_offset, row_count, shell_code = located
    row_size = (
        ORDER_DETAIL_RECORD_SIZE
        if period == ORDER_DETAIL_PERIOD
        else CANCEL_DETAIL_RECORD_SIZE
    )
    records: list[dict] = []
    for index in range(row_count):
        row = normalized[
            data_offset + index * row_size : data_offset + (index + 1) * row_size
        ]
        if period == ORDER_DETAIL_PERIOD:
            order_id, placed_ts, price_raw, volume, kind_raw = struct.unpack(
                "<IIIII", row
            )
            side_code = kind_raw & 0xFF
            side = "buy" if side_code == 1 else "sell" if side_code == 2 else None
            try:
                placed_time = datetime.fromtimestamp(placed_ts)
            except (OSError, ValueError, OverflowError):
                placed_time = None
            records.append({
                "event": "order",
                "code": shell_code,
                "side": side,
                "time": placed_time,
                "ts": placed_ts,
                "placed_time": placed_time,
                "placed_ts": placed_ts,
                "price": decode_ths_float(price_raw),
                "price_raw": price_raw,
                "volume": volume,
                "hands": volume / 100.0,
                "order_id": order_id,
                "kind_raw": kind_raw,
                "kind_flags": kind_raw & ~0xFF,
                "dt1": order_id,
                "dt56": placed_ts,
                "dt10": price_raw,
                "dt13": volume,
                "dt12": kind_raw,
            })
            continue

        cancel_id = struct.unpack_from("<I", row, 0)[0]
        row_code = row[5:11].decode("ascii", errors="replace")
        placed_ts, cancelled_ts, price_raw, volume, order_id = struct.unpack_from(
            "<IIIII", row, 11
        )
        try:
            placed_time = datetime.fromtimestamp(placed_ts)
            cancelled_time = datetime.fromtimestamp(cancelled_ts)
        except (OSError, ValueError, OverflowError):
            placed_time = cancelled_time = None
        side = "buy" if period == BUY_CANCEL_PERIOD else "sell"
        records.append({
            "event": "cancel",
            "code": row_code or shell_code,
            "side": side,
            "time": cancelled_time,
            "ts": cancelled_ts,
            "placed_time": placed_time,
            "placed_ts": placed_ts,
            "cancelled_time": cancelled_time,
            "cancelled_ts": cancelled_ts,
            "elapsed_seconds": cancelled_ts - placed_ts,
            "price": decode_ths_float(price_raw),
            "price_raw": price_raw,
            "volume": volume,
            "hands": volume / 100.0,
            "cancel_id": cancel_id,
            "order_id": order_id,
            "dt1": cancel_id,
            "dt56": placed_ts,
            "dt82": cancelled_ts,
            "dt20": price_raw,
            "dt13": volume,
            "dt37": order_id,
        })
    return records


def build_superorder_query(
    code: str,
    market: int = 33,
    start_ts: int = 0,
    end_ts: int = 0,
    *,
    pageid: int = SUPERORDER_L2_PAGEID,
    seq: int = 0x00CB,
) -> bytes:
    """构造 7169 逐笔成交回放请求（Level2 市场连接专用）。

    Args:
        code: 股票代码（如 ``"000938"``、``"603118"``）。
        market: 市场码（17=沪, 33=深）。
        start_ts: 区间起点 unix 时间戳（秒）。0 表示从最近开始往前回放。
        end_ts: 区间终点 unix 时间戳（秒）。0 表示到当前/收盘。
        pageid: ``4214``（逐笔面板）或 ``4260``（超级盘口）；两通道响应同构。
        seq: 请求序号（默认对齐 2026-08-05 抓包）。

    Returns:
        ``encode_frame`` 包装后的请求帧（``fdfdfdfd`` + 8 位 ASCII 长度 + body）。

    请求是三层嵌套帧（2026-08-05 抓包逐字节确认，与 auction L2 同源）::

        外层 (cmd=0x09, route=0x02fc): CodeList + pageid
          内层1 (route=0x02e2): CodeList + pageid
            内层2 (route=0x01fc): CodeList + DataType + DateTime + LackTime + pageid

    最内层文本::

        CodeList=33(000938,);
        DataType=10,12,13,
        DateTime=7169(<start_unix>-<end_unix>)
        LackTime=0,0,0,0,0,0,0,0
        pageid=4214
    """
    datatype_text = ",".join(str(v) for v in SUPERORDER_DATATYPE) + ","
    market_text = f"{market}({code},);"

    # 三层嵌套（2026-08-05 抓包逐字节确认，结构与 build_auction_query 同源）
    # 外层 + 内层1 都只带 CodeList + pageid；内层2 带 DataType/DateTime/LackTime
    outer_text = (
        f"CodeList={market_text}\r\npageid={pageid}\r\n"
    ).encode("gbk")
    inner1_text = (
        f"CodeList={market_text}\r\npageid={pageid}\r\n"
    ).encode("gbk")
    inner2_text = (
        f"CodeList={market_text}\r\n"
        f"DataType={datatype_text}\r\n"
        f"DateTime={SUPERORDER_PERIOD}({start_ts}-{end_ts})\r\n"
        f"LackTime=0,0,0,0,0,0,0,0\r\n"
        f"pageid={pageid}\r\n"
    ).encode("gbk")

    # 内层2 header（22B，route=0x01fc，与 auction L2 内层一致）
    inner2_header = bytearray(22)
    inner2_header[0:4] = b"\x00\x16\x00\x00"
    struct.pack_into("<H", inner2_header, 4, 0x019D)   # seq（对齐抓包）
    inner2_header[6:10] = b"\x12\x00\x09\x00"
    inner2_header[10:12] = b"\xfc\x01"                 # route 0x01fc
    inner2_header[12:14] = b"\x00\x00"
    inner2_header[14:16] = b"\x40\x00"
    inner2_header[16:18] = b"\x01\x1c"
    struct.pack_into("<H", inner2_header, 18, len(inner2_text))
    inner2_frame = bytes(inner2_header) + inner2_text

    # 内层1 header（22B，route=0x02e2）
    inner1_header = bytearray(22)
    inner1_header[0:4] = b"\x00\x16\x00\x00"
    inner1_header[6:10] = b"\x12\x00\x02\x00"
    inner1_header[10:12] = b"\xe2\x02"                 # route 0x02e2
    struct.pack_into("<I", inner1_header, 18, len(inner1_text))
    inner1_frame = bytes(inner1_header) + inner1_text + inner2_frame

    # 外层 header（23B，cmd=0x09，route=0x02fc）
    outer_header = bytearray(23)
    outer_header[0] = 0x09
    outer_header[1:5] = b"\x00\x16\x00\x00"
    struct.pack_into("<H", outer_header, 5, seq & 0xFFFF)
    outer_header[7:11] = b"\x12\x00\x02\x00"
    outer_header[11:13] = _SUPERORDER_ROUTE            # route 0x02fc
    struct.pack_into("<I", outer_header, 19, len(outer_text))
    body = bytes(outer_header) + outer_text + inner1_frame
    return encode_frame(body)


def _ts_valid(ts: int) -> bool:
    """unix 时间戳是否落在合理交易时段区间。"""
    return _TS_LO <= ts <= _TS_HI


def _locate_data_offset(body: bytes, shell_search_from: int) -> tuple[int, str]:
    """定位记录区起点 + 提取股票代码。

    The stock shell is 22 bytes, with its market marker four bytes in.
    Rows therefore start at marker+18 with trade_no, followed by timestamp.

    为兜住偶发的填充长度漂移，在 marker+18 附近 ±2 字节小窗口内取**首个使连续记录
    ts 合法**的偏移。窗口很窄（不扫描整个填充区），避免误定位到 body 其它位置的
    合法 ts 序列（多段拼接帧的假阳性）。

    Returns:
        (data_off, code)；未找到返回 (-1, "")。
    """
    # 在字段表后 120 字节窗口内找个股壳（0x11/0x21 + 6 位数字）
    window_end = min(len(body), shell_search_from + 120)
    for off in range(shell_search_from, window_end):
        marker = body[off]
        if marker not in (0x11, 0x21):
            continue
        candidate = body[off + 1: off + 7]
        if len(candidate) < 6:
            continue
        try:
            code = candidate.decode("ascii")
        except UnicodeDecodeError:
            continue
        if not code.isdigit():
            continue
        for delta in (18, 17, 19, 16, 20):
            doff = off + delta
            if doff + 8 > len(body):
                continue
            ts0 = struct.unpack_from("<I", body, doff + 4)[0]
            if _ts_valid(ts0) and _validate_run_start(body, doff + 4):
                return doff, code
        # 壳找到了但数据起点定位不到，不再找别的壳
        break
    return -1, ""


def _validate_run_start(body: bytes, doff: int) -> bool:
    """验证从 doff 起的前几条记录（stride=32）ts 合法且单调近距。

    验证 min(4, 可读条数) 条；单条帧（仅 1 条）退化为验证那 1 条。
    """
    hs = SUPERORDER_RECORD_SIZE
    prev = None
    for i in range(4):
        pos = doff + i * hs
        if pos + 4 > len(body):
            return i >= 1   # 已验证 ≥1 条即接受
        ts = struct.unpack_from("<I", body, pos)[0]
        if not _ts_valid(ts):
            return False
        if prev is not None and not (0 <= ts - prev <= 600):
            return False
        prev = ts
    return True


def parse_superorder_response(body: bytes) -> list[dict]:
    """解析 7169 逐笔成交回放响应，返回逐笔记录列表。

    自动处理 ``cmd=0x0a`` 外层压缩（沪深均需先 normalize）。沪深字段表完全一致，
    解析路径统一；委托号语义差异（深=买/卖，沪=主动/被动）见模块 docstring。

    每条记录::

        {
            "code": "000938",
            "time": datetime,          # dt1, 撮合时刻
            "price": 37.75,            # dt56, 成交价（元）
            "volume": 100,             # dt10, raw quantity; unit not normalized
            "direction": 5,            # dt13, 1=主动买(外盘) / 5=主动卖(内盘)
            "delegate_a": 37048499,    # dt12, 委托号 A（深=卖方 / 沪=主动方）
            "delegate_b": 37045605,    # dt74, 委托号 B（深=买方 / 沪=被动方挂单）
            "seq": 497839,             # dt75, 逐笔序号（本帧内严格 +1）
            "trade_no": 37048731,      # dt18, 成交号/委托序号
            # 原始 dt 值另存供调试
            "dt1": 1785907131, "dt56": ..., "dt10": ..., "dt13": ...,
            "dt12": ..., "dt74": ..., "dt75": ..., "dt18": ...,
        }

    Args:
        body: 单个 8901 响应帧 body（含或不含 ``\\x0a`` 外层压缩均可）。

    Returns:
        逐笔记录列表（按帧内顺序，时间正序）；非 7169 帧或解析失败返回 []。
    """
    # 1. 入口 normalize（cmd=0x0a 外层压缩，沪深均需）
    if body.startswith(b"\x0a"):
        try:
            body = normalize_8901_response(body, strict=True)
        except Incomplete8901Response as exc:
            body = exc.normalized_prefix
        except ValueError as exc:
            logger.debug("7169 外层正规化失败: %s", exc)
            return []

    records: list[dict] = []
    position = 0
    while True:
        marker = body.find(b"hd1.0\x00", position)
        if marker < 0:
            break
        position = marker + 6
        base = marker + 6
        if len(body) < base + 10:
            continue
        record_count, flag, hs, fc = struct.unpack_from("<IHHH", body, base)
        # 2. flag/布局校验：7169 是 0x0046 行主序定长，非 BitRLE
        if flag != SUPERORDER_FLAG:
            continue
        if hs != SUPERORDER_RECORD_SIZE or fc != SUPERORDER_FIELD_COUNT:
            continue
        if record_count == 0 or record_count > 2_000_000:
            continue
        # 3. 字段表（base+10 起 fc*4 字节）
        fields = tuple(_parse_hd_field_table(body, base + 10, fc))
        if fields != _SUPERORDER_FIELDS:
            continue
        # 4. 定位记录起点 + 股票代码
        shell_search_from = base + 10 + fc * 4
        next_table = body.find(b"hd1.0\x00", shell_search_from)
        table_end = next_table if next_table >= 0 else len(body)
        data_off, code = _locate_data_offset(body[:table_end], shell_search_from)
        if data_off < 0:
            continue

        # 5. 行主序切记录 + 逐条 ts 合法性 + 单调近距过滤
        # （截断帧尾部会混入下帧头部，需同时用 ts 合法性和相邻 ts 差 ≤ 600s 过滤）
        prev_ts: int | None = None
        for i in range(record_count):
            row_off = data_off + i * hs
            if row_off + hs > table_end:
                break
            trade_no, ts, price_raw, vol, direction, delegate_a, delegate_b, seq = (
                struct.unpack_from("<8I", body, row_off)
            )
            if not _ts_valid(ts):
                # 一旦遇到非法 ts，后续都是越界数据（下帧头部/填充），停止本帧
                break
            if prev_ts is not None and not (0 <= ts - prev_ts <= 600):
                # 相邻 ts 差过大（跨段拼接/帧边界），停止本帧
                break
            prev_ts = ts
            if seq > _SEQ_MAX:
                break
            try:
                t = datetime.fromtimestamp(ts)
            except (OSError, ValueError, OverflowError):
                t = None
            records.append({
                "code": code,
                "time": t,
                "price": decode_ths_float(price_raw),
                "volume": vol,
                "direction": direction,
                "delegate_a": delegate_a,
                "delegate_b": delegate_b,
                "seq": seq,
                "trade_no": trade_no,
                # 原始 dt 值（调试/回归用）
                "dt1": ts, "dt56": price_raw, "dt10": vol, "dt13": direction,
                "dt12": delegate_a, "dt74": delegate_b, "dt75": seq, "dt18": trade_no,
            })
        # 7169 单帧通常已含全部数据；继续找下一个 hd1.0（多帧分页兜底）
    return records


def _market_response_evidence(
    body: bytes, *, period: int, code: str | None = None,
) -> dict:
    """Validate all tables of one feed; filtering rows never hides frame errors."""
    if period not in (
        SUPERORDER_PERIOD, ORDER_DETAIL_PERIOD, BUY_CANCEL_PERIOD, SELL_CANCEL_PERIOD,
    ):
        raise ValueError(f"unsupported market detail period: {period}")
    result = {
        "recognized": False, "complete": False, "errors": [],
        "declared_count": 0, "parsed_count": 0, "rows": [],
        "table_codes": [], "truncated": False,
    }
    errors = result["errors"]
    try:
        body = normalize_8901_response(body, strict=True)
    except Incomplete8901Response as exc:
        body = exc.normalized_prefix
        errors.append("compressed_source_exhausted")
        result["truncated"] = True
    except ValueError:
        errors.append("invalid_compressed_response")
        return result

    position = 0
    while True:
        marker = body.find(b"hd1.0\x00", position)
        if marker < 0:
            break
        position = marker + 6
        if marker + 16 > len(body):
            errors.append("incomplete_table_header")
            break
        count, flag, size, field_count = struct.unpack_from("<IHHH", body, marker + 6)
        field_start = marker + 16
        field_end = field_start + field_count * 4
        if field_end > len(body):
            errors.append("incomplete_field_table")
            break
        fields = tuple(_parse_hd_field_table(body, field_start, field_count))
        layout = (flag, size, field_count)
        if period == SUPERORDER_PERIOD:
            matches = layout == (SUPERORDER_FLAG, 32, 8)
            matches = matches and tuple(field[0] for field in fields[:3]) == (1, 56, 10)
        elif period == ORDER_DETAIL_PERIOD:
            matches = layout == (ORDER_DETAIL_FLAG, 20, 5)
            matches = matches and fields == _ORDER_DETAIL_FIELDS
        else:
            matches = layout == (CANCEL_DETAIL_FLAG, 31, 7)
            matches = matches and fields == _CANCEL_DETAIL_FIELDS
        if not matches:
            continue
        next_table = body.find(b"hd1.0\x00", field_end)
        table_end = next_table if next_table >= 0 else len(body)
        table_code = None
        for offset in range(field_end, min(field_end + 120, table_end - 6)):
            candidate = body[offset + 1:offset + 7]
            if body[offset] in (0x11, 0x21) and candidate.isalnum():
                table_code = candidate.decode("ascii")
                break
        if table_code is None:
            errors.append("missing_table_code")
            continue
        result["table_codes"].append(table_code)
        result["declared_count"] += count
        selected = code is None or table_code == code
        result["recognized"] = result["recognized"] or selected
        shell_complete = offset + 18 <= table_end
        if not shell_complete:
            errors.append(f"incomplete_stock_shell:{table_code}")
        signature_valid = period != SUPERORDER_PERIOD or fields == _SUPERORDER_FIELDS
        if not signature_valid:
            errors.append(f"field_signature_mismatch:{table_code}")
        valid_widths = sum(field[2] for field in fields) == size
        if period == SUPERORDER_PERIOD:
            valid_widths = valid_widths and all(field[2] == 4 for field in fields)
        if not valid_widths:
            errors.append(f"field_width_mismatch:{table_code}")
            parsed = []
        elif not shell_complete or not signature_valid:
            parsed = []
        elif count > 2_000_000:
            errors.append(f"invalid_row_count:{table_code}:{count}")
            parsed = []
        else:
            table_body = body[marker:table_end]
            parsed = (
                parse_superorder_response(table_body)
                if period == SUPERORDER_PERIOD
                else parse_order_detail_response(table_body, period=period)
            )
        if any(row.get("code") != table_code for row in parsed):
            errors.append(f"row_code_mismatch:{table_code}")
        if period == ORDER_DETAIL_PERIOD and any(
            row.get("side") not in ("buy", "sell") for row in parsed
        ):
            errors.append(f"unknown_order_side:{table_code}")
        if len(parsed) != count:
            errors.append(f"row_count_mismatch:{table_code}:{count}:{len(parsed)}")
        result["parsed_count"] += len(parsed)
        if selected:
            result["rows"].extend(parsed)
    result["table_codes"] = sorted(set(result["table_codes"]))
    result["complete"] = result["recognized"] and not errors
    result["truncated"] = (
        result["truncated"] or result["parsed_count"] < result["declared_count"]
    )
    return result


def is_superorder_response(body: bytes, *, code: str | None = None) -> bool:
    """Return whether *body* contains the requested 7169 trade table.

    7169 shares its ``0x46/32/8`` header layout with index 4096 tables and a
    busy L2 lane carries many unrelated ``hd1.0`` pushes. Match the field
    signature and optional stock code before a synchronous caller consumes the
    frame; a structurally valid zero-row table is still a confirmed response.
    """
    if body.startswith(b"\x0a"):
        try:
            body = normalize_8901_response(body)
        except ValueError:
            return False

    pos = 0
    while True:
        marker = body.find(b"hd1.0", pos)
        if marker < 0:
            return False
        base = marker + 6
        if base + 10 <= len(body):
            _count, flag, record_size, field_count = struct.unpack_from(
                "<IHHH", body, base
            )
            field_offset = base + 10
            field_end = field_offset + field_count * 4
            if (
                (flag, record_size, field_count)
                == (
                    SUPERORDER_FLAG,
                    SUPERORDER_RECORD_SIZE,
                    SUPERORDER_FIELD_COUNT,
                )
                and field_end <= len(body)
                and tuple(
                    body[field_offset + index * 4] for index in range(3)
                )
                == (1, 56, 10)
            ):
                if code is None:
                    return True
                shell_end = min(field_end + 160, len(body))
                if code.encode("ascii") in body[field_end:shell_end]:
                    return True
        pos = marker + 6


def build_snapshot_replay_query(
    code: str,
    market: int = 33,
    *,
    pageid: int = SNAPSHOT_REPLAY_PAGEID,
    seq: int = 0x00C0,
    companion_seq: int = 0x00C2,
    start_ts: int = 0,
    end_ts: int = 0,
) -> bytes:
    """构造 4096 盘口快照回放请求（超级盘口分时曲线）。

    - ``pageid=4417``（盘后/历史）：**单子帧** 0x09/0x017d，字节对齐
      2026-08-07 盘后抓包 fr1986（DataType=7,10,12,13,...,157,6,66,1110）。
    - ``pageid=4260``（盘中）：双子帧 0x09（route=0x0158），SUB1=盘口快照主体
      （DataType 含十档），SUB2=伴随查询（DataType=7,10,2419,...）。
    DateTime=4096(<start>-<end>)：
      - 0-0：当日全天每 3 秒一个完整盘口快照（~4927 点）
      - 绝对 unix 秒区间：历史日期（如 4096(1785979800-1785999660) = 08-06 全天）
      - 相对负区间：如 4096(-6-0)
    pageid：盘中 4260（默认）；盘后/历史 4417（2026-08-07 抓包确认）。

    Args:
        code: 股票代码（如 ``"000938"``）。
        market: 市场码（17=沪, 33=深）。
        pageid: 4260（盘中）或 4417（盘后/历史）。
        start_ts: 区间起点 unix 秒；0 = 当日全天/从开头。
        end_ts: 区间终点 unix 秒；0 = 到当前/收盘。也可传负值表示相对窗口。
    """
    target = f"{market}({code},);"
    if pageid == SNAPSHOT_REPLAY_HIST_PAGEID:
        # 单子帧形态（抓包 fr1986，字节级对齐）
        dt_text = ",".join(str(v) for v in SNAPSHOT_REPLAY_HIST_DATATYPE) + ","
        text = (
            f"CodeList={target}\r\n"
            f"DataType={dt_text}\r\n"
            f"DateTime={SNAPSHOT_REPLAY_PERIOD}({start_ts}-{end_ts})\r\n"
            f"LackTime=0,0,0,0,0,0,0,0\r\n"
            f"pageid={pageid}\r"
        ).encode("gbk")
        header = bytearray(23)
        header[0] = 0x09
        header[1:5] = b"\x00\x16\x00\x00"
        struct.pack_into("<H", header, 5, seq & 0xFFFF)
        header[7:11] = b"\x12\x00\x09\x00"
        header[11:13] = b"\x7d\x01"
        header[13:19] = b"\x00\x00\x00\x00\x00\x10"
        struct.pack_into("<I", header, 19, len(text) + 1)
        return encode_frame(bytes(header) + text)

    if pageid == SNAPSHOT_REPLAY_INDEX_PAGEID:
        # 指数双子帧形态（2026-08-07 盘后抓包 fr112/fr542，字节级对齐）：
        # 每对 = outer 0x0002/0x0038（CodeList+pageid）+ inner 0x0009/0x0138
        # （CodeList+DataType+DateTime+LackTime+pageid）。
        # 客户端一帧内发两对：4096(0-0) + 4096(<请求区间>)，服务器因此回两张表
        # （今日 + 目标日），由服务层按请求区间过滤出目标日。
        dt_text = ",".join(str(v) for v in SNAPSHOT_REPLAY_HIST_DATATYPE) + ","

        def _pair(
            inner_seq: int,
            start: int,
            end: int,
            *,
            final: bool = False,
        ) -> bytes:
            outer_text = (
                f"CodeList={target}\r\npageid={pageid}\r\n"
            ).encode("gbk")
            # 抓包：中间子帧以 \r\n 结尾，帧内最后一个子帧只以 \r 结尾。
            pageid_suffix = "\r" if final else "\r\n"
            inner_text = (
                f"CodeList={target}\r\n"
                f"DataType={dt_text}\r\n"
                f"DateTime={SNAPSHOT_REPLAY_PERIOD}({start}-{end})\r\n"
                f"LackTime=0,0,0,0,0,0,0,0\r\n"
                f"pageid={pageid}{pageid_suffix}"
            ).encode("gbk")
            # 帧级 0x09 只出现一次（在 encode_frame 前手动加），
            # 每对的 outer 头是 22B，无 0x09（2026-08-07 抓包字节确认）。
            outer_header = bytearray(22)
            outer_header[0:4] = b"\x00\x16\x00\x00"
            outer_header[6:10] = b"\x12\x00\x02\x00"
            outer_header[10:12] = b"\x38\x00"
            struct.pack_into("<I", outer_header, 18, len(outer_text))
            inner_header = bytearray(22)
            inner_header[0:4] = b"\x00\x16\x00\x00"
            struct.pack_into("<H", inner_header, 4, inner_seq & 0xFFFF)
            inner_header[6:10] = b"\x12\x00\x09\x00"
            inner_header[10:12] = b"\x38\x01"
            inner_header[12:18] = b"\x00\x00\x00\x00\x00\x10"
            # 抓包：帧内最后一个子帧的 length 字段 = 文本长度 + 1（与 4417 单帧一致）
            struct.pack_into(
                "<I",
                inner_header,
                18,
                len(inner_text) + (1 if final else 0),
            )
            return bytes(outer_header) + outer_text + bytes(inner_header) + inner_text

        body = _pair(seq, 0, 0, final=(start_ts <= 0 and end_ts <= 0))
        if start_ts > 0 or end_ts > 0:
            body += _pair(companion_seq, start_ts, end_ts, final=True)
        return encode_frame(b"\x09" + body)

    dt_text = ",".join(str(v) for v in SNAPSHOT_REPLAY_DATATYPE) + ","
    main_text = (
        f"CodeList={target}\r\nDataType={dt_text}\r\n"
        f"DateTime={SNAPSHOT_REPLAY_PERIOD}({start_ts}-{end_ts})\r\n"
        f"LackTime=0,0,0,0,0,0,0,0\r\npageid={pageid}\r"
    ).encode("gbk")
    comp_dt = ",".join(str(v) for v in SNAPSHOT_REPLAY_COMPANION_DATATYPE) + ","
    comp_text = (
        f"CodeList={target}\r\nDataType={comp_dt}\r\n"
        f"DateTime=0(0-0)\r\n"
        f"LackTime=0,0,0,0,0,0,0,0\r\npageid={pageid}\r"
    ).encode("gbk")

    def _sub(seq_val, text):
        h = bytearray(22)
        h[0:4] = b"\x00\x16\x00\x00"
        struct.pack_into("<H", h, 4, seq_val & 0xFFFF)
        h[6:10] = b"\x12\x00\x09\x00"
        struct.pack_into("<H", h, 10, _SNAPSHOT_REPLAY_ROUTE)
        h[12:14] = b"\x00\x00"
        h[14:16] = b"\x00\x10"
        struct.pack_into("<I", h, 18, len(text))
        return bytes(h) + text

    return encode_frame(b"\x09" + _sub(seq, main_text) + _sub(companion_seq, comp_text))


def is_snapshot_replay_response(body: bytes, *, code: str | None = None) -> bool:
    """Return whether *body* contains a recognized 4096 replay table.

    An empty table is still a matching response.  Callers need this distinction
    because a busy L2 socket can deliver many unrelated push frames before the
    requested 4096 response; exhausting a frame budget must not be interpreted
    as a valid empty replay.
    """
    if body.startswith(b"\x0a"):
        try:
            body = normalize_8901_response(body)
        except ValueError:
            return False

    layouts = {
        (SNAPSHOT_REPLAY_FLAG, 216, 54),
        (
            SNAPSHOT_REPLAY_HIST_FLAG,
            SNAPSHOT_REPLAY_HIST_RECORD_SIZE,
            SNAPSHOT_REPLAY_HIST_FIELD_COUNT,
        ),
        (
            SNAPSHOT_REPLAY_INDEX_FLAG,
            SNAPSHOT_REPLAY_INDEX_RECORD_SIZE,
            SNAPSHOT_REPLAY_INDEX_FIELD_COUNT,
        ),
    }
    pos = 0
    while True:
        marker = body.find(b"hd1.0", pos)
        if marker < 0:
            return False
        base = marker + 6
        if base + 10 <= len(body):
            flag, record_size, field_count = struct.unpack_from(
                "<HHH", body, base + 4
            )
            layout = (flag, record_size, field_count)
            field_offset = base + 10
            field_end = field_offset + field_count * 4
            if layout in layouts and field_end <= len(body):
                # 4096 index tables share 0x46/32/8 with 7169 trades. Their
                # second field is dt10 (price), while 7169 starts dt1/dt56.
                if layout == (
                    SNAPSHOT_REPLAY_INDEX_FLAG,
                    SNAPSHOT_REPLAY_INDEX_RECORD_SIZE,
                    SNAPSHOT_REPLAY_INDEX_FIELD_COUNT,
                ) and (
                    body[field_offset] != 1
                    or body[field_offset + 4] != 10
                ):
                    pos = marker + 6
                    continue
                if code is not None:
                    shell_end = min(field_end + 160, len(body))
                    if code.encode("ascii") not in body[field_end:shell_end]:
                        pos = marker + 6
                        continue
                return True
        pos = marker + 6


def parse_snapshot_replay_response(body: bytes) -> list[dict]:
    """解析 4096 盘口快照回放响应（hd1.0 行主序）。

    每条记录是一个时刻的完整盘口快照（~3 秒间隔），含：
    - ``time``：dt1 unix 时间戳 → datetime
    - ``price``：dt10 最新价
    - 十档买卖价量（dt24-35 买1-买5/卖1-卖5 + dt102-125 六~十档）

    支持两种服务端布局：
    - 盘中 4260 通道：flag=0x00FE，hs=216，fc=54（2026-08-06 破译）
    - 盘后/历史 4417 通道：flag=0x009E，hs=120，fc=30（2026-08-07 抓包确认，
      字段为 dt1/10/13/12/20/21/49/18/19/75 + 买卖档位，无 102-125）

    Args:
        body: 8901 响应帧（可能含 0x0a 外层压缩）。

    Returns:
        盘口快照记录列表，按时间正序。
    """
    if body.startswith(b"\x0a"):
        try:
            body = normalize_8901_response(body)
        except ValueError as exc:
            logger.debug("snapshot replay normalization failed: %s", exc)
            return []

    records: list[dict] = []
    pos = 0
    while True:
        marker = body.find(b"hd1.0", pos)
        if marker < 0:
            break
        pos = marker + 6
        table_records = _parse_snapshot_replay_table(body, marker)
        if table_records:
            records.extend(table_records)
    return records


def _parse_snapshot_replay_table(body: bytes, marker_pos: int) -> list[dict]:
    """解析单个 hd1.0 快照回放表（0xFE / 0x9E / 0x46 布局）。

    一个响应帧可能含多张表（如指数帧 = 今日 + 请求历史日），主解析器遍历全部
    hd1.0 标记并逐表调用本函数，结果按顺序拼接。
    """
    base = marker_pos + 6
    if base + 10 > len(body):
        return []

    record_count = struct.unpack_from("<I", body, base)[0]
    flag = struct.unpack_from("<H", body, base + 4)[0]
    record_size = struct.unpack_from("<H", body, base + 6)[0]
    field_count = struct.unpack_from("<H", body, base + 8)[0]
    if flag not in (
        SNAPSHOT_REPLAY_FLAG,
        SNAPSHOT_REPLAY_HIST_FLAG,
        SNAPSHOT_REPLAY_INDEX_FLAG,
    ):
        return []
    if record_size == 0 or record_count == 0:
        return []
    # 历史嵌套帧的 dc 高 16 位是壳标记，低 16 位才是记录数（如 0x040012E2 → 4834）
    if record_count > 0xFFFF:
        record_count &= 0xFFFF

    # 字段表（fc 可能 >50，手动解析）
    ft_off = base + 10
    if ft_off + field_count * 4 > len(body):
        return []
    fields = []
    for i in range(field_count):
        ft = body[ft_off + i * 4 : ft_off + i * 4 + 4]
        fields.append((ft[0], ft[1], ft[2], ft[3]))  # dt, fmt, flags, width

    # 壳段（22B，含代码标签）
    shell_off = ft_off + field_count * 4
    if shell_off + 22 > len(body):
        return []
    # 行起点：优先用「壳后连续 ≥2 条合法 unix 秒」定位（历史帧壳后有 0xFF 填充），
    # 找不到再退回 shell+22。
    data_off = shell_off + 22
    best = None
    for ds in range(shell_off + 18, min(shell_off + 160, len(body) - record_size * 2)):
        n = 0
        prev = None
        for i in range(8):
            o = ds + i * record_size
            if o + 4 > len(body):
                break
            v = struct.unpack_from("<I", body, o)[0]
            if not (1_700_000_000 <= v <= 1_900_000_000):
                break
            if prev is not None and not (0 < v - prev <= 300):
                break
            prev = v
            n += 1
        if n > (best[0] if best else 0):
            best = (n, ds)
    if best is not None and best[0] >= 2:
        data_off = best[1]

    # 字段偏移表
    offsets = {}
    off = 0
    for dt, fmt, _flags, width in fields:
        offsets[dt] = (off, width)
        off += width
    # 指数 0x46/32/8 布局与 7169 逐笔同 flag，必须用字段表区分：
    # 指数快照 dt1@0、dt10@4；7169 逐笔 dt1@0、dt56@4。
    if flag == SNAPSHOT_REPLAY_INDEX_FLAG and (
        offsets.get(1) != (0, 4) or offsets.get(10) != (4, 4)
    ):
        return []
    if offsets.get(1) is None or offsets.get(10) is None:
        return []

    records: list[dict] = []
    prev_ts: int | None = None
    first_date = None
    for index in range(record_count):
        row_start = data_off + index * record_size
        row = body[row_start : row_start + record_size]
        if len(row) < record_size:
            break
        # dt1 时间戳校验：合法 unix 秒 + 与首行同日期 + 间隔 ≤2h（午休 11:30-13:00），
        # 超出即截断（历史嵌套帧尾部会混入后续小表的字节）。
        ts_value = struct.unpack_from("<I", row, offsets[1][0])[0]
        if not (1_700_000_000 <= ts_value <= 1_900_000_000):
            break
        from datetime import datetime as _datetime
        try:
            ts_date = _datetime.fromtimestamp(ts_value).date()
        except (OSError, ValueError, OverflowError):
            break
        if first_date is None:
            first_date = ts_date
        elif ts_date != first_date:
            break
        if prev_ts is not None and not (0 < ts_value - prev_ts <= 7200):
            break
        prev_ts = ts_value
        rec: dict = {}
        for dt, (value_off, width) in offsets.items():
            chunk = row[value_off : value_off + width]
            if width != 4 or len(chunk) != 4:
                continue
            raw_value = struct.unpack("<I", chunk)[0]
            if dt == 1:
                rec["time"] = datetime.fromtimestamp(raw_value).strftime("%H:%M:%S")
                rec["ts"] = raw_value
            elif dt == 10:
                rec["price"] = round(decode_ths_float(raw_value), 3)
            elif dt in (13, 19, 49):
                rec[f"dt{dt}"] = decode_ths_float(raw_value)
            elif dt in (24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35,
                        102, 103, 104, 105, 106, 107, 108, 109, 110, 111,
                        112, 113, 114, 115, 116, 117, 118, 119, 120, 121,
                        122, 123, 124, 125, 150, 151, 152, 153, 154, 155, 156, 157,
                        18):
                rec[f"dt{dt}"] = decode_ths_float(raw_value)
        records.append(rec)
    return records


__all__ = [
    "SUPERORDER_PERIOD",
    "SUPERORDER_L2_PAGEID",
    "SUPERORDER_SUPER_PAGEID",
    "SUPERORDER_DATATYPE",
    "SUPERORDER_FLAG",
    "SUPERORDER_RECORD_SIZE",
    "SUPERORDER_FIELD_COUNT",
    "SNAPSHOT_REPLAY_PERIOD",
    "SNAPSHOT_REPLAY_PAGEID",
    "SNAPSHOT_REPLAY_DATATYPE",
    "SNAPSHOT_REPLAY_FLAG",
    "SNAPSHOT_REPLAY_HIST_PAGEID",
    "SNAPSHOT_REPLAY_HIST_FLAG",
    "SNAPSHOT_REPLAY_HIST_RECORD_SIZE",
    "SNAPSHOT_REPLAY_HIST_FIELD_COUNT",
    "SNAPSHOT_REPLAY_HIST_DATATYPE",
    "SNAPSHOT_REPLAY_INDEX_FLAG",
    "SNAPSHOT_REPLAY_INDEX_RECORD_SIZE",
    "SNAPSHOT_REPLAY_INDEX_FIELD_COUNT",
    "is_snapshot_replay_response",
    "SNAPSHOT_REPLAY_INDEX_PAGEID",
    "ORDER_QUEUE_BUY_PERIOD",
    "ORDER_QUEUE_SELL_PERIOD",
    "ORDER_QUEUE_DATATYPE",
    "ORDER_QUEUE_PAGEID",
    "ORDER_QUEUE_HIST_PAGEID",
    "ORDER_QUEUE_FLAG",
    "ORDER_QUEUE_RECORD_SIZE",
    "ORDER_QUEUE_FIELD_COUNT",
    "ORDER_DETAIL_PERIOD",
    "BUY_CANCEL_PERIOD",
    "SELL_CANCEL_PERIOD",
    "ORDER_DETAIL_DATATYPE",
    "CANCEL_DETAIL_DATATYPE",
    "ORDER_DETAIL_FLAG",
    "ORDER_DETAIL_RECORD_SIZE",
    "ORDER_DETAIL_FIELD_COUNT",
    "CANCEL_DETAIL_FLAG",
    "CANCEL_DETAIL_RECORD_SIZE",
    "CANCEL_DETAIL_FIELD_COUNT",
    "build_superorder_query",
    "is_superorder_response",
    "parse_superorder_response",
    "build_snapshot_replay_query",
    "parse_snapshot_replay_response",
    "build_order_queue_query",
    "parse_order_queue_response",
    "build_order_detail_query",
    "parse_order_detail_response",
]


# ── 北交所（BSE）秒级逐笔窗口（2026-09-08 双账号抓包确认）──
# DateTime=7176(unixStart-unixEnd) 平文本时间窗（区别于沪深的嵌套 pair
# 结构），pageid=10443，route=0x01fc、子帧头 [14:16]=0x0040，走
# main.123ths.com 系连接。窗口通常 600s（早盘竞价 09:15-09:25 等），
# 历史日期的竞价窗换 6144 tag、pageid=10444。响应为 0x0a-LZ 外层的
# flag=0x003a 表（20B 行：dt1=unix 秒、dt10=价、dt49=累计量、
# dt27/dt33=买/卖未匹配），逐笔事件驱动、时间不连续（BSE 流动性差）。
BSE_TICK_WINDOW_PAGEID = 10443
BSE_TICK_WINDOW_TAG = 7176
BSE_TICK_WINDOW_DATATYPE = [10, 27, 33, 49]
# 历史竞价窗（分时页历史日期的 09:15-09:25 逐笔，2026-09-08 日期标定抓包）：
# tag=6144、pageid=10444、route=0x0100（非 0x01FC）、w14=0x0000、b17=0x18，
# 响应仍是 0x003a/rs20/fc5 表（字段 1,10,49,27,33），由同一解析器处理。
BSE_AUCTION_WINDOW_TAG = 6144
BSE_AUCTION_WINDOW_PAGEID = 10444

_BSE_TICK_SEQ = __import__("itertools").count(0x0300, 2)

# ── 北交所盘中超级盘口（pageid=1207 + DateTime=4096，2026-09-08 复抓）──
# 官方"超级盘口"页当日形态：注册子帧 + 4096 全日窗主体 + 状态子帧三联发
# （单个 fd 帧内嵌三子帧）。响应 flag=0x0096 大表（rsize=112 / 28 字段），
# 每行一个逐笔事件并携带完整五档快照；同请求另回 0x003a 轻量表（dt49
# 分段累计，单笔量不可靠，权威字段在 0x0096 表）。
BSE_SUPERORDER_PAGEID = 1207
BSE_SUPERORDER_ROUTE = 0x016F
BSE_SUPERORDER_TABLE_FLAG = 0x0096
# 金样本（2026-09-08 抓包 frame1468）逐字节对齐的 DataType 序列。
BSE_SUPERORDER_DATATYPE = [
    10, 12, 13, 14, 18, 19, 20, 21,
    25, 26, 27, 28, 29, 31, 32, 33, 34, 35,
    49, 75, 150, 151, 152, 153, 154, 155, 156, 157,
    6, 407, 619, 1110,
]
# 五档价量字段（价, 量）对：买1-5 / 卖1-5（金样本末行五档单调性验证）。
BSE_SUPERORDER_BID_FIELDS = [(20, 25), (26, 27), (28, 29), (150, 151), (154, 155)]
BSE_SUPERORDER_ASK_FIELDS = [(21, 31), (32, 33), (34, 35), (152, 153), (156, 157)]

_BSE_SUPERORDER_SEQ = __import__("itertools").count(0x0600, 2)


def _bse_subframe(
    seq: int,
    sub_type: bytes,
    route: int,
    flag14: int,
    byte16: int,
    byte17: int,
    text: bytes,
) -> bytes:
    header = bytearray(22)
    header[0:4] = b"\x00\x16\x00\x00"
    struct.pack_into("<H", header, 4, seq & 0xFFFF)
    header[6:10] = sub_type
    struct.pack_into("<H", header, 10, route)
    struct.pack_into("<H", header, 14, flag14)
    header[16] = byte16
    header[17] = byte17
    struct.pack_into("<I", header, 18, len(text))
    return bytes(header) + text


def build_bse_superorder_query(
    code: str,
    *,
    market: int = 151,
    preday: bool = False,
    end_ts: int | None = None,
    seqs: tuple[int, int, int] | None = None,
) -> bytes:
    """构建北交所盘中超级盘口请求（pageid=1207，嵌套三子帧）。

    默认 ``DateTime=4096(0-0)``（当日全日）；``preday=True`` 时为官方滚动
    翻页形态 ``PreDay=1 + DateTime=4096(-10000-<end_ts>)``（T-1 全日至
    end_ts）。``seqs`` 供金样本测试注入官方观测值；默认用滚动计数器
    （seq 具体值随连接变化，服务端不校验起始）。
    """
    if seqs is None:
        base = next(_BSE_SUPERORDER_SEQ)
        seqs = (0x0000, base, base + 2)
    dt_text = ",".join(str(v) for v in BSE_SUPERORDER_DATATYPE) + ","
    window = (
        f"4096(-10000-{end_ts})" if preday and end_ts is not None
        else "4096(0-0)"
    )
    main_text = (
        ("PreDay=1\r\n" if preday else "")
        + f"CodeList={market}({code},);\r\nDataType={dt_text}\r\n"
        + f"DateTime={window}\r\nLackTime=0,0,0,0,0,0,0,0\r\n"
        + f"pageid={BSE_SUPERORDER_PAGEID}\r\n"
    ).encode("gbk")
    register_text = (
        f"CodeList={market}({code},);\r\npageid={BSE_SUPERORDER_PAGEID}\r\n"
    ).encode("gbk")
    status_text = (
        f"CodeList={market}({code},);\r\n"
        "DataType=7,10,69,70,2419,2420,6,45,402,619,\r\n"
        "DateTime=0(0-0)\r\nLackTime=0,0,0,0,0,0,0,0\r\n"
        f"pageid={BSE_SUPERORDER_PAGEID}\r\n"
    ).encode("gbk")
    packet = b"\x09" + b"".join((
        _bse_subframe(seqs[0], b"\x12\x00\x02\x00", 0x006F, 0, 0, 0, register_text),
        _bse_subframe(seqs[1], b"\x12\x00\x09\x00", BSE_SUPERORDER_ROUTE, 0, 0, 0x10, main_text),
        _bse_subframe(seqs[2], b"\x12\x00\x09\x00", BSE_SUPERORDER_ROUTE, 0, 0, 0, status_text),
    ))
    return encode_frame(packet)


def parse_bse_superorder_response(body: bytes, *, code: str | None = None) -> list[dict]:
    """解析北交所盘中超级盘口 0x0096 表 → 逐笔+五档快照行。

    每行 ``{code, index, ts, price, volume, dt13=累计量, dt19=累计额,
    bids/asks=[{price, volume}×5], dt14, dt75, ...}``；ts 非法的哨兵行
    （如 T-1 响应首行）直接丢弃。一个响应帧可能含多张表（当日 + PreDay
    的 T-1），全部拼接返回。
    """
    from ..codecs.compression import (
        _decode_bitrle_0x13746d0,
        _transpose_bitplane_0x1763410,
    )

    if body.startswith(b"\x0a"):
        try:
            body = normalize_8901_response(body)
        except ValueError:
            return []

    records: list[dict] = []
    pos = 0
    while True:
        table_pos = body.find(b"hd3.1\x00", pos)
        if table_pos < 0:
            break
        pos = table_pos + 6
        if len(body) < table_pos + 16:
            break
        raw_count, flag, rsize, fcount = struct.unpack_from(
            "<IHHH", body, table_pos + 6,
        )
        if flag != BSE_SUPERORDER_TABLE_FLAG or rsize == 0 or not 1 <= fcount <= 50:
            continue
        count = raw_count & 0xFFFF
        if count == 0:
            continue
        fields = _parse_hd_field_table(body, table_pos + 16, fcount)
        if sum(w for _, _, w in fields) != rsize:
            continue
        shell_off = table_pos + 16 + fcount * 4
        if len(body) < shell_off + 30:
            continue
        shell = body[shell_off:shell_off + 26]
        if shell[:4] != b"\x16\x00\x01\x00":
            continue
        shell_code = shell[5:11].decode("ascii", errors="replace")
        if code is not None and shell_code != code:
            continue
        if struct.unpack_from(">I", body, shell_off + 26)[0] != count * rsize:
            continue
        plane = _decode_bitrle_0x13746d0(body[shell_off + 26:], count * rsize)
        rows = _transpose_bitplane_0x1763410(plane, rsize, count)

        offsets: dict[int, int] = {}
        offset = 0
        for datatype, _fmt, width in fields:
            offsets[datatype] = offset
            offset += width

        for index in range(count):
            row = rows[index * rsize:(index + 1) * rsize]
            record: dict = {"code": shell_code, "index": index}
            ts = 0
            for datatype, field_offset in offsets.items():
                chunk = row[field_offset:field_offset + 4]
                if len(chunk) != 4:
                    continue
                raw = struct.unpack("<I", chunk)[0]
                if datatype == 1:
                    ts = raw
                else:
                    record[f"dt{datatype}"] = decode_ths_float(raw)
            # 哨兵/基线行（2038 年时间戳或 0）与窗口无关，直接丢弃。
            if not 1_700_000_000 <= ts <= 1_900_000_000:
                continue
            record["ts"] = ts
            record["price"] = record.get("dt10")
            record["volume"] = record.get("dt49")
            record["bids"] = [
                {"price": record.get(f"dt{p}"), "volume": record.get(f"dt{v}")}
                for p, v in BSE_SUPERORDER_BID_FIELDS
            ]
            record["asks"] = [
                {"price": record.get(f"dt{p}"), "volume": record.get(f"dt{v}")}
                for p, v in BSE_SUPERORDER_ASK_FIELDS
            ]
            records.append(record)
    return records


def build_bse_tick_window_query(
    code: str,
    *,
    market: int = 151,
    start_ts: int,
    end_ts: int,
    tag: int = BSE_TICK_WINDOW_TAG,
    pageid: int = BSE_TICK_WINDOW_PAGEID,
    seq: int | None = None,
    route: int = 0x01FC,
    flag14: int = 0x0040,
    byte16: int = 0x08,
    byte17: int = 0x1C,
) -> bytes:
    """构建北交所逐笔/竞价回放窗口请求（DateTime=7176/6144 平文本窗）。

    7176（当日逐笔回放，超级盘口页）：route=0x01FC、[14:18]=40 00 08 1C。
    6144（历史竞价 09:15-09:25，分时页）：route=0x0100、[14:18]=00 00 00 18。
    """
    if seq is None:
        seq = next(_BSE_TICK_SEQ)
    dt_text = ",".join(str(v) for v in BSE_TICK_WINDOW_DATATYPE) + ","
    text = (
        f"CodeList={market}({code},);\r\nDataType={dt_text}\r\n"
        f"DateTime={tag}({start_ts}-{end_ts})\r\n"
        f"LackTime=0,0,0,0,0,0,0,0\r\npageid={pageid}\r\n"
    ).encode("gbk")
    header = bytearray(22)
    header[0:4] = b"\x00\x16\x00\x00"
    struct.pack_into("<H", header, 4, seq & 0xFFFF)
    header[6:10] = b"\x12\x00\x09\x00"
    struct.pack_into("<H", header, 10, route)
    struct.pack_into("<H", header, 14, flag14)
    header[16] = byte16
    header[17] = byte17
    struct.pack_into("<I", header, 18, len(text))
    return encode_frame(b"\x09" + bytes(header) + text)


def bse_tick_window_identity(body: bytes) -> tuple[str | None, int] | None:
    """轻量识别 0x003a 逐笔窗响应，返回 ``(code, 行数)``；非本族返回 None。

    与 :func:`parse_bse_tick_response` 共用表头判据但不解码行数据，供
    ``bse_tick_window`` 区分"服务端确认的空窗口"（0 行表）与无关帧——
    否则空窗口会被当作未响应一直等到读超时。空表可能没有壳/行区，
    此时 code 为 None（表头判据已足够定性）。
    """
    if body.startswith(b"\x0a"):
        try:
            body = normalize_8901_response(body)
        except ValueError:
            return None
    pos = body.find(b"hd3.1\x00")
    if pos < 0 or len(body) < pos + 16:
        return None
    raw_count, flag, rsize, fcount = struct.unpack_from("<IHHH", body, pos + 6)
    if flag != 0x003A or rsize == 0 or not 1 <= fcount <= 50:
        return None
    count = raw_count & 0xFFFF
    if count == 0:
        return (None, 0)
    shell_off = pos + 16 + fcount * 4
    if len(body) < shell_off + 30:
        return None
    shell = body[shell_off:shell_off + 26]
    if shell[:4] != b"\x16\x00\x01\x00":
        return None
    return (shell[5:11].decode("ascii", errors="replace"), count)


def parse_bse_tick_response(body: bytes) -> list[dict]:
    """解析北交所 0x003a 逐笔表 → ``{code, ts, price, volume, ...}``。

    dt49 为累计量，逐笔量取相邻差分；首行差分基线为自身（窗口起点）。
    """
    from ..codecs.compression import (
        _decode_bitrle_0x13746d0,
        _transpose_bitplane_0x1763410,
    )

    if body.startswith(b"\x0a"):
        try:
            body = normalize_8901_response(body)
        except ValueError:
            return []
    pos = body.find(b"hd3.1\x00")
    if pos < 0 or len(body) < pos + 16:
        return []
    raw_count, flag, rsize, fcount = struct.unpack_from("<IHHH", body, pos + 6)
    if flag != 0x003A or rsize == 0 or not 1 <= fcount <= 50:
        return []
    # dc 高 16 位是修饰位（如 0x0600，2026-09-08 历史竞价响应 dc=0x0600001c
    # 共 28 行）；行数取低 16 位，与 BE32 长度字交叉校验兜底。
    count = raw_count & 0xFFFF
    if count == 0:
        return []
    fields = _parse_hd_field_table(body, pos + 16, fcount)
    if sum(w for _, _, w in fields) != rsize:
        return []
    shell_off = pos + 16 + fcount * 4
    if len(body) < shell_off + 30:
        return []
    shell = body[shell_off:shell_off + 26]
    if shell[:4] != b"\x16\x00\x01\x00":
        return []
    code = shell[5:11].decode("ascii", errors="replace")
    if struct.unpack_from(">I", body, shell_off + 26)[0] != count * rsize:
        return []
    plane = _decode_bitrle_0x13746d0(body[shell_off + 26:], count * rsize)
    rows = _transpose_bitplane_0x1763410(plane, rsize, count)

    records: list[dict] = []
    prev_cum: float | None = None
    for index in range(count):
        row = rows[index * rsize:(index + 1) * rsize]
        record: dict = {"code": code, "index": index}
        offset = 0
        for datatype, fmt, width in fields:
            chunk = row[offset:offset + width]
            offset += width
            if width != 4:
                continue
            raw = struct.unpack("<I", chunk)[0]
            if datatype == 1:
                record["ts"] = raw
            elif fmt in (0x70, 0x64):
                record[f"dt{datatype}"] = decode_ths_float(raw)
        cum = record.get("dt49")
        record["volume"] = cum if prev_cum is None or cum is None else max(cum - prev_cum, 0)
        if cum is not None:
            prev_cum = cum
        record["price"] = record.get("dt10")
        records.append(record)
    return records
