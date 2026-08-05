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

from ..codecs.compression import normalize_8901_response
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

# 外层请求路由标记（2026-08-05 抓包确认，0x02FC = 小端 fc 02；区别于 auction 的 0x01FC）
_SUPERORDER_ROUTE = b"\xfc\x02"


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

    7169 帧的个股壳格式：``\\x11``(沪)/``\\x21``(深) + 6 位 ASCII 代码。壳之后到
    第一条记录之间是**固定的 22 字节头部**（含 dt5 市场标记等，沪深实测一致）。
    因此 data_off = shell + 7（标记+代码）+ 15（头部填充）= shell + 22。

    为兜住偶发的填充长度漂移，在 shell+22 附近 ±2 字节小窗口内取**首个使连续记录
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
        # 壳后 22 字节是记录起点（沪深实测一致）；±2 兜填充漂移
        for delta in (22, 21, 23, 20, 24):
            doff = off + delta
            if doff + 4 > len(body):
                continue
            ts0 = struct.unpack_from("<I", body, doff)[0]
            if _ts_valid(ts0) and _validate_run_start(body, doff):
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
            "volume": 100,             # dt10, 成交量（手）
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
            body = normalize_8901_response(body)
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
        fields = _parse_hd_field_table(body, base + 10, fc)
        if len(fields) < fc:
            continue
        # 校验前 3 字段是 dt1/dt56/dt10（7169 固定字段表）
        leading = tuple(dt for dt, _, _ in fields[:3])
        if leading != (1, 56, 10):
            continue
        # 4. 定位记录起点 + 股票代码
        shell_search_from = base + 10 + fc * 4
        data_off, code = _locate_data_offset(body, shell_search_from)
        if data_off < 0:
            continue

        # 5. 行主序切记录 + 逐条 ts 合法性 + 单调近距过滤
        # （截断帧尾部会混入下帧头部，需同时用 ts 合法性和相邻 ts 差 ≤ 600s 过滤）
        prev_ts: int | None = None
        for i in range(record_count):
            row_off = data_off + i * hs
            if row_off + hs > len(body):
                break
            ts = struct.unpack_from("<I", body, row_off)[0]
            if not _ts_valid(ts):
                # 一旦遇到非法 ts，后续都是越界数据（下帧头部/填充），停止本帧
                break
            if prev_ts is not None and not (0 <= ts - prev_ts <= 600):
                # 相邻 ts 差过大（跨段拼接/帧边界），停止本帧
                break
            prev_ts = ts
            # seq (dt75) 在 row_off+24，超上限说明读到帧边界垃圾，停止本帧
            seq = struct.unpack_from("<I", body, row_off + 24)[0]
            if seq > _SEQ_MAX:
                break
            price_raw, vol, direction, delegate_a, delegate_b, seq, trade_no = (
                struct.unpack_from("<7I", body, row_off + 4)
            )
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


__all__ = [
    "SUPERORDER_PERIOD",
    "SUPERORDER_L2_PAGEID",
    "SUPERORDER_SUPER_PAGEID",
    "SUPERORDER_DATATYPE",
    "SUPERORDER_FLAG",
    "SUPERORDER_RECORD_SIZE",
    "SUPERORDER_FIELD_COUNT",
    "build_superorder_query",
    "parse_superorder_response",
]
