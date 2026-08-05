"""Pure wire contracts for the 9601 board statistics channel.

2026-08-05 看盘抓包（``kanpan_20260805_010356.pcap`` 等）确认：真实客户端的
板块列表除 8901（``392``/``5716``，已实现为 ``board_quotes``）外，还走 9601 的
纯文本计算协议。两种方法（``statscalc`` / ``calcext``）共享一个帧封装：

    ``\\x09`` + ``\\n`` 分隔的 GBK key=value 文本 + ``\\x00`` 结束符

请求与响应都用此封装，**无二进制子帧头、无 route/seq**（纯文本协议，与 8901
不同）。文本头之后的负载取决于 ``rettype``。

节点路由（抓包确认 + ``SERVER_MATRIX.md`` 铁证）：
- **statscalc**（批量板块指数聚合计算，``rettype=hdfile``）走**独立统计节点**
  （抓包 ``8.132.233.77:9601``，不在 DNS/passport，是客户端缓存发现的），
  不能复用 REALORDER seed ``106.14.65.90``。
- **calcext**（单股/单板块扩展计算，``rettype=json``）与 ``qurealorder`` /
  ``subrealorder`` 共用 REALORDER 节点（普通 ``106.14.65.90:9601`` /
  Level2 ``122.9.184.31:9601``）。
"""
from __future__ import annotations

import json
import os
import socket
import struct


# ── statscalc 专属统计节点 ──
# 抓包快照 IP；不在 passport/DNS 中，是客户端缓存发现的物理节点，可能轮换。
# 用环境变量 ``THSPYPC_STATSCALC_HOST`` 覆盖，连接失败时优雅降级。
STATSCALC_HOST = os.environ.get("THSPYPC_STATSCALC_HOST", "8.132.233.77")
STATSCALC_PORT = 9601

# datatype 编号（抓包确认）
DATATYPE_INTERVAL_STAT = "330342"           # 区间涨跌幅/涨速聚合（dataclass=intervalcalc）
DATATYPE_UPDOWNLIMIT = "330326,330328"      # 涨跌停统计（dataclass=updownlimit）
DATATYPE_MARKETCAP = "199359"               # 流通市值（calcext，返回 json）

BOARD_MARKET = 48  # 板块指数统一挂在 market=48（行业 881xxx / 概念 885xxx 等）


def _build_codelist(market: int, codes) -> str:
    """构造 ``<market>(<code>,<code>,...,);`` 形式的 codelist 值（带尾逗号）。"""
    inner = ",".join(str(c).strip() for c in codes) + ","
    return f"{market}({inner});"


def build_statscalc_query(
    instance: int,
    codes,
    *,
    market: int = BOARD_MARKET,
    datatype: str = DATATYPE_INTERVAL_STAT,
    dataclass: str = "intervalcalc",
    interval: str = "0-0",
    rights_type: str = "forward",
    period: int = 0,
    datetime_value: str = "0(0-0)",
) -> bytes:
    """构造一个 statscalc 批量板块统计请求体。

    字段顺序逐字节对齐 2026-08-05 抓包（``kanpan_unknown_pnopid_r3030_*``）：
    ``instid/method/market/codelist/datatype/dataclass/interval/rightstype/
    period/datetime/rettype``。``market``/``codelist``/``datatype`` 值带尾逗号，
    文本以 ``\\x00`` 结束。

    Args:
        instance: instid（每会话递增的实例号，由服务层 ``next_instance`` 产生）。
        codes: 板块指数代码列表（如 ``["881121", "885897"]``）。
        market: 板块市场（默认 48）。
        datatype: 统计字段编号。``330342``=区间涨跌幅/涨速聚合；
            ``330326,330328``=涨跌停统计。
        dataclass: 计算类型。``intervalcalc``=区间聚合；``updownlimit``=涨跌停。
        interval: 区间（``0-0``=当日全区间）。
        period: 周期（0=当日）。
        datetime_value: 日期游标（``0(0-0)``=当日）。
    """
    parts = [
        f"instid={instance}",
        "method=statscalc",
        f"market={market},",
        f"codelist={_build_codelist(market, codes)}",
        f"datatype={datatype},",
        f"dataclass={dataclass}",
        f"interval={interval}",
        f"rightstype={rights_type}",
        f"period={period}",
        f"datetime={datetime_value}",
        "rettype=hdfile",
    ]
    return b"\x09" + "\n".join(parts).encode("gbk") + b"\x00"


def build_calcext_query(
    instance: int,
    code: str,
    market: int,
    *,
    datatype: str = DATATYPE_MARKETCAP,
    rights_type: str = "forward",
) -> bytes:
    """构造一个 calcext 单股/单板块扩展计算请求体。

    字段顺序逐字节对齐抓包：``instid/method/codelist/datatype/rightstype/rettype``。
    注意 calcext **不带** ``market=``/``dataclass``/``interval``/``period``/
    ``datetime``（这些是 statscalc 专属）。``rettype=json``。

    Args:
        instance: instid。
        code: 单个证券代码（如 ``"600030"`` / ``"881121"``）。
        market: 代码所属市场（17=沪 / 33=深 / 48=板块）。
        datatype: 计算字段编号，默认 ``199359``（流通市值）。
    """
    parts = [
        f"instid={instance}",
        "method=calcext",
        f"codelist={_build_codelist(market, [code])}",
        f"datatype={datatype},",
        f"rightstype={rights_type}",
        "rettype=json",
    ]
    return b"\x09" + "\n".join(parts).encode("gbk") + b"\x00"


def parse_statscalc_response(body: bytes) -> list[dict]:
    """解析 statscalc 的 hdfile 响应（hd1.0 表）。

    响应结构（逐字节确认自 ``kanpan_unknown_pnopid_r3030_*``）::

        \\tinstid=...\\nmethod=statscalc\\n...\\nidname=330342:20160127至今\\n
        \\x00 + LE32(payload_len) + hd1.0\\x00
        + LE16(record_count) + 26B 字段元数据 + N × <record_len> 定长记录

    每条记录（24 字节）：code(ASCII, 8B, NUL 填充, 前导零补 7 位) + pad(8B) +
    date(LE32, 形如 20160127) + value(LE float, 涨跌幅%)。

    metadata 帧（无 ``hd1.0``，只有 ``\\x00\\x00\\x00\\x00\\x00``）返回空列表。
    ``record_len`` 由 ``(payload_len - 6 - 28) / record_count`` 计算（不写死 24），
    以兼容未来字段扩展。
    """
    magic_pos = body.find(b"hd1.0")
    if magic_pos < 0:
        return []  # metadata 帧或空响应
    payload_len = struct.unpack("<I", body[magic_pos - 4 : magic_pos])[0]
    base = magic_pos + 6  # 跳过 "hd1.0\x00"
    if len(body) < base + 2:
        return []
    record_count = struct.unpack("<H", body[base : base + 2])[0]
    if record_count == 0 or payload_len <= 6 + 28:
        return []
    header_len = 28  # record_count(LE16) + 26B 字段元数据
    record_region = payload_len - 6 - header_len
    record_len = record_region // record_count if record_count else 0
    if record_len <= 0:
        return []
    records_start = base + header_len
    records: list[dict] = []
    for index in range(record_count):
        offset = records_start + index * record_len
        record = body[offset : offset + record_len]
        if len(record) < record_len:
            break
        code = record[0:8].split(b"\x00")[0].decode("ascii", errors="replace")
        # 记录布局：code(8) + pad(8) + date(4) + value(4) = 24
        # date/value 在记录尾部，用相对末尾的偏移以兼容前置字段扩展
        date_val = 0
        value = 0.0
        if record_len >= 24:
            date_val = struct.unpack("<I", record[record_len - 8 : record_len - 4])[0]
            value = struct.unpack("<f", record[record_len - 4 : record_len])[0]
        records.append(
            {
                "code": code,
                "date": date_val,
                "value": round(value, 4),
            }
        )
    return records


def parse_calcext_response(body: bytes) -> list[dict]:
    """解析 calcext 的 json 响应。

    响应结构（逐字节确认自 ``kanpan_unknown_pnopid_r3033_*``）::

        \\tinstid=...\\nmethod=calcext\\nrettype=json\\n
        \\x00 + LE32(json_len) + 原始 ASCII JSON

    JSON 形如::

        {"status_code":0,"status_msg":null,
         "data":[{"3":<market>,"4":"<code>","<datatype>":<value>}, ...]}

    返回每条 ``data`` 元素归一化后的 dict 列表（``market``/``code``/``value``），
    其中 ``value`` 取与请求 datatype 对应的数值字段。
    """
    text_end = body.find(b"rettype=json\n")
    if text_end < 0:
        return []
    payload_start = text_end + len(b"rettype=json\n")
    if payload_start >= len(body):
        return []
    # 文本头以 \x00 结束，之后是 LE32 json 长度
    nul = body.find(b"\x00", payload_start)
    if nul < 0 or nul + 5 > len(body):
        return []
    json_len = struct.unpack("<I", body[nul + 1 : nul + 5])[0]
    json_bytes = body[nul + 5 : nul + 5 + json_len]
    if not json_bytes:
        return []
    try:
        payload = json.loads(json_bytes.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return []
    data_items = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(data_items, list):
        return []
    records: list[dict] = []
    for item in data_items:
        if not isinstance(item, dict):
            continue
        market = item.get("3")
        code = item.get("4")
        # 数值字段键名即 datatype 编号；取第一个非 "3"/"4" 的数值字段
        value = None
        for key, raw_value in item.items():
            if key in ("3", "4", "status_code", "status_msg"):
                continue
            if isinstance(raw_value, (int, float)):
                value = raw_value
                break
        records.append(
            {
                "market": market,
                "code": code,
                "value": value,
            }
        )
    return records


def read_frame_board_stats(sock: socket.socket) -> bytes:
    """Read one 9601 stats response (same +1 length quirk as realorder)."""
    from ..codecs.framing import FRAME_MAGIC, _read_frame_body_length, read_exact

    magic = bytearray()
    while True:
        magic += read_exact(sock, 1)
        if len(magic) > len(FRAME_MAGIC):
            magic.pop(0)
        if bytes(magic) == FRAME_MAGIC:
            break
    body_len = _read_frame_body_length(sock) + 1
    return read_exact(sock, body_len)


__all__ = [
    "BOARD_MARKET",
    "DATATYPE_INTERVAL_STAT",
    "DATATYPE_MARKETCAP",
    "DATATYPE_UPDOWNLIMIT",
    "STATSCALC_HOST",
    "STATSCALC_PORT",
    "build_calcext_query",
    "build_statscalc_query",
    "parse_calcext_response",
    "parse_statscalc_response",
    "read_frame_board_stats",
]
