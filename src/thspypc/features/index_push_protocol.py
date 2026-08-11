"""看盘界面指数实时推送解析（8901 ``09 7b d0 0f`` 帧）。

2026-08-05 盘中抓包确认（两份包）：
- ``captures_live/kanpan_push_20260805_132347.pcap``（深市 121.37.31.87）
- ``captures_live/index_push_20260805_140642.pcapng``（沪市 8.134.115.123 + 深市）

看盘界面的指数实时行情由 pageid=5716 + ``PushField=16:241;32:241`` + subreal
（URS/UCT/UNX/UCX/UME）订阅触发，服务端持续推送 ``09 7b d0 0f`` 头的二进制帧。
客户端启动时一次性注册五大指数全局推送列表，页面切换只做分时/K线查询。

**五大指数**（客户端启动注册列表）：
    1A0001 上证指数 / 1B0680 科创50 / 899050 北证50 / 399001 深证成指 / 399006 创业板指

帧结构按市场分两套（字段顺序一致，起点偏移不同）：

- **深市指数**（399001/399006）：代码@22（ASCII 6 位）+ GBK 名称（NUL 结束）+
  填充到 off=48，价格区从 off=48 起，321B 定长。服务器 121.37.31.87 / 8.134.86.216。
- **沪市指数**（1A0001/1B0680）：代码@33（ASCII 6 位，大写字母开头）+ 无名称区，
  价格区从 off=39 起，298-302B。服务器 8.134.115.123 / 122.9.202.190。
- **北证50**（899050）：盘中代码@29、97-98B 紧凑帧，字段用**相对代码偏移**（与分时响应
  交叉验证逐字节确认）：``code+6`` dt10 最新点位、``code+10`` dt13 累计量、
  ``code+14`` dt19 累计额、``code+30`` dt22、``code+34`` dt23。无 dt6/dt7/高/低
  （需从分时响应取）。存在 93B 子类型（字段掩码不同），按非稳态帧处理不解价格。

价格区字段顺序（每 4 字节 LE THS-float，深市/沪市一致）：

    dt6 昨收（固定）→ dt7 开盘（固定）→ 最高（固定）→ 最低（固定）
    → dt10 最新价（盘中变化）

``dt19`` 成交额（全天累计，单调递增）在价格区之后，偏移随市场不同（深市 off=76，
沪市 off=63）。

字段定义（客户端 ``DataType=7,10,19,6,66``）：
    dt6=昨收  dt7=开盘  dt10=最新  dt19=成交额  dt66=涨跌幅

活网验证（2026-08-05 盘中）：
    399001 深证成指 dt10=14129.57 dt6=13885.711 dt19=12172亿
    1A0001 上证指数 dt10=3872.66  dt6=3822.28  dt19=10079亿
    1B0680 科创50   dt10=1928.93  dt6=1841.99  dt19=3494亿
"""
from __future__ import annotations

import struct

from ..codecs.numeric import decode_ths_float


# ── 帧标志 ──
INDEX_PUSH_MAGIC = b"\x09\x7b\xd0\x0f"
SZ_INDEX_FLAG = bytes.fromhex("8083818080808120")  # 深市指数 body[14:22]
SH_INDEX_FLAG_PREFIX = b"\x80\x83\x81\x80\x80\x80\x81"  # 沪市 body[14:21]，末字节变长


def is_index_push(body: bytes) -> bool:
    """判断是否为 ``09 7b d0 0f`` 指数/行情推送帧。"""
    return body[0:4] == INDEX_PUSH_MAGIC


def _read_ths(body: bytes, off: int) -> float:
    """读取 off 处的 4 字节 LE THS-float；越界返回 0。"""
    if off + 4 > len(body):
        return 0.0
    return decode_ths_float(struct.unpack("<I", body[off:off + 4])[0])


def _parse_price_block(body: bytes, base: int) -> dict:
    """从 base 起读 5 个价格字段（dt6/dt7/高/低/dt10），每 4 字节。

    字段顺序（深市 base=48 / 沪市 base=39 一致）：
        base+0  dt6 昨收（固定）
        base+4  dt7 开盘（固定）
        base+8  最高（固定）
        base+12 最低（固定）
        base+16 dt10 最新价（盘中变化）
    """
    prevclose = _read_ths(body, base)
    open_price = _read_ths(body, base + 4)
    high = _read_ths(body, base + 8)
    low = _read_ths(body, base + 12)
    price = _read_ths(body, base + 16)
    change_pct = (
        round((price - prevclose) / prevclose * 100, 2)
        if prevclose else 0.0
    )
    return {
        "prevclose": round(prevclose, 3),
        "open": round(open_price, 3),
        "high": round(high, 3),
        "low": round(low, 3),
        "price": round(price, 3),
        "change_pct": change_pct,
    }


def parse_index_push(body: bytes) -> dict | None:
    """解析一个指数实时推送帧。

    支持沪深北指数的盘中稳态帧和 2026-08-11 实测集合竞价阶段帧。竞价阶段
    ``097bd00f`` 只含近静态参考价，不含 ``pageid=6240 Auction.newprice``；因此
    竞价结果明确返回 ``phase="auction"`` 和 ``reference_price``，不把参考价误报
    成实时撮合价 ``price``。

    Returns:
        盘中返回 ``{code, name, phase, prevclose, open, price, high, low,
        change_pct, amount, volume}``；竞价返回 ``{code, name, phase,
        reference_price, ...}``；格式不符返回 ``None``。
    """
    if not is_index_push(body):
        return None
    if len(body) < 60:
        return None

    # ── 深市盘中指数：代码@22 ──
    if body[14:22] == SZ_INDEX_FLAG:
        code = body[22:28].decode("ascii", errors="replace")
        if not code.isdigit():
            return None
        name_end = body.find(b"\x00", 28)
        name = body[28:name_end].decode("gbk", errors="replace") if name_end > 28 else ""
        result = {"code": code, "name": name, "phase": "continuous"}
        result.update(_parse_price_block(body, 48))
        result["amount"] = round(_read_ths(body, 76), 0)  # dt19 成交额
        result["volume"] = round(_read_ths(body, 80), 0)
        return result

    # ── 竞价阶段：沪深代码都右移到 off33 ──
    # 沪市没有名称区，参考价@39；深市有 GBK 名称区，参考价@59。
    # 市场标志末字节会随阶段变化，故以代码本身判市场，不依赖 body[14:22]
    # 完整相等。Auction.newprice/leadprice/volume 来自 pageid=6240 JSON 轮询，
    # 不能用这里的近静态值替代。
    if body[14:21] == SH_INDEX_FLAG_PREFIX:
        code = body[33:39].decode("ascii", errors="replace")
        if _is_sh_index_code(code):
            prices = _parse_price_block(body, 39)
            # 盘中五个 OHLC 字段均为有效正数；竞价期中间字段为 0/哨兵，
            # off39/off55 是两项近静态快照值。
            if all(prices[field] > 0 for field in ("prevclose", "open", "high", "low", "price")):
                result = {
                    "code": code,
                    "name": _sh_index_name(code),
                    "phase": "continuous",
                }
                result.update(prices)
                result["amount"] = round(_read_ths(body, 63), 0)
                result["volume"] = round(_read_ths(body, 67), 0)
                return result
            return {
                "code": code,
                "name": _sh_index_name(code),
                "phase": "auction",
                "reference_price": round(_read_ths(body, 39), 3),
                "secondary_reference_price": round(_read_ths(body, 55), 3),
            }

        if _is_sz_index_code(code):
            name_end = body.find(b"\x00", 39, 59)
            name = body[39:name_end].decode("gbk", errors="replace") if name_end > 39 else ""
            return {
                "code": code,
                "name": name,
                "phase": "auction",
                "reference_price": round(_read_ths(body, 59), 3),
            }

    # ── 北证50（899050）：代码@29，97-98B 紧凑帧，字段相对代码偏移 ──
    # 布局（2026-08-05 逆向 + 分时响应交叉验证逐字节确认）：
    #   code+6  dt10 最新点位
    #   code+10 dt13 累计量
    #   code+14 dt19 累计额
    #   code+30 dt22
    #   code+34 dt23
    # 注：存在 93B 子类型（字段掩码不同，code+6 非绝对价格），当前按 97-98B 稳态帧解析；
    #     93B 帧返回基础信息不解价格（避免误报）。
    if b"899050" in body[20:40] and len(body) in (97, 98):
        code_idx = body.find(b"899050", 20, 40)
        return {
            "code": "899050",
            "name": "北证50",
            "phase": "continuous",
            "price": round(_read_ths(body, code_idx + 6), 3),
            "volume": round(_read_ths(body, code_idx + 10), 0),   # dt13 累计量
            "amount": round(_read_ths(body, code_idx + 14), 0),   # dt19 累计额
            # 北证50 紧凑帧无 dt6/dt7/高/低（需从分时响应取，见 timeline 协议）
            "change_pct": 0.0,
        }
    if b"899050" in body[20:40] and 117 <= len(body) <= 121:
        code_idx = body.find(b"899050", 20, 40)
        name_end = body.find(b"\x00", code_idx + 6, code_idx + 26)
        name = (
            body[code_idx + 6:name_end].decode("gbk", errors="replace")
            if name_end > code_idx + 6
            else "北证50"
        )
        return {
            "code": "899050",
            "name": name,
            "phase": "auction",
            "reference_price": round(_read_ths(body, code_idx + 26), 3),
        }
    if b"899050" in body[20:40]:
        # 93B 等非稳态子类型：字段掩码不同，不解价格
        return {"code": "899050", "name": "北证50", "note": "non-steady subtype, price TBD"}

    return None


def _is_sh_index_code(code: str) -> bool:
    return (
        len(code) == 6
        and code[0].isdigit()
        and code[1].isalpha()
        and code[2:].isdigit()
    )


def _is_sz_index_code(code: str) -> bool:
    return len(code) == 6 and code.startswith("399") and code.isdigit()


def _sh_index_name(code: str) -> str:
    """沪市指数代码 → 中文名称（抓包未含名称区，用已知映射）。"""
    names = {
        "1A0001": "上证指数",
        "1B0680": "科创50",
        "1B0688": "科创50",  # 历史别名
    }
    return names.get(code, code)


__all__ = [
    "INDEX_PUSH_MAGIC",
    "SH_INDEX_FLAG_PREFIX",
    "SZ_INDEX_FLAG",
    "is_index_push",
    "parse_index_push",
]
