"""
同花顺 Windows PC 免费版行情协议层 — 纯 Python 实现。

移植自 thspy（Mac 版），针对 PC 免费版（8901 端口）改造：
  - HTTP 三步鉴权链路原样复用（先用 Mac 参数验证 8901 是否接受）
  - 帧编解码（FD FD FD FD + ASCII hex 长度）原样复用
  - head128 / passport64 构造算法原样复用
  - login 帧重写为 PC 免费版格式（抓包实测，比 Mac 版更简洁）
  - 端口 8901（PC 主行情），服务器 IP 从抓包取（不走 M_hqdns）

参考：D:\\code\\ths\\PROTOCOL.md（§2 帧格式、§4 握手、§4.2.1 普通/L2 对照）
"""
from __future__ import annotations

import base64
import logging
import re
import socket
import struct
import time
import urllib.parse
from datetime import datetime

from .codecs.compression import (
    _MAX_NORMALIZED_8901_SIZE,
    _decode_bitrle_0x13746d0,
    _transpose_bitplane_0x1763410,
    normalize_8901_response,
)
from .codecs.framing import (
    encode_frame,
    read_frame,
)
from .codecs.hd import (
    _parse_hd_field_table,
    _parse_hd_records,
    parse_hd1_response,
    parse_hd3_response,
)
from .codecs.numeric import _FLOAT_TABLE, decode_ths_float
from .features.auth_protocol import DEFAULT_LOGIN_PROTOCOL_PROFILE
from .features.auction_protocol import (
    AUCTION_DATATYPE,
    AUCTION_PERIOD,
    BASIC_AUCTION_PAGEID,
    BASIC_HISTORY_AUCTION_PAGEID,
    BASIC_HISTORY_AUCTION_PERIOD,
    CLOSING_AUCTION_DATATYPE,
    CLOSING_AUCTION_PERIOD,
    INDEX_AUCTION_PAGEID,
    INDEX_CLOSING_AUCTION_CODES,
    _AUCTION_SENTINEL_FIELDS,
    _AUCTION_SENTINELS,
    _auction_ts_in_range,
    _auction_value,
    _split_auction_history_segment,
    build_auction_query,
    build_basic_auction_query,
    build_index_auction_context_query,
    build_index_auction_query,
    build_l2_closing_auction_query,
    build_l2_history_auction_query,
    parse_auction_response,
    parse_closing_auction_response,
    parse_index_auction_response,
)
from .features.history_timeline_protocol import (
    HISTORY_TIMELINE_BAR_SPAN,
    HISTORY_TIMELINE_DATATYPE,
    HISTORY_TIMELINE_PAGEID,
    INDEX_HISTORY_TIMELINE_DATATYPE,
    INDEX_HISTORY_TIMELINE_PAGEID,
    NORMAL_HISTORY_TIMELINE_DATATYPE,
    NORMAL_HISTORY_TIMELINE_PAGEID,
    TIMELINE_BAR_DAYS_SCALE,
    TIMELINE_BAR_EPOCH_ORDINAL,
    TIMELINE_INTRADAY_BAR,
    _date_to_ordinal,
    _decode_history_timeline_rows,
    _history_timeline_first_row,
    _history_timeline_row_anchors,
    build_history_timeline_query,
    build_index_history_timeline_query,
    build_normal_history_timeline_query,
    date_to_normal_timeline_bar,
    date_to_timeline_bar,
    normal_timeline_bar_to_date,
    parse_history_timeline_response,
    timeline_bar_to_date,
)
from .features.kline_protocol import (
    KLINE_DATATYPE,
    KLINE_DT_AMT,
    KLINE_DT_CLOSE,
    KLINE_DT_HIGH,
    KLINE_DT_LOW,
    KLINE_DT_OPEN,
    KLINE_DT_VOL,
    KLINE_PERIOD_1MIN,
    KLINE_PERIOD_5MIN,
    KLINE_PERIOD_15MIN,
    KLINE_PERIOD_30MIN,
    KLINE_PERIOD_60MIN,
    KLINE_PERIOD_DAY,
    KLINE_PERIOD_MONTH,
    KLINE_PERIOD_QUARTER,
    KLINE_PERIOD_WEEK,
    KLINE_PERIOD_YEAR,
    _kline_decode_time,
    _kline_dt1_is_bar_index,
    build_kline_query,
    parse_kline_hd3_response,
)
from .features.quote_protocol import (
    BUY_LEVEL_FIELDS,
    DEPTH_QUOTE_DATATYPE,
    DEPTH_QUOTE_DATATYPE_10,
    LIST_QUOTE_DATATYPE_DEFAULT,
    SELL_LEVEL_FIELDS,
    build_depth_quote_query,
    build_depth_ten_query,
    build_list_quote_query,
    parse_depth_quote_response,
)
from .features.snapshot_protocol import (
    MARKET_SNAPSHOT_DATATYPE,
    MARKET_SNAPSHOT_MARKETS,
    SNAPSHOT_DATATYPE,
    SNAPSHOT_PAGEID,
    SNAPSHOT_PAGEID_SUB,
    SNAPSHOT_SUBTYPE,
    build_market_snapshot_query,
    build_snapshot_subscribe,
    is_depth_push,
    is_snapshot_push,
    parse_depth_push,
    parse_snapshot_push,
)
from .features.superorder_protocol import (
    SUPERORDER_DATATYPE,
    SUPERORDER_FIELD_COUNT,
    SUPERORDER_FLAG,
    SUPERORDER_L2_PAGEID,
    SUPERORDER_PERIOD,
    SUPERORDER_RECORD_SIZE,
    SUPERORDER_SUPER_PAGEID,
    build_superorder_query,
    parse_superorder_response,
)
from .features.stock_list_protocol import (
    DDE_LEVEL2_MARKETS,
    DDE_LEVEL2_ROUTE,
    DDE_PAGEID,
    DDE_RESPONSE_FIELDS,
    DDE_STANDARD_MARKETS,
    DDE_STANDARD_ROUTE,
    FULL_STOCK_LIST_MARKETS,
    INIT_C_MODULES,
    INIT_MARKET_CODE,
    INIT_STOCK_LINKS,
    SORT_BY_VALUES,
    STOCK_LIST_DATATYPE,
    STOCK_LIST_MARKETS,
    _dt5_market,
    _parse_stock_list_hd10_variant,
    _parse_stock_list_hd31_variant,
    build_dde_query,
    build_init_query,
    build_full_stock_list_query,
    build_stock_list_query,
    parse_init_response,
    parse_dde_response,
    parse_stock_list_replay,
    parse_stock_list_response,
)
from .features.stock_name_protocol import (
    BLOCK_ENCODED_SEGMENTS,
    _BLOCK_ENCODED_SEGMENTS,
    _is_block_encoded,
    _iter_name_segments,
    _name_code_is_valid,
    _parse_name_text,
    build_upstockname_request,
    decode_name_frame,
)
from .features.timeline_protocol import (
    INDEX_TIMELINE_FLAGS,
    INDEX_TIMELINE_MARKETS,
    TIMELINE_DATATYPE,
    TIMELINE_L2_DATATYPE,
    TIMELINE_PAGEID,
    TIMELINE_PERIOD,
    build_timeline_l2_query,
    build_timeline_query,
    enrich_index_lead_line,
    is_index_timeline,
    parse_index_timeline_response,
    parse_timeline_l2_response,
    parse_timeline_response,
)
from .models import DepthLevel, DepthQuote

logger = logging.getLogger(__name__)

# =============================================================================
# 协议常量（PC 免费版）
# =============================================================================

# HTTP 鉴权（与客户端类型无关，通用）
AUTH_HOST = "auth.10jqka.com.cn"
AUTH_PORT = 80

# PC 免费版 A 股 MAIN 行情服务器（8901）。仅保留 ifindhq 域名的历史解析结果；
# fu4/hkus/euhq 等市场组能完成普通 login，但不会响应沪深 list_quotes。
#
# ⚠ 这是 DNS 解析失败时的回退 IP 列表。正常运行走 :func:`resolve_market_hosts`
# 从 passport 的 M_hqdns 动态解析（拿到当前最新 IP）。
#
# MAIN 与 L2 都在各自 socket 上执行 login -> init。MAIN 使用普通身份和标准
# build_init_query()；L2 使用 Level2 passport + thsuser 行情登录壳，并按
# shlv2/szlv2 分别发送
# MarketCode=16;144;/32。HTTP 鉴权生成的 Passport64 可被各角色按需复用，
# 但 TCP 登录和 init 状态不能跨 socket 继承。
MARKET_PORT = 8901
MARKET_HOSTS = [
    # ifindhq.123ths.com 解析快照（2026-07-28）。
    "8.132.233.199",
    "8.132.233.143",
    "1.94.58.146",
    "1.1.182.181",
    "119.3.156.145",
    "8.134.123.179",
    "8.145.213.52",
    "1.94.9.136",
    "115.175.74.247",
    "139.159.135.214",
    "8.145.212.60",
    "8.134.121.153",
]


def resolve_market_hosts(passport_bytes: bytes) -> list[str]:
    """从 passport 的 M_hqdns 字段解析域名，DNS 查询得到 8901 服务器 IP 列表。

    hexin 客户端不硬编码 IP——HTTP 鉴权返回的 passport 里有 M_hqdns 字段，
    普通账号冷启动抓包确认 ``main.123ths.com`` 承载沪深基础行情；较早的
    独立登录验证也确认 ``ifindhq.123ths.com`` 可承载同类请求。因此优先使用
    passport 明示的 ``main`` 域名，仅在它缺失时回退到 ``ifindhq``，不把
    fu4/hkus/euhq/lv2 等其他市场组混入 MAIN。

    Args:
        passport_bytes: HTTP 鉴权返回的原始 passport_bytes（含 M_hqdns 字段）。

    Returns:
        去重后的 IP 列表。解析失败返回空列表（调用方回退到 MARKET_HOSTS）。
    """
    import socket as _socket
    # M_hqdns 在 passport_bytes（| 分隔的字段流）里
    text = passport_bytes.decode("latin-1", errors="replace")
    m = re.search(r'M_hqdns="([^"]*)"', text)
    if not m:
        # 试试无引号的 | 分隔格式
        for field in text.split("|"):
            if field.startswith("M_hqdns="):
                m_hqdns = field.split("=", 1)[1]
                break
        else:
            return []
    else:
        m_hqdns = m.group(1)

    # M_hqdns 格式: domain:port:markets;:,domain:port:markets;:,...
    # 官方普通账号客户端优先连接 main；旧 passport 没有 main 时兼容
    # 已实测可用的 ifindhq。shlv2/szlv2 由独立解析器处理。
    main_domains = []
    fallback_domains = []
    for entry in m_hqdns.split(","):
        dm = re.match(r'([\w.]+):(\d+):', entry.strip())
        if dm and dm.group(2) == str(MARKET_PORT):
            domain = dm.group(1).lower()
            if domain == "main.123ths.com" or domain.startswith("main."):
                main_domains.append(dm.group(1))
            elif (
                domain == "ifindhq.123ths.com"
                or domain.startswith("ifindhq.")
            ):
                fallback_domains.append(dm.group(1))

    # 2026-08-06：优先 main.123ths.com（支持北交所 market 151），
    # ifindhq 的 IP 不支持北交所。passport 不含 main 时硬编码补上。
    # 只在 main 解析不出 IP 时才 fallback 到 ifindhq。
    if "main.123ths.com" not in main_domains:
        main_domains.insert(0, "main.123ths.com")
    domains = main_domains
    if not domains:
        domains = fallback_domains
    if not domains:
        return []

    # DNS 解析每个域名，收集所有 IP（去重，保序）
    ips: list[str] = []
    seen: set[str] = set()
    for domain in domains:
        try:
            _, _, addrs = _socket.gethostbyname_ex(domain)
            for ip in addrs:
                if ip not in seen:
                    seen.add(ip)
                    ips.append(ip)
        except OSError:
            continue  # DNS 解析失败，跳过

    if ips:
        logger.info(
            "M_hqdns 动态解析 %d 个 MAIN A股域名（%s）→ %d 个 IP: %s",
            len(domains),
            "main" if main_domains else "ifindhq fallback",
            len(ips),
            ips[:5],
        )
    return ips


def resolve_l2_hosts(passport_bytes: bytes) -> list[str]:
    """从 passport 的 M_hqdns 解析 **L2 行情服务器** IP（只取 lv2 域名）。

    M_hqdns 里混有多种服务器域名，只有 ``shlv2``/``szlv2``（域名含 ``lv2``）
    才是 Level2 行情服务器，解析出的 IP 才支持 pageid=4214 推送注册 +
    init(MarketCode=32) 完整配置帧（23KB+）。非 L2 域名（``fu4``/``hkus``/
    ``ifindhq`` 等）的 IP init 只回 210B、4214 注册 CodeListSize=0。

    实测对比（2026-07-24）::

        shlv2.123ths.com → 8.134.98.163 等（L2，支持推送）
        szlv2.123ths.com → 8.134.112.142 等（L2，支持推送）
        fu4.123ths.com   → 8.138.46.177 等（非L2，不支持推送）

    Args:
        passport_bytes: HTTP 鉴权返回的 passport_bytes（含 M_hqdns 字段）。

    Returns:
        L2 服务器的 IP 列表（去重保序）。无 L2 域名时返回空列表。
    """
    import socket as _socket
    text = passport_bytes.decode("latin-1", errors="replace")
    m = re.search(r'M_hqdns="([^"]*)"', text)
    if not m:
        for field in text.split("|"):
            if field.startswith("M_hqdns="):
                m_hqdns = field.split("=", 1)[1]
                break
        else:
            return []
    else:
        m_hqdns = m.group(1)

    # 只收域名含 "lv2" 的条目（shlv2/szlv2）
    l2_domains = []
    for entry in m_hqdns.split(","):
        dm = re.match(r'([\w.]+):(\d+):', entry.strip())
        if dm and dm.group(2) == str(MARKET_PORT) and "lv2" in dm.group(1).lower():
            l2_domains.append(dm.group(1))

    if not l2_domains:
        logger.warning("M_hqdns 中无 lv2 域名（账号可能无 L2 权限）")
        return []

    ips: list[str] = []
    seen: set[str] = set()
    for domain in l2_domains:
        try:
            _, _, addrs = _socket.gethostbyname_ex(domain)
            for ip in addrs:
                if ip not in seen:
                    seen.add(ip)
                    ips.append(ip)
        except OSError:
            continue

    if ips:
        logger.info("L2 服务器（%s）解析 → %d 个 IP: %s",
                    ",".join(l2_domains), len(ips), ips[:5])
    return ips


def pick_l2_market(market: int) -> str:
    """把行情市场码归约为沪深分组键。

    thspypc 内部 market 用两套数值（见 client.snapshot_subscribe 注释）：

        - snapshot 订阅帧：17=沪市主板，33=深市
        - init MarketCode：16=沪，144=沪市科创板，32=深

    归约为连接池键 ``"sh"`` / ``"sz"``，用于路由到对应的 L2 服务器
    （shlv2 / szlv2）。

    Args:
        market: 上述任一套数值。

    Returns:
        ``"sh"``（沪市：含 16/17/144）或 ``"sz"``（深市：32/33）。

    Raises:
        ValueError: market 非法。
    """
    if market in (16, 17, 144):
        return "sh"
    if market in (32, 33):
        return "sz"
    raise ValueError(f"market 非法（仅支持 16/17/144=沪, 32/33=深）: {market}")


def resolve_l2_hosts_grouped(passport_bytes: bytes) -> dict[str, list[str]]:
    """从 passport 的 M_hqdns 解析 L2 行情服务器 IP，按沪深分组返回。

    ★ 2026-07-24 实测铁证（diag_l2_hosts.py）：沪深 L2 行情是**两套完全独立
    的服务器**，IP 集合 0 重叠::

        shlv2.123ths.com:8901:16;144  → 沪市 5 个 IP（8.134.98.163 等）
        szlv2.123ths.com:8901:32      → 深市 9 个 IP（8.134.86.216 等）

    M_hqdns 域名后缀的市场码直接对应：``shlv2`` 服务沪市（16/144），
    ``szlv2`` 服务深市（32）。把两者合并成一个列表（旧
    :func:`resolve_l2_hosts` 的做法）会随机连错市，导致 init 只回 210B 小帧、
    4214 注册 CodeListSize=0——这是 docs/handoffs/HANDOFF.md 里
    "支持 push 的 IP 比例约 30%"
    的真因。

    Args:
        passport_bytes: HTTP 鉴权返回的原始 passport_bytes。

    Returns:
        ``{"sh": [沪市 L2 IP...], "sz": [深市 L2 IP...]}``。
        某组无 lv2 域名时该 key 对应空列表。
    """
    import socket as _socket
    text = passport_bytes.decode("latin-1", errors="replace")
    m = re.search(r'M_hqdns="([^"]*)"', text)
    if not m:
        m_hqdns = ""
        for field in text.split("|"):
            if field.startswith("M_hqdns="):
                m_hqdns = field.split("=", 1)[1]
                break
    else:
        m_hqdns = m.group(1)

    # 域名 → 分组键
    def _group(domain: str) -> str | None:
        d = domain.lower()
        if d.startswith("shlv2"):
            return "sh"
        if d.startswith("szlv2"):
            return "sz"
        return None

    grouped: dict[str, list[str]] = {"sh": [], "sz": []}
    seen: dict[str, set[str]] = {"sh": set(), "sz": set()}
    for entry in m_hqdns.split(","):
        dm = re.match(r'([\w.]+):(\d+):', entry.strip())
        if not dm or dm.group(2) != str(MARKET_PORT):
            continue
        key = _group(dm.group(1))
        if key is None:
            continue
        try:
            _, _, addrs = _socket.gethostbyname_ex(dm.group(1))
        except OSError:
            continue
        for ip in addrs:
            if ip not in seen[key]:
                seen[key].add(ip)
                grouped[key].append(ip)

    if grouped["sh"]:
        logger.info("L2 沪市服务器（shlv2）→ %d 个 IP: %s",
                    len(grouped["sh"]), grouped["sh"][:5])
    else:
        logger.warning("M_hqdns 无 shlv2 域名（沪市 L2 不可用）")
    if grouped["sz"]:
        logger.info("L2 深市服务器（szlv2）→ %d 个 IP: %s",
                    len(grouped["sz"]), grouped["sz"][:5])
    else:
        logger.warning("M_hqdns 无 szlv2 域名（深市 L2 不可用）")
    return grouped


def resolve_fu4_hosts(passport_bytes: bytes) -> list[str]:
    """从 passport 的 M_hqdns 解析板块专用通道（fu4）服务器 IP。

    ★ 2026-08-01 抓包铁证（tests/_board_channel_ips.py）：板块行情/分时/竞价/
    成分股必须走 **fu4.123ths.com** 市场组（``MarketCode=96;128;88;216;48;``，
    subreal 通道 URS/UCT/UNX/UCX/UME），不能在 MAIN/ifindhq 上重放——MAIN
    连接即使原样重放引导序列与抓包帧，服务器也只回 CodeListSize=0/无数据。
    L2 与普通账号的 pcap 板块通道 IP（106.15.249.238 / 122.9.78.232）均属于
    fu4.123ths.com 解析结果。

    Args:
        passport_bytes: HTTP 鉴权返回的原始 passport_bytes。

    Returns:
        fu4 组 IP 列表；passport 无 fu4 域名时返回空列表（调用方回退
        :data:`MARKET_HOSTS`）。
    """
    import socket as _socket
    text = passport_bytes.decode("latin-1", errors="replace")
    m = re.search(r'M_hqdns="([^"]*)"', text)
    if not m:
        m_hqdns = ""
        for field in text.split("|"):
            if field.startswith("M_hqdns="):
                m_hqdns = field.split("=", 1)[1]
                break
    else:
        m_hqdns = m.group(1)

    ips: list[str] = []
    seen: set[str] = set()
    for entry in m_hqdns.split(","):
        dm = re.match(r'([\w.]+):(\d+):', entry.strip())
        if not dm or dm.group(2) != str(MARKET_PORT):
            continue
        if not dm.group(1).lower().startswith("fu4."):
            continue
        try:
            _, _, addrs = _socket.gethostbyname_ex(dm.group(1))
        except OSError:
            continue
        for ip in addrs:
            if ip not in seen:
                seen.add(ip)
                ips.append(ip)
    if ips:
        logger.info("板块通道服务器（fu4）解析 → %d 个 IP: %s",
                    len(ips), ips[:5])
    else:
        logger.warning("M_hqdns 中无 fu4 域名（板块通道不可用）")
    return ips


# --- 客户端身份参数（PC 免费版，从 login_lv2.pcapng 的 passport 实测）---
# 首次测试用 Mac 参数被 8901 拒（VerifyCode=-1, PromptText=-6:），服务器返回
# thshq-hwyeast-globalthsindex-gateway，判定 passport 身份（Mac）与 PC 网关不符。
# 改用抓包里 PC Level2 passport 的真实值。参数集中在登录 profile 中，后续普通
# 账号若有字节差异可增加独立 profile；当前别名保持旧导入和请求字节不变。
PRODUCT = DEFAULT_LOGIN_PROTOCOL_PROFILE.product
SECURITIES = DEFAULT_LOGIN_PROTOCOL_PROFILE.securities
VERSION_HTTP = DEFAULT_LOGIN_PROTOCOL_PROFILE.http_version
TA_APPID = "2022021114090152"
UA_GBK = "同花顺/7.0.10 CFNetwork/1333.0.4 Darwin/21.5.0"

# PC 免费版 login 帧的版本号（抓包实测）
C_VERSION_PC = DEFAULT_LOGIN_PROTOCOL_PROFILE.tcp_version

# mainverify 的 qsid。PC 版 passport 的 M_qs=6800，推断 qsid=6800（Mac 是 7004）。
QSID = DEFAULT_LOGIN_PROTOCOL_PROFILE.qsid

# head128 的账号类型标签（5 字节前缀）。
# Mac 版 (thspy): 44 04 2d 80 00；PC 免费版实测: be 06 06 80 00。
# 用 Mac 值时服务器返回 PromptText=-300（head128 校验失败）；
# 改 PC 值后通过 head128 校验。
ACCOUNT_TYPE = DEFAULT_LOGIN_PROTOCOL_PROFILE.account_type


# =============================================================================
# Mac64 生成（已逆向：base64(0x18 + 前4个网卡MAC)）
# =============================================================================
# 逆向来源：hdp 日志的 register license 记录了 device_info.mac_address（4 个 MAC），
# 与抓包 Mac64 解码后的字节完全对应：
#   Mac64 解码 = 0x18 + MAC0(6B) + MAC1(6B) + MAC2(6B) + MAC3(6B)  共 25 字节
# 4 个 MAC 来自 GetAdaptersInfo 返回的前 4 个网卡（含物理网卡和虚拟网卡）。
# 实测自动生成的 Mac64 与抓包值逐字节一致。
MAC64_HEADER = 0x18  # 固定头（= 24，表示后跟 24 字节 = 4×6 MAC）


def _get_adapters_info():
    """GetAdaptersInfo 公共封装，供 generate_mac64 / generate_imei 复用。"""
    import ctypes

    class IP_ADAPTER_INFO(ctypes.Structure):
        pass
    IP_ADAPTER_INFO._fields_ = [
        ("Next", ctypes.POINTER(IP_ADAPTER_INFO)),
        ("ComboIndex", ctypes.c_ulong),
        ("AdapterName", ctypes.c_char * 260),
        ("Description", ctypes.c_char * 132),
        ("AddressLength", ctypes.c_uint),
        ("Address", ctypes.c_ubyte * 8),
        ("Index", ctypes.c_ulong),
        ("Type", ctypes.c_uint),
        ("DhcpEnabled", ctypes.c_uint),
        ("CurrentIpAddress", ctypes.c_void_p),
    ]

    iphlpapi = ctypes.windll.iphlpapi
    buf = (ctypes.c_char * 8192)()
    size = ctypes.c_ulong(8192)
    ret = iphlpapi.GetAdaptersInfo(buf, ctypes.byref(size))
    if ret != 0:
        raise OSError(f"GetAdaptersInfo 失败: error {ret}")
    return ctypes.cast(buf, ctypes.POINTER(IP_ADAPTER_INFO)), IP_ADAPTER_INFO


def generate_mac64() -> str:
    """用 GetAdaptersInfo 取前 4 个网卡 MAC，构造 login 帧的 Mac64 字段。

    返回 base64 字符串（与 hexin.exe 生成的一致）。
    仅 Windows 可用（依赖 iphlpapi.dll）。

    网卡不足 4 个时（如禁用了虚拟网卡/WiFi 断开），用已有 MAC 循环填充到 4 个，
    而非报错——Mac64 的 4 个槽位本质是固定长度填充物，服务器不强校验每个槽的
    唯一性（实测重复 MAC 也能 VerifyCode=0）。
    """
    import base64

    ptr, _ = _get_adapters_info()
    macs: list[bytes] = []
    while ptr and len(macs) < 4:
        info = ptr.contents
        if info.AddressLength == 6:
            macs.append(bytes(info.Address[:6]))
        ptr = info.Next

    if not macs:
        raise RuntimeError("GetAdaptersInfo 未返回任何 6 字节 MAC 网卡，无法生成 Mac64")

    # 不足 4 个时循环复用已有 MAC 补齐（保持 24 字节固定长度）
    while len(macs) < 4:
        macs.append(macs[len(macs) % len(macs)] if macs else b"\x00" * 6)

    raw = bytes([MAC64_HEADER]) + b"".join(macs[:4])
    return base64.b64encode(raw).decode()


# =============================================================================
# imei 生成（已逆向：MD5( 第1个网卡MAC大写带连字符 + "0"*30 )）
# =============================================================================
# 逆向来源：通过内存 patch 捕获 hexin.exe 调用 MD5 时的输入（47 字节），
# 实测 MD5(输入) 与抓包 imei 逐字节一致：
#   输入 = MAC0(大写连字符 17B, 如 "38-A7-46-43-C0-6E") + "0"*30  共 47 字节
#   imei = MD5(输入).hex().upper()
#
# MAC0 是 GetAdaptersInfo 返回的第 1 个网卡（AddressLength==6），与 Mac64
# 用同一数据源的第 1 个（Mac64 用前 4 个）。
#
# "0"*30 的来源：hexin 的 BIOS 采集函数扫描 \Device\PhysicalMemory（F0000~FFFFF）
# 找 "Award Modular BIOS" / "American Megatrends Inc" 字符串；找不到时返回
# 30 个 '0' 作为 fallback（默认值见 0x1ec54ac）。大多数 OEM 机器（如本机 LENOVO）
# 走这个 fallback 分支，所以后半段固定是 30 个零。
#
# 注意：若机器 BIOS ROM 恰好含 Award/AMI 签名串，后半段会是 BIOS 版本串而非
# 30 个零——但实测市售 PC 极少命中（Award 已多年未出新 BIOS，AMI 签名格式也变了）。
IMEI_BIOS_FALLBACK = "0" * 30


def generate_imei() -> str:
    """生成同花顺 PC 版 mainverify 用的 imei 设备指纹（32 字符大写 hex）。

    算法：MD5( 第1个网卡MAC大写带连字符 + "0"*30 )，返回大写 hex。
    仅 Windows 可用（依赖 iphlpapi.dll）。
    """
    import hashlib

    ptr, _ = _get_adapters_info()
    mac_str: str | None = None
    while ptr:
        info = ptr.contents
        if info.AddressLength == 6:
            mac_bytes = bytes(info.Address[:6])
            mac_str = "-".join(f"{b:02X}" for b in mac_bytes)
            break
        ptr = info.Next
    if mac_str is None:
        raise RuntimeError("找不到 MAC 地址（无 AddressLength==6 的网卡）")

    payload = (mac_str + IMEI_BIOS_FALLBACK).encode("ascii")
    return hashlib.md5(payload).hexdigest().upper()


# =============================================================================
# HTTP 三步鉴权（原样复用自 thspy，链路通用）
# =============================================================================

def http_get(host: str, path: str, timeout: float = 30) -> bytes:
    """裸 socket 发 HTTP GET（auth.10jqka.com.cn 走 80 端口明文）。"""
    s = socket.create_connection((host, AUTH_PORT), timeout=timeout)
    s.settimeout(timeout)
    req = (
        f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: ".encode()
        + UA_GBK.encode("gbk")
        + b"\r\nConnection: close\r\n\r\n"
    )
    s.sendall(req)
    raw = b""
    try:
        while True:
            c = s.recv(8192)
            if not c:
                break
            raw += c
    except socket.timeout:
        pass
    s.close()
    return raw


def _extract_xml_attr(xml: str | bytes, attr: str) -> str:
    m = re.search(rf'{attr}="([^"]*)"', xml if isinstance(xml, str) else xml.decode("gb18030", "replace"))
    return m.group(1) if m else ""


def rsa_encrypt(plaintext: str, pubkey_pem: str) -> str:
    """RSA-PKCS1v15 加密（账号/密码用）。"""
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_v1_5
    key = RSA.import_key(pubkey_pem)
    cipher = PKCS1_v1_5.new(key)
    encrypted = cipher.encrypt(plaintext.encode("gbk"))
    return base64.b64encode(encrypted).decode()


def fetch_rsa_pubkey() -> tuple[str, str]:
    """第一步：拿 RSA 公钥。"""
    body = http_get(AUTH_HOST, "/verify2?reqtype=do_rsa&type=get_pubkey")
    body_str = body.decode("gb2312", "replace")
    m = re.search(r'pubkey="(-----BEGIN PUBLIC KEY-----.*?-----END PUBLIC KEY-----)"', body_str, re.DOTALL)
    m2 = re.search(r'rsa_version="([^"]+)"', body_str)
    if not m:
        raise RuntimeError(f"无法获取 RSA 公钥: {body_str[:200]}")
    return m.group(1), (m2.group(1) if m2 else "default_5")


def http_unified_login(username: str, password: str, rsa_version: str, pubkey_pem: str) -> dict:
    """第二步：统一登录，拿 userid/sessionid。"""
    acct = rsa_encrypt(username, pubkey_pem)
    passwd = rsa_encrypt(password, pubkey_pem)
    path = (
        f"/verify2?account={urllib.parse.quote(acct, safe='')}"
        f"&msg=1&passwd={urllib.parse.quote(passwd, safe='')}"
        f"&reqtype=unified_login&rsa_version={rsa_version}"
        f"&ta_appid={TA_APPID}"
    )
    body = http_get(AUTH_HOST, path)
    body_str = body.decode("gb18030", "replace")
    item = re.search(r"<item ([^>]*)/>", body_str)
    if not item:
        raise RuntimeError(f"统一登录失败: {body_str[-300:]}")
    attrs = item.group(1)
    return {
        "userid": _extract_xml_attr(attrs, "userid"),
        "sessionid": _extract_xml_attr(attrs, "sessionid"),
        "third_sign": _extract_xml_attr(attrs, "third_sign"),
        "this_time": _extract_xml_attr(attrs, "this_time"),
        "expires": _extract_xml_attr(attrs, "expires"),
    }


def http_mainverify(userid: str, sessionid: str, rsa_version: str, imei: str | None = None) -> dict:
    """第三步：主验证，拿 passport 票据 + signature + M_hqdns。

    Args:
        imei: 设备 ID。32 字符十六进制串，hexin.exe 本地生成的硬件指纹。
              算法已逆向（见 generate_imei()）：MD5( MAC大写连字符 + "0"*30 )。
              不传则自动生成；错误的 imei 会被服务端写进 passport，
              导致 8901 登录时设备校验失败。
    """
    if imei is None:
        imei = generate_imei()
    path = (
        f"/verify2?reqtype=mainverify&userid={userid}&sessionid={sessionid}"
        f"&qsid={QSID}&product={urllib.parse.quote(PRODUCT.encode('gbk'), safe='')}"
        f"&version={VERSION_HTTP}&imei={imei}&sdsn="
        f"&rsa_version={rsa_version}&nohqlist=0"
        f"&securities={urllib.parse.quote(SECURITIES.encode('gbk'), safe='')}"
    )
    raw = http_get(AUTH_HOST, path)
    seg = re.search(rb"<mainverify>(.*?)</mainverify>", raw, re.DOTALL)
    if not seg:
        raise RuntimeError(f"主验证失败: {raw[-300:]!r}")
    xml_body = seg.group(1)
    pm = re.search(rb'passport="(.*?)"', xml_body, re.DOTALL)
    sm = re.search(rb'signature="(.*?)"', xml_body, re.DOTALL)
    hm = re.search(rb'M_hqdns="(.*?)"', xml_body)
    return {
        "passport_bytes": pm.group(1) if pm else b"",
        "signature": sm.group(1).decode("ascii") if sm else "",
        "M_hqdns": hm.group(1).decode("ascii") if hm else "",
    }


def full_http_auth(username: str, password: str, imei: str | None = None) -> dict:
    """HTTP 三步鉴权完整流程：RSA 公钥 → 统一登录 → 主验证。

    Args:
        username: 同花顺账号
        password: 密码
        imei: 设备 ID（32 字符十六进制，hexin.exe 本地生成的硬件指纹）。
              不传则用 generate_imei() 自动生成（MD5(MAC + "0"*30)）。
              以前需从抓包取，现已完全本地生成，thspypc 脱离抓包运行。
    """
    pem, rsa_ver = fetch_rsa_pubkey()
    login_resp = http_unified_login(username, password, rsa_ver, pem)
    verify_resp = http_mainverify(login_resp["userid"], login_resp["sessionid"], rsa_ver, imei)
    return {**login_resp, **verify_resp, "pem": pem, "rsa_version": rsa_ver}


# ── 集合竞价协议（2026-07-26 抓包 auction_20260726 破解）──
#
# 集合竞价数据（9:15-9:25 每 9 秒一次虚拟撮合）走与分时不同的协议：
#   - 周期码 **7176**（分时是 8192、日K是 16384）
#   - DateTime 两参数是 **unix 时间戳（秒）**，不是 bar 序号：
#       DateTime=7176(<9:15:00 时间戳>-<9:25:00 时间戳>)
#     如 2026-07-24：DateTime=7176(1784855700-1784856300)
#   - 响应是 **hd1.0 帧 flag=0x003a**（不是 hd3.1），hs=20B/条，约 68 条记录
#
# 请求格式（pageid=4214 推送通道，hexin 打开分时图「集合竞价」小窗时发）::
#
#     CodeList=33(000938,);\r\n
#     DataType=10,27,33,49,\r\n
#     DateTime=7176(1784855700-1784856300)\r\n
#     LackTime=0,0,0,0,0,0,0,0\r\n
#     pageid=4214\r\n
#
# 响应字段（hd1.0 字段表 fc=5，2026-07-27 六股 × thsdk oracle 全量验证）：
#   dt1  = unix 时间戳（秒级，9:15:00-9:24:57 每 3-9 秒一条）
#   dt10 = 集合竞价撮合价（虚拟开盘价，逐 tick 收敛）
#   dt49 = 累计竞价量（单位：股，÷100=手）  ← 锚点 954000=9540手 ✓
#   dt27 = 买方未匹配量（单位：股，÷100=手）= thsdk buy2
#   dt33 = 卖方未匹配量（单位：股，÷100=手）= thsdk sell2
#
# ★ dt27/dt33 经六股（600276/600519/601318/603118/688825/688981）全量对照
#   thsdk「买2量/卖2量」确认：dt27≡buy2、dt33≡sell2（约 99.5% 匹配，少量
#   偏差是两通道 ±1~2 秒时间戳错位）。集合竞价撮合时被动方总被吃光，故每条
#   tick 恰好一侧为哨兵 0x80000000（=无该方向未匹配委托），归一化为 None。
#
# ⚠ 同一 dt 号在不同接口含义不同，切勿混淆：
#   - 竞价(hd1.0/flag=0x003a)：dt33=卖方未匹配量（本接口）
#   - 分时(hd3.1)：            dt33=成交额（见 _parse_hd_records）
#   - list_quotes：            dt33=注册制上市日（见 capture_list_quote_fields）
#   dt 号是协议层的字段槽位号，语义由所在接口的字段表定义，不跨接口复用。
#
# ★ 竞昨比/换手率是 hexin 客户端**本地算的衍生值**（dt49÷本地缓存的昨量/流通
#   股本），不在竞价响应里。9:21:03 锚点反推：换手0.03%=9540手÷28.6亿股 ✓
QUOTE_INFO_DATATYPE = [
    7, 8, 9, 10, 13, 14, 19, 69, 70, 74, 75, 85, 90, 92, 130,
    6, 45, 66,
    380, 402, 407, 663, 665, 1606, 2081, 262763,
]


def parse_quote_info_response(body: bytes) -> dict:
    """解析个股基本资料响应（嵌套壳帧 dc=0x01000001），返回行情统计+股本财务。

    这是盘口页"基本资料"区域的响应（2026-07-23 抓包确认）。含开/高/低/收、
    涨跌停价、内外盘、盘后数据、股本、净利润等。响应是 hd1.0 变体帧
   （dc=0x01000001 嵌套壳标记，字段表含 dt74 等基本资料字段）。

    双值字段（fmt=0x61/0x62/0x66/0x68，width=8）= (日期, 数值)，日期如
    20260331=季报日、19700101=哨兵（无数据）。单值字段（fmt=0x70，width=4）
    用 decode_ths_float。

    Args:
        body: 完整 TCP 帧体（含 hd1.0 标记）。

    Returns:
        dict::

            {
              "code": "002487",
              "fields": {  # 单值字段
                "dt7": 37.12, "dt10": 39.55, "dt69": 40.83, "dt146": ...,
                ...
              },
              "dual": {   # 双值字段 (日期, 值)
                "dt146_61": (20260707, 740085850),  # 总股本
                "dt151_61": (20260707, 630920270),  # 流通股本
                ...
              },
              "derived": {  # 本地计算的派生字段
                "inner": 14832495,      # 内盘(股) = dt13 - dt14
                "turnover": 4.87,       # 换手% = 成交量/流通股本
                "circ_mv": 24950000000, # 流通值 = 流通股本×现价
                "total_mv": ...,        # 总市值 = 总股本×现价
              },
            }

        未找到基本资料帧（字段表不含 dt74）时返回空 dict。
    """
    pos = body.find(b"hd1.0")
    if pos < 0:
        return {}
    base = pos + 6
    if base + 10 > len(body):
        return {}
    dc = struct.unpack("<I", body[base:base+4])[0]
    hs = struct.unpack("<H", body[base+6:base+8])[0]
    fc = struct.unpack("<H", body[base+8:base+10])[0]
    # 基本资料帧: dc=0x01000001(嵌套壳) 或标准 dc=1，字段表含 dt74
    if not (0 < hs < 500 and 0 < fc < 50):
        return {}
    ftoff = base + 10
    ft = body[ftoff:ftoff + fc*4]
    if len(ft) < fc*4:
        return {}
    fields = [(ft[i*4], ft[i*4+1], ft[i*4+3]) for i in range(fc)]  # (dt,fmt,width)
    if not any(d == 74 for d, _, _ in fields):
        return {}  # 非基本资料帧

    # 嵌套壳帧的记录区前有一段壳头（全0 + 0004 0021 前缀），需定位代码标记
    recoff = ftoff + fc*4
    # 找记录起点：dt5 字段格式 [市场码1B][6B ASCII代码]，扫到 6 位 ASCII 数字
    rec_start = -1
    for off in range(recoff, min(recoff + hs, len(body) - 7)):
        code_b = body[off+1:off+7]
        if len(code_b) == 6 and all(48 <= b <= 57 for b in code_b):
            rec_start = off
            break
    if rec_start < 0:
        return {}

    rec: dict = {}
    dual: dict = {}
    o = rec_start
    for dt, fmt, width in fields:
        chunk = body[o:o+width]
        o += width
        if len(chunk) < width:
            break
        if dt == 5 and fmt == 0x20:
            rec["code"] = chunk[1:1+6].split(b"\x00")[0].decode("ascii", errors="replace")
        elif width == 4:
            rec[f"dt{dt}"] = decode_ths_float(struct.unpack("<I", chunk)[0])
        elif width == 8:
            v1 = decode_ths_float(struct.unpack("<I", chunk[:4])[0])
            v2 = decode_ths_float(struct.unpack("<I", chunk[4:8])[0])
            dual[f"dt{dt}_{fmt:02x}"] = (v1, v2)

    # 派生字段（本地计算）
    derived: dict = {}
    dt13 = rec.get("dt13", 0)   # 成交量(股)
    dt14 = rec.get("dt14", 0)   # 外盘(股)
    if dt13:
        derived["inner"] = dt13 - dt14  # 内盘 = 总量 - 外盘
    # 流通股本 dt151(fmt61) 第二值
    liutong = _dual_second(dual, 151, 0x61)
    if liutong and rec.get("dt10"):
        derived["circ_share"] = liutong
        derived["circ_mv"] = liutong * rec["dt10"]   # 流通值
        if dt13:
            derived["turnover"] = (dt13/100) / (liutong/100) * 100  # 换手%
    # 总股本 dt146(fmt61) 第二值
    zong = _dual_second(dual, 146, 0x61)
    if zong and rec.get("dt10"):
        derived["total_share"] = zong
        derived["total_mv"] = zong * rec["dt10"]     # 总市值
    # 实际流通股 dt124(fmt61) -> 实换手
    shiji = _dual_second(dual, 124, 0x61)
    if shiji and dt13:
        derived["real_turnover"] = (dt13/100) / (shiji/100) * 100

    # 动/静态市盈率（600056 验证 差异=0.00）
    # 动态PE = 总市值 ÷ TTM净利润(dt151_fmt62)
    # 静态PE = 总市值 ÷ 上年年报净利润(dt107_fmt62)
    total_mv = derived.get("total_mv")
    if total_mv:
        ttm = _dual_second(dual, 151, 0x62)   # TTM净利润(近4季)
        if ttm and ttm > 0:   # 亏损时 PE 无意义，不计算
            derived["pe_ttm"] = total_mv / ttm
        ann = _dual_second(dual, 107, 0x62)   # 上年年报净利润
        if ann and ann > 0:
            derived["pe_annual"] = total_mv / ann

    return {"code": rec.get("code", ""), "fields": rec, "dual": dual,
            "derived": derived}


def _dual_second(dual: dict, dt: int, fmt: int) -> float | None:
    """从 dual 字典取指定 dt/fmt 的第二值（数值部分，第一值通常是日期）。"""
    v = dual.get(f"dt{dt}_{fmt:02x}")
    return v[1] if v else None


def _local_ip() -> str:
    """获取本机内网 IP（心跳 st= 字段用，非必需但抓包里有）。"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except OSError:
        return "0.0.0.0"
    finally:
        sock.close()


def build_heartbeat_8901(seq: int = 0) -> bytes:
    """构造 8901 心跳帧（每 3 秒发一次，维持行情连接）。"""
    timestamp = f"{int(time.time()):x}"
    ip = _local_ip()
    text = (
        f"10,{timestamp},0000;st={ip};"
        f"tsi0={timestamp}:0;tsi1={timestamp}:0;tsi2={timestamp}:0;"
        f"tsi3={timestamp}:0;tso4={timestamp}:0;"
        f"tr={timestamp}:0;tc={timestamp}:0"
    ).encode("gbk")
    header = bytearray(23)
    header[0] = 0x09
    header[1:5] = b"\x00\x16\x00\x00"
    struct.pack_into("<H", header, 5, seq & 0xFFFF)
    header[7:11] = b"\x12\x00\x03\x00"
    header[11] = 0x05
    header[18] = 0xA7
    return encode_frame(bytes(header) + text)


SUBREAL_CHANNELS = ["URS", "UNX", "UCX", "UME", "UCT"]

_SUBREAL_CLASS_PREFIX = {
    "URS": "URSI",
    "UCT": "UCTF",
    "UNX": "UNXF",
    "UCX": "UCXF",
    "UME": "UMEF",
}


def build_subreal_query(
    instance: int,
    channel: str = "URS",
    action=1,
    codelist: str = "",
    class_prefix: str | None = None,
    pageid: int = 1341,
) -> bytes:
    """构造 8901 的 subreal 实时订阅请求。"""
    if class_prefix is None:
        class_prefix = _SUBREAL_CLASS_PREFIX.get(channel, channel + "I")
    code_list = codelist if codelist != "" else " "
    text = (
        f"instid={instance}\n"
        f"method=subreal\nmarket={channel}\nperiod=0\n"
        f"action={action}\nclass={class_prefix}\n"
        f"codelist={code_list}\npageid={pageid}\n"
    )
    return b"\x09" + text.encode("gbk")


# Keep the historical protocol surface bound to the extracted RealOrder
# implementation.
from .features.realorder_protocol import (  # noqa: E402,F811
    ALL_REALORDER_CATEGORY_IDS,
    ANOMALY_BYTE_MAP,
    ANOMALY_GROUP_PREFIX,
    ANOMALY_MAP_DXJL,
    DXJL_DATATYPE,
    LEVEL2_ONLY_REALORDER_CATEGORY_IDS,
    REALORDER_HOST,
    REALORDER_PORT,
    SUBREALORDER_MARKETS,
    STANDARD_REALORDER_CATEGORY_IDS,
    build_category_id,
    build_datatype,
    build_heartbeat_9601,
    build_qurealorder_query,
    build_subrealorder_query,
    parse_pushrealorder_response,
    parse_qurealorder_response,
    read_frame_realorder,
)

from .features.board_stats_protocol import (  # noqa: E402,F811
    BOARD_MARKET as _BOARD_STATS_MARKET,
    DATATYPE_INTERVAL_STAT,
    DATATYPE_MARKETCAP,
    DATATYPE_UPDOWNLIMIT,
    STATSCALC_HOST,
    STATSCALC_PORT,
    build_calcext_query,
    build_statscalc_query,
    parse_calcext_response,
    parse_statscalc_response,
    read_frame_board_stats,
)

from .features.index_push_protocol import (  # noqa: E402,F811
    INDEX_PUSH_MAGIC,
    SZ_INDEX_FLAG,
    is_index_push,
    parse_index_push,
)

# Preserve the historical protocol surface while authentication callers move to
# AuthService; the duplicate authentication source block has been removed.
from .features.auth_protocol import (  # noqa: E402,F811
    PASSPORT_DROP_FIELDS as _PASSPORT_DROP_FIELDS,
    build_head128 as build_head128_pure,
    build_manual_login_body,
    build_passport64,
    build_standard_login_body as build_login_body_pc,
    parse_login_response,
    parse_passport_fields,
    signature_to_nibbles as _sig_to_nibbles,
)
