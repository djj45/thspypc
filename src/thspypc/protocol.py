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
    _AUCTION_SENTINEL_FIELDS,
    _AUCTION_SENTINELS,
    _auction_ts_in_range,
    _auction_value,
    _parse_auction_sh,
    _split_auction_history_segment,
    _split_auction_state_rows,
    build_auction_query,
    parse_auction_response,
)
from .features.history_timeline_protocol import (
    HISTORY_TIMELINE_BAR_SPAN,
    HISTORY_TIMELINE_DATATYPE,
    HISTORY_TIMELINE_PAGEID,
    TIMELINE_BAR_DAYS_SCALE,
    TIMELINE_BAR_EPOCH_ORDINAL,
    TIMELINE_INTRADAY_BAR,
    _date_to_ordinal,
    _decode_history_timeline_rows,
    _history_timeline_first_row,
    _history_timeline_row_anchors,
    build_history_timeline_query,
    date_to_timeline_bar,
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
    KLINE_PERIOD_5MIN,
    KLINE_PERIOD_15MIN,
    KLINE_PERIOD_30MIN,
    KLINE_PERIOD_60MIN,
    KLINE_PERIOD_DAY,
    KLINE_PERIOD_MONTH,
    KLINE_PERIOD_WEEK,
    _kline_decode_time,
    _kline_dt1_is_bar_index,
    build_kline_query,
    parse_kline_hd3_response,
)
from .features.quote_protocol import (
    BUY_LEVEL_FIELDS,
    DEPTH_QUOTE_DATATYPE,
    LIST_QUOTE_DATATYPE_DEFAULT,
    SELL_LEVEL_FIELDS,
    build_depth_quote_query,
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
    is_snapshot_push,
    parse_snapshot_push,
)
from .features.stock_list_protocol import (
    INIT_C_MODULES,
    INIT_MARKET_CODE,
    INIT_STOCK_LINKS,
    SORT_BY_VALUES,
    STOCK_LIST_DATATYPE,
    STOCK_LIST_MARKETS,
    _dt5_market,
    _parse_stock_list_hd10_variant,
    _parse_stock_list_hd31_variant,
    build_init_query,
    build_stock_list_query,
    parse_init_response,
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
    TIMELINE_DATATYPE,
    TIMELINE_L2_DATATYPE,
    TIMELINE_PAGEID,
    TIMELINE_PERIOD,
    build_timeline_l2_query,
    build_timeline_query,
    parse_timeline_l2_response,
)
from .models import DepthLevel, DepthQuote

logger = logging.getLogger(__name__)

# =============================================================================
# 协议常量（PC 免费版）
# =============================================================================

# HTTP 鉴权（与客户端类型无关，通用）
AUTH_HOST = "auth.10jqka.com.cn"
AUTH_PORT = 80

# PC 免费版主行情服务器（8901）。多 IP 冗余，抓包实测。
# 登录时按顺序尝试，任一成功即可。
# 注意：实测部分 IP 只做登录网关、对行情请求(CodeList)无响应（timeout），
# 行情查询需要连到真正处理 CodeList 的服务器（标 ★ 的是实测能返回
# hd1.0/hd3.1 数据的 IP）。把这些排在前面提高 list_quotes 命中率。
#
# ⚠ 这是 DNS 解析失败时的回退 IP 列表。正常运行走 :func:`resolve_market_hosts`
# 从 passport 的 M_hqdns 动态解析（拿到当前最新 IP）。
#
# 历史误判澄清（2026-07-23 最终结论）：此前认为旧 IP（122.9.202.190 等）"退化为
# 纯登录网关、行情查询超时"，**已被推翻**。真正根因是 login 后缺 init 握手帧——
# connect() 直接发行情查询导致超时。补上 init 握手后（见 client._send_init_handshake），
# 旧 IP 同样能正常返回 list_quotes/stock_list_hot 行情。新旧 IP 都是行情网关，
# 不存在"退化"一说。注释中的"新/旧集群"分组已无实际意义，保留 IP 仅为扩充回退池。
MARKET_PORT = 8901
MARKET_HOSTS = [
    # 通用行情服务器 IP（2026-07-23 实测可用，hexin 抓包 / init 握手后验证）。
    # ⚠ 仅放通用服务器，不放 lv2 IP——主连接普通 login 连 lv2 会被拒。
    # lv2 IP（shlv2/szlv2）由 resolve_l2_hosts_grouped() 动态解析，专供 L2 推送连接。
    # 已确认的 lv2 IP（勿混入）：shlv2=122.9.115.201/122.9.202.190/8.134.98.163/
    #   szlv2=8.134.101.39/121.37.31.87
    "8.134.146.31",
    "47.101.161.13",
    "139.159.135.214",
    "122.9.204.225",
    "122.9.125.190",
    "116.63.108.136",
    "8.138.46.177",
    "8.145.212.55",
]


def resolve_market_hosts(passport_bytes: bytes) -> list[str]:
    """从 passport 的 M_hqdns 字段解析域名，DNS 查询得到 8901 服务器 IP 列表。

    hexin 客户端不硬编码 IP——HTTP 鉴权返回的 passport 里有 M_hqdns 字段，
    格式如 ``shlv2.123ths.com:8901:16;144;:,szlv2.123ths.com:8901:32;:,...``，
    含多个域名。hexin DNS 解析这些域名拿到当前可用的 IP（DNS 轮询，每次可能
    不同），并发连接。这是 thspypc 拿到最新可用 IP 的正确方式（硬编码快照
    会过时——2026-07-23 实测旧 IP 退化为纯登录网关）。

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
    # 提取所有 :8901 的域名，但排除 lv2 域名（shlv2/szlv2）。
    # ★ lv2 服务器只接受 __manual 登录 + 配套 init，普通 login（主连接用的
    # build_login_body_pc）连 lv2 IP 会被服务器立即 FIN 关闭（表现为"连接已关闭"，
    # 收不到 VerifyCode）。lv2 域名由 resolve_l2_hosts_grouped() 专用于 L2 推送
    # 连接，主连接只解析通用行情域名（fu4/fu2/hkus/ifindhq/euhq/usotc）。
    domains = []
    for entry in m_hqdns.split(","):
        # entry 如 "shlv2.123ths.com:8901:16;144;:"
        dm = re.match(r'([\w.]+):(\d+):', entry.strip())
        if dm and dm.group(2) == str(MARKET_PORT):
            domain = dm.group(1)
            if "lv2" in domain:   # shlv2=沪L2 / szlv2=深L2，主连接禁用
                continue
            domains.append(domain)

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
        logger.info("M_hqdns 动态解析 %d 个通用行情域名（已排除 lv2）→ %d 个 IP: %s",
                    len(domains), len(ips), ips[:5])
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
    4214 注册 CodeListSize=0——这是 HANDOFF 里"支持 push 的 IP 比例约 30%"
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
def _legacy_build_auction_query(
    code: str,
    market: int = 33,
    trade_date=None,
    datatype: list[int] | None = None,
    seq: int = 0x0079,
) -> bytes:
    """构造**集合竞价**查询请求（pageid=4214 推送通道，周期码 7176）。

    与 :func:`build_timeline_l2_query`（盘中分时，周期码 8192）的差异（2026-07-26
    抓包 auction_20260726 逐字节对照确认）::

        - DateTime 第一参数 = 7176（分时是 8192）
        - DateTime 括号两参数是 **unix 时间戳（秒）**：
            DateTime=7176(<9:15:00 时间戳>-<9:25:00 时间戳>)
          如 2026-07-24：DateTime=7176(1784855700-1784856300)
          （分时是 ``8192(0-0)`` 当日 / bar 序号历史回忆，语义完全不同）
        - DataType 用 4 个竞价字段（分时是 31 个 level2 字段）
        - **路由 0xfc01**（分时是 0x0201）、**hdr[15]=0x40 / hdr[17]=0x08 /
          hdr[18]=0x1c**（分时这三个字节为 0/0/0x20）、seq 高字节 0x01（分时是
          0x10）——同为 pageid=4214 推送通道，但路由+标记位区分竞价 vs 分时；
          子帧类型仍 0x0009
        - LackTime 全 0（分时是 ``0,3,0,0,20031231,2,0,0``）

    沪深两市集合竞价时段相同（9:15-9:25），无需区分；仅 ``market`` 码不同。

    ⚠ 必须在 ``__manual`` 登录的连接上发送（4214 通道需要 __manual 身份），
       与 :func:`build_timeline_l2_query` 共用同一条推送连接。

    Args:
        code: 股票代码（如 ``"000938"``）。
        market: 市场码（33=深 17=沪）。
        trade_date: 交易日。``None``（默认）= 最近交易日（服务器返回最近交易日
            数据，DateTime 用 ``(0-0)``，与 :func:`build_timeline_l2_query` 一致）；
            传 ``date``/``datetime`` = 指定交易日（算该日 9:15/9:25 unix 时间戳）。
            ★ 历史日期的 DateTime 参数格式基于当日抓包推断（仍是 unix 时间戳，
              因参数语义是「时间区间」）；若实测不符需在此调整。
        datatype: 字段集（默认 :data:`AUCTION_DATATYPE` = ``[10,27,33,49]``）。
        seq: 序列号（hexin 用 0x105b，高字节 0x10）。

    Returns:
        完整请求帧字节（含 fdfdfdfd magic），可直接 sendall。
    """
    return build_auction_query(
        code=code,
        market=market,
        trade_date=trade_date,
        datatype=datatype,
        seq=seq,
    )


def _legacy_parse_auction_sh(body: bytes) -> list[dict]:
    """启发式解析无法完成外层正规化的沪市集合竞价原始响应。

    .. warning::

       这是为损坏帧和旧语料保持兼容的回退扫描器。正常 ``cmd=0x0a`` 响应会先由
       :func:`normalize_8901_response` 解开外层；只有内层无法按定长行验收时才进入
       这里。2026-07-27
       的多股票、多变体语料和 thsdk 真值证明，同一逻辑结果会由服务器随机选用
       多种外层打包状态；原始 ``hd1.*`` 字节不能直接按固定 CHQuote 头或逐 tick
       记录解释。变体专属字节也不能简单删除，它们携带重建固定头/记录流所需状态。

    当前实现只在原始字节中寻找形似竞价时间戳和价格的片段，因此可能漏报、误报，
    也尚不能解析 dt49/dt27。代码中的模 3 过滤只是旧数据上的降噪启发式；真实
    thsdk 时间间隔已经观察到 2、3、4 秒及更长间隔，不能把它当作协议约束。

    字段（与定长路径语义一致，但编码不同；此回退路径仅解析 time/dt10）::

        time ← dt1（unix 时间戳秒，3 字节压缩识别，转 datetime）
        dt10 = 撮合价（变长：b0 标记前的 LE16 尾数 ÷1000；仅价格变化的 tick 含此字段）
        dt49/dt27/dt33 = 累计量/买方未匹配/卖方未匹配（有前值状态的变长编码，
        边界规则未完全破解，此路径暂不解析）。dt49 已确认会省略与前值相同的 LE
        低位字节前缀；值完全不变时
        整个字段省略，剩余载荷中仍可能夹入控制字节。

    价格解析（已用 603118 9:15:03 锚点 15.01、600276 9:15:50 锚点 54.71 验证）：

        时间戳 off+4 起是字段区。找首个 0xb0 字节（ths_float exp=3 除 1000 标记），
        候选价格有两个来源：字段区 rec[0:2] LE16 ÷1000（多数 b0@3 记录的价格尾数
        在记录开头）和 b0 紧邻前 2 字节 ÷1000（b0@2 记录或 rec[0] 是前字段的情况）。
        价格合理性范围 1-2000 元（覆盖低价股 ~5 元到高价股 ~1700 元茅台）。

        候选选择策略（解决 ``rec[0]`` 有时是前字段数据、有时是价尾数的问题）：
        有前价时，选与前价偏差 < 20% 的候选（过滤误匹配时间戳字段里的 b0 噪声）；
        无前价（首条）时，优先取 rec[0:2]。无 b0 或无合理候选的 tick 沿用前价。

    Args:
        body: 沪市单帧响应体（含 Ihd1.0 标记 + 字段表 + 变长记录区）。

    Returns:
        沪市竞价记录列表，每条 ``{time, dt10}``（无 b0 的 tick 沿用前价），
        按时间正序（9:15:00-9:24:57，通常约 200 条）。无法识别时返回空列表。
    """
    records: list[dict] = []
    # 扫描时间戳变体：标准形式类似 [b0,b1,66,6a]，控制字节可能落在
    # [b0,b1] 之后，也可能把 b0/b1 隔开（688825 实测 09:15:10 =
    # 1e 43 b1 66 6a）。日期标记目前见过 0x62/0x66；不把 b1 的具体日期
    # 范围写死，最终由时分秒范围过滤二进制噪声。
    ts_candidates: dict[int, int] = {}   # ts -> off
    time_markers = (0x62, 0x66)
    # 第一遍只扫 b0/b1 相邻的旧形态；这些 offset 已用 603118 oracle 验证，
    # 必须全局优先，不能被记录区内碰巧成立的弱插入候选覆盖。
    for i in range(len(body) - 3):
        for marker in time_markers:
            if marker not in body[i + 2:i + 4]:
                continue
            ts = ((0x6a << 24) | (marker << 16) |
                  (body[i + 1] << 8) | body[i]) & 0xFFFFFFFF
            if _auction_ts_in_range(ts):
                ts_candidates.setdefault(ts, i)

    # 第二遍仅补第一遍不存在的 [b0,ctrl,b1,marker,...]。高位 0x6a 可能存在，
    # 也可能被控制流替代（ed f8 b1 66 44）；“仅补缺”是消除假 offset 的关键。
    for i in range(len(body) - 4):
        marker = body[i + 3]
        if marker not in time_markers:
            continue
        ts = ((0x6a << 24) | (marker << 16) |
              (body[i + 2] << 8) | body[i]) & 0xFFFFFFFF
        if not _auction_ts_in_range(ts):
                continue
        ts_candidates.setdefault(ts, i)

    if len(ts_candidates) < 3:
        return records

    # 旧兼容启发式：用候选时间的模 3 众数压制扫描假阳性。thsdk 真值已证明
    # 真实 tick 并非严格 3 秒节拍，所以这一步会漏掉部分记录；在外层打包算法
    # 破解前保留旧行为，避免悄然扩大生产解析器的误报面。
    residue_counts: dict[int, int] = {}
    for ts in ts_candidates:
        residue = ts % 3
        residue_counts[residue] = residue_counts.get(residue, 0) + 1
    cadence_residue = max(residue_counts, key=residue_counts.get)
    ts_map = {ts: off for ts, off in ts_candidates.items()
              if ts % 3 == cadence_residue}
    if len(ts_map) < 3:
        return records
    # 按时间戳排序（body 内数据乱序，必须按 ts 排序而非 off）
    sorted_ts = sorted(ts_map.keys())
    # 第一遍：收集所有 tick 的价格候选（rec[0:2] 和 b0-2），用于建立基准价
    tick_candidates: list[tuple[int, list[float]]] = []   # (ts, candidates)
    for ts in sorted_ts:
        off = ts_map[ts]
        rec = body[off + 4: off + 32]
        b0_pos = -1
        for j in range(min(len(rec), 6)):
            if rec[j] == 0xb0:
                b0_pos = j
                break
        cands: list[float] = []
        if b0_pos >= 0:
            if len(rec) >= 2:
                m0 = struct.unpack("<H", rec[0:2])[0]
                p0 = m0 / 1000.0
                if 1.0 <= p0 <= 2000.0:
                    cands.append(p0)
            if b0_pos >= 2:
                m1 = struct.unpack("<H", rec[b0_pos-2:b0_pos])[0]
                p1 = m1 / 1000.0
                if 1.0 <= p1 <= 2000.0:
                    cands.append(p1)
        tick_candidates.append((ts, cands))

    # 建立基准价：找前 N 个有候选的 tick，取所有候选里 "使最多候选聚集" 的值
    # （即簇中心）。避免首条误匹配锁定错误基准。
    seed_cands: list[float] = []
    for _, cs in tick_candidates:
        if cs:
            seed_cands.extend(cs)
        if len(seed_cands) >= 10:
            break
    base_price: float | None = None
    if seed_cands:
        # 找一个值，使最多的候选落在其 ±20% 范围内
        best_count = 0
        for anchor in seed_cands:
            lo, hi = anchor * 0.8, anchor * 1.2
            cnt = sum(1 for c in seed_cands if lo <= c <= hi)
            if cnt > best_count:
                best_count = cnt
                base_price = anchor

    # 第二遍：用基准价作首条 prev_price，逐条解析
    prev_price = base_price
    for ts, cands in tick_candidates:
        price: float | None = None
        if cands:
            if prev_price is not None:
                close = [p for p in cands
                         if abs(p - prev_price) / prev_price < 0.2]
                if close:
                    close.sort(key=lambda p: abs(p - prev_price))
                    price = close[0]
                # 无 close：b0 是误匹配（字段噪声），沿用前价
            else:
                price = cands[0]
        if price is not None:
            prev_price = price
        elif prev_price is not None:
            price = prev_price   # 无 b0 或候选都不合理：沿用前价（价格未变）
        try:
            t = datetime.fromtimestamp(ts)
        except (OSError, ValueError, OverflowError):
            t = None
        records.append({"time": t, "dt10": price})
    return records


def _legacy_parse_auction_response(body: bytes) -> list[dict]:
    """解析集合竞价响应（pageid=4214 推送通道，沪深两市格式不同）。

    **深市**（szlv2，hd1.0 帧 flag=0x003a）::

        - 响应是 hd1.0 帧（分时是 hd3.1）
        - flag=0x003a（分时是 0x00b4）
        - 记录区**直接定长明文**（无 BitRLE 压缩，hd3.1 才有 BitRLE+位平面转置）
        - hs=20B/条，约 68 条记录（9:15:00-9:24:57 每 9 秒一次虚拟撮合）

    **沪市**（shlv2）原始响应使用 ``cmd=0x0a`` 外层压缩。解析器先调用
    :func:`normalize_8901_response`，还原 ``0x1600`` 包装和 ``hd1.0`` 表体。
    若内层全部记录都通过定长行时间戳校验，则按字段表返回五字段结果；若仅有
    行尾高位零字节被省略，则按直接 ``dt1`` 重锚并恢复短行。其他未知旧变体才
    回退到 :func:`_parse_auction_sh` 启发式扫描。

    字段（hd1.0 字段表 fc=5，2026-07-27 六股 × thsdk oracle 全量验证）：
        time ← dt1（unix 时间戳秒，转 datetime；非 bar 序号）
        dt10 = 集合竞价撮合价（虚拟开盘价，逐 tick 收敛）
        dt49 = 累计竞价量（股，÷100=手）     ← 锚点 954000=9540手 ✓
        dt27 = 买方未匹配量（股，÷100=手）   = thsdk buy2
        dt33 = 卖方未匹配量（股，÷100=手）   = thsdk sell2（非"额"，见下方警告）

    ⚠ 同一 dt 号在不同接口含义不同：dt33 在竞价=卖方未匹配量，在分时=成交额，
    在 list_quotes=注册制上市日。dt 号是协议槽位号，语义由字段表定义。

    dt27 / dt33 的「无值」哨兵（``0x80000000`` / ``0xFFFFFFFF``）归一化为
    :data:`None`，与真实数值 ``0.0`` 区分。实测集合竞价撮合时被动方总被吃光，
    故 dt27/dt33 每条 tick 恰好一侧为哨兵（该方向无未匹配委托）。
    dt10 / dt49 六股全部变体实测从不带哨兵。

    Args:
        body: 完整 TCP 帧体（含 ``hd1.0`` 标记）。

    Returns:
        集合竞价记录列表。定长内层返回
        ``{time, dt10, dt49, dt27, dt33}``；兼容回退仅返回
        ``{time, dt10}``。非竞价帧返回空。``dt27`` / ``dt33`` 的值类型为
        ``float | None``（哨兵 → None）。
    """
    original_body = body
    if body.startswith(b"\x0a"):
        try:
            body = normalize_8901_response(body)
        except ValueError as exc:
            logger.debug("集合竞价 0x0a 外层正规化失败，回退原始扫描: %s", exc)

    pos = 0
    records: list[dict] = []
    # 一个响应里可能含多个 hd1.0 帧（不同 flag），遍历找竞价帧 flag=0x003a。
    # 注意 body 里也可能含二进制噪声恰好出现 "hd1.0" 字节序列，靠 flag+dc+hs 校验排除。
    while True:
        p = body.find(b"hd1.0", pos)
        if p < 0:
            break
        pos = p + 6
        base = p + 6   # 跳过 hd1.0\0
        if len(body) < base + 10:
            continue
        dc = struct.unpack("<I", body[base:base+4])[0]
        flag = struct.unpack("<H", body[base+4:base+6])[0]
        hs = struct.unpack("<H", body[base+6:base+8])[0]
        fc = struct.unpack("<H", body[base+8:base+10])[0]
        # 竞价帧特征：flag=0x003a，fc=5，hs=20（dt1/dt10/dt49/dt27/dt33 各 4B）
        if flag != 0x003a or hs == 0 or fc == 0:
            continue
        # 盘后历史帧：dc 字段非标准 LE32（编码不同，值 >1000），响应含竞价+全天
        # 分时。盘中正常帧 dc 是标准 LE32（<1000）。对历史帧用时间戳扫描确定
        # 竞价段记录数，替代 dc 走定长路径。
        if dc > 1000:
            history_recs = _split_auction_history_segment(body, base, hs, fc)
            if history_recs:
                return history_recs
            continue
        if dc == 0:
            continue
        fields = _parse_hd_field_table(body, base + 10, fc)
        rec_off = base + 10 + fc * 4
        if len(body) < rec_off + dc * hs:
            continue
        # 记录区前有个 ~22B 壳头（含 ``!000938`` 代码标记），首条 dt1 不是时间戳
        # 而是壳头字节。扫描首个「连续三条 dt1 都递增且步长不超过 10 秒」定位
        # 真实数据起点。深市样本约 9 秒一步，沪市正规化后的 200 条记录约 3 秒一步。
        data_start = -1
        scan_end = min(rec_off + hs * 3, len(body) - hs * 2)
        for off in range(rec_off, scan_end):
            v = struct.unpack("<I", body[off:off+4])[0]
            if 1_700_000_000 < v < 1_800_000_000:
                v_next = struct.unpack("<I", body[off+hs:off+hs+4])[0]
                v_third = struct.unpack("<I", body[off+hs*2:off+hs*2+4])[0]
                if 1 <= v_next - v <= 10 and 1 <= v_third - v_next <= 10:
                    data_start = off
                    break
        if data_start < 0:
            continue
        frame_records: list[dict] = []
        frame_valid = True
        for r in range(dc):
            row = body[data_start + r*hs: data_start + (r+1)*hs]
            if len(row) < hs:
                frame_valid = False
                break
            rec: dict = {}
            off = 0
            for dt, fmt, width in fields:
                chunk = row[off: off + width]
                off += width
                if len(chunk) < width:
                    break
                if width == 4:
                    raw = struct.unpack("<I", chunk)[0]
                    if dt == 1:
                        # dt1 = unix 时间戳（秒），非 bar 序号；转 datetime
                        # 校验合理范围（1.7e9~1.8e9 ≈ 2024-2027），噪声跳过
                        if 1_700_000_000 < raw < 1_800_000_000:
                            try:
                                rec["time"] = datetime.fromtimestamp(raw)
                            except (OSError, ValueError, OverflowError):
                                rec["time"] = None
                                rec["ts"] = raw
                        else:
                            rec["ts"] = raw
                            frame_valid = False
                    else:
                        rec[f"dt{dt}"] = _auction_value(raw, dt)
                else:
                    rec[f"dt{dt}_raw"] = chunk
            frame_records.append(rec)
        if frame_valid and len(frame_records) == dc:
            return frame_records
        state_rows = (
            _split_auction_state_rows(body, data_start, dc, hs)
            if len(fields) == fc and sum(width for _, _, width in fields) == hs
            else []
        )
        if state_rows:
            state_records: list[dict] = []
            state_valid = True
            for row in state_rows:
                rec: dict = {}
                off = 0
                for dt, fmt, width in fields:
                    chunk = row[off: off + width]
                    off += width
                    if len(chunk) < width:
                        state_valid = False
                        break
                    if width != 4:
                        rec[f"dt{dt}_raw"] = chunk
                        continue
                    raw = struct.unpack("<I", chunk)[0]
                    if dt == 1:
                        if not 1_700_000_000 < raw < 1_800_000_000:
                            state_valid = False
                            break
                        try:
                            rec["time"] = datetime.fromtimestamp(raw)
                        except (OSError, ValueError, OverflowError):
                            state_valid = False
                            break
                    else:
                        rec[f"dt{dt}"] = _auction_value(raw, dt)
                state_records.append(rec)
            if state_valid and len(state_records) == dc:
                return state_records
        logger.debug(
            "集合竞价 hd1.0 记录区不是完整定长行流（dc=%d），回退原始扫描",
            dc,
        )
    # 正规化后的 flag=0x003a 帧未命中 → 尝试旧的沪市原始流兼容扫描。
    if not records:
        sh_records = _parse_auction_sh(original_body)
        if sh_records:
            return sh_records
    return records


def _legacy_build_history_timeline_query(
    code: str,
    bar_start: int | None = None,
    market: int = 33,
    datatype: list[int] | None = None,
    pageid: int = HISTORY_TIMELINE_PAGEID,
    seq: int = 0x0025,
    inner_seq: int = 0x0000,
    dt_prev_off: int = -61,
    date=None,
    benchmark_market: int | None = None,
    benchmark_code: str | None = None,
) -> bytes:
    """构造 8901 端口**历史分时（回忆）**请求帧（嵌套子帧结构）。

    请求格式（2026-07-24 PCAP 逐字节确认）：

    - 指数：``cmd=09 + 完整查询(0x0009/0x0158) + 指数壳(0x0002/0x0258)``。
    - 个股：``cmd=09 + 目标壳(0x0002/0x0058) +
      基准指数+目标股完整查询(0x0009/0x0158) + 基准壳(0x0002/0x0258)``。

    当前只对深市个股复刻抓包中的 ``32(399002,)`` 伴随序列。2026-07-28
    已在正确的 ``__manual + szlv2 + init(32)`` 连接上证明该代码可替换为
    ``33(000001,)``，因此它不是服务器硬编码依赖。三段是否为服务器接受请求的
    最小形态仍须做主动 A/B；此前在主行情连接上的断连不能作为“缺壳必断”的证据。
    沪市个股尚无对应历史分时请求抓包，不自动猜测伴随指数。

    与当日分时（build_timeline_query）的区别：
      - **pageid 4417**（当日是 9354）
      - **子帧 0x0009** + 路由 0x0158（当日是单层 0x0002 + 0x000a）
      - **嵌套结构**（个股为目标壳 + 混合查询 + 基准壳）
      - **DataType 26 个 level2 字段**（含 201-230 大单金额，当日无）
      - DateTime 带具体 bar 序号区间（当日是 0-0）
      - 多 ``DTPrevOff=-61``（含义待确认，抓包恒为 -61）

    ★ **bar_start（日期定位参数）**：``DateTime=8192(bar_start-bar_start+355)`` 里
    的两个大数是该交易日**首条分时 bar 的全局序号**，编码已破解（4 锚点验证，
    见 :func:`date_to_timeline_bar`）::

        bar_start = (目标日期 - 1849-04-06).days × 2048 + 606

    传 ``date`` 参数即可自动换算（推荐），无需手算 bar_start。

    Args:
        code: 股票代码（如 ``"000938"``；指数用 ``"1A0002"``）。
        bar_start: 该交易日首条 bar 的全局序号。与 ``date`` 二选一（``date`` 优先）。
        date: 目标交易日（``date``/``datetime``/``"YYYY-MM-DD"`` 字符串）。
            优先于 ``bar_start``，自动用 :func:`date_to_timeline_bar` 换算。
        market: 市场码（17=沪 33=深；指数 1A0002 用 16）。
        datatype: 字段集，None 用 :data:`HISTORY_TIMELINE_DATATYPE`。
        pageid: 4417（历史分时）。
        seq: 外层帧序列标签。
        inner_seq: 内层子帧序列标签。
        dt_prev_off: DTPrevOff 值（抓包恒 -61，含义待确认）。
        benchmark_market: 个股混合查询的伴随代码市场码；深市个股在两项均为
            None 时复刻 PC 抓包，自动使用 32。沪市不自动猜测。
        benchmark_code: 个股混合查询的伴随代码；深市个股默认 ``399002``。

    Returns:
        完整请求帧字节（含 fdfdfdfd magic），可直接 sendall。
    """
    return build_history_timeline_query(
        code=code,
        bar_start=bar_start,
        market=market,
        datatype=datatype,
        pageid=pageid,
        seq=seq,
        inner_seq=inner_seq,
        dt_prev_off=dt_prev_off,
        date=date,
        benchmark_market=benchmark_market,
        benchmark_code=benchmark_code,
    )


def _legacy_parse_history_timeline_response(
    body: bytes,
    code: str | None = None,
) -> list[dict]:
    """解析历史分时响应，返回可验证的逐点行情。

    沪深个股的大响应通常先套 ``cmd=0x0a`` 字典压缩。本函数先调用
    :func:`normalize_8901_response`，再处理正规 ``hd1.0`` 表体。压缩流里偶然
    保留下来的字面量 ``hd1.0`` 不是字段头，不能直接解释。

    正规化后的响应结构（2026-07-24 抓包确认，文档 §14h）::

        hd1.0\\0
        + dc(LE32)            ← 0x040000f2；低16位含 241 个点和壳/尾记录
        + flag(LE16=0x007e)
        + hs(LE16=88)         ← 逻辑字段区长度（= 字段表 width 累加）
        + fc(LE16=22)         ← 字段数
        + 字段表(fc×4B)       ← dt1/10/13/19/22/23/201-230，width 全=4
        + 一个或多个个股壳     ← 市场码、代码、padding
        + 241 点记录区

    指数块的物理行通常恰为 88 字节；个股块在 88 字节逻辑字段后还带 1-4 个
    状态字节，所以物理行常见 89-92 字节。本函数不按 93/94 等经验长度硬切，
    而用交易日 241 点的 ``bar_index`` 序列重新锚定每行。``code`` 用于从
    hexin 常见的“指数 + 个股”混合响应中选择目标块。

    少数更强的状态省略帧会连 ``bar_index`` 的中高位也省略。若完整锚点少于
    200 条，本函数返回空列表，让客户端重请求随机出现的完整锚点变体；绝不把
    错位字节伪装成 242 条有效记录。

    dt1（时间字段）= 该 bar 的**全局序号**（首条 = 请求里的 bar_start，每条 +1）。
    午间和集合竞价边界有固定跳号，不是全日简单 ``+1``。
    其它字段（dt10 现价/dt13 量/dt19 额/dt201-230 大单）用 decode_ths_float。

    Args:
        body: 完整 TCP 帧体（含 hd1.0 标记）。
        code: 可选目标代码。混合响应应传入，例如 ``"000938"``；省略时选第一块。

    Returns:
        记录列表，每条 ``{bar_index, dt10, dt13, dt19, dt22, dt23, ...}``。
        dt10=现价、dt13=成交量、dt19=成交额、dt201-230=level2 大单金额。
        未找到历史分时帧或帧属于尚未安全恢复的强状态省略变体时返回空列表。
    """
    return parse_history_timeline_response(body, code=code)


# =============================================================================
# 个股基本资料（行情统计 + 股本财务）—— 8901 端口
#
# 2026-07-23 多票对照界面值破解（002487/001317/600056）。请求是嵌套子帧
# （外层 cmd=0x09 子帧0x0002 路由0x001c + 内层 0x0009），响应是 hd1.0 变体帧
# （dc=0x01000001 嵌套壳标记，hs=159 fc=27）。
#
# 字段表含单值(fmt0x70)和双值(fmt0x61/0x62/0x66/0x68, 8字节=日期+数值)两类。
#
# ★ 已确认字段（三票界面对照，PE 公式精确验证 差异=0.00）：
#   dt7=开盘 dt8=最高 dt9=最低 dt10=现价 dt13=成交量(股) dt14=外盘(股)
#   dt19=成交额 dt66=涨幅% dt69=涨停价(昨收×1.1) dt70=跌停价(昨收×0.9)
#   dt74=盘后量(股) dt75=盘后笔数
#   dt146(fmt61)=总股本    dt151(fmt61)=流通股本
#   dt151(fmt62)=TTM净利润(近4季之和,动态PE分母) dt107(fmt62)=上年年报净利润(静态PE分母)
#   dt124(fmt61)=实际流通股(实换手分母,含义待细化)
#   dt33(fmt68)=注册制上市日（001317=2024-08-29 已确认）
#
# PE 公式验证（600056 中国医药，差异 0.00）：
#   动态PE = 总市值(dt146×现价) ÷ TTM净利(dt151_fmt62) = 141.21亿/4.83亿 = 29.24 ✓
#   静态PE = 总市值(dt146×现价) ÷ 年报净利(dt107_fmt62) = 141.21亿/4.73亿 = 29.84 ✓
#
# ⚠ 待查字段：dt70(fmt66)=(19700101, 7.02) 非PE非EPS；dt45；dt90/dt92；dt130
#
# 本地计算（服务器不给）：换手=成交量÷流通股本 流通值=流通股本×现价
#                          总市值=总股本×现价 动/静态PE 量比/委比需历史或盘口数据
# =============================================================================

# 基本资料请求的 DataType（2026-07-23 抓包 002487 真值，26 字段）
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


def _legacy_parse_timeline_l2_response(body: bytes) -> list[dict]:
    """解析 L2 当日分时响应（hd3.1 变体 flag=0x00b4，pageid=4214 推送通道）。

    与 K线响应（:func:`parse_kline_hd3_response`）的差异（2026-07-24 抓包确认）::

        - flag=0x00b4（K线是 0x0042/0x0046）
        - 壳头 44 字节（K线是 26B），含两只票的代码壳（指数 + 个股）
        - dc=482 是两只票合计（各 241 根），不是单票根数
        - BitRLE + 位平面转置与 K线完全相同

    壳头结构（44B，2026-07-26 沪深实测）::

        [0:5]   市场码 + 标记(0x20/0x10)  ← 指数（深 399002 / 沪 1A0002）
        [5:12]  6B ASCII 代码 + padding
        [12:22] padding
        [22:23] 市场标记字节             ← 个股：0x21=深(33) / 0x11=沪(17)
        [23:30] 6B ASCII 代码 + padding  ← 个股代码（如 000938 / 603118）
        [30:44] padding/f1 标记

    ⚠ 个股标记字节随市场不同：深市 0x21、沪市 0x11（= 市场码 33/17 的低字节，
    与 :func:`build_timeline_l2_query` 的 ``market`` 参数一致）。早期版本只认
    0x21 导致沪市 ``code`` 解析为空——已在下方用 ``(0x11, 0x21)`` 双标记修复。

    解码后按 hs 切分行，前 dc//2 行是第一只票，后 dc//2 行是第二只票。
    本函数返回**个股**分时记录（跳过指数）。

    Args:
        body: 完整 TCP 帧体（含 ``hd3.1\\0`` 标记）。

    Returns:
        个股分时记录列表，每条 ``{code, bar_index, dt10, dt13, dt19, ...}``。
        非分时帧返回空。字段含义见 :data:`TIMELINE_L2_DATATYPE` 注释。
    """
    return parse_timeline_l2_response(body)


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
    ANOMALY_BYTE_MAP,
    ANOMALY_GROUP_PREFIX,
    ANOMALY_MAP_DXJL,
    DXJL_DATATYPE,
    REALORDER_HOST,
    REALORDER_PORT,
    SUBREALORDER_MARKETS,
    build_category_id,
    build_datatype,
    build_heartbeat_9601,
    build_qurealorder_query,
    build_subrealorder_query,
    parse_pushrealorder_response,
    parse_qurealorder_response,
    read_frame_realorder,
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
