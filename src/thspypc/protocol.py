"""
同花顺 Windows PC 远航版行情协议层 — 纯 Python 实现。

移植自 thspy（Mac 版），针对 PC 远航版（8901 端口）改造：
  - HTTP 三步鉴权链路原样复用（先用 Mac 参数验证 8901 是否接受）
  - 帧编解码（FD FD FD FD + ASCII hex 长度）原样复用
  - head128 / passport64 构造算法原样复用
  - login 帧重写为 PC 远航版格式（抓包实测，比 Mac 版更简洁）
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

logger = logging.getLogger(__name__)

# =============================================================================
# 协议常量（PC 远航版）
# =============================================================================
FRAME_MAGIC = b"\xfd\xfd\xfd\xfd"

# HTTP 鉴权（与客户端类型无关，通用）
AUTH_HOST = "auth.10jqka.com.cn"
AUTH_PORT = 80

# PC 远航版主行情服务器（8901）。多 IP 冗余，抓包实测。
# 登录时按顺序尝试，任一成功即可。
# 注意：实测部分 IP 只做登录网关、对行情请求(CodeList)无响应（timeout），
# 行情查询需要连到真正处理 CodeList 的服务器（标 ★ 的是 2026-07-17 实测能返回
# hd1.0/hd3.1 数据的 IP）。把这些排在前面提高 list_quotes 命中率。
MARKET_PORT = 8901
MARKET_HOSTS = [
    "122.9.202.190",   # ★ 2026-07-17 实测：登录+行情查询均可用
    "122.9.125.190",   # ★ 2026-07-17 实测：登录+行情查询均可用
    "116.63.108.136",  # 登录可用，行情查询可能 timeout
    "8.134.98.163",
    "121.37.31.87",
    "8.138.46.177",
    "8.145.212.55",
]

# --- 客户端身份参数（PC 远航版，从 login_lv2.pcapng 的 passport 实测）---
# 首次测试用 Mac 参数被 8901 拒（VerifyCode=-1, PromptText=-6:），服务器返回
# thshq-hwyeast-globalthsindex-gateway，判定 passport 身份（Mac）与 PC 网关不符。
# 改用抓包里 PC Level2 passport 的真实值：
#   pro=E02, securities=同花顺统一版, M_qs=6800, ver=9.60.20.0031
PRODUCT = "E02"                       # mainverify 的 product 参数 → passport 的 pro 字段
SECURITIES = "同花顺统一版"            # mainverify 的 securities 参数 → passport 的 securities 字段
VERSION_HTTP = "9.60.20.0031"         # mainverify 的 version 参数 → passport 的 ver 字段
TA_APPID = "2022021114090152"
UA_GBK = "同花顺/7.0.10 CFNetwork/1333.0.4 Darwin/21.5.0"

# PC 远航版 login 帧的版本号（抓包实测）
C_VERSION_PC = "E029.60.20.0031"

# mainverify 的 qsid。PC 版 passport 的 M_qs=6800，推断 qsid=6800（Mac 是 7004）。
QSID = "6800"

# head128 的账号类型标签（5 字节前缀）。
# Mac 版 (thspy): 44 04 2d 80 00；PC 远航版实测: be 06 06 80 00。
# 用 Mac 值时服务器返回 PromptText=-300（head128 校验失败）；
# 改 PC 值后通过 head128 校验。
ACCOUNT_TYPE = bytes([0xbe, 0x06, 0x06, 0x80, 0x00])


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
    """
    import base64

    ptr, _ = _get_adapters_info()
    macs: list[bytes] = []
    while ptr and len(macs) < 4:
        info = ptr.contents
        if info.AddressLength == 6:
            macs.append(bytes(info.Address[:6]))
        ptr = info.Next

    if len(macs) < 4:
        raise RuntimeError(
            f"网卡数不足 4 个（GetAdaptersInfo 只返回 {len(macs)} 个 MAC），"
            "无法生成 Mac64"
        )

    raw = bytes([MAC64_HEADER]) + b"".join(macs)
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
# TCP 帧编解码（原样复用自 thspy，协议层通用）
# =============================================================================

def encode_frame(body: bytes) -> bytes:
    """编码帧：FD FD FD FD + 8 位 ASCII hex 长度 + body。"""
    len_str = f"{len(body):08x}".encode("ascii")
    return FRAME_MAGIC + len_str + body


def read_exact(sock: socket.socket, n: int) -> bytes:
    """精确读取 n 字节。"""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("连接已关闭")
        buf += chunk
    return bytes(buf)


def read_frame(sock: socket.socket) -> bytes:
    """读取一帧：扫描 magic → 读 8 位 ASCII hex 长度 → 读 body。"""
    magic = bytearray()
    while True:
        b = read_exact(sock, 1)
        if not magic and b == b"\x00":
            continue
        magic += b
        if len(magic) > 4:
            magic.pop(0)
        if bytes(magic) == FRAME_MAGIC:
            break
    len_str = read_exact(sock, 8)
    body_len = int(len_str, 16)
    return read_exact(sock, body_len)


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


# =============================================================================
# head128 / passport64（原样复用自 thspy，算法通用）
# =============================================================================

def _sig_to_nibbles(sig: str) -> bytes:
    """signature 字符串 → 字节流（每两个字符按 nibble 组合后减 0x51）。"""
    out = bytearray()
    for i in range(len(sig) // 2):
        b_even = ord(sig[i * 2])
        b_odd = ord(sig[i * 2 + 1])
        out.append((b_even + (b_odd << 4) - 0x51) & 0xff)
    return bytes(out)


def build_head128_pure(signature: str) -> tuple[bytes, bytes]:
    """从 signature 构造 128 字节二进制头 + 5 字节前缀。

    head128 = ACCOUNT_TYPE(5B) + _sig_to_nibbles(signature)[:123]
    prefix_5b = _sig_to_nibbles(signature)[123:128]
    """
    decoded = _sig_to_nibbles(signature)
    return (ACCOUNT_TYPE + decoded[:123]), decoded[123:128]


# 服务端 passport_bytes 里这些字段是「客户端路由/配置」信息（行情服务器地址等），
# 不参与行情网关的 passport 校验。hexin.exe 缓存的 Passport64 会把它们去掉，
# 只保留身份/权限字段。实测：带这些字段的 passport 能登录（VerifyCode=0）但
# 行情查询返回空（无权限）；去掉后即恢复行情权限（2026-07-17 实测确认）。
# 过滤后 b64 长度与 hexin 缓存完全一致（2304 字符），字段集也一致。
_PASSPORT_DROP_FIELDS = frozenset({
    "M_hq", "M_hqdns", "M_wg", "M_zx",          # 行情/短线/网关服务器地址
    "UpdateSvr", "download",                      # 升级/下载服务器
    "Foss_url",                                   # 外部资源 URL
    "DownloadSelfStock", "UploadSelfStock",       # 自选股同步地址
    "signlength",                                 # 签名长度（随字段集变化，去掉）
})


def build_passport64(auth_info: dict, mac_b64: str = "") -> str:
    """
    构造 Passport64：head128(128B) + prefix_5b(5B) + 服务端 passport 字段 + base64。

    重要：PC 版不截断 passport 字段（保留 userflag 之后的 bind/sk/sv 等）。
    thspy 截断到 userflag= 的做法在 PC 版会导致 VerifyCode=-1（sk/sv 是会话密钥，
    服务器要校验）。实测保留全部身份字段才能登录成功。

    但服务端返回的 passport_bytes 里含一批客户端路由/配置字段（M_hq/M_hqdns/
    download 等），hexin.exe 缓存的 Passport64 会把它们去掉（见 _PASSPORT_DROP_FIELDS）。
    实测：带这些字段的 passport 能登录但**无行情查询权限**；去掉后行情正常
    （2026-07-17 实测，去掉后 b64 长度与 hexin 缓存逐字符一致，行情查询解出
    600056 等股票现价）。
    """
    signature = auth_info.get("signature", "")
    passport_bytes = auth_info.get("passport_bytes", b"")
    if isinstance(passport_bytes, str):
        passport_bytes = passport_bytes.encode()
    head128, prefix_5b = build_head128_pure(signature)
    # 过滤掉客户端路由/配置字段（hexin 缓存的 passport 不含这些）
    fields = [
        f for f in passport_bytes.split(b"|")
        if f.split(b"=", 1)[0].decode("gbk", errors="replace").strip()
        not in _PASSPORT_DROP_FIELDS
    ]
    fields_body = b"\r\n".join(fields)
    buffer = head128 + prefix_5b + fields_body + b"\r\n "
    return base64.b64encode(buffer).decode()


# =============================================================================
# PC 远航版 login 帧（重写 — 按抓包实测字段集）
# =============================================================================

def build_login_body_pc(passport64: str, mac_b64: str) -> bytes:
    """
    构造 PC 远航版 login 帧 body。

    抓包实测字段集（D:\\code\\ths\\login_lv2.pcapng，8901 端口）：
        Ask=login
        C-Version=E029.60.20.0031
        VerifyType=1
        Mac64=<base64>
        C-SupportPushVer=1.0
        C-SupReqDataVer=hq6.0
        C-SupPushDataVer=hq6.0
        Passport64=<票据>

    注意：PC 版 login 帧的 account/userclass/M_qs/qsid 等字段全部 absent
    （身份信息都封装在 Passport64 里），比 thspy 的 Mac 版 login 帧更简洁。
    """
    parts = [
        ("Ask", "login"),
        ("C-Version", C_VERSION_PC),
        ("VerifyType", "1"),
        ("Mac64", mac_b64),
        ("C-SupportPushVer", "1.0"),
        ("C-SupReqDataVer", "hq6.0"),
        ("C-SupPushDataVer", "hq6.0"),
        ("Passport64", passport64),
    ]
    fields = "\n".join(f"{k}={v}" for k, v in parts)
    # 帧头前缀：\t A \t \x00 zh_CN.GBK <校验字节> \t
    # (PROTOCOL.md §2.2)
    #
    # 校验字节：抓包实测 7 个 login 帧里 6 个 = 0xaa、1 个 = 0xcc，是 body
    # 内容的某种函数，但 xor/sum 等常见算法均不匹配，未逆向出确切算法。
    # thspy 用 0x15 0x06（Mac 版值）能登录 9602，推测服务器不严格校验此字节。
    # 先用最常见的 0xaa 实测 8901；若被拒再深究（可能需 hook hexin.exe）。
    return b"\x09\x41\x09\x00" + b"zh_CN.GBK\xAA\x09" + fields.encode("gbk")


def parse_login_response(body: bytes) -> dict:
    """解析 login 响应。成功标志：VerifyCode=0。"""
    text_start = body.find(b"Reply=")
    if text_start < 0:
        return {"raw": body.hex()}
    text = body[text_start:].decode("gbk", errors="replace")
    result = {}
    for line in text.replace("\r\n", "\n").split("\n"):
        if "=" in line:
            k, v = line.split("=", 1)
            result[k.strip()] = v.strip()
    return result


def parse_passport_fields(passport_bytes: bytes) -> dict:
    """从服务端 passport_bytes（| 分隔）解析字段，用于诊断打印。"""
    if isinstance(passport_bytes, str):
        passport_bytes = passport_bytes.encode()
    fields = {}
    for f in passport_bytes.split(b"|"):
        s = f.decode("gbk", errors="replace")
        if "=" in s:
            k, _, v = s.partition("=")
            fields[k.strip()] = v.strip()
    return fields


# =============================================================================
# 8901 个股列表行情：请求构造 + hd1.0/hd3.1 响应解析（纯 Python）
# （移植自 thspy，纯 Python 移植 hexin.exe 9.60.20 真实机器码，无 unicorn 依赖）
# 参考：D:\code\ths\PROTOCOL_REVERSE_8901.md
# =============================================================================

# 8901 列表行情请求的 DataType 编号（六次抓包逐列对照确认）。
# 组成"精简7列表头"：代码/开盘价/竞价委托笔数/全天成交量/4分钟涨幅/
# 现价/竞价成交量/昨收/涨幅/日期+小数。
LIST_QUOTE_DATATYPE_DEFAULT = [7, 49, 13, 48, 10, 17, 6, 66, 1111]


def build_list_quote_query(
    codes: list[str],
    market: int = 17,
    datatype: list[int] | None = None,
    pageid: int = 1335,
    seq: int = 0x0025,
) -> bytes:
    """构造 8901 端口个股列表行情请求帧（fdfdfdfd magic + 8字节hex长度 + body）。

    请求格式（2026-07-17 实时抓包 hexin 9.60.20 确认，单子帧）：
      body = cmd(0x09) + 22字节二进制头 + GBK 文本
      文本：``CodeList=<市场>(<代码>,);\\r\\nDataType=<dt>,\\r\\n``
            ``DateTime=0(0-0)\\r\\nLackTime=0,0,0,0,0,0,0,0\\r\\npageid=<pid>\\r``
      （行分隔 ``\\r\\n``，末尾仅 ``\\r`` 无 ``\\n``）

    二进制头布局（23B，抓包真值对照；hdr[19:21]=文本长度+1 LE16）：
      [0]    cmd = 0x09
      [1:5]  00 16 00 00             固定标记
      [5:7]  序列标签 LE16           随请求递增（抓包见 0x0025/0x0038/0x018c...）
      [7:11] 12 00 09 00             子帧类型（CodeList+DataType 单子帧）
      [11:13] 00 01                  路由标签
      [13:18] 00 ×5
      [18]    变化（0x00/0x40）       用 0x00
      [19:21] 文本长度+1 LE16        ★关键：等于 GBK 文本字节数 + 1
      [21:23] 00 00

    Args:
        codes: 股票代码列表（纯数字，如 ["600056","600057"]）
        market: 市场码（17=沪 33=深）
        datatype: DataType 编号列表（默认=精简7列）
        pageid: 页面 id（抓包常见 1334/1335/5716）
        seq: 序列标签（hdr[5:7]）；同值重复请求可保持不变

    Returns:
        完整请求帧字节（含 fdfdfdfd magic + hex 长度），可直接 sendall。
    """
    if datatype is None:
        datatype = LIST_QUOTE_DATATYPE_DEFAULT
    # 空 codes 时生成 "市场()"（不是 "市场(,)"），用于请求全市场代码表
    codes_str = ",".join(codes) + ("," if codes else "")
    market_str = f"{market}({codes_str})"
    dt_str = ",".join(str(d) for d in datatype) + ","
    # 文本：行分隔 \r\n，末尾 \r（抓包真值，frame11/17/40 均如此）
    text = (
        f"CodeList={market_str};\r\nDataType={dt_str}\r\n"
        f"DateTime=0(0-0)\r\nLackTime=0,0,0,0,0,0,0,0\r\npageid={pageid}\r"
    ).encode("gbk")

    hdr = bytearray(23)
    hdr[0] = 0x09
    hdr[1:5] = b"\x00\x16\x00\x00"
    struct.pack_into("<H", hdr, 5, seq & 0xFFFF)
    hdr[7:11] = b"\x12\x00\x09\x00"
    hdr[11:13] = b"\x00\x01"
    # [13:18] 已为 0；[18] = 0x00
    struct.pack_into("<H", hdr, 19, len(text) + 1)  # 抓包：文本长度+1
    body = bytes(hdr) + text
    return encode_frame(body)


# 全市场快照请求的默认市场码集（stock_list.pcap frame 1046 真值）
# 16/17/18/19/20/22 = 沪深 A 股主板/创业板/科创板/B 股
# 144/145/146/147/150/151 = 深圳系列市场（含北交所）
MARKET_SNAPSHOT_MARKETS = [16, 17, 18, 19, 20, 22, 144, 145, 146, 147, 150, 151]
# 快照请求默认字段：[5]=代码 [55]=名称（抓包 frame 1046 真值）
# 注：快照请求的 DataType 语法是 [N] 方括号包裹（区别于 list_quote 的普通逗号分隔）
MARKET_SNAPSHOT_DATATYPE = [5, 55]


def build_market_snapshot_query(
    markets: list[int] | tuple[int, ...] | None = None,
    datatype: list[int] | None = None,
    pageid: int = 5716,
    seq: int = 0x0001,
) -> bytes:
    """构造全市场行情快照请求（空括号语法，一个请求拿整个市场）。

    这是 hexin 打开 A 股列表时发的请求（stock_list.pcap frame 1046 真值）。
    与 :func:`build_list_quote_query` 的关键区别：

    - **空括号** ``CodeList=16();17();...``——不塞具体代码，表示"给我这些市场的
      全部股票"。服务器据此一次性返回整个市场的快照（实测 ~0.13s 拿沪深全量）。
    - **DataType 方括号语法** ``DataType=[5],[55]``——每个字段编号用方括号包裹，
      逗号分隔（区别于 list_quote 的普通 ``7,49,13``）。
    - 文本字段顺序、DateTime 格式略有不同（``DateTime=0`` 不带括号，无 LackTime 行）。

    二进制头布局与 build_list_quote_query 相同（cmd=0x09 + 22B 头），仅文本不同。

    Args:
        markets: 市场码列表，None 用 :data:`MARKET_SNAPSHOT_MARKETS`
            （16-22/144-151，覆盖沪深 A 股全市场）。
        datatype: DataType 字段编号列表，None 用 :data:`MARKET_SNAPSHOT_DATATYPE`
            （[5]=代码, [55]=名称）。
        pageid: 页面 id（frame 1046 真值=5716）。
        seq: 序列标签（hdr[5:7]），frame 1046 真值=0x0001。

    Returns:
        完整请求帧字节（含 fdfdfdfd magic + hex 长度），可直接 sendall。
    """
    if markets is None:
        markets = MARKET_SNAPSHOT_MARKETS
    if datatype is None:
        datatype = MARKET_SNAPSHOT_DATATYPE
    # 空括号全市场语法：16();17();...
    codelist = "".join(f"{m}();" for m in markets)
    # DataType 方括号语法：[5],[55]
    dt_str = ",".join(f"[{d}]" for d in datatype)
    # 文本（frame 1046 真值：DataType 在前，CodeList 在后，行分隔 \r\n，末尾 \r）
    text = (
        f"DataType={dt_str}\r\n"
        f"CodeList={codelist}\r\n"
        f"DateTime=0\r\n"
        f"pageid={pageid}\r"
    ).encode("gbk")

    hdr = bytearray(23)
    hdr[0] = 0x09
    hdr[1:5] = b"\x00\x16\x00\x00"
    struct.pack_into("<H", hdr, 5, seq & 0xFFFF)
    hdr[7:11] = b"\x12\x00\x09\x00"
    hdr[11:13] = b"\x00\x01"
    struct.pack_into("<H", hdr, 19, len(text) + 1)
    body = bytes(hdr) + text
    return encode_frame(body)


# 股票列表请求的默认市场组合（抓包帧3898确认：hexin 用 17/22/151 拉沪+深A+北交所）
# ⚠ 深市 A 股主板的市场码是 22（不是 33）—— 抓包确认。
#   33 是深市的另一个分类（创业板/基金等），hexin 用单独一条并发连接拉 33。
#   默认 (17, 22, 151) 覆盖沪 A + 深 A + 北交所，与 hexin 主连接一致。
STOCK_LIST_MARKETS = [(17, "沪"), (22, "深"), (151, "北交所")]
# DataType=199112 = 返回代码表（抓包帧3898确认：DataType=199112, 末尾只有一个逗号，不带 55）
STOCK_LIST_DATATYPE = [199112]


def build_stock_list_query(
    markets: list[int] | tuple[int, ...] = (17, 22, 151),
    sort_begin: int = 0,
    sort_count: int = 29,
    datatype: list[int] | None = None,
    pageid: int = 1334,
    seq: int = 0x0025,
) -> bytes:
    """构造股票列表查询请求（空 CodeList + DataType=199112，8901端口）。

    同花顺在用户打开「沪深A股」列表界面时发此请求（抓包帧3898确认）。
    注意：这不是启动时拉全量代码表的请求 —— 启动时走 init/qustocklink。
    本请求是「排序代码表查询」，服务器按 SortBy 排序后返回前 SortCount 条。

    请求文本（抓包帧3898真值）：
      CodeList=17();22();151();   ← 空括号 = 该市场全部（17=沪 22=深A 151=北交所）
      DataType=199112,            ← 199112 返回代码表（不带 ,55）
      SortType=Sort
      SortBy=199112
      SortDir=D                   ← 降序
      SortAppend=YC
      SortBegin=0                 ← 抓包确认：恒为 0（不是真翻页游标）
      SortCount=29                ← 本次要的条数（hexin 逐步放大直到拿到全量）
      FuncPeriod=0
      DateTime=0(0-0)
      LackTime=0,0,0,0,0,0,0,0
      pageid=1334

    ⚠ 翻页模型（抓包帧3898→4967确认）：hexin 不是用 SortBegin 递增翻页，
    而是固定 SortBegin=0，把 SortCount 从 29 逐步放大（29→261→2538→2645），
    直到服务器返回的 SortDataCount == SortTotal（一次性拿全量）。

    Args:
        markets: 市场码列表。17=沪 22=深A 151=北交所（默认）。
            抓包确认深 A 市场码是 22（不是 33；33 是深市另一类，hexin 单独拉）。
        sort_begin: 抓包恒为 0（保留参数仅为兼容）。
        sort_count: 本次要的条数。hexin 从 29 开始逐步放大。
        datatype: DataType 列表，默认 [199112]（抓包真值，不带 55）。
        pageid: 固定 1334。
        seq: 序列标签。

    Returns:
        完整请求帧字节（含 fdfdfdfd magic），可直接 sendall。
    """
    if datatype is None:
        datatype = STOCK_LIST_DATATYPE
    # 多市场空 CodeList：17();22();151();
    codelist = "".join(f"{m}();" for m in markets)
    dt_str = ",".join(str(d) for d in datatype) + ","
    text = (
        f"CodeList={codelist}\r\nDataType={dt_str}\r\n"
        f"SortType=Sort\r\nSortBy=199112\r\nSortDir=D\r\nSortAppend=YC\r\n"
        f"SortBegin={sort_begin}\r\nSortCount={sort_count}\r\n"
        f"FuncPeriod=0\r\nDateTime=0(0-0)\r\n"
        f"LackTime=0,0,0,0,0,0,0,0\r\npageid={pageid}\r"
    ).encode("gbk")

    hdr = bytearray(23)
    hdr[0] = 0x09
    hdr[1:5] = b"\x00\x16\x00\x00"
    struct.pack_into("<H", hdr, 5, seq & 0xFFFF)
    # 子帧类型 0x000f（排序代码表查询，区别于行情查询的 0x0009；抓包帧3898确认）
    # 路由标签 0x0156（抓包真值；行情查询用 0x0001）
    hdr[7:11] = b"\x12\x00\x0f\x00"
    hdr[11:13] = b"\x56\x01"
    struct.pack_into("<H", hdr, 19, len(text) + 1)
    body = bytes(hdr) + text
    return encode_frame(body)


def parse_stock_list_response(body: bytes) -> dict:
    """解析股票列表响应（文本头 + hd3.1 16-bit 变体帧），返回分页元数据 + 代码列表。

    响应结构（抓包帧3900确认）：
        SortTotal=2645          ← 全市场代码总数
        SortTop=1900544
        SortBegin=0             ← 恒为 0
        SortCount=29            ← 本次请求的条数（= 请求里的 SortCount）
        SortCalcProgress=1
        SortDataFirst=0
        SortDataCount=29        ← 数据区实际条数（min(SortCount, SortTotal)）
        OrderList=
        hd3.1\\0 + 16-bit 变体头 + 字段表 + BitRLE流

    ⚠ 注意：此响应**不含股票名称**。DataType=199112 只返回代码表，
    名称要靠另外的请求（DataType=10 之类行情字段）拿。
    因此 stocks 里每条的 name 字段为空字符串。

    Args:
        body: 完整 TCP 帧体（含文本头 + hd3.1）。注意必须传完整帧，截断会导致
              BitRLE 解码数据不足、后半记录代码为空。

    Returns:
        dict: ``{sort_total, sort_begin, sort_count, sort_data_count, stocks}``，
        stocks 为 ``[{code, name}, ...]``。name 恒为 ""（响应不含名称）。
        hd3.1 解码失败时 stocks 为空列表（但 sort_total 等元数据仍可用）。
    """
    text = body.decode("gbk", errors="replace")
    meta = {"sort_total": 0, "sort_begin": 0, "sort_count": 0,
            "sort_data_count": 0, "stocks": []}
    # 提取分页元数据（字段名驼峰：SortTotal/SortBegin/SortCount/SortDataCount）
    for key, field in (("sort_total", "SortTotal"), ("sort_begin", "SortBegin"),
                       ("sort_count", "SortCount"),
                       ("sort_data_count", "SortDataCount")):
        m = re.search(rf"(?:^|[^0-9A-Za-z_-]){field}=(\d+)", text)
        if m:
            meta[key] = int(m.group(1))
    # 解码 hd3.1 16-bit 变体（DataType=199112 响应专用格式）
    meta["stocks"] = _parse_stock_list_hd31_variant(body)
    return meta


def _parse_stock_list_hd31_variant(body: bytes) -> list[dict]:
    """解析 stock_list 响应的 hd3.1 16-bit 变体（DataType=199112 响应）。

    抓包帧3900确认的头格式（区别于标准 hd3.1 的 dc(LE32)+unk(LE16)）：
        hd3.1\\0
        dc(LE16)            ← 记录数（= SortDataCount，16-bit 不是 32-bit！）
        flag(LE16=0x0100)   ← 变体标记（同 hd1.0 分页变体）
        +2B(LE16=0x001c)    ← 含义未知
        hs(LE16)            ← 单条记录字节长度（实测=11）
        fc(LE16)            ← 字段数（实测=2）
        字段表: fc × 4B（dt, fmt, flags, width）
        preamble(8B!)       ← 标准 hd3.1 是 4B，这里是 8B
        BitRLE头(BE32=dc*hs)+位流

    字段表（帧3900实测）：dt5(width=7) + dt200(width=4)，hs=7+4=11
    记录布局（每条 11B）：
        [0]    市场码（0x11=沪 0x16=深22 0x21=深33 0x97=北交所）
        [1:7]  6B ASCII 代码（如 "920305"/"600227"）
        [7:11] 4B 其他数据（dt200，含义未知）

    Returns:
        ``[{code, name, market}, ...]``。name 恒为 ""（响应不含名称）。
        market 是市场码整数（用于区分沪深北）。
    """
    pos = body.find(b"hd3.1\x00")
    if pos < 0:
        return []
    base = pos + 6
    if len(body) < base + 10:
        return []
    dc = struct.unpack("<H", body[base:base+2])[0]
    flag = struct.unpack("<H", body[base+2:base+4])[0]
    if flag != 0x0100:
        return []  # 非 stock_list 变体
    hs = struct.unpack("<H", body[base+6:base+8])[0]
    fc = struct.unpack("<H", body[base+8:base+10])[0]
    if dc == 0 or hs == 0 or fc == 0:
        return []
    fields = _parse_hd_field_table(body, base + 10, fc)
    # 16-bit 变体 preamble 是 8B（不是标准 hd3.1 的 4B），然后 BitRLE 头 BE32=dc*hs
    bitrle_off = base + 10 + fc * 4 + 8
    if len(body) < bitrle_off + 4:
        return []
    expect = dc * hs
    bitrle_head = struct.unpack(">I", body[bitrle_off:bitrle_off+4])[0]
    if bitrle_head != expect:
        logger.debug("stock_list hd3.1 变体 BitRLE 头不匹配: got=0x%x expect=0x%x(dc*hs=%d)",
                     bitrle_head, expect, expect)
        return []
    bitplane = _decode_bitrle_0x13746d0(body[bitrle_off:], expect)
    if len(bitplane) < expect:
        return []
    recs = _transpose_bitplane_0x1763410(bitplane, hs, dc)
    # 按 dt5 字段定位代码偏移（dt5 宽度=7，代码在 chunk[1:7]，跳过 1B 市场码）
    # 找 dt5 字段的偏移
    dt5_off = 0
    for dt, fmt, width in fields:
        if dt == 5:
            break
        dt5_off += width
    else:
        dt5_off = 0  # 无 dt5 字段（异常），从头开始
    stocks = []
    for i in range(dc):
        row = recs[i*hs: (i+1)*hs]
        if len(row) < hs:
            break
        # dt5: [1B market][6B ASCII code]
        market = row[dt5_off]
        code_b = row[dt5_off+1: dt5_off+7]
        if not all(48 <= b <= 57 for b in code_b):
            continue  # 非 ASCII 数字，跳过
        stocks.append({
            "code": code_b.decode("ascii"),
            "name": "",  # 响应不含名称
            "market": market,
        })
    return stocks


# init 请求的默认配置（抓包帧1090确认）
# C-Modules=MEQT 是同花顺方案的标准模块集；MarketCode=16;144; 是沪市+创业板
INIT_C_MODULES = "MEQT"
INIT_MARKET_CODE = "16;144;"

# init 控制字节（StockLinkVer 字段用，抓包确认）
_B_BLOCK = b"\x02"   # ^b 块开始
_B_SECT = b"\x01"    # ^B 节开始
_B_REC = b"\x0e"     # ^n 记录/行结束
_B_KEY = b"\x05"     # ^e 键值分隔
_B_RT = b"\x12"      # ^r （成对出现）

# 28 个 Stock 配置项（StockLinkVer 里客户端声明的全部板块）
INIT_STOCK_LINKS = [
    "Stock_176_H_QC", "Stock_176_H_QP", "Stock_16_A_SO", "Stock_16_F_SO",
    "Stock_16_B_SO", "Stock_16_Z_SO", "Stock_32_A_SO", "Stock_32_B_SO",
    "Stock_32_F_SO", "Stock_32_Z_SO", "Stock_68_C_DO", "Stock_69_C_ZO",
    "Stock_64_C_SO", "Stock_64_C_DO", "Stock_64_C_ZO", "Stock_144_P_SC",
    "Stock_144_Y_SC", "Stock_16_X_IO", "Stock_176_H_BULL", "Stock_176_H_BEAR",
    "Stock_88_H_QC", "Stock_88_H_QP", "Stock_88_H_BULL", "Stock_88_H_BEAR",
    "Stock_UGFF_F_O", "Stock_32_X_IO", "Stock_64_F_OS", "Stock_112_H_HF",
    "Stock_64_F_DL",
]


def build_init_query(
    config_ver: str = "0",
    market_code: str = INIT_MARKET_CODE,
    c_modules: str = INIT_C_MODULES,
    seq: int = 0x0000,
) -> bytes:
    """构造 init 请求（启动时拿全量代码表，8901端口）。

    同花顺登录后第一个请求就是 init，服务器响应里夹带 dc=7524 全量代码表
    （hd3.1 unk=0x18 标准 BitRLE，含 code + dt55 名称）。这是获取完整 A 股
    列表的正道（DataType=199112 只返回变体分页小帧）。

    请求结构（抓包帧1090确认）：
      - 二进制头：子帧类型 0x0001，路由 0x0000（区别于 list_quote 的 0x0009）
      - 文本（\\r\\n 分隔，无 method= 字段）：
        C-Language=2052
        C-Version=E029.60.20.0031
        C-Config=同花顺方案
        C-Modules=MEQT
        C-UACS=20120716#0#
        MarketCode=16;144;
        MarketDate=16(...);144(...);
        StockLinkVer=^bConfigInfo^B^r^nConfigVer^e{ver}^r^n^bStock_16_A_SO^B...

    Args:
        config_ver: StockLinkVer 的 ConfigVer。"0" 表示本地无缓存，骗服务器发全量。
        market_code: 市场码（默认 "16;144;" 沪市+创业板）。
        c_modules: 模块集（默认 MEQT）。
        seq: 序列标签。

    Returns:
        完整请求帧字节（含 fdfdfdfd magic），可直接 sendall。
    """
    # 构造 StockLinkVer（含控制字节）
    slv_parts = [_B_BLOCK + b"ConfigInfo" + _B_SECT + _B_RT + _B_REC
                 + b"ConfigVer" + _B_KEY + config_ver.encode("gbk") + _B_RT + _B_REC]
    for stock in INIT_STOCK_LINKS:
        slv_parts.append(_B_BLOCK + stock.encode("gbk") + _B_SECT + _B_RT + _B_REC
                         + b"ConfigVer" + _B_KEY + config_ver.encode("gbk") + _B_RT + _B_REC)
    stocklinkver = b"".join(slv_parts)

    text = (
        f"C-Language=2052\r\n"
        f"C-Version=E029.60.20.0031\r\n"
        f"C-Config=同花顺方案\r\n"
        f"C-Modules={c_modules}\r\n"
        f"C-UACS=20120716#0#\r\n"
        f"MarketCode={market_code}\r\n"
        f"MarketDate=16(0);144(0);\r\n"
    ).encode("gbk") + b"StockLinkVer=" + stocklinkver

    hdr = bytearray(23)
    hdr[0] = 0x09
    hdr[1:5] = b"\x00\x16\x00\x00"
    struct.pack_into("<H", hdr, 5, seq & 0xFFFF)
    hdr[7:11] = b"\x12\x00\x01\x00"   # 子帧类型 0x0001（init）
    hdr[11:13] = b"\x00\x00"           # 路由 0x0000
    hdr[13:15] = b"\x00\x20"           # 抓包真值（init 特有）
    struct.pack_into("<H", hdr, 19, len(text) + 1)
    body = bytes(hdr) + text
    return encode_frame(body)


def parse_init_response(body: bytes) -> dict:
    """解析 init 响应，提取全量代码表 + 配置信息。

    init 响应夹带多个 hd3.1 帧，其中 unk=0x18 的大帧（dc≈7526）是全量代码表
    （冷启动抓包 stream 44 帧2390 确认，dc=7526, hs=71, fc=2）。
    字段：dt5(code, w7) + dt55(w64)。注意 dt55 在此帧里**不含名称**（全 0），
    名称走单独的 upstockname 请求，故返回的 stocks 里 name 恒为 ""。

    解码用标准 parse_hd3_response（unk=0x18 = BitRLE 变体，preamble 4B，
    BE32 头==dc*hs）。不要用 parse_stock_list_response（那个专解
    DataType=199112 的 16-bit dc 变体）。

    Args:
        body: 完整 TCP 帧体（read_frame 读出的单帧，或拼接的多帧）。

    Returns:
        dict: ``{stocks: [{code, name, market}, ...], server_info: {...},
        hd31_frames: [...]}``。stocks 为全量代码列表（dc 最大的 unk=0x18 帧）；
        server_info 含 S-OS/S-Version 等服务器信息；hd31_frames 列出所有
        hd3.1 帧的元数据（dc/unk/hs/fc），便于调试其他子帧。
    """
    result = {"stocks": [], "server_info": {}, "hd31_frames": []}
    text = body.decode("gbk", errors="replace")
    # 提取服务器信息
    for key in ("S-OS", "S-Version", "S-Name", "S-Time", "S-ClientIP", "S-WebPort"):
        m = re.search(rf"{key}=([^\r\n]+)", text)
        if m:
            result["server_info"][key] = m.group(1).strip()

    # 遍历所有 hd3.1\x00 标记，记录元数据，解码 unk=0x18 的标准 BitRLE 帧
    best_recs: list[dict] = []
    for m in re.finditer(rb"hd3\.1\x00", body):
        pos = m.start()
        base = pos + 6
        if base + 10 > len(body):
            continue
        dc = struct.unpack("<I", body[base:base+4])[0]
        unk = struct.unpack("<H", body[base+4:base+6])[0]
        hs = struct.unpack("<H", body[base+6:base+8])[0]
        fc = struct.unpack("<H", body[base+8:base+10])[0]
        # 跳过明显异常的（解析错位产生的超大 dc）
        if dc == 0 or dc > 100000 or hs == 0:
            continue
        result["hd31_frames"].append({
            "pos": pos, "dc": dc, "unk": unk, "hs": hs, "fc": fc,
        })
        # 只解码 unk=0x18 的标准 BitRLE 全量帧
        if unk != 0x18:
            continue
        # 从这个 hd3.1 标记到 body 末尾交给 parse_hd3_response
        # （它会自己定位 BitRLE 流，且要求 BE32 头==dc*hs）
        recs = parse_hd3_response(body[pos:])
        if len(recs) > len(best_recs):
            best_recs = [
                {"code": r.get("code", ""), "name": "", "market": _dt5_market(r)}
                for r in recs if r.get("code")
            ]

    result["stocks"] = best_recs
    return result


def _dt5_market(rec: dict) -> int:
    """从 parse_hd3_response 的记录里提取 dt5 首字节（市场码）。

    parse_hd3_response 经 _parse_hd_records 处理后，dt5 被解析为 code 字段
    （取 chunk[1:7]），但市场码（chunk[0]）丢失了。这里无法恢复，返回 0。
    如需市场码，应直接用底层 _transpose_bitplane + 手动解析。
    """
    return 0  # parse_hd3_response 不暴露 dt5[0]，留空


# -----------------------------------------------------------------------------
# THS 定点浮点解码（字段值 fmt=0x70 时用）：4 字节 LE32 → 浮点
# -----------------------------------------------------------------------------

_FLOAT_TABLE = [1.0, 10.0, 100.0, 1000.0, 10000.0, 100000.0, 1000000.0, 10000000.0]


def decode_ths_float(le32: int) -> float:
    """解码同花顺定点浮点（fmt=0x70 字段的 4 字节 LE32 值）。

    编码：bit31=是否除法，bit30..28=指数（查 _FLOAT_TABLE），bit27=符号，
    bit26..0=尾数。结果 = sign × (mantissa ×/÷ factor)。
    无效值哨兵：0xFFFFFFFF（未完成/占位）显式归零。
    """
    le32 &= 0xFFFFFFFF
    if le32 == 0xFFFFFFFF:
        return 0.0
    divide = bool(le32 & 0x80000000)
    exp = (le32 >> 28) & 7
    sign = -1.0 if (le32 & 0x08000000) else 1.0
    mantissa = le32 & 0x07FFFFFF
    factor = _FLOAT_TABLE[exp]
    return sign * (mantissa / factor if divide else mantissa * factor)


# -----------------------------------------------------------------------------
# hd1.0 / hd3.1 响应解析
# -----------------------------------------------------------------------------

def _parse_hd_field_table(buf: bytes, off: int, fc: int) -> list[tuple[int, int, int]]:
    """解析 hd1.0/hd3.1 字段表（4B/条: dt, fmt, flags, width）。返回 [(dt, fmt, width)]。"""
    fields = []
    for i in range(fc):
        e = buf[off + i*4: off + (i+1)*4]
        if len(e) < 4:
            break
        fields.append((e[0], e[1], e[3]))  # dt, fmt, width
    return fields


def _parse_hd_records(recs: bytes, fields: list[tuple[int, int, int]],
                      hs: int, dc: int) -> list[dict]:
    """按字段表切分行主序记录区。代码字段(dt5)=1B长度前缀+ASCII；数值字段(fmt0x70)
    用 decode_ths_float；fmt=0x64 是宽/双值（两个 LE32）。"""
    records = []
    for r in range(dc):
        row = recs[r*hs: (r+1)*hs]
        if len(row) < hs:
            break
        rec: dict = {}
        off = 0
        for dt, fmt, width in fields:
            chunk = row[off: off + width]
            off += width
            if len(chunk) < width:
                break
            if dt == 5:  # 代码字段：1B 长度前缀 + ASCII + \0 填充
                code = chunk[1:1+6].split(b"\x00")[0].decode("ascii", errors="replace")
                rec["code"] = code
            elif fmt in (0x70, 0x64):  # THS 定点浮点数值
                if width == 4:
                    rec[f"dt{dt}"] = decode_ths_float(struct.unpack("<I", chunk)[0])
                elif width == 8:
                    v1 = struct.unpack("<I", chunk[:4])[0]
                    v2 = struct.unpack("<I", chunk[4:8])[0]
                    rec[f"dt{dt}_a"] = decode_ths_float(v1)
                    rec[f"dt{dt}_b"] = decode_ths_float(v2)
                else:
                    rec[f"dt{dt}_raw"] = chunk
            else:  # 其他（字符串/原始）
                rec[f"dt{dt}_raw"] = chunk
        records.append(rec)
    return records


def parse_hd1_response(body: bytes) -> list[dict]:
    """解析 hd1.0 明文响应（少量股票 ≤5 走此格式）。

    结构（单股 600015 验证，字段全对）：
        hd1.0\\0
        [0:4]   dc   = 记录数 (LE32)
        [4:6]   reserved (LE16)
        [6:8]   hs   = 单条记录字节长度 (LE16) = 字段表 width 累加
        [8:10]  fc   = 字段数 (LE16)
        字段表: fc 条，4字节/条: dt, fmt, flags, width
        记录区: dc 条，每条 hs 字节，行主序
    """
    pos = body.find(b"hd1.0")
    if pos < 0:
        return []
    base = pos + 6  # 跳过 hd1.0\0
    if len(body) < base + 10:
        return []
    dc = struct.unpack("<I", body[base:base+4])[0]
    hs = struct.unpack("<H", body[base+6:base+8])[0]
    fc = struct.unpack("<H", body[base+8:base+10])[0]
    if dc == 0 or hs == 0:
        return []
    fields = _parse_hd_field_table(body, base + 10, fc)
    rec_off = base + 10 + fc * 4
    return _parse_hd_records(body[rec_off:rec_off + dc*hs], fields, hs, dc)


def parse_hd3_response(body: bytes) -> list[dict]:
    """解析 hd3.1 批量响应（≥6 股走此格式）。

    解码链（纯 Python 移植 hexin.exe 真实机器码，与 Unicorn 逐字节对照验证）：
        hd3.1\\0 + 头(10B) + 字段表(fc×4) + preamble(4B) + BitRLE流
        → _decode_bitrle_0x13746d0(BitRLE解码) → dc×hs 字节位平面
        → _transpose_bitplane_0x1763410(位平面转置, 参数 hs/dc) → 行主序记录

    只处理标准 BitRLE 变体（unk≈0x38，preamble 后 BE32==dc*hs）；
    其他变体（unk=0x36/0x42/0x4a 等非 BitRLE 编码）自动跳过返回空。

    Args:
        body: 完整 TCP 帧体（含 hd3.1\\0 标记）

    Returns:
        记录列表，每条 {code, dt<N>...}（同 parse_hd1_response 字段命名）
    """
    pos = body.find(b"hd3.1\x00")  # 必须后跟 \0，避免误匹配 hd3.1m
    if pos < 0:
        return []
    base = pos + 6
    if len(body) < base + 10:
        return []
    dc = struct.unpack("<I", body[base:base+4])[0]
    unk = struct.unpack("<H", body[base+4:base+6])[0]
    hs = struct.unpack("<H", body[base+6:base+8])[0]
    fc = struct.unpack("<H", body[base+8:base+10])[0]
    if dc == 0 or hs == 0:
        return []
    fields = _parse_hd_field_table(body, base + 10, fc)
    expect = dc * hs
    # 数据区：preamble(4B) + BitRLE头(BE32=dc*hs) + 位流
    bitrle_off = base + 10 + fc * 4 + 4
    if len(body) < bitrle_off + 4:
        return []
    bitrle_head = struct.unpack(">I", body[bitrle_off:bitrle_off+4])[0]
    if bitrle_head != expect:
        logger.debug("hd3.1 非 BitRLE 变体(unk=0x%x, 头=0x%x), 跳过", unk, bitrle_head)
        return []
    bitrle = body[bitrle_off:]

    bitplane = _decode_bitrle_0x13746d0(bitrle, expect)
    recs = _transpose_bitplane_0x1763410(bitplane, hs, dc)
    return _parse_hd_records(recs, fields, hs, dc)


def _decode_bitrle_0x13746d0(src: bytes, expect: int) -> bytes:
    """纯 Python 移植 hexin.exe 0x13746d0（hd3.1 BitRLE 解码器）。

    src = BE32 长度头 + 位流；返回 out_len 字节位平面。
    与 Unicorn 模拟真实机器码逐字节对照验证（6 帧 × 1363 字节 + 7526 条全量表
    534346 字节，全部一致）。无 unicorn 依赖。
    """
    if len(src) < 4:
        return b""
    out_len = struct.unpack(">I", src[:4])[0]
    if not (0 < out_len <= 12_000_000):
        return b""
    out = bytearray(out_len)
    out_end = out_len
    src_end = len(src)
    edi = src[4] if len(src) > 4 else 0   # 位寄存器（当前位所在字节）
    edx = 5                               # 字节读取指针（字面值/重载用）
    esi = 8                                # edi 中剩余位数（8..1）
    optr = 0                               # 输出写指针

    def rb():
        nonlocal edx
        if edx < src_end:
            b = src[edx]; edx += 1; return b
        return 0

    def reload():
        nonlocal edi, esi
        edi = rb(); esi = 8

    def bit():
        # 镜像汇编：mov ecx,edi; add edi,edi; and ecx,0x80; sub esi,1; (重载)
        nonlocal edi, esi
        ecx = edi & 0x80
        edi = (edi + edi) & 0xFF
        esi -= 1
        if esi == 0:
            reload()
        return ecx  # 0 或 0x80

    def emit(b):
        nonlocal optr
        if optr < out_end:
            out[optr] = b & 0xFF
        optr += 1

    while optr < out_end:
        # bit1：0→2 字面值；1→RLE
        if bit() == 0:
            a = rb(); b = rb(); emit(a); emit(b)
            continue
        # bit2：0→1 字面值
        if bit() == 0:
            emit(rb())
        # bit3 → bl（填充字节，0x00 或 0xFF）
        bl = 0xFF if bit() != 0 else 0x00
        emit(bl)
        if optr >= out_end:
            break
        # bit4：0→仅 1 bl，结束本组
        if bit() == 0:
            continue
        emit(bl)
        if optr >= out_end:
            break
        slot_m8 = bit()    # bit5 → [ebp-8]
        slot_m18 = bit()   # bit6 → [ebp-0x18]
        if slot_m8 == 0:
            if slot_m18 != 0:
                emit(bl)
            continue
        # bit5 置位：emit 2 bl
        emit(bl); emit(bl)
        if optr >= out_end:
            break
        if slot_m18 == 0:
            continue
        # bit6 置位：先无条件 emit 1 bl（0x137485b），再读 bit7/bit8
        emit(bl)
        if optr >= out_end:
            break
        slot_pc = bit()    # bit7 → [ebp+0xc]
        slot_m8 = bit()    # bit8 → [ebp-8]
        if slot_pc == 0:
            b9 = bit()
            if slot_m8 == 0:
                if b9 != 0:
                    emit(bl)
            else:
                emit(bl); emit(bl)
                if optr >= out_end:
                    break
                if b9 != 0:
                    emit(bl)
            continue
        # bit7 置位：emit bl ×4
        for _ in range(4):
            emit(bl)
            if optr >= out_end:
                break
        if optr >= out_end:
            break
        b9 = bit()
        if slot_m8 == 0:
            if b9 != 0:
                emit(bl)
            continue
        emit(bl); emit(bl)
        if optr >= out_end:
            break
        if b9 == 0:
            continue
        emit(bl)
        if optr >= out_end:
            break
        # 显式计数循环（0x13748e0 / 0x1374919）
        while True:
            cnt = rb()
            if cnt > 0x7f:
                cnt2 = rb()
                cnt = ((cnt - 0x80) << 8) + cnt2
            if cnt:
                for _ in range(cnt):
                    if optr >= out_end:
                        break
                    emit(bl)
            if cnt != 0x7fff:
                break
            if edx >= src_end:
                break

    return bytes(out[:out_len])


def _transpose_bitplane_0x1763410(src: bytes, hs: int, dc: int) -> bytes:
    """纯 Python 移植 hexin.exe 0x1763410（位平面转置）。

    把 _decode_bitrle_0x13746d0 输出的 dc*hs 字节位平面转成 dc 条行主序记录
    （每条 hs 字节）。算法（反汇编 + Unicorn 逐位对照）：源位流 LSB-first 读取，
    按列主序：
      for 字节列 c(0..hs-1): for 位 p(0..7): for 记录 r(0..dc-1): 读源位
        源读取序号 m = (c*8 + p)*dc + r → 源字节[m//8] 的第 (m%8) 位（LSB）
      输出字节 (r,c) 的第 p 位（LSB）置为该源位。
    与 Unicorn 对照 6 帧 1363 字节 + 7526 条 534346 字节全部一致。
    """
    out = bytearray(dc * hs)
    if dc == 0 or hs == 0:
        return bytes(out)
    outlen = len(out)
    srclen = len(src)
    for c in range(hs):
        for p in range(8):
            for r in range(dc):
                m = (c * 8 + p) * dc + r
                byte = m >> 3
                if byte < srclen and (src[byte] >> (m & 7)) & 1:
                    if r * hs + c < outlen:
                        out[r * hs + c] |= (1 << p)
    return bytes(out)


# =============================================================================
# upstockname —— 8901 端口全量/增量股票名称同步
#
# method=upstockname 请求（\\x09 分隔的纯文本帧）：
#   instid=65536\\nmethod=upstockname\\nmarket=<CHANNEL>\\nStockNameVer=;;\\n...
# 服务器返回含若干 [name_<MARKET>] 段的响应。
#
# 段编码分两类（2026-07-22 抓包样本 stream35/37/38/40/41 全量验证）：
#   1. 纯文本 GBK（行分隔 \\r\\n 或 \\n）：name_96_*（外汇）、name_88_*、
#      name_128_*、name_216_*、name_48_48、name_64_*（期货/北交所，数万条）、
#      name_UNS*、name_UHI*（外盘）—— 占绝大多数市场，直接 decode('gbk')
#   2. 块状变长 LZ 编码：name_16_16（沪深 A 股）、name_168_16（混合）
#      —— 17 字节单元 [ctrl][16B]，ctrl=0x00 时 16B 全 literal，
#      ctrl≠0x00 时含 1 字节 LZ match（如 0xc1→展开 4 字节"A000"）。
#      match 字节的 offset/len 编码尚未完全破解（见 HANDOFF §6/§四）。
#
# 每行格式：CODE=NAME|ALIAS@FLAG  （CODE 前可有 @ 前缀，见 UNS 段）
# =============================================================================

# 已知使用块状变长 LZ 编码的段（沪/深 A 股名称）。其余段为纯文本。
_BLOCK_ENCODED_SEGMENTS = {"16_16", "168_16"}


def build_upstockname_request(
    market: str = "URS",
    stock_name_ver: str = ";;",
    pageid: int = 5716,
    instid: int = 65536,
) -> bytes:
    """构造 upstockname 请求帧（\\x09 分隔的纯文本帧）。

    请求格式与 hexin 客户端字节级一致（2026-07-19/22 抓包确认）::

        \\x09instid=65536\\nmethod=upstockname\\nmarket=<CHANNEL>\\n
        StockNameVer=;;\\nprototype=kvproto\\npageid=5716\\n

    Args:
        market: 市场通道码，如 ``URS``（沪A）、``UNX``（深A）、``UCX``（北交所）、
            ``UNS``（纳斯达克）、``UHI``（港交所）。决定服务器下发哪些 [name_] 段。
        stock_name_ver: 本地名称版本号。``;;`` 表示无缓存，请求全量；
            传服务器上次下发的 ``ConfigVer`` 则只拿增量。
        pageid: 抓包实测 5716（hexin 客户端用），冷启动全量链路用 392。
        instid: 登录后的实例 ID，默认 65536。

    Returns:
        请求帧体 bytes（不含 FD FD FD FD 帧头，由发送层封装）。

    Note:
        实测服务器按账号追踪名称版本状态——即使发 ``StockNameVer=;;``，
        thspypc 账号通常也只能拿到增量（~12 条）。全量下发需 hexin 客户端
        冷启动触发（清空 stockname 缓存后启动）。详见 HANDOFF §6。
    """
    body = (
        f"instid={instid}\n"
        f"method=upstockname\n"
        f"market={market}\n"
        f"StockNameVer={stock_name_ver}\n"
        f"prototype=kvproto\n"
        f"pageid={pageid}\n"
    )
    return b"\x09" + body.encode("gbk")


def _iter_name_segments(body: bytes):
    """从 upstockname 响应体中迭代出 (段名, 数据起止)。

    段名形如 ``name_16_16``（去掉方括号）。数据区从段头后的分隔符之后
    开始，到下一个 ``[name_`` 段头前结束。

    Args:
        body: upstockname 响应帧体（含若干 ``[name_..]`` 段）。

    Yields:
        (seg_name:str, data_start:int, data_end:int) 三元组。
    """
    # 段名形如 ``name_16_16``，但部分段名内含 \0 字节（如 ``[name_168_16\x00]``），
    # 解析时剔除 \0。
    matches = list(re.finditer(rb"\[name_([^\]]+)\]", body))
    for i, m in enumerate(matches):
        seg_name = m.group(1).replace(b"\x00", b"").decode("ascii", errors="replace")
        # 段头后跳过分隔符（\r\n / \n / \0 的任意组合）
        ds = m.end()
        while ds < len(body) and body[ds] in (0x0d, 0x0a, 0x00):
            ds += 1
        de = matches[i + 1].start() if i + 1 < len(matches) else len(body)
        yield seg_name, ds, de


def _name_code_is_valid(code: str) -> bool:
    """校验代码字段是否是合理的股票/品种代码。

    正常代码（如 ``600000``、``AUDUSD``、``HKEXT100``、``NDX``）全部由可打印
    ASCII 字符组成，无控制字符，长度 ≤ 16。块状编码段产生的乱码"行"键会
    含大量控制字符（\\x00-\\x1f）和超长字符串，借此剔除。
    """
    if not code or len(code) > 16:
        return False
    # 含控制字符或非可打印 ASCII（GBK 中文代码极罕见，这里从严）
    for ch in code:
        o = ord(ch)
        if o < 0x20 or o == 0x7f:
            return False
        if 0x80 <= o <= 0x9f:  # GBK 扩展区控制字符
            return False
    return True


def _parse_name_text(seg_data: bytes) -> dict[str, str]:
    """解析纯文本名称段（GBK，行分隔 \\r\\n/\\n）。

    每行 ``CODE=NAME|ALIAS@FLAG``，CODE 前可有 ``@`` 前缀。
    仅保留非空的 NAME（取 ``|`` 和 ``@`` 之前的部分）。
    代码和名称都校验，剔除块状编码段误入时产生的乱码行。
    """
    names: dict[str, str] = {}
    try:
        text = seg_data.decode("gbk", errors="replace")
    except (UnicodeDecodeError, ValueError):
        return names
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("[") or line.startswith("ConfigVer"):
            continue
        if "=" not in line:
            continue
        code, _, rest = line.partition("=")
        code = code.strip().lstrip("@")
        if not _name_code_is_valid(code):
            continue
        name = rest.split("|")[0].split("@")[0].strip()
        # 过滤乱码名称（块状编码段误入时会出现替换字符/控制字符）
        if name and "\ufffd" not in name and not any(ord(c) < 0x20 for c in name):
            names[code] = name
    return names


def _is_block_encoded(seg_data: bytes) -> bool:
    """启发式判断段是否用了块状变长 LZ 编码。

    纯文本段的 GBK 解码有效行率高（>85%）；块状段因 ctrl/match 字节
    插入，GBK 解码会产生大量乱码行（有效行率 <60%）。
    """
    try:
        text = seg_data.decode("gbk", errors="replace")
    except (UnicodeDecodeError, ValueError):
        return True
    valid = bad = 0
    for line in text.splitlines():
        line = line.strip().lstrip("@")
        if "=" not in line or line.startswith(("ConfigVer", "[")):
            continue
        code, _, rest = line.partition("=")
        if code.strip() and rest.strip():
            if "\ufffd" in rest[:8]:
                bad += 1
            else:
                valid += 1
    total = valid + bad
    if total < 3:
        return False
    return valid / total < 0.60


def decode_name_frame(body: bytes) -> dict:
    """解析 upstockname 响应帧，提取各市场段的股票名称。

    遍历所有 ``[name_<MARKET>]`` 段，对纯文本段直接解出 ``CODE→NAME`` 映射；
    对块状变长 LZ 编码段（沪/深 A 股 name_16_16 等）当前跳过并记录到
    ``skipped`` —— 这类段的 match 字节 offset/len 编码尚未逆向完成
    （见模块 docstring 与 HANDOFF §6）。

    Args:
        body: upstockname 响应帧体。

    Returns:
        dict::

            {
              "names": {code: name, ...},   # 所有可解段合并（后段覆盖前段）
              "by_segment": {seg_name: {code: name, ...}, ...},
              "skipped": [seg_name, ...],    # 块状编码、未解的段
              "segments": [(seg_name, data_len, kind), ...],  # kind: "text"/"block"
            }
    """
    result = {
        "names": {},
        "by_segment": {},
        "skipped": [],
        "segments": [],
    }
    for seg_name, ds, de in _iter_name_segments(body):
        seg_data = body[ds:de]
        # 先按段名快速判断，再用启发式兜底
        base = seg_name.split("_")[0] if "_" in seg_name else seg_name
        is_block = (seg_name in _BLOCK_ENCODED_SEGMENTS
                    or base in ("16", "168")
                    or _is_block_encoded(seg_data))
        if is_block:
            result["skipped"].append(seg_name)
            result["segments"].append((seg_name, len(seg_data), "block"))
            logger.debug("decode_name_frame: 跳过块状编码段 [%s] (%dB)",
                         seg_name, len(seg_data))
            continue
        seg_names = _parse_name_text(seg_data)
        result["by_segment"][seg_name] = seg_names
        result["names"].update(seg_names)
        result["segments"].append((seg_name, len(seg_data), "text"))
        logger.debug("decode_name_frame: 解析纯文本段 [%s] → %d 条名称",
                     seg_name, len(seg_names))
    return result


# =============================================================================
# 短线精灵（DXJL）—— 9601 端口 qurealorder 历史翻页
# （移植自 thspy，PC 远航版复用同一 9601 协议）
# =============================================================================

# 9601 短线精灵/异动服务器（抓包确认）
REALORDER_HOST = "106.14.65.90"
REALORDER_PORT = 9601

# 短线精灵 datatype 过滤表达式（2026-07-17 全选抓包确认）：
#
# 类别 ID 结构：category_id = group_prefix | anomaly_byte
#   高 3 字节 = 组前缀（异动按字节范围分组，每组一个固定前缀）
#   低 1 字节 = 异动字节（见 ANOMALY_MAP_DXJL 的 key，如 0xd6=大笔买入）
#
# 组前缀表（全选 53 个类别实测确认）：
#   0x40080c00 → 0xd1~0xf8 核心异动（大笔/涨跌停/急速/放量/封板，29个）
#   0x00090a00 → 0xbc~0xbf   特大主动/被动买卖（4个）
#   0x00020b00 → 0x66~0x6f   挂单/撤单（特大挂/撤，8个）
#   0x00020a00 → 0xa2~0xa5   拖拉机/远价位（4个）
#   0x003f0d00 → 0xab~0xb0   新版异动（含义未知，6个）
#   0x000b0b00 → 0x99~0x9a   新版异动（含义未知，2个）
#
# 阈值表达式（可选，跟在类别 ID 后的 {} 里）：
#   {字段[下限~上限]|字段[下限~上限]}
#   字段编号（抓包对照同花顺客户端设置确认）：
#     19 = 成交手数（单位：手，如 10000=1万手）
#     17 = 成交金额（单位：元，如 5000000=500万）
#   '|' = OR（满足任一条件，实测确认，非 AND）
#   '~' = 范围分隔，'-' = 无限（如 [10000~-] = ≥1万手）
#   无 {} 表示该异动类型无条件过滤（涨跌停/封板/急速等）。
#
# 默认方案：大笔买卖 + 打开涨跌停（4 个类型）
#   大笔买卖阈值：成交手数≥1万手 OR 金额≥500万（对齐同花顺客户端默认）
#   打开涨跌停无阈值
DXJL_DATATYPE = (
    "1074269398{19[10000~-]|17[5000000~-]},"
    "1074269399{19[10000~-]|17[5000000~-]},"
    "1074269401,1074269403"
)

# 异动字节 → 组前缀（用于按异动类型生成 category_id，见 build_category_id）。
# 组前缀决定该异动字节在 datatype 表达式里的高 3 字节。
# 类型注释对照 ANOMALY_MAP_DXJL；未在 ANOMALY_MAP_DXJL 出现的标注「未知」。
ANOMALY_GROUP_PREFIX = {
    # ── 0x40080c00 核心异动组（大笔/涨跌停/急速/放量/封板，0xd1~0xf8）──
    0xd1: 0x40080c00,  # 区间放量涨
    0xd2: 0x40080c00,  # 区间放量跌
    0xd3: 0x40080c00,  # 未知（全选抓包出现，ANOMALY_MAP_DXJL 未收录）
    0xd4: 0x40080c00,  # 未知
    0xd5: 0x40080c00,  # 未知
    0xd6: 0x40080c00,  # 大笔买入
    0xd7: 0x40080c00,  # 大笔卖出
    0xd8: 0x40080c00,  # 涨停封板
    0xd9: 0x40080c00,  # 打开涨停板
    0xda: 0x40080c00,  # 跌停封板
    0xdb: 0x40080c00,  # 打开跌停板
    0xdc: 0x40080c00,  # 急速拉升
    0xdd: 0x40080c00,  # 猛烈打压
    0xde: 0x40080c00,  # 未知
    0xdf: 0x40080c00,  # 未知
    0xe0: 0x40080c00,  # 逼近涨停
    0xe1: 0x40080c00,  # 逼近跌停
    0xe2: 0x40080c00,  # 涨停大减
    0xe3: 0x40080c00,  # 跌停大减
    0xe4: 0x40080c00,  # 强势封涨停
    0xe5: 0x40080c00,  # 未知
    0xe6: 0x40080c00,  # 未知
    0xe7: 0x40080c00,  # 未知
    0xe8: 0x40080c00,  # 未知
    0xe9: 0x40080c00,  # 未知
    0xea: 0x40080c00,  # 未知
    0xeb: 0x40080c00,  # 未知
    0xec: 0x40080c00,  # 未知
    0xed: 0x40080c00,  # 未知
    0xee: 0x40080c00,  # 强势封跌停
    0xef: 0x40080c00,  # 未知（全选抓包出现）
    0xf0: 0x40080c00,  # 未知（全选抓包出现）
    0xf1: 0x40080c00,  # 未知（全选抓包出现）
    0xf2: 0x40080c00,  # 未知（全选抓包出现）
    0xf3: 0x40080c00,  # 未知（全选抓包出现）
    0xf4: 0x40080c00,  # 未知（全选抓包出现）
    0xf5: 0x40080c00,  # 未知（全选抓包出现）
    0xf6: 0x40080c00,  # 未知（全选抓包出现）
    0xf7: 0x40080c00,  # 未知（全选抓包出现）
    0xf8: 0x40080c00,  # 未知（全选抓包出现）
    # ── 0x00090a00 特大主动/被动买卖组（0xbc~0xbf）──
    0xbc: 0x00090a00,  # 特大主动买
    0xbd: 0x00090a00,  # 特大被动买
    0xbe: 0x00090a00,  # 特大主动卖
    0xbf: 0x00090a00,  # 特大被动卖
    # ── 0x00020b00 挂单/撤单组（0x66~0x6f）──
    0x66: 0x00020b00,  # 特大挂买
    0x67: 0x00020b00,  # 特大挂卖
    0x68: 0x00020b00,  # 未知
    0x69: 0x00020b00,  # 未知
    0x6a: 0x00020b00,  # 未知（全选抓包出现）
    0x6b: 0x00020b00,  # 未知（全选抓包出现）
    0x6c: 0x00020b00,  # 撤特大买
    0x6d: 0x00020b00,  # 撤涨停买
    0x6e: 0x00020b00,  # 撤特大卖
    0x6f: 0x00020b00,  # 撤跌停卖
    # ── 0x00020a00 拖拉机/远价位组（0xa2~0xa5）──
    0xa2: 0x00020a00,  # 拖拉机挂买
    0xa3: 0x00020a00,  # 拖拉机挂卖
    0xa4: 0x00020a00,  # 远价位垫单
    0xa5: 0x00020a00,  # 远价位压单
    # ── 0x000b0b00 新版异动组（含义未知，2026-07-17 全选抓包确认前缀）──
    0x99: 0x000b0b00,  # 未知
    0x9a: 0x000b0b00,  # 未知
    # ── 0x003f0d00 新版异动组（含义未知，全选抓包确认前缀）──
    0xab: 0x003f0d00,  # 未知
    0xac: 0x003f0d00,  # 未知
    0xad: 0x003f0d00,  # 未知
    0xae: 0x003f0d00,  # 未知
    0xaf: 0x003f0d00,  # 未知
    0xb0: 0x003f0d00,  # 未知
}


def build_category_id(anomaly_byte: int) -> int:
    """根据异动字节生成短线精灵类别 ID。

    类别 ID = 组前缀 | 异动字节（见 ANOMALY_GROUP_PREFIX）。
    例：0xd6(大笔买入) → 0x40080cd6 = 1074269398。

    Args:
        anomaly_byte: 异动字节（ANOMALY_MAP_DXJL 的 key，如 0xd6）。

    Returns:
        类别 ID（整数）。未知字节默认用核心组前缀 0x40080c00。
    """
    prefix = ANOMALY_GROUP_PREFIX.get(anomaly_byte, 0x40080c00)
    return prefix | anomaly_byte


def build_datatype(anomaly_bytes, volume_min: int | None = None,
                   amount_min: int | None = None) -> str:
    """按异动类型生成 datatype 过滤表达式。

    Args:
        anomaly_bytes: 异动字节列表（如 [0xd6, 0xd7] = 大笔买卖），
                       或 "all" 表示全部已知类型。
        volume_min: 字段19(成交手数)下限，单位=手，None=不加。
                    如 10000 = 1万手。
        amount_min: 字段17(成交金额)下限，单位=元，None=不加。
                    如 5000000 = 500万。

    两个阈值之间是 OR 关系（满足任一即可，实测确认）。

    Returns:
        datatype 字符串（逗号分隔的类别表达式）。
    """
    if anomaly_bytes == "all":
        anomaly_bytes = sorted(ANOMALY_GROUP_PREFIX.keys())
    # 阈值表达式
    thr = ""
    if volume_min is not None or amount_min is not None:
        parts = []
        if volume_min is not None:
            parts.append(f"19[{volume_min}~-]")
        if amount_min is not None:
            parts.append(f"17[{amount_min}~-]")
        thr = "{" + "|".join(parts) + "}"
    return ",".join(f"{build_category_id(b)}{thr}" for b in anomaly_bytes) + ","

# 异动类型映射（抓包 650 条确认）：
#   (anomaly_byte, direction_4bytes) → 中文名
ANOMALY_MAP_DXJL = {
    # 特大主动/被动买卖（有金额）
    (0xbc, b"\xff\x32\x32\x00"): "特大主动买",
    (0xbd, b"\xff\x32\x32\x00"): "特大被动买",
    (0xbe, b"\x00\xe6\x00\x00"): "特大主动卖",
    (0xbf, b"\x00\xe6\x00\x00"): "特大被动卖",
    # 大笔买卖（有金额）
    (0xd6, b"\xff\x32\x32\x00"): "大笔买入",
    (0xd7, b"\x00\xe6\x00\x00"): "大笔卖出",
    # 区间放量（无金额）
    (0xd1, b"\xff\x32\x32\x00"): "区间放量涨",
    (0xd2, b"\x00\xe6\x00\x00"): "区间放量跌",
    # 涨停封板/跌停封板（无金额，≈±10%/±20%）
    (0xd8, b"\xff\x32\x32\x00"): "涨停封板",
    (0xda, b"\x00\xe6\x00\x00"): "跌停封板",
    # 打开涨停/跌停（无金额）
    (0xd9, b"\x00\xe6\x00\x00"): "打开涨停板",
    (0xdb, b"\xff\x32\x32\x00"): "打开跌停板",
    # 逼近涨停/跌停（无金额，±8~10%）
    (0xe0, b"\xff\x32\x32\x00"): "逼近涨停",
    (0xe1, b"\x00\xe6\x00\x00"): "逼近跌停",
    # 涨停大减/跌停大减（有金额，±10%/±20%）
    (0xe2, b"\xff\x32\x32\x00"): "涨停大减",
    (0xe3, b"\x00\xe6\x00\x00"): "跌停大减",
    # 强势封涨停/跌停（有金额，±10%/±20%）
    (0xe4, b"\xff\x32\x32\x00"): "强势封涨停",
    (0xee, b"\x00\xe6\x00\x00"): "强势封跌停",
    # 急速拉升/猛烈打压（无金额，不论涨跌）
    (0xdc, b"\xff\x32\x32\x00"): "急速拉升",
    (0xdd, b"\x00\xe6\x00\x00"): "猛烈打压",
    # 撤单类（有金额）
    (0x6c, b"\xff\x32\x32\x00"): "撤特大买",
    (0x6d, b"\xff\x32\x32\x00"): "撤涨停买",
    (0x6e, b"\x00\xe6\x00\x00"): "撤特大卖",
    (0x6f, b"\x00\xe6\x00\x00"): "撤跌停卖",
    # 特大挂买/挂卖（有金额，涨跌≈0%）
    (0x66, b"\xff\x32\x32\x00"): "特大挂买",
    (0x67, b"\x00\xe6\x00\x00"): "特大挂卖",
    # 拖拉机挂买/挂卖（有金额，涨跌≈0%）
    (0xa2, b"\xff\x32\x32\x00"): "拖拉机挂买",
    (0xa3, b"\x00\xe6\x00\x00"): "拖拉机挂卖",
    # 远价位垫单/压单（有金额）
    (0xa4, b"\xff\x32\x32\x00"): "远价位垫单",
    (0xa5, b"\x00\xe6\x00\x00"): "远价位压单",
}

# 仅按异动字节的回退映射（推送帧常无方向标记 ff323200/00e60000）。
# d6/d7 等由异动字节唯一确定；bc/bd/be/bf 需方向标记区分，回退取主动类。
ANOMALY_BYTE_MAP = {
    0xd6: "大笔买入", 0xd7: "大笔卖出",
    0xd1: "区间放量涨", 0xd2: "区间放量跌",
    0xd8: "涨停封板", 0xda: "跌停封板",
    0xd9: "打开涨停板", 0xdb: "打开跌停板",
    0xdc: "急速拉升", 0xdd: "猛烈打压",
    0xe0: "逼近涨停", 0xe1: "逼近跌停",
    0xe2: "涨停大减", 0xe3: "跌停大减",
    0xe4: "强势封涨停", 0xee: "强势封跌停",
    0x66: "特大挂买", 0x67: "特大挂卖",
    0xa2: "拖拉机挂买", 0xa3: "拖拉机挂卖",
    0xa4: "远价位垫单", 0xa5: "远价位压单",
    0x6c: "撤特大买", 0x6d: "撤涨停买",
    0x6e: "撤特大卖", 0x6f: "撤跌停卖",
    0xbc: "特大主动买", 0xbd: "特大被动买",
    0xbe: "特大主动卖", 0xbf: "特大被动卖",
}


def read_frame_realorder(sock: socket.socket) -> bytes:
    """读取 9601 短线精灵服务器的响应帧。

    与 read_frame 的区别：9601 响应的长度字段是 len-1 编码，
    实际 body 比长度字段多 1 字节。抓包确认：len=0x184=388，实际 body=389。
    """
    magic = bytearray()
    while True:
        b = read_exact(sock, 1)
        magic += b
        if len(magic) > 4:
            magic.pop(0)
        if bytes(magic) == FRAME_MAGIC:
            break
    len_str = read_exact(sock, 8)
    body_len = int(len_str, 16) + 1  # 9601 响应 len = 实际body - 1
    return read_exact(sock, body_len)


def build_qurealorder_query(instance: int, market: int, endtime_us: int,
                            maxcount: int = 80, datatype: str | None = None) -> bytes:
    """构造短线精灵历史翻页请求（9601 端口，method=qurealorder）。

    Args:
        instance: 请求序列号（每次递增）。
        market: 市场代码，32=深 16=沪。
        endtime_us: 微秒时间戳游标（取此时间之前的记录）。
        maxcount: 每页记录数上限。同花顺客户端实测用 80~120；旧默认 5 太小
                  （15:00 异动密集时一页不够，导致翻页漏数据）。
        datatype: 过滤表达式，默认用 DXJL_DATATYPE。
                  可用 build_datatype() 按异动类型生成，或传 "" 查全部类型。

    Returns:
        请求帧 body（含 \\x09 前缀，不含 FD FD FD FD 头）。
    """
    if datatype is None:
        datatype = DXJL_DATATYPE
    # 注意：endtime 是最后字段，无尾 \\n（抓包确认）
    text = (
        f"instid={instance}\n"
        f"method=qurealorder\nreqtype=4\nmaxcount={maxcount}\n"
        f"market={market}\n"
        f"datatype={datatype}\n"
        f"rettype=hqfile\nendtime={endtime_us}"
    )
    return b"\x09" + text.encode("gbk")


def parse_qurealorder_response(body: bytes, market: str) -> list[dict]:
    """解析 qurealorder 的 hq1.0 响应，返回 list[dict]。

    hq1.0 结构（抓包确认）:
      [0:8]  magic "hq1.0\\0\\0\\0"
      [8:12] hdr_len   头总长（=88）
      [12:16] rec_count 记录数
      [16:20] field_count 字段数（含 1 元字段）
      [20:24] rec_len   单条记录长度（=45）
      [24:28] reserved
      [28:88] 字段表（8B/条）
      [88:]   记录区（rec_count × rec_len 字节）

    字段表 8B/条: dt(LE32, 低字节=字段编号) | fmt(1B) | sub(1B) | width(LE16)
    """
    hq_off = body.find(b"hq1.0")
    if hq_off < 0:
        return []
    b = body[hq_off:]
    if len(b) < 28:
        return []
    hdr_len = struct.unpack("<I", b[8:12])[0]
    rec_count = struct.unpack("<I", b[12:16])[0]
    rec_len = struct.unpack("<I", b[20:24])[0]
    if rec_len == 0 or rec_count == 0:
        return []
    if len(b) - hdr_len < rec_len:
        return []

    # 解析字段表（8B/条，从 b[24] 起）
    fields = []
    fc = struct.unpack("<I", b[16:20])[0]
    for i in range(fc + 1):
        off = 24 + i * 8
        if off + 8 > hdr_len:
            break
        e = b[off:off + 8]
        dt = struct.unpack("<I", e[0:4])[0]
        width = struct.unpack("<H", e[6:8])[0]
        if dt == 0:
            continue  # 元字段
        fields.append((dt & 0xFF, width))

    field_offsets = {}
    off = 0
    for fid, width in fields:
        field_offsets[fid] = (off, width)
        off += width

    records = []
    for i in range(rec_count):
        r = b[hdr_len + i * rec_len: hdr_len + (i + 1) * rec_len]
        if len(r) < rec_len:
            break
        rec = _parse_dxjl_record(r, field_offsets, market)
        if rec:
            records.append(rec)
    return records


def _parse_dxjl_record(r: bytes, offsets: dict, market: str) -> dict | None:
    """解析单条 45 字节短线精灵记录。"""
    try:
        ts_off, ts_w = offsets.get(199, (0, 8))
        timestamp_us = struct.unpack("<Q", r[ts_off:ts_off + ts_w])[0]

        code_off, code_w = offsets.get(5, (8, 17))
        code = r[code_off + 1: code_off + 7].decode("ascii", errors="replace")

        a_off, a_w = offsets.get(61, (25, 4))
        anomaly_code = r[a_off]

        d_off, d_w = offsets.get(64, (29, 4))
        f64 = r[d_off: d_off + d_w]

        amt_off, amt_w = offsets.get(17, (37, 4))
        amount = decode_ths_float(struct.unpack("<I", r[amt_off:amt_off + amt_w])[0])

        c_off, c_w = offsets.get(18, (41, 4))
        change_pct = decode_ths_float(struct.unpack("<I", r[c_off:c_off + c_w])[0])

        anomaly_type = ANOMALY_MAP_DXJL.get(
            (anomaly_code, f64), f"未知0x{anomaly_code:02x}")
        return {
            "时间": timestamp_us,
            "市场": market,
            "代码": code,
            "异动类型": anomaly_type,
            "异动编码": anomaly_code,
            "金额": round(amount, 2),
            "涨跌幅": round(change_pct, 2),
        }
    except Exception:
        return None


# =============================================================================
# 心跳（keep-alive）—— 维持 8901/9601 长连接
# （2026-07-17 抓包确认：hexin 静置时 8901 每 3 秒、9601 每 30 秒发心跳）
# =============================================================================

def _local_ip() -> str:
    """获取本机内网 IP（心跳 st= 字段用，非必需但抓包里有）。"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "0.0.0.0"
    finally:
        s.close()


def build_heartbeat_8901(seq: int = 0) -> bytes:
    """构造 8901 心跳帧（每 3 秒发一次，维持行情连接）。

    抓包结构（2026-07-17 确认）：
      cmd=0x09，header 23B（subtype=12 00 03 00，区别于行情请求的 12 00 09 00）
      text: ``10,<hex时间戳>,0000;st=<IP>;tsi0=<ts>:0;...;tr=<ts>:0;tc=<ts>:0``

    tsi/tr/tc 是流量统计（hex 字节计数）。发 0 值最小化——服务器只记录不校验。
    时间戳 = 当前 Unix 秒的 hex 编码。
    """
    ts = f"{int(time.time()):x}"
    ip = _local_ip()
    text = (
        f"10,{ts},0000;st={ip};"
        f"tsi0={ts}:0;tsi1={ts}:0;tsi2={ts}:0;tsi3={ts}:0;tso4={ts}:0;"
        f"tr={ts}:0;tc={ts}:0"
    ).encode("gbk")
    hdr = bytearray(23)
    hdr[0] = 0x09
    hdr[1:5] = b"\x00\x16\x00\x00"
    struct.pack_into("<H", hdr, 5, seq & 0xFFFF)
    hdr[7:11] = b"\x12\x00\x03\x00"   # 心跳 subtype
    hdr[11] = 0x05
    # [13:21] 抓包真值：00 00 00 00 00 00 a7 00（[18]=0xa7 标记，[19:21]=0）
    hdr[18] = 0xa7
    # [19:21] 心跳帧固定 00 00（不填文本长度，区别于行情请求）
    body = bytes(hdr) + text
    return encode_frame(body)


def build_heartbeat_9601(seq: int) -> bytes:
    """构造 9601 心跳帧（每 30 秒发一次，维持短线精灵连接）。

    抓包结构（2026-07-17 确认）：5 字节 body = 0x09 + 4 字节变化值，
    hexlen=00000004。byte[4]=0x07 固定，前 3 字节递增序号 big-endian。
    """
    seq_bytes = (seq & 0xFFFFFF).to_bytes(3, "big")
    body = b"\x09" + seq_bytes + b"\x07"
    return encode_frame(body)


# =============================================================================
# 短线精灵实时推送 —— subreal 订阅 + pushrealorder 推送解析
# （9601 端口，盘中约 1500 条异动/分钟。文档 §7-8）
# =============================================================================

# 异动通道（Universe 通道，与普通市场并列出现在 Passport64 的 MarketCode 里）。
#   URS=综合异动信号，UNX=大单成交，UCX=盘口状态变化(封/打开涨跌停)，
#   UME=主力资金，UCT=集合竞价+计算类异动。
SUBREAL_CHANNELS = ["URS", "UNX", "UCX", "UME", "UCT"]

# 通道 → 订阅类别前缀（subreal 的 class= 字段）
_SUBREAL_CLASS_PREFIX = {
    "URS": "URSI", "UCT": "UCTF", "UNX": "UNXF", "UCX": "UCXF", "UME": "UMEF",
}


def build_subreal_query(instance: int, channel: str = "URS", action: int = 1,
                        codelist: str = "", class_prefix: str | None = None) -> bytes:
    """构造 subreal 实时订阅请求（8901 端口，method=subreal）。

    ⚠️ 这是 8901 上的 subreal 格式（订阅异动通道 URS/UNX 等）。
    实测 8901 subreal 后服务器**不推送**。实时推送要用 9601 的 subrealorder
    （见 build_subrealorder_query）。本函数保留供参考/兼容。

    Args:
        instance: 请求序列号。
        channel: 异动通道，URS/UCT/UNX/UCX/UME（见 SUBREAL_CHANNELS）。
        action: 1=全新订阅 2=取消 3=增代码 4=删代码。
        codelist: 订阅代码，空=全市场。
        class_prefix: 订阅类别前缀，默认按 channel 自动推导。

    Returns:
        请求帧 body（含 \\x09 前缀，不含 FD FD FD FD 头）。
    """
    if class_prefix is None:
        class_prefix = _SUBREAL_CLASS_PREFIX.get(channel, channel + "I")
    text = (
        f"instid={instance}\n"
        f"method=subreal\nmarket={channel}\nperiod=0\n"
        f"action={action}\nclass={class_prefix}\n"
        f"codelist={codelist}\npageid=1341"
    )
    return b"\x09" + text.encode("gbk")


# 9601 subrealorder 订阅的市场代码（抓包确认 hexin 发 market=16/32/151/48）
SUBREALORDER_MARKETS = [16, 32, 151, 48]  # 沪/深/北交所/板块


def build_subrealorder_query(instance: int, market: int,
                             action: str = "add") -> bytes:
    """构造 9601 实时订阅请求（method=subrealorder）。

    抓包确认（2026-07-17 hexin stream 9）：订阅 market=16/32/151/48 后，
    服务器持续推送 pushrealorder 帧（盘中 1125 帧/90s）。

    Args:
        instance: 请求序列号（每次递增）。
        market: 市场代码（16=沪 32=深 151=北交所 48=板块）。
        action: ``add``=订阅 ``del``=取消。

    Returns:
        请求帧 body（含 \\x09 前缀，不含 FD FD FD FD 头）。
    """
    text = (
        f"instid={instance}\n"
        f"method=subrealorder\n"
        f"action={action}\n"
        f"market={market}\n"
        f"accept_ziptype=snappy\n"
        f"rettype=hqfile"
    )
    return b"\x09" + text.encode("gbk")


# 推送记录区代码提取正则：
#   格式A: 0x21('!') + 6位ASCII代码（0/3/6开头）
#   格式B: 0x2d('-') + 1~2字节长度/标记 + 6位ASCII代码
_PUSH_CODE_RE_A = re.compile(rb"\x21([036]\d{5})")
_PUSH_CODE_RE_B = re.compile(rb"\x2d.{1,2}([036]\d{5})", re.DOTALL)

# 涨幅字段的 THS LE32 模式：低 3 字节为 abs(涨幅%)×100 的整数，高字节 0xa0(正)/0xa8(负)
_PUSH_CHG_RE = re.compile(rb"([\x00-\xff]{3})[\xa0\xa8]")


def _extract_push_payload(raw: bytes) -> bytes:
    """[已废弃] 从 push 记录的 raw_bytes 提取纯数据区（跳过 Format B/A 壳），
    并包含格式 B 声明长度之后的 extra 字节。

    2026-07-22：parse_pushrealorder_response 已重写为异动字节锚定 + THS float
    精确解码，不再调用本函数。保留供历史参考。

    原 docstring（Format B/A 壳解析）:
      Format B: 0x2d + len(1B) + [market_prefix(1B)?] + code(6B) + payload [+ extra ...]
      Format A: 0x21 + code(6B) + payload
    """
    if not raw:
        return b""
    if raw[0] == 0x2d and len(raw) >= 3:          # Format B
        dlen = raw[1]
        data = raw[2:2 + dlen]                     # 声明长度的数据
        extra = raw[2 + dlen:]                     # 声明长度之后的额外字节
        # 检查是否有市场前缀（代码以 '0'-'9' 即 0x30-0x39 开头）
        if len(data) >= 7 and data[0] not in range(0x30, 0x3A):
            return data[7:] + extra                # 前缀(1) + 代码(6) = 7 字节
        elif len(data) >= 6:
            return data[6:] + extra                # 代码(6)
        return data + extra
    elif raw[0] == 0x21 and len(raw) >= 7:         # Format A
        return raw[7:]                             # 标记(1) + 代码(6)
    return raw


def _decode_push_single(raw: bytes) -> dict:
    """[已废弃] 解码单条推送记录的数值字段（金额、涨幅）。

    2026-07-22：parse_pushrealorder_response 已重写（异动字节锚定 + THS float
    精确解码，金额/涨幅 100% 准确），不再调用本函数。保留供历史参考。

    编码发现（2026-07-21，245 条对照样本验证）：
    - 涨幅：THS 定点 LE32，高字节 0xa0(正)/0xa8(负)，exp=2（÷100），
           低 3 字节 = abs(涨幅%)×100。检测率 93%。
    - 金额：THS 定点 LE32，位于 payload 内。检测率受偏移变化影响。

    策略：
    1. 先去壳（跳过 Format B/A 头部），得到纯 payload
    2. 在 payload 中扫描 0xa0/0xa8 结尾的 4 字节窗口 → 涨幅
    3. 在 payload 中扫描所有 THS LE32，过滤取最大非涨幅正数 → 金额候选
    """
    result = {"金额": 0.0, "涨幅": 0.0, "金额_来源": "none"}
    payload = _extract_push_payload(raw)
    if len(payload) < 4:
        return result

    # ── 涨幅：扫描 3 数据字节 + 0xa0/0xa8 标记 ──
    best_chg = None
    best_chg_abs = 0.0
    for i in range(len(payload) - 3):
        if payload[i + 3] in (0xa0, 0xa8):
            le32 = int.from_bytes(payload[i:i + 4], "little")
            val = decode_ths_float(le32)
            # 涨幅应该在合理范围内（±100），过滤掉异常大的 THS 解码值
            if abs(val) <= 200 and abs(val) > best_chg_abs:
                best_chg = val
                best_chg_abs = abs(val)
    if best_chg is not None:
        result["涨幅"] = best_chg

    # ── 金额：THS LE32 + plain LE32 ──
    AMT_MIN = 10000
    AMT_MAX = 500000000
    best_amt = 0.0

    # 优先在涨幅标记前 30 字节搜索
    search_range = range(len(payload) - 3)
    if best_chg is not None:
        for i in range(len(payload) - 3):
            if payload[i + 3] in (0xa0, 0xa8):
                le32_chk = int.from_bytes(payload[i:i + 4], "little")
                val_chk = decode_ths_float(le32_chk)
                if abs(val_chk - best_chg) < 0.01:
                    chg_end = i + 4
                    search_start = max(0, chg_end - 30)
                    search_range = range(search_start, chg_end - 3)
                    break

    for i in search_range:
        le32 = int.from_bytes(payload[i:i + 4], "little")
        # THS 定点
        val = decode_ths_float(le32)
        if AMT_MIN < val < AMT_MAX and val > best_amt:
            best_amt = val
        # plain unsigned LE32（部分记录金额是纯整数）
        if AMT_MIN < le32 < AMT_MAX and float(le32) > best_amt:
            best_amt = float(le32)

    if best_amt > 0:
        result["金额"] = best_amt
        result["金额_来源"] = "ths_le32"

    return result


def parse_pushrealorder_response(body: bytes) -> list[dict]:
    """解析 9601 pushrealorder 推送帧，返回异动记录列表。

    推送帧结构（2026-07-22 确认，见 HANDOFF §8）::

        文本头: \\tmethod=pushrealorder\\ninstid=...\\nmarket=...\\n...\\n\\x00
        hq1.0 容器头 (88B) + 记录区

    记录区::

        [marker 0x11/0x21] [代码 6B ASCII] [01 25 09 01 50 ...]
          └─ 每条异动子记录（同一代码可有多条）:
             [异动字节 d6/d7/66...] [0c 08 40 头] [方向标记 ff323200/00e60000]
             [变长中间字段] [金额 THS float 4B] [涨幅 THS float 4B]

    数值字段解码（2026-07-22 历史对照 100% 验证）：
      - 涨幅 = THS float（LE32，高字节 a0=正/a8=负），扫描异动字节后首个 a0/a8 标记
      - 金额 = THS float（LE32），紧跟涨幅前 4 字节
      - 异动类型 = (异动字节, 方向标记) 组合查 ANOMALY_MAP_DXJL

    Args:
        body: pushrealorder 响应帧 body（含文本头 + hq1.0 容器）。

    Returns:
        list[dict]，每项 ``{代码, 市场, 异动类型, 异动编码, 金额, 涨幅, raw_bytes}``。
        非 pushrealorder 帧返回空。
    """
    if b"pushrealorder" not in body:
        return []

    # 文本头里的 market 字段
    market = ""
    m = re.search(rb"market=(\d+)", body[:200])
    if m:
        market = m.group(1).decode("ascii", errors="replace")

    records = []
    # 异动字节集合（ANOMALY_MAP_DXJL 的所有 key 低字节）
    anomaly_bytes = set(k[0] for k in ANOMALY_MAP_DXJL)
    # 方向标记
    dir_buy = b"\xff\x32\x32\x00"   # 买/涨方向
    dir_sell = b"\x00\xe6\x00\x00"  # 卖/跌方向

    # 扫描所有代码标记（格式A: 0x21+代码，格式B: 0x2d+变长+代码）
    code_matches = []
    for pat in (_PUSH_CODE_RE_A, _PUSH_CODE_RE_B):
        code_matches.extend(pat.finditer(body))
    code_matches.sort(key=lambda cm: cm.start())

    for i, cm in enumerate(code_matches):
        code = cm.group(1).decode("ascii", errors="replace")
        # 记录区范围：本代码到下一代码（或帧尾）
        rec_start = cm.start()
        rec_end = code_matches[i + 1].start() if i + 1 < len(code_matches) else len(body)
        rec = body[rec_start:rec_end]

        # 在此代码的记录区扫描异动记录。
        # 有效异动记录 = 异动字节 + 后跟 0c 08 40 头（字段 64 方向标记的前缀）。
        # 这避免把数据区碰巧等于异动字节的字节误判为异动。
        j = 0
        while j < len(rec) - 7:
            ab = rec[j]
            if ab not in anomaly_bytes:
                j += 1
                continue
            # 要求异动字节后紧跟 0c 08 40 头（容忍 0c 08 的其他变体）
            if rec[j + 1:j + 4] != b"\x0c\x08\x40":
                j += 1
                continue

            # 0c 08 40 头之后是方向标记 + 变长字段 + 金额 + 涨幅
            # 方向标记（ff323200 或 00e60000，在头后 16 字节内）
            direction = b""
            search_region = rec[j + 4:j + 20]
            for marker in (dir_buy, dir_sell):
                mp = search_region.find(marker)
                if mp >= 0:
                    direction = marker
                    break

            # 异动类型：优先用 (异动字节, 方向标记) 精确匹配，
            # 方向标记缺失时回退到仅异动字节（ANOMALY_BYTE_MAP）。
            if direction:
                anomaly_type = ANOMALY_MAP_DXJL.get(
                    (ab, direction), ANOMALY_BYTE_MAP.get(ab, f"未知0x{ab:02x}"))
            else:
                anomaly_type = ANOMALY_BYTE_MAP.get(ab, f"未知0x{ab:02x}")

            # 扫描涨幅：异动字节后首个 a0/a8 结尾的 THS float（值在 ±50 内）
            change_pct = 0.0
            amount = 0.0
            for pos in range(j + 4, min(j + 25, len(rec) - 3)):
                if rec[pos + 3] in (0xa0, 0xa8):
                    val = decode_ths_float(struct.unpack("<I", rec[pos:pos + 4])[0])
                    if -50 < val < 50:
                        change_pct = round(val, 2)
                        # 金额 = 涨幅前 4 字节（THS float）
                        if pos >= 4:
                            amt_val = decode_ths_float(
                                struct.unpack("<I", rec[pos - 4:pos])[0])
                            if 10000 < amt_val < 1_000_000_000:
                                amount = round(amt_val, 2)
                        break

            records.append({
                "代码": code,
                "市场": market,
                "异动类型": anomaly_type,
                "异动编码": ab,
                "金额": amount,
                "涨幅": change_pct,
                "raw_bytes": rec[j:j + 20].hex(),
            })
            j += 4  # 跳过已处理的异动记录头
    return records
