"""
thspypc.blocks — 同花顺(THS) 板块管理模块（PC 远航版）。

移植自 thspy（Mac 版），纯 Python 实现，提供板块/股票分组的序列化、解析与
增删改查所需的协议原语、数据模型与异常体系。走标准 HTTPS（443），不依赖
私有 TCP 协议，零内部模块依赖（仅标准库 + requests）。
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import NamedTuple, Any
from urllib.parse import quote

import requests

_WIRETYPE_VARINT = 0
_WIRETYPE_LEN = 2


def _encode_varint(value: int) -> bytes:
    """编码无符号整数为 protobuf varint 格式。"""
    buf = bytearray()
    while value > 0x7F:
        buf.append((value & 0x7F) | 0x80)
        value >>= 7
    buf.append(value & 0x7F)
    return bytes(buf)


def _decode_varint(data: bytes, offset: int) -> tuple[int, int]:
    """从 data[offset] 解码 varint，返回 (value, new_offset)。"""
    value = 0
    shift = 0
    while offset < len(data):
        byte = data[offset]
        value |= (byte & 0x7F) << shift
        offset += 1
        if not (byte & 0x80):
            break
        shift += 7
    return value, offset


def _field_varint(field_number: int, value: int) -> bytes:
    """编码 protobuf varint 字段: tag(wire_type=0) + value。"""
    tag = (field_number << 3) | _WIRETYPE_VARINT
    return _encode_varint(tag) + _encode_varint(value)


def _field_bytes(field_number: int, payload: bytes) -> bytes:
    """编码 protobuf bytes 字段: tag(wire_type=2) + length + payload。"""
    tag = (field_number << 3) | _WIRETYPE_LEN
    return _encode_varint(tag) + _encode_varint(len(payload)) + payload


# 市场代码映射
_MARKET_CODE = {
    "SH": "17", "SHETF": "20", "ST": "22", "SZ": "33", "SZETF": "36",
    "ZS": "48", "CYB": "38", "KC": "18", "BJ": "71", "HK": "55",
    "US": "61", "FT": "50", "QH": "51", "QZ": "53", "OP": "79",
    "JJ": "39", "ZQ": "45", "XSB": "67",
}
_MARKET_NAME = {v: k for k, v in _MARKET_CODE.items()}
_MARKET_NAME["151"] = "BJ"


def market_code(abbr: str) -> str:
    if not abbr:
        return abbr
    return _MARKET_CODE.get(abbr.upper(), abbr)


def market_abbr(code: str) -> str:
    if not code:
        return code
    return _MARKET_NAME.get(code, code)


# 异常类
class BlockError(Exception):
    """板块操作基础异常。"""


class BlockNetworkError(BlockError):
    def __init__(self, action: str, message: str) -> None:
        self.action = action
        super().__init__(f"{action} 失败: {message}")


class BlockAPIError(BlockError):
    def __init__(self, action: str, message: str, code: str | None = None) -> None:
        self.action = action
        self.message = message
        self.code = code
        detail = f"{message} (code={code})" if code else message
        super().__init__(f"{action} 失败: {detail}")


class BlockConflictError(BlockAPIError):
    """版本冲突，重试后仍失败。"""


class BlockAuthError(BlockError):
    """鉴权失败。"""


class BlockReadOnlyError(BlockError):
    """对动态板块执行增删操作。"""


# 数据模型
@dataclass(frozen=True)
class StockItem:
    code: str
    market: str | None = None
    price: float | None = None
    added_at: str | None = None

    def __post_init__(self) -> None:
        if self.market:
            object.__setattr__(self, "market", self.market.upper())


@dataclass
class StockGroup:
    name: str
    group_id: str
    items: list[StockItem] = field(default_factory=list)
    is_dynamic: bool = False


class StockEntry(NamedTuple):
    """原始 API 股票条目: 代码 + 数字市场类型码。"""
    code: str
    market_type: str


class BlockstockGroup(NamedTuple):
    group_name: str
    group_type: int
    stock_list: list[StockEntry]


class BlockstockDownload(NamedTuple):
    count: int
    version: int
    groups: list[BlockstockGroup]


def parse_symbol(symbol: str) -> StockEntry:
    if "." not in symbol:
        raise BlockAPIError("解析股票代码", f"股票代码格式无效: '{symbol}'")
    code_part, market_suffix = symbol.rsplit(".", 1)
    mcode = market_code(market_suffix)
    return StockEntry(code_part, mcode)


def is_version_conflict(error: BlockAPIError) -> bool:
    msg = error.message or ""
    code = (error.code or "").lower()
    lowered = msg.lower()

    if code in ("409", "version_conflict"):
        return True
    en_tokens = ("outdated", "mismatch", "refresh", "expired", "stale", "conflict")
    if "version" in lowered and any(t in lowered for t in en_tokens):
        return True
    cn_tokens = ("过期", "失效", "不一致", "不匹配", "刷新", "版本冲突", "版本过期")
    if "版本" in msg and any(t in msg for t in cn_tokens):
        return True
    return False


def parse_group_content(content: str) -> list[StockEntry]:
    if not content:
        return []
    parts = content.split(",", 1)
    codes = [c for c in parts[0].split("|") if c]
    markets = [m for m in parts[1].split("|") if m] if len(parts) > 1 else []
    result: list[StockEntry] = []
    for i, code in enumerate(codes):
        mtype = markets[i] if i < len(markets) else ""
        result.append(StockEntry(code, mtype))
    return result


def encode_blockstock_payload(
    group_name: str, group_type: int, stock_list: list[StockEntry]
) -> bytes:
    gbk_bytes = group_name.encode("gbk")
    group_id_b64 = base64.b64encode(gbk_bytes).decode("ascii")
    codes = "|".join(e.code for e in stock_list)
    types = "|".join(e.market_type for e in stock_list)
    stock_str = f"{codes},{types}"
    group_data = _field_bytes(1, group_id_b64.encode("ascii")) + _field_bytes(
        3, stock_str.encode("ascii")
    )
    group_payload = _field_bytes(1, _field_varint(1, group_type)) + _field_bytes(3, group_data)
    return _field_bytes(1, group_payload)


def _parse_blockstock_group(data: bytes) -> BlockstockGroup:
    offset = 0
    group_type = 0
    group_name = ""
    stock_list: list[StockEntry] = []

    while offset < len(data):
        tag, offset = _decode_varint(data, offset)
        field_number = tag >> 3
        wire_type = tag & 0x07

        if wire_type == 0:
            value, offset = _decode_varint(data, offset)
            if field_number == 1:
                group_type = value
        elif wire_type == 2:
            length, offset = _decode_varint(data, offset)
            chunk = data[offset : offset + length]
            offset += length
            if field_number == 1:
                inner_tag, _ = _decode_varint(chunk, 0)
                if (inner_tag >> 3) == 1:
                    inner_val, _ = _decode_varint(chunk, 1)
                    group_type = inner_val
            elif field_number == 3:
                inner_offset = 0
                gid = ""
                stock_raw = ""
                while inner_offset < len(chunk):
                    itag, inner_offset = _decode_varint(chunk, inner_offset)
                    ifn = itag >> 3
                    iwt = itag & 0x07
                    if iwt == 2:
                        ilen, inner_offset = _decode_varint(chunk, inner_offset)
                        ichunk = chunk[inner_offset : inner_offset + ilen]
                        inner_offset += ilen
                        if ifn == 1:
                            gid = ichunk.decode("ascii")
                        elif ifn == 3:
                            stock_raw = ichunk.decode("ascii")
                if gid:
                    try:
                        group_name = base64.b64decode(gid).decode("gbk")
                    except (ValueError, UnicodeDecodeError):
                        group_name = gid
                if stock_raw:
                    stock_list = parse_group_content(stock_raw)

    return BlockstockGroup(
        group_name=group_name, group_type=group_type, stock_list=stock_list
    )


def parse_blockstock_response(data: bytes) -> BlockstockDownload:
    offset = 0
    count = 0
    version = 0
    groups: list[BlockstockGroup] = []

    while offset < len(data):
        tag, offset = _decode_varint(data, offset)
        field_number = tag >> 3
        wire_type = tag & 0x07

        if wire_type == 0:
            value, offset = _decode_varint(data, offset)
            if field_number == 1:
                count = value
            elif field_number == 2:
                version = value
        elif wire_type == 2:
            length, offset = _decode_varint(data, offset)
            chunk = data[offset : offset + length]
            offset += length
            if field_number == 3:
                groups.append(_parse_blockstock_group(chunk))

    return BlockstockDownload(count=count, version=version, groups=groups)


# ---------------------------------------------------------------------------
# Task 4: BlockAuth (docookie2 + cookie cache)
# ---------------------------------------------------------------------------
_logger = logging.getLogger(__name__)


def _parse_cookie_header(header: str) -> dict[str, str]:
    """解析 Set-Cookie header 或 cookie 字符串为字典。"""
    cookies: dict[str, str] = {}
    if not header:
        return cookies
    for part in header.split(";"):
        segment = part.strip()
        if not segment or "=" not in segment:
            continue
        name, value = segment.split("=", 1)
        cookies[name.strip()] = value.strip()
    return cookies


_UPASS_BASE = "https://upass.10jqka.com.cn"
_DOC_COOKIE_PATH = "/docookie2.php"
_BLOCK_UA = (
    "Hexin_Gphone/11.28.03 (Royal Flush) hxtheme/0 innerversion/G037.09.028.1.32 "
    "followPhoneSystemTheme/0 userid/000000000 getHXAPPAccessibilityMode/0 "
    "hxNewFont/1 isVip/0 getHXAPPFontSetting/normal getHXAPPAdaptOldSetting/0 okhttp/3.14.9"
)
_AUTH_TIMEOUT = 10.0


class BlockAuth:
    """通过 docookie2.php 获取 HTTP cookies，带本地缓存（24h TTL）。"""

    def __init__(
        self,
        cache_path: str = "ths_cookie_cache.json",
        ttl: int = 86400,
        http_session: requests.Session | None = None,
    ) -> None:
        self._cache_path = cache_path
        self._ttl = ttl
        self._http = http_session or requests.Session()

    def docookie2(self, userid: str, sessionid: str, signvalid: str) -> dict[str, str]:
        """调用 docookie2.php 换取 HTTP cookies。"""
        params = {"userid": userid, "sessionid": sessionid, "signvalid": signvalid}
        try:
            resp = self._http.get(
                f"{_UPASS_BASE}{_DOC_COOKIE_PATH}",
                params=params,
                headers={"User-Agent": _BLOCK_UA},
                timeout=_AUTH_TIMEOUT,
            )
            resp.raise_for_status()
        except requests.RequestException as exc:
            raise BlockAuthError(f"docookie2 网络错误: {exc}") from exc

        cookies = resp.cookies.get_dict()
        if not cookies:
            cookie_header = resp.headers.get("Set-Cookie", "")
            if cookie_header:
                cookies = _parse_cookie_header(cookie_header)
        if not cookies:
            raise BlockAuthError("docookie2.php 未返回 cookies")
        return cookies

    def get_cookies(
        self,
        userid: str,
        sessionid: str,
        signvalid: str,
        *,
        cache_key: str | None = None,
    ) -> dict[str, str]:
        """带缓存的获取 cookies。"""
        if cache_key is None:
            cache_key = f"credentials::{hashlib.sha256(userid.encode()).hexdigest()}"
        elif not cache_key.startswith("credentials::"):
            cache_key = f"credentials::{cache_key}"

        cached = self._read_cache(cache_key)
        if cached and not self._is_expired(cached):
            return cached["cookies"]

        cookies = self.docookie2(userid, sessionid, signvalid)
        self._write_cache(cache_key, cookies)
        return cookies

    def _read_cache(self, cache_key: str) -> dict[str, Any] | None:
        if not os.path.exists(self._cache_path):
            return None
        try:
            with open(self._cache_path, encoding="utf-8") as f:
                data = json.load(f)
            entry = data.get(cache_key)
            if isinstance(entry, dict) and entry.get("cookies"):
                return entry
        except (json.JSONDecodeError, OSError):
            pass
        return None

    def _write_cache(self, cache_key: str, cookies: dict[str, str]) -> None:
        data: dict[str, Any] = {}
        if os.path.exists(self._cache_path):
            try:
                with open(self._cache_path, encoding="utf-8") as f:
                    data = json.load(f)
            except (json.JSONDecodeError, OSError):
                pass
        data[cache_key] = {"cookies": cookies, "timestamp": time.time()}
        try:
            with open(self._cache_path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False)
        except OSError as exc:
            _logger.warning("写入 cookie 缓存失败: %s", exc)

    def _is_expired(self, entry: dict[str, Any]) -> bool:
        ts = entry.get("timestamp", 0)
        try:
            return time.time() - float(ts) > self._ttl
        except (TypeError, ValueError):
            return True


# ---------------------------------------------------------------------------
# Task 5: BlockManager core (list_groups + selfstock_detail)
# ---------------------------------------------------------------------------

# HTTP API 端点常量
_API_BASE = "https://ugc.10jqka.com.cn"
_QUERY_GROUPS_PATH = "/optdata/selfgroup/open/api/group/v1/query"
_ADD_ITEM_PATH = "/optdata/selfgroup/open/api/content/v1/add"
_DELETE_ITEM_PATH = "/optdata/selfgroup/open/api/content/v1/delete"
_ADD_GROUP_PATH = "/optdata/selfgroup/open/api/group/v1/add"
_DELETE_GROUP_PATH = "/optdata/selfgroup/open/api/group/v1/delete"
_SHARE_GROUP_PATH = "/optdata/sharing_service/open/api/sharing/v1/create"

_SELFSTOCK_V1_QUERY = "/optdata/selfstock/open/api/v1/query"
_SELFSTOCK_V1_MODIFY = "/optdata/selfstock/open/api/v1/modify"

_SELFSTOCK_V2_BASE = "https://t.10jqka.com.cn"
_SELFSTOCK_V2_LIST = "/newcircle/group/getSelfStockWithMarket/"
_SELFSTOCK_V2_MODIFY = "/newcircle/group/modifySelfStock/"

_MULTISTORAGE_URL = "https://cs.10jqka.com.cn/multiStorage"
_BLOCKSTOCK_APPNAME = "blockstock"
_MULTISTORAGE_CLIENTTYPE = "hevo_pc"

_DYNAMIC_PLATE_URL = (
    "https://apigate.10jqka.com.cn/d/platform/dynamicplate/stocks/self/v4/select"
)

_SELFSTOCK_DETAIL_URL = "https://ugc.10jqka.com.cn/selfstock_detail"

_DEFAULT_FROM = "sjcg_gphone"
_GROUP_QUERY_TYPES = "0,1"
_SELF_STOCK_GROUP_ID = "__selfstock__"
_SELF_STOCK_DEFAULT_NAME = "我的自选"
_DYNAMIC_GROUP_PREFIX = "1_"
_HTTP_TIMEOUT = 10.0


def _parse_selfstock_detail_response(xml_text: str) -> tuple[str | None, list[dict[str, Any]]]:
    """解析 selfstock_detail XML 响应。"""
    import xml.etree.ElementTree as ET

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None, []

    item = root.find("item")
    if item is None:
        return None, []

    version = item.attrib.get("version")
    detail_blob = item.attrib.get("selfstock_detail", "")
    if not detail_blob:
        return version, []

    try:
        decoded = base64.b64decode(detail_blob)
        text = decoded.decode("utf-8", errors="replace").strip()
        if not text:
            return version, []
        return version, json.loads(text)
    except (ValueError, json.JSONDecodeError):
        return version, []


class BlockManager:
    """板块/自选股/动态板块管理器。不依赖 TCP 连接，仅需 cookies + requests。"""

    def __init__(
        self,
        cookies: dict[str, str] | None = None,
        *,
        http_session: requests.Session | None = None,
    ) -> None:
        self._http = http_session or requests.Session()
        self._cookies = cookies or {}
        if not self._cookies.get("userid"):
            raise BlockAuthError("cookies 中缺少 userid，请先登录")

        self._groups_cache: dict[str, StockGroup] = {}
        self._current_version: str | None = None
        self._detail_map: dict[tuple[str, str], dict[str, Any]] = {}
        self._detail_version: str | None = None

    def _headers(self) -> dict[str, str]:
        return {"User-Agent": _BLOCK_UA}

    def _cookies_dict(self) -> dict[str, str]:
        return dict(self._cookies)

    def list_groups(self) -> list[StockGroup]:
        """获取所有自选股分组（含动态板块标记）。"""
        params = {"from": _DEFAULT_FROM, "types": _GROUP_QUERY_TYPES}
        try:
            resp = self._http.get(
                f"{_API_BASE}{_QUERY_GROUPS_PATH}",
                params=params,
                headers=self._headers(),
                cookies=self._cookies_dict(),
                timeout=_HTTP_TIMEOUT,
            )
            resp.raise_for_status()
        except requests.RequestException as exc:
            raise BlockNetworkError("获取分组", str(exc)) from exc

        payload = resp.json()
        data = self._extract_data(payload, "获取分组")

        version = data.get("version")
        if version is not None:
            self._current_version = str(version)

        raw_groups = data.get("group_list", [])
        result: list[StockGroup] = []
        self._groups_cache.clear()

        for g in raw_groups:
            gid = g.get("id", "")
            gname = g.get("name", "")
            content = g.get("content", "")
            entries = parse_group_content(content)
            items = [
                StockItem(
                    code=e.code,
                    market=market_abbr(e.market_type) if e.market_type else None,
                )
                for e in entries
            ]
            is_dyn = gid.startswith(_DYNAMIC_GROUP_PREFIX)
            group = StockGroup(name=gname, group_id=gid, items=items, is_dynamic=is_dyn)
            result.append(group)
            self._groups_cache[gname] = group

        self._refresh_detail_best_effort("获取分组")
        for group in result:
            if not group.is_dynamic:
                for i, item in enumerate(group.items):
                    meta = self._lookup_detail(item.code, item.market)
                    if meta:
                        group.items[i] = StockItem(
                            code=item.code,
                            market=item.market,
                            price=meta.get("price"),
                            added_at=meta.get("added_at"),
                        )
        return result

    def get_group(self, name: str, *, refresh: bool = False) -> StockGroup | None:
        if refresh or not self._groups_cache:
            self.list_groups()
        return self._groups_cache.get(name)

    def refresh_selfstock_detail(self, force: bool = False) -> str | None:
        if not force and self._detail_map:
            return self._detail_version
        userid = self._cookies.get("userid", "")
        params = {"reqtype": "download", "app_flag": "0E", "userid": userid}
        headers = {**self._headers(), "userid": userid}
        try:
            resp = self._http.get(
                _SELFSTOCK_DETAIL_URL,
                params=params,
                headers=headers,
                cookies=self._cookies_dict(),
                timeout=_HTTP_TIMEOUT,
            )
            resp.raise_for_status()
        except requests.RequestException as exc:
            _logger.warning("selfstock_detail 请求失败: %s", exc)
            return None
        version, detail_list = _parse_selfstock_detail_response(resp.text)
        index: dict[tuple[str, str], dict[str, Any]] = {}
        for entry in detail_list:
            code = entry.get("C", "")
            mtype = entry.get("M", "")
            if not code:
                continue
            mabbr = market_abbr(mtype) if mtype else ""
            price_raw = entry.get("P")
            price_val = None
            if price_raw not in (None, ""):
                try:
                    price_val = float(price_raw)
                except (TypeError, ValueError):
                    pass
            index[(code, mabbr.upper())] = {"price": price_val, "added_at": entry.get("T")}
        self._detail_map = index
        self._detail_version = version
        _logger.info("selfstock_detail 刷新成功: 版本 %s, %d 条", version or "?", len(index))
        return version

    def _refresh_detail_best_effort(self, context: str) -> None:
        try:
            self.refresh_selfstock_detail(force=True)
        except Exception as exc:
            _logger.warning("%s 时刷新 selfstock_detail 失败: %s", context, exc)

    def _lookup_detail(self, code: str, market: str | None) -> dict[str, Any] | None:
        if not self._detail_map:
            return None
        mkey = (market or "").upper()
        return self._detail_map.get((code, mkey)) or self._detail_map.get((code, ""))

    @staticmethod
    def _extract_data(payload: Any, action: str) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise BlockAPIError(action, "响应格式无效")
        status_code = payload.get("status_code")
        if status_code != 0:
            raise BlockAPIError(
                action, payload.get("status_msg", "未知业务错误"),
                str(status_code) if status_code is not None else None,
            )
        data = payload.get("data")
        if not isinstance(data, dict):
            raise BlockAPIError(action, "响应缺少 data 字段")
        return data

    def _ensure_version(self) -> str:
        if self._current_version is None:
            self.list_groups()
        if self._current_version is None:
            raise BlockAPIError("版本检查", "无法获取版本号")
        return self._current_version

    def _find_group_id(self, group_name: str) -> str | None:
        if not self._groups_cache:
            self.list_groups()
        group = self._groups_cache.get(group_name)
        return group.group_id if group else None

    # ── 分组增删 ──

    def add_group(self, name: str) -> str:
        """新建分组，返回 group_id。"""
        if not name:
            raise BlockAPIError("添加分组", "分组名称不能为空")

        def api_call(version: str) -> dict[str, Any]:
            return self._post_with_version(
                _ADD_GROUP_PATH, {"name": name, "type": "0"}, version, "添加分组"
            )

        def cache_updater(response: dict[str, Any]) -> None:
            gid = response.get("id") or response.get("group_id") or response.get("groupid")
            if gid:
                self._groups_cache[name] = StockGroup(name=name, group_id=str(gid))

        result = self._write_with_retry("添加分组", api_call, cache_updater)
        return str(result.get("id") or result.get("group_id") or result.get("groupid") or "")

    def delete_group(self, name: str) -> None:
        """删除分组。"""
        gid = self._find_group_id(name)
        if not gid:
            raise BlockAPIError("删除分组", f"未找到分组 '{name}'")

        def api_call(version: str) -> dict[str, Any]:
            return self._post_with_version(
                _DELETE_GROUP_PATH, {"ids": gid}, version, "删除分组"
            )

        def cache_updater(_: dict[str, Any]) -> None:
            self._groups_cache.pop(name, None)

        self._write_with_retry("删除分组", api_call, cache_updater)

    def share_group(self, name: str, valid_time: int = 604800) -> dict[str, Any]:
        """生成分享链接。"""
        gid = self._find_group_id(name)
        if not gid:
            raise BlockAPIError("分享分组", f"未找到分组 '{name}'")
        userid = self._cookies.get("userid", "")
        biz_suffix = gid.split("_", 1)[1] if "_" in gid else gid
        payload = {
            "biz": "selfstock",
            "valid_time": int(valid_time),
            "biz_key": f"{userid}_{biz_suffix}",
            "name": name,
            "url_style": 0,
        }
        try:
            resp = self._http.post(
                f"{_API_BASE}{_SHARE_GROUP_PATH}",
                json=payload,
                headers={**self._headers(), "Content-Type": "application/json"},
                cookies=self._cookies_dict(),
                timeout=_HTTP_TIMEOUT,
            )
            resp.raise_for_status()
        except requests.RequestException as exc:
            raise BlockNetworkError("分享分组", str(exc)) from exc
        return self._extract_data(resp.json(), "分享分组")

    # ── 股票增删 ──

    def add_stock(self, group: str, symbols: str | list[str]) -> None:
        if isinstance(symbols, str):
            symbols = [symbols]
        if not symbols:
            raise BlockAPIError("添加股票", "股票列表不能为空")
        self._check_writable(group)
        if self._is_self_stock(group):
            self._add_self_stock(symbols)
            return
        gid = self._find_group_id(group)
        if not gid:
            raise BlockAPIError("添加股票", f"未找到分组 '{group}'")
        entries = [parse_symbol(s) for s in symbols]
        if len(entries) == 1:
            self._add_single(gid, entries[0])
        else:
            self._add_batch(group, entries)

    def remove_stock(self, group: str, symbols: str | list[str]) -> None:
        if isinstance(symbols, str):
            symbols = [symbols]
        if not symbols:
            raise BlockAPIError("删除股票", "股票列表不能为空")
        self._check_writable(group)
        if self._is_self_stock(group):
            self._remove_self_stock(symbols)
            return
        gid = self._find_group_id(group)
        if not gid:
            raise BlockAPIError("删除股票", f"未找到分组 '{group}'")
        entries = [parse_symbol(s) for s in symbols]
        if len(entries) == 1:
            self._remove_single(gid, entries[0])
        else:
            self._remove_batch(group, entries)

    # ── 写操作内部实现 ──

    def _write_with_retry(self, action: str, api_call_factory, cache_updater) -> dict[str, Any]:
        for attempt in range(2):
            version = self._ensure_version()
            try:
                result = api_call_factory(version)
            except BlockAPIError as exc:
                if attempt == 0 and is_version_conflict(exc):
                    _logger.warning("%s 遇到版本冲突，刷新后重试", action)
                    self.list_groups()
                    continue
                if attempt == 1 and is_version_conflict(exc):
                    raise BlockConflictError(action, exc.message, exc.code) from exc
                raise
            new_ver = result.get("version")
            if new_ver is not None:
                self._current_version = str(new_ver)
            try:
                cache_updater(result)
            except Exception:
                _logger.exception("%s 成功但更新缓存失败", action)
                self.list_groups()
            return result
        raise BlockConflictError(action, "重试后仍失败")

    def _post_with_version(self, endpoint: str, payload: dict[str, Any], version: str, action: str) -> dict[str, Any]:
        data = {**payload, "version": str(version), "from": _DEFAULT_FROM}
        try:
            resp = self._http.post(
                f"{_API_BASE}{endpoint}",
                data=data,
                headers={**self._headers(), "Content-Type": "application/x-www-form-urlencoded"},
                cookies=self._cookies_dict(),
                timeout=_HTTP_TIMEOUT,
            )
            resp.raise_for_status()
        except requests.RequestException as exc:
            raise BlockNetworkError(action, str(exc)) from exc
        return self._extract_data(resp.json(), action)

    def _add_single(self, group_id: str, entry: StockEntry) -> None:
        def api_call(version: str) -> dict[str, Any]:
            return self._post_with_version(
                _ADD_ITEM_PATH,
                {"id": group_id, "content": f"{entry.code},{entry.market_type}", "num": "1"},
                version, "添加股票",
            )
        self._write_with_retry("添加股票", api_call, lambda _: None)

    def _remove_single(self, group_id: str, entry: StockEntry) -> None:
        def api_call(version: str) -> dict[str, Any]:
            return self._post_with_version(
                _DELETE_ITEM_PATH,
                {"id": group_id, "content": f"{entry.code},{entry.market_type}", "num": "1"},
                version, "删除股票",
            )
        self._write_with_retry("删除股票", api_call, lambda _: None)

    def _add_batch(self, group_name: str, entries: list[StockEntry]) -> None:
        self._batch_via_multistorage(group_name, entries, action="add")

    def _remove_batch(self, group_name: str, entries: list[StockEntry]) -> None:
        self._batch_via_multistorage(group_name, entries, action="delete")

    def _batch_via_multistorage(self, group_name: str, entries: list[StockEntry], *, action: str) -> None:
        auth_params = self._get_auth_params()
        download = self._download_blockstock(auth_params)
        group_type = 0
        current: list[StockEntry] = []
        for g in download.groups:
            if g.group_name == group_name:
                group_type = g.group_type
                current = g.stock_list
                break
        merged = _merge_entries(current, entries, action)
        self._upload_blockstock(auth_params, group_name, group_type, merged, str(download.version))

    # ── "我的自选" 协议 ──

    def _is_self_stock(self, group_name: str) -> bool:
        return group_name in (_SELF_STOCK_DEFAULT_NAME, _SELF_STOCK_GROUP_ID)

    def _add_self_stock(self, symbols: list[str]) -> None:
        if len(symbols) == 1:
            entry = parse_symbol(symbols[0])
            self._modify_self_stock_v2("add", f"{entry.code}_{entry.market_type}")
        else:
            entries = [parse_symbol(s) for s in symbols]
            self._modify_self_stock_v1_batch(entries, "add")

    def _remove_self_stock(self, symbols: list[str]) -> None:
        if len(symbols) == 1:
            entry = parse_symbol(symbols[0])
            self._modify_self_stock_v2("del", f"{entry.code}_{entry.market_type}")
        else:
            entries = [parse_symbol(s) for s in symbols]
            self._modify_self_stock_v1_batch(entries, "delete")

    def _modify_self_stock_v2(self, op: str, stockcode: str) -> None:
        try:
            resp = self._http.get(
                f"{_SELFSTOCK_V2_BASE}{_SELFSTOCK_V2_MODIFY}",
                params={"op": op, "stockcode": stockcode},
                headers=self._headers(),
                cookies=self._cookies_dict(),
                timeout=_HTTP_TIMEOUT,
            )
            resp.raise_for_status()
        except requests.RequestException as exc:
            raise BlockNetworkError("我的自选", str(exc)) from exc
        self._check_v2_result(resp.json())

    def _modify_self_stock_v1_batch(self, entries: list[StockEntry], action: str) -> None:
        current = self._download_self_stocks_v1()
        merged = _merge_entries(current[1], entries, action)
        self._modify_self_stocks_v1(merged, current[0])

    def _download_self_stocks_v1(self) -> tuple[str, list[StockEntry]]:
        userid = self._cookies.get("userid", "")
        headers = {**self._headers(), "userid": userid} if userid else self._headers()
        params = {"support_all": "0", "from": "thspc_hevo"}
        try:
            resp = self._http.get(
                f"{_API_BASE}{_SELFSTOCK_V1_QUERY}",
                params=params, headers=headers,
                cookies=self._cookies_dict(), timeout=_HTTP_TIMEOUT,
            )
            resp.raise_for_status()
        except requests.RequestException as exc:
            raise BlockNetworkError("我的自选", str(exc)) from exc
        payload = resp.json()
        data = self._extract_data(payload, "我的自选")
        raw = data.get("selfstock", "")
        version = str(data.get("version", ""))
        entries = parse_group_content(raw) if raw else []
        return version, entries

    def _modify_self_stocks_v1(self, entries: list[StockEntry], version: str) -> None:
        codes = "|".join(e.code for e in entries)
        types = "|".join(e.market_type for e in entries)
        data = {
            "selfstock": f"{codes},{types}",
            "from": "thspc_hevo", "version": str(version),
            "num": str(len(entries)),
        }
        userid = self._cookies.get("userid", "")
        headers = {**self._headers(), "Content-Type": "application/x-www-form-urlencoded"}
        if userid:
            headers["userid"] = userid
        try:
            resp = self._http.post(
                f"{_API_BASE}{_SELFSTOCK_V1_MODIFY}",
                data=data, headers=headers,
                cookies=self._cookies_dict(), timeout=_HTTP_TIMEOUT,
            )
            resp.raise_for_status()
        except requests.RequestException as exc:
            raise BlockNetworkError("我的自选", str(exc)) from exc
        self._extract_data(resp.json(), "我的自选")

    def _check_v2_result(self, payload: Any) -> None:
        if not isinstance(payload, dict):
            raise BlockAPIError("我的自选", "响应格式无效")
        error_code = payload.get("errorCode")
        if error_code != 0:
            raise BlockAPIError("我的自选", payload.get("errorMsg", "未知错误"), str(error_code))

    # ── multiStorage 协议 ──

    def _get_auth_params(self) -> dict[str, str]:
        userid = self._cookies.get("userid", "")
        sessionid = ""
        user_raw = self._cookies.get("user", "")
        if user_raw:
            import urllib.parse as _urlparse
            decoded = _urlparse.unquote(user_raw)
            try:
                text = base64.b64decode(decoded).decode("utf-8", errors="replace")
                parts = text.split(":")
                if len(parts) > 17:
                    sessionid = parts[17]
            except (ValueError, UnicodeDecodeError):
                pass
        if not sessionid:
            sessionid = self._cookies.get("sessionid", "")
        from datetime import datetime as _dt
        expires = _dt.fromtimestamp(time.time() + 86400).strftime("%Y-%m-%d %H:%M:%S")
        return {"userid": userid, "sessionid": sessionid, "expires": expires}

    def _download_blockstock(self, auth_params: dict[str, str]) -> BlockstockDownload:
        data = {
            "reqtype": "download", "userid": auth_params.get("userid", ""),
            "storepath": "/", "sessionid": auth_params.get("sessionid", ""),
            "expires": auth_params.get("expires", ""), "appname": _BLOCKSTOCK_APPNAME,
            "storetype": "2", "clienttype": _MULTISTORAGE_CLIENTTYPE, "version": "0",
        }
        try:
            resp = self._http.post(
                _MULTISTORAGE_URL, data=data, headers=self._headers(),
                cookies=self._cookies_dict(), timeout=_HTTP_TIMEOUT,
            )
            resp.raise_for_status()
        except requests.RequestException as exc:
            raise BlockNetworkError("blockstock download", str(exc)) from exc
        return parse_blockstock_response(resp.content)

    def _upload_blockstock(self, auth_params: dict[str, str], group_name: str, group_type: int, stock_list: list[StockEntry], version: str) -> dict[str, Any]:
        payload_bytes = encode_blockstock_payload(group_name, group_type, stock_list)
        data = {
            "appname": _BLOCKSTOCK_APPNAME, "reqtype": "upload", "version": str(version),
            "storepath": "/", "clienttype": _MULTISTORAGE_CLIENTTYPE,
            "compresstype": "none", "compresstype_upload": "none",
            "compresstype_download": "none",
            "userid": auth_params.get("userid", ""), "sessionid": auth_params.get("sessionid", ""),
            "expires": auth_params.get("expires", ""),
        }
        files = {"uploadFile": ("testFileList", payload_bytes, "application/octet-stream")}
        try:
            resp = self._http.post(
                _MULTISTORAGE_URL, data=data, files=files, headers=self._headers(),
                cookies=self._cookies_dict(), timeout=_HTTP_TIMEOUT,
            )
            resp.raise_for_status()
        except requests.RequestException as exc:
            raise BlockNetworkError("blockstock upload", str(exc)) from exc
        result = parse_blockstock_response(resp.content)
        if result.version:
            self._current_version = str(result.version)
        return {"version": result.version}

    # ── 辅助 ──

    def _check_writable(self, group_name: str) -> None:
        if group_name in (_SELF_STOCK_DEFAULT_NAME, _SELF_STOCK_GROUP_ID):
            return
        gid = self._find_group_id(group_name)
        if gid and gid.startswith(_DYNAMIC_GROUP_PREFIX):
            raise BlockReadOnlyError(f"动态板块 '{group_name}' 为只读，不能增删股票")

    # ── "我的自选"查询 ──

    def get_self_stocks(self) -> StockGroup:
        """获取"我的自选"列表。"""
        try:
            resp = self._http.get(
                f"{_SELFSTOCK_V2_BASE}{_SELFSTOCK_V2_LIST}",
                headers=self._headers(),
                cookies=self._cookies_dict(),
                timeout=_HTTP_TIMEOUT,
            )
            resp.raise_for_status()
        except requests.RequestException as exc:
            raise BlockNetworkError("我的自选", str(exc)) from exc

        payload = resp.json()
        self._check_v2_result(payload)
        result = payload.get("result", [])
        items: list[StockItem] = []
        for entry in result:
            if isinstance(entry, dict):
                code = str(entry.get("code", ""))
                marketid = str(entry.get("marketid", ""))
                mabbr = market_abbr(marketid) if marketid else None
                items.append(StockItem(code=code, market=mabbr))

        self._refresh_detail_best_effort("获取我的自选")
        for i, item in enumerate(items):
            meta = self._lookup_detail(item.code, item.market)
            if meta:
                items[i] = StockItem(
                    code=item.code, market=item.market,
                    price=meta.get("price"), added_at=meta.get("added_at"),
                )

        return StockGroup(
            name=_SELF_STOCK_DEFAULT_NAME,
            group_id=_SELF_STOCK_GROUP_ID,
            items=items,
        )

    # ── 动态板块查询 ──

    def query_dynamic_plate(self, condition: str, num: int = 3000) -> list[str]:
        """用问财条件实时查询成分股。返回 ["600519.SH", ...]"""
        url = f"{_DYNAMIC_PLATE_URL}?query={quote(condition)}&num={num}"
        try:
            resp = self._http.get(
                url, headers=self._headers(),
                cookies=self._cookies_dict(), timeout=_HTTP_TIMEOUT,
            )
        except requests.RequestException as exc:
            raise BlockNetworkError("动态板块", str(exc)) from exc

        if resp.status_code == 204 or not resp.content:
            return []

        try:
            payload = resp.json()
        except ValueError as exc:
            raise BlockAPIError("动态板块", f"响应非 JSON: {resp.text[:200]}") from exc

        result: list[str] = []
        stock_list = payload.get("stockList")
        if isinstance(stock_list, list):
            for c in stock_list:
                code = str(c.get("stock_code", ""))
                mkt = str(c.get("marketid", ""))
                mabbr = market_abbr(mkt) if mkt else mkt
                result.append(f"{code}.{mabbr}")
        else:
            data = payload.get("data") or {}
            if isinstance(data, dict):
                for c in data.get("codes", []):
                    code = str(c.get("code", ""))
                    mkt = str(c.get("market", ""))
                    mabbr = market_abbr(mkt) if mkt else mkt
                    result.append(f"{code}.{mabbr}")
        return result

    def list_dynamic_plates(self) -> dict[str, list[str]]:
        """列出所有动态板块及其成分股（云端快照，非实时计算）。"""
        groups = self.list_groups()
        result: dict[str, list[str]] = {}
        for g in groups:
            if g.is_dynamic:
                stocks = [f"{item.code}.{item.market}" for item in g.items if item.market]
                result[g.name] = stocks
        return result


def _merge_entries(
    current: list[StockEntry],
    new_entries: list[StockEntry],
    action: str,
) -> list[StockEntry]:
    """合并当前列表与增删变化，按 code 去重。"""
    current_map = {e.code: e for e in current}
    if action == "add":
        merged = dict(current_map)
        for e in new_entries:
            merged[e.code] = e
    elif action == "delete":
        delete_codes = {e.code for e in new_entries}
        merged = {c: e for c, e in current_map.items() if c not in delete_codes}
    else:
        raise BlockAPIError("批量操作", f"未知操作: {action}")
    return list(merged.values())
