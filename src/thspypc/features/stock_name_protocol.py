"""Stock-name synchronization request and partial response decoder."""
from __future__ import annotations

import logging
import re

from ..codecs.compression import normalize_8901_response
from ..codecs.framing import encode_frame


logger = logging.getLogger(__name__)

# Legacy fallback for raw, non-normalized streams. After normalize_8901_response,
# name_16_* A-share sections are plain GBK text and parse normally.
BLOCK_ENCODED_SEGMENTS = {"16_16", "168_16"}


def build_upstockname_request(
    market: str = "URS",
    stock_name_ver: str = ";;",
    pageid: int = 5716,
    instid: int = 65536,
) -> bytes:
    """Build the newline-delimited, unframed upstockname request body."""
    body = (
        f"instid={instid}\n"
        "method=upstockname\n"
        f"market={market}\n"
        f"StockNameVer={stock_name_ver}\n"
        "prototype=kvproto\n"
        f"pageid={pageid}\n"
    )
    return b"\x09" + body.encode("gbk")


def build_stock_name_ver_frame(
    markets: str = "16;144;208;",
    stock_name_ver: str = ";;",
    pageid: int = 5716,
) -> bytes:
    """Build the framed 0x001c StockNameVer request used by name sync.

    Byte-for-byte match with the hexin cold-start frame that triggered the
    full ``name_16_16`` download on 2026-08-08 (deleted-cache capture): a
    23-byte binary header with a LE32 text length at offset 19, followed by
    ``MarketCode=...\r\nStockNameVer=...\r\npageid=...\r``. Sending
    ``StockNameVer=;;`` makes the server treat market 16 as unversioned and
    return the full compressed name list.
    """
    text = (
        f"MarketCode={markets}\r\n"
        f"StockNameVer={stock_name_ver}\r\n"
        f"pageid={pageid}\r"
    ).encode("gbk")
    header = (
        b"\x09\x00\x16\x00\x00\x00\x00\x12\x00\x1c"
        + b"\x00" * 9
        + (len(text) + 1).to_bytes(4, "little")
    )
    return encode_frame(header + text)


def _iter_name_segments(body: bytes):
    """Yield ``(name, start, end)`` for each ``[name_*]`` section."""
    matches = list(re.finditer(rb"\[name_([^\]]+)\]", body))
    for index, match in enumerate(matches):
        name = (
            match.group(1)
            .replace(b"\x00", b"")
            .decode("ascii", errors="replace")
        )
        data_start = match.end()
        while (
            data_start < len(body)
            and body[data_start] in (0x0D, 0x0A, 0x00)
        ):
            data_start += 1
        data_end = (
            matches[index + 1].start()
            if index + 1 < len(matches)
            else len(body)
        )
        yield name, data_start, data_end


def _name_code_is_valid(code: str) -> bool:
    if not code or len(code) > 16:
        return False
    for character in code:
        value = ord(character)
        if value < 0x20 or value == 0x7F or 0x80 <= value <= 0x9F:
            return False
    return True


def _parse_name_text(segment_data: bytes) -> dict[str, str]:
    names: dict[str, str] = {}
    try:
        text = segment_data.decode("gbk", errors="replace")
    except (UnicodeDecodeError, ValueError):
        return names
    for line in text.splitlines():
        line = line.strip()
        if (
            not line
            or line.startswith("[")
            or line.startswith("ConfigVer")
            or "=" not in line
        ):
            continue
        # 历史名行形如 ``code=旧名@h1|旧名2@h2|...``（@hN 标志）。同一代码在
        # 响应里同时有 ``code=现名|别名@f`` 与历史行；若都解析会互相覆盖
        # （600664 被 "S哈药" 覆盖、000001 被 "深发展A" 覆盖），故跳过历史行。
        if "@h" in line:
            continue
        code, _, rest = line.partition("=")
        code = code.strip().lstrip("@")
        if not _name_code_is_valid(code):
            continue
        name = rest.split("|")[0].split("@")[0].strip()
        if (
            name
            and "\ufffd" not in name
            and not any(ord(character) < 0x20 for character in name)
        ):
            names[code] = name
    return names


_ST_PREFIX_RE = re.compile(r"^[S*]*ST")


def is_st_name(name: str) -> bool:
    """名称是否为风险警示股（ST/*ST/SST/S*ST 前缀）。

    风险警示股在 8901 里：沪市走独立风险警示板 17→22（2026-08-13 抓包确认
    600525/600745 请求走 CodeList=22(...)）；深市无独立市场码，仍用 33。
    """
    return bool(name) and _ST_PREFIX_RE.match(name.strip()) is not None


def st_market(base_market: int) -> int:
    """风险警示股市场码映射：仅沪市 17→22（风险警示板），其余原样。

    深市无独立的风险警示板市场码——002759 (ST天际) 实测仍用 market 33 返回
    行情，market 34 超时。
    """
    return 22 if base_market == 17 else base_market


def _is_block_encoded(segment_data: bytes) -> bool:
    try:
        text = segment_data.decode("gbk", errors="replace")
    except (UnicodeDecodeError, ValueError):
        return True
    valid = 0
    bad = 0
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
    """Decode text sections and report unresolved block-encoded sections.

    ``cmd=0x0a`` responses are LZ-expanded first (``name_16_*`` A-share
    streams arrive compressed); already-plaintext bodies pass through
    unchanged.

    盘中名称组/MAIN 连接上会混入行情推送等二进制帧，其 body 碰巧以
    ``0x0a`` 开头时（约 1/256）会被误当压缩流并在解压时抛
    ``ValueError``——调用方（``_collect_group`` 等）对此无捕获，会炸掉
    整次名称同步。与 ``parse_init_response`` 的处理对齐：解压失败按
    「非名称帧」返回空结果，由调用方跳过。
    """
    try:
        body = normalize_8901_response(body)
    except ValueError as exc:
        logger.debug("decode_name_frame: 0x0a 解压失败，视为非名称帧: %s", exc)
        return {
            "names": {},
            "by_segment": {},
            "skipped": [],
            "segments": [],
        }
    result = {
        "names": {},
        "by_segment": {},
        "skipped": [],
        "segments": [],
    }
    for segment_name, data_start, data_end in _iter_name_segments(body):
        segment_data = body[data_start:data_end]
        segment_names = _parse_name_text(segment_data)
        if segment_names:
            result["by_segment"][segment_name] = segment_names
            result["names"].update(segment_names)
            result["segments"].append(
                (segment_name, len(segment_data), "text")
            )
            logger.debug(
                "decode_name_frame: parsed text section [%s] -> %d names",
                segment_name,
                len(segment_names),
            )
            continue

        # Raw/legacy streams can still carry undecoded block payloads.
        if segment_name in BLOCK_ENCODED_SEGMENTS or _is_block_encoded(
            segment_data
        ):
            result["skipped"].append(segment_name)
            result["segments"].append(
                (segment_name, len(segment_data), "block")
            )
            logger.debug(
                "decode_name_frame: skipped block section [%s] (%dB)",
                segment_name,
                len(segment_data),
            )
            continue

        result["by_segment"][segment_name] = {}
        result["segments"].append(
            (segment_name, len(segment_data), "text")
        )
    return result


_BLOCK_ENCODED_SEGMENTS = BLOCK_ENCODED_SEGMENTS

__all__ = [
    "BLOCK_ENCODED_SEGMENTS",
    "build_stock_name_ver_frame",
    "build_upstockname_request",
    "decode_name_frame",
    "is_st_name",
    "st_market",
]
