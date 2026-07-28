"""Stock-name synchronization request and partial response decoder."""
from __future__ import annotations

import logging
import re


logger = logging.getLogger(__name__)

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
    """Decode text sections and report unresolved block-encoded sections."""
    result = {
        "names": {},
        "by_segment": {},
        "skipped": [],
        "segments": [],
    }
    for segment_name, data_start, data_end in _iter_name_segments(body):
        segment_data = body[data_start:data_end]
        base_name = (
            segment_name.split("_")[0]
            if "_" in segment_name
            else segment_name
        )
        is_block = (
            segment_name in BLOCK_ENCODED_SEGMENTS
            or base_name in ("16", "168")
            or _is_block_encoded(segment_data)
        )
        if is_block:
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

        segment_names = _parse_name_text(segment_data)
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
    return result


_BLOCK_ENCODED_SEGMENTS = BLOCK_ENCODED_SEGMENTS

__all__ = [
    "BLOCK_ENCODED_SEGMENTS",
    "build_upstockname_request",
    "decode_name_frame",
]
