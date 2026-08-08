"""Local stock-name cache with per-segment ConfigVer (mirrors hexin).

Keeps the downloaded name_16_16 result in a text file under the user home
directory (cross-platform, no Windows client dependency). The stored
ConfigVer values are reported back in the next 0x001c StockNameVer frame so
the server can skip the full download when the local version is current.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

_CONFIG_RE = re.compile(rb"\[name_([^\]]+)\]\r?\nConfigVer=([^\r\n]+)")
_LINE_RE = re.compile(rb"^([^=\r\n]+)=([^\r\n|@]+)", re.M)


def default_cache_root() -> Path:
    return Path(os.path.expanduser("~")) / ".thspypc" / "stockname"


def default_cache_path(account_kind) -> Path:
    key = (
        account_kind.value
        if hasattr(account_kind, "value")
        else str(account_kind)
    )
    return default_cache_root() / f"stockname_{key}_0.txt"


def group_cache_path(group_key: str) -> Path:
    return default_cache_root() / f"stockname_{group_key}_0.txt"


def extract_config_vers(frame_body: bytes) -> dict[str, str]:
    """Extract {segment: ConfigVer} from a full name_16_16 response frame."""
    from ..codecs.compression import normalize_8901_response

    data = normalize_8901_response(frame_body)
    out: dict[str, str] = {}
    for match in _CONFIG_RE.finditer(data):
        segment = match.group(1).decode("ascii", errors="replace")
        version = match.group(2).decode("ascii", errors="replace")
        out.setdefault(segment, version)
    return out


def save_name_cache(
    names: dict[str, str],
    config_vers: dict[str, str],
    path: str | Path,
) -> Path:
    """Write the cache as hexin-style text: segments + ConfigVer + names."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    chunks: list[bytes] = []
    for segment in sorted(config_vers):
        chunks.append(
            f"[name_{segment}]\r\nConfigVer={config_vers[segment]}\r\n".encode(
                "ascii"
            )
        )
    for code, name in sorted(names.items()):
        line = f"{code}={name}\r\n".encode("gbk", errors="replace")
        chunks.append(line)
    path.write_bytes(b"".join(chunks))
    return path


def load_name_cache(
    path: str | Path,
) -> tuple[dict[str, str], dict[str, str]] | None:
    """Load (config_vers, names) from the cache; None when missing/broken."""
    path = Path(path)
    if not path.exists():
        return None
    try:
        data = path.read_bytes()
    except OSError:
        return None
    config_vers: dict[str, str] = {}
    names: dict[str, str] = {}
    current_segment: str | None = None
    for line in data.splitlines():
        if line.startswith(b"[name_"):
            match = re.match(rb"\[name_([^\]]+)\]", line)
            current_segment = (
                match.group(1).decode("ascii", errors="replace")
                if match
                else None
            )
            continue
        if current_segment is None:
            continue
        if line.startswith(b"ConfigVer="):
            config_vers[current_segment] = line[10:].decode(
                "ascii", errors="replace"
            )
            continue
        match = _LINE_RE.match(line)
        if match:
            code = match.group(1).decode("ascii", errors="replace")
            name = match.group(2).decode("gbk", errors="replace").strip()
            if code and name:
                names[code] = name
    if not config_vers:
        return None
    return config_vers, names


def build_version_value(
    config_vers: dict[str, str],
    markets: str,
) -> str:
    """Build the hexin ^B/^r/^n escaped StockNameVer value.

    Hexin repeats the per-segment list three times separated by ';'
    (base/real/history). The response only exposes one ConfigVer per segment,
    so the same list is repeated to keep the wire format compatible.
    """
    def segment_key(segment: str) -> tuple:
        prefix, _, suffix = segment.partition("_")
        try:
            prefix_num = int(prefix)
        except ValueError:
            prefix_num = prefix
        try:
            suffix_num = int(suffix)
        except ValueError:
            suffix_num = suffix
        return (prefix_num, suffix_num)

    group = []
    for segment in sorted(config_vers, key=segment_key):
        group.append(
            f"^bname_{segment}^B^r^nConfigVer^e{config_vers[segment]}^r^n"
        )
    value = "".join(group)
    return ";".join([value, value, value])


__all__ = [
    "build_version_value",
    "default_cache_path",
    "default_cache_root",
    "extract_config_vers",
    "group_cache_path",
    "load_name_cache",
    "save_name_cache",
]
