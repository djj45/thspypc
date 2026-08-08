# -*- coding: utf-8 -*-
"""Stock-name cold-start bootstrap builders.

The 0x001c StockNameVer cold-start sequences are generated from structured
templates (``stock_name_bootstrap_data.json``) captured from hexin on
2026-08-08, instead of embedding raw hex. Each compound frame is a 0x09
prefix plus one or more binary subframes:

    \\x00\\x16 | \\x00\\x00 | route(2) | \\x12\\x00 | subtype(2)
    | field_a(4) | field_b(4) | LE32(len) | text

The builders reproduce the captured bytes exactly; tests assert equality
against the captured templates when they are available.
"""
from __future__ import annotations

import base64
import json
import struct
from pathlib import Path

_DATA_PATH = Path(__file__).with_name("stock_name_bootstrap_data.json")


def _pack_subreal(market: str, cls: str, pageid: int) -> bytes:
    text = (
        "instid=2147483647\nmethod=subreal\n"
        f"market={market}\nperiod=0\naction=change\nclass={cls}\n"
        f"codelist= \npageid={pageid}\n"
    ).encode()
    return b"\x09" + text[:-1]


def _pack_subframe(entry: dict, text: bytes) -> bytes:
    return (
        b"\x00\x16\x00\x00"
        + bytes.fromhex(entry["route"])
        + b"\x12\x00"
        + bytes.fromhex(entry["subtype"])
        + bytes.fromhex(entry["field_a"])
        + bytes.fromhex(entry["field_b"])
        + struct.pack("<I", entry["length"])
        + text
    )


def _build_frames(entries: list[dict]) -> tuple[bytes, ...]:
    frames = []
    for entry in entries:
        if entry["kind"] == "subreal":
            frames.append(
                _pack_subreal(entry["market"], entry["cls"], entry["pageid"])
            )
        elif entry["kind"] == "subframe":
            frames.append(
                b"\x09"
                + b"".join(
                    _pack_subframe(
                        sub, base64.b64decode(sub["text_b64"])
                    )
                    for sub in entry["subs"]
                )
            )
        elif entry["kind"] == "upstockname":
            text = (
                "instid=65536\nmethod=upstockname\n"
                f"market={entry['market']}\nStockNameVer=;;\n"
                "prototype=kvproto\n"
                f"pageid={entry['pageid']}\n"
            ).encode()
            frames.append(b"\x09" + text[:-1])
        else:
            frames.append(base64.b64decode(entry["body_b64"]))
    return tuple(frames)


def _load_templates() -> dict:
    return json.loads(_DATA_PATH.read_text(encoding="utf-8"))


_TEMPLATES = _load_templates()
_GROUPS_PATH = Path(__file__).with_name("stock_name_groups_data.json")
_GROUPS = json.loads(_GROUPS_PATH.read_text(encoding="utf-8"))


def build_group_frames(group_key: str) -> tuple[bytes, ...]:
    """Build the captured cold-start frames for one market group."""
    return _build_frames(_GROUPS[group_key]["frames"])


def stock_name_group(group_key: str) -> dict:
    """Return (domain, markets, pageid) metadata for a market group."""
    entry = _GROUPS[group_key]
    return {
        "domain": entry["domain"],
        "markets": entry["markets"],
        "pageid": entry["pageid"],
    }


LEVEL2_BOOTSTRAP_FRAMES = _build_frames(_TEMPLATES["level2_plain"])
LEVEL2_VERSIONED_BOOTSTRAP_FRAMES = _build_frames(
    _TEMPLATES["level2_versioned"]
)
STANDARD_BOOTSTRAP_FRAMES = _build_frames(_TEMPLATES["standard"])

STOCK_NAME_DOMAINS = {
    "level2": "shlv2.123ths.com",
    "standard": "main.123ths.com",
}

STOCK_NAME_GROUPS = {
    "level2": [
        "level2_16", "level2_32", "fu4_96", "hkus_176",
        "hkus_168", "ifindhq_120", "fu2_64", "usotc_UNS",
    ],
    "standard": [
        "standard_32", "standard_hkus_176", "standard_fu4_96",
        "standard_ifindhq_120", "standard_fu2_64", "standard_usotc_UNS",
    ],
}

__all__ = [
    "LEVEL2_BOOTSTRAP_FRAMES",
    "LEVEL2_VERSIONED_BOOTSTRAP_FRAMES",
    "STANDARD_BOOTSTRAP_FRAMES",
    "STOCK_NAME_DOMAINS",
    "STOCK_NAME_GROUPS",
    "build_group_frames",
    "stock_name_group",
]