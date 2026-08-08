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
        else:
            frames.append(base64.b64decode(entry["body_b64"]))
    return tuple(frames)


def _load_templates() -> dict:
    return json.loads(_DATA_PATH.read_text(encoding="utf-8"))


_TEMPLATES = _load_templates()

LEVEL2_BOOTSTRAP_FRAMES = _build_frames(_TEMPLATES["level2_plain"])
LEVEL2_VERSIONED_BOOTSTRAP_FRAMES = _build_frames(
    _TEMPLATES["level2_versioned"]
)
STANDARD_BOOTSTRAP_FRAMES = _build_frames(_TEMPLATES["standard"])

STOCK_NAME_DOMAINS = {
    "level2": "shlv2.123ths.com",
    "standard": "main.123ths.com",
}

__all__ = [
    "LEVEL2_BOOTSTRAP_FRAMES",
    "LEVEL2_VERSIONED_BOOTSTRAP_FRAMES",
    "STANDARD_BOOTSTRAP_FRAMES",
    "STOCK_NAME_DOMAINS",
]