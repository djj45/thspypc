#!/usr/bin/env python
"""Compare library constituent-connection wire bytes against clean captures.

Two data sources are supported:

1. ``--dump-dir DIR`` — live dumps produced by the library tracer
   (``THS_FRAME_DUMP_DIR``, see ``src/thspypc/_transport/tracing.py``).  Each
   socket becomes ``<role>/<stamp>_<seq>_<host>_{c2s,s2c}.bin`` plus
   ``*_frames.txt`` and ``*_meta.json``.
2. ``--build normal|level2`` — offline: rebuild the login + constituent
   bootstrap with the current builders and compare them against the clean
   client captures without touching the network.

Captures (kept in ``captures_live/``):

    normal  system_blocks_20260801_163756.pcap  stream 0  (pageid=4180)
    level2  system_blocks_20260801_164040.pcap  streams 0/1 (pageid=6000)

Three comparison depths are available (``--level``):

    stream  whole-direction raw byte streams
    frames  outer FD frame sequences (shows packaging/grouping differences)
    nested  flattened nested request bodies (semantic request bytes)

Usage:
    py tests/_compare_constituent_capture.py --dump-dir captures_live/frame_dump
    py tests/_compare_constituent_capture.py --build normal
    py tests/_compare_constituent_capture.py --build level2
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests")]

import capture_system_blocks as capture  # noqa: E402
from _analyze_clean_constituents import nested_frames, outer_frames  # noqa: E402
from thspypc.codecs.compression import normalize_8901_response  # noqa: E402
from thspypc.features.auth_protocol import (  # noqa: E402
    PC_LEVEL2_LOGIN_PROFILE,
    PC_STANDARD_LOGIN_PROFILE,
    LoginIdentity,
    build_login_body,
)
from thspypc.features.system_blocks_protocol import (  # noqa: E402
    build_board_constituent_bootstrap_stages,
    load_local_board_stocklink_ver,
)

PCAPS = {
    "normal": "system_blocks_20260801_163756.pcap",
    "level2": "system_blocks_20260801_164040.pcap",
}
DETAIL_PAGEID = {
    "normal": b"pageid=4180",
    "level2": b"pageid=6000",
}
CAP_MAC64 = "GHRdIuxqLKg7diotlao7dioNtao7diodpQ=="
CAP_PASSPORT64 = "vgYGgAAFzDqigorqU62cDKnbV104BTU6JCFc3BNIs1mSneWw"


def mask_credentials(body: bytes) -> bytes:
    """Blank account/device-specific values for structural comparison."""
    body = re.sub(b"Passport64=[^\r\n]*", b"Passport64=<masked>", body)
    body = re.sub(b"Mac64=[^\r\n]*", b"Mac64=<masked>", body)
    return body


def first_diff(left: bytes, right: bytes) -> int:
    """Byte offset of the first difference; -1 when equal (same length)."""
    common = min(len(left), len(right))
    for index in range(common):
        if left[index] != right[index]:
            return index
    if len(left) != len(right):
        return common
    return -1


def digest(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()[:12]


def request_items(frames: list[bytes]) -> list[tuple[str, bytes]]:
    """Flatten outer frames into semantic request items.

    Frames carrying nested ``\\x00\\x16`` requests are split into their nested
    payloads; plain text frames (login, subreal, qureal-init...) are kept as a
    single item so different outer-frame packaging still aligns.
    """
    items: list[tuple[str, bytes]] = []
    for body in frames:
        nested = list(nested_frames(body))
        if nested:
            for item in nested:
                kind = f"{item['subtype']:02x}@{item['route']:02x}"
                items.append((kind, mask_credentials(item["payload"])))
        else:
            kind = "plain"
            if b"Ask=login" in body:
                kind = "login"
            elif b"Reply=login" in body:
                kind = "login-reply"
            items.append((kind, mask_credentials(body)))
    return items


def frame_hint(body: bytes) -> str:
    text = body.decode("gbk", errors="replace")
    method = re.search(r"method=(\w+)", text)
    page = re.search(r"pageid=(\d+)", text)
    market = re.search(r"market=(\w+)", text)
    method_text = method.group(1) if method else "-"
    page_text = page.group(1) if page else "-"
    market_text = market.group(1) if market else "-"
    return f"{method_text}/page={page_text}/mkt={market_text}"


def hd3_signature(body: bytes) -> list[str]:
    """Summarise every hd3.1 table as flag=0x.. rc=N rec=N fields=N."""
    try:
        norm = (
            normalize_8901_response(body)
            if body.startswith(b"\x0a")
            else body
        )
    except Exception:
        return []
    signatures = []
    for match in re.finditer(b"hd3\\.1\x00", norm):
        tail = norm[match.start() :]
        if len(tail) < 16:
            continue
        rc, flag, rec_size, fields = struct.unpack_from("<IHHH", tail, 6)
        signatures.append(
            f"0x{flag:x}/rc={rc}/rec={rec_size}/fc={fields}"
        )
    return signatures


def extract_streams(pcap_name: str) -> list[tuple[str, bytes, bytes]]:
    path = ROOT / "captures_live" / pcap_name
    return list(capture._tshark_streams(str(path), 8901))


def classify_side(client: bytes, detail: bytes) -> str:
    """Classify a candidate stream as sh/sz by its first detail request."""
    for body in outer_frames(client):
        if detail not in body:
            continue
        markets: set[str] = set()
        for item in request_items([body]):
            text = item[1].decode("gbk", errors="replace")
            for market, _values in re.findall(
                r"CodeList=(-?\d+)\(([^)]*)\)", text
            ):
                markets.add(market)
        if markets & {"33", "32"}:
            return "sz"
        if markets & {"17", "16", "144"}:
            return "sh"
        return ""
    return ""


def constituent_streams(
    pcap_name: str,
) -> dict[str, dict]:
    account = "level2" if pcap_name == PCAPS["level2"] else "normal"
    detail = DETAIL_PAGEID[account]
    result: dict[str, dict] = {}
    for sid, client, server in extract_streams(pcap_name):
        if detail not in client:
            continue
        side = classify_side(client, detail)
        if not side:
            continue
        result[side] = {
            "sid": sid,
            "client": client,
            "server": server,
            "frames_c": outer_frames(client),
            "frames_s": outer_frames(server),
        }
    return result


def compare_sequences(
    label: str,
    mine: list[bytes],
    captured: list[bytes],
    *,
    max_diff: int,
    title: str,
) -> int:
    """Index-aligned byte comparison; returns the number of differing frames."""
    count = min(len(mine), len(captured))
    diffs = []
    for index in range(count):
        left = mask_credentials(mine[index])
        right = mask_credentials(captured[index])
        offset = first_diff(left, right)
        if offset >= 0:
            diffs.append((index, offset, len(mine[index]), len(captured[index])))
    print(f"  {title}: mine={len(mine)} captured={len(captured)} "
          f"compared={count} identical={count - len(diffs)} differ={len(diffs)}")
    for index, offset, left_len, right_len in diffs[:max_diff]:
        left = mine[index]
        right = captured[index]
        left = mask_credentials(left)
        right = mask_credentials(right)
        print(
            f"    frame[{index:03d}] {label} differ@{offset} "
            f"len {left_len}B vs {right_len}B "
            f"mine={frame_hint(left)} capture={frame_hint(right)}"
        )
        window = max(0, offset - 8)
        print("      mine:", left[window : offset + 24].hex(" "))
        print("      cap :", right[window : offset + 24].hex(" "))
    return len(diffs)


def compare_pair(
    label: str,
    mine_c2s: bytes,
    mine_s2c: bytes,
    captured: dict,
    *,
    levels: set[str],
    max_diff: int,
) -> None:
    cap_c2s = captured["client"]
    cap_s2c = captured["server"]
    print(
        f"\n== {label} vs capture stream {captured['sid']} "
        f"({len(cap_c2s)}B c2s / {len(cap_s2c)}B s2c) =="
    )

    if "stream" in levels:
        offset = first_diff(mine_c2s, cap_c2s)
        print(
            f"C2S raw stream: mine={len(mine_c2s)}B capture={len(cap_c2s)}B "
            f"{'IDENTICAL' if offset < 0 else f'differ@{offset}'}"
        )
        offset = first_diff(mine_s2c, cap_s2c)
        print(
            f"S2C raw stream: mine={len(mine_s2c)}B capture={len(cap_s2c)}B "
            f"{'IDENTICAL' if offset < 0 else f'differ@{offset}'}"
        )

    mine_frames_c = outer_frames(mine_c2s)
    mine_frames_s = outer_frames(mine_s2c)
    if "frames" in levels:
        compare_sequences(
            "C->S",
            mine_frames_c,
            captured["frames_c"],
            max_diff=max_diff,
            title="C2S outer frames",
        )
        compare_sequences(
            "S->C",
            mine_frames_s,
            captured["frames_s"],
            max_diff=max_diff,
            title="S2C outer frames",
        )

    if "nested" in levels:
        mine_items = request_items(mine_frames_c)
        cap_items = request_items(captured["frames_c"])
        count = min(len(mine_items), len(cap_items))
        diffs = []
        for index in range(count):
            offset = first_diff(mine_items[index][1], cap_items[index][1])
            if offset >= 0:
                diffs.append(
                    (
                        index,
                        mine_items[index][0],
                        cap_items[index][0],
                        offset,
                        len(mine_items[index][1]),
                        len(cap_items[index][1]),
                    )
                )
        print(
            f"  C2S flattened requests: mine={len(mine_items)} "
            f"capture={len(cap_items)} compared={count} "
            f"identical={count - len(diffs)} differ={len(diffs)}"
        )
        for index, mine_kind, cap_kind, offset, left_len, right_len in diffs[:max_diff]:
            print(
                f"    item[{index:03d}] differ@{offset} len {left_len}B vs "
                f"{right_len}B mine={mine_kind} capture={cap_kind}"
            )

    print(
        f"  S2C frames: mine={len(mine_frames_s)} capture={len(captured['frames_s'])}"
    )
    for index, body in enumerate(mine_frames_s[:6]):
        sig = hd3_signature(body)
        print(
            f"    mine[{index:03d}] {len(body)}B "
            f"hd3={','.join(sig) if sig else 'none'} {frame_hint(body)}"
        )
    for index, body in enumerate(captured["frames_s"][:6]):
        sig = hd3_signature(body)
        print(
            f"    cap [{index:03d}] {len(body)}B "
            f"hd3={','.join(sig) if sig else 'none'} {frame_hint(body)}"
        )


def built_frames(
    account: str,
    side: str,
) -> list[bytes]:
    """Rebuild login + constituent bootstrap with the current builders."""
    if account == "level2":
        identity = LoginIdentity.STANDARD if side == "sh" else LoginIdentity.MANUAL
        profile = PC_LEVEL2_LOGIN_PROFILE
    else:
        identity = LoginIdentity.STANDARD
        profile = PC_STANDARD_LOGIN_PROFILE
    login = build_login_body(
        CAP_PASSPORT64,
        CAP_MAC64,
        identity=identity,
        profile=profile,
    )
    stages = build_board_constituent_bootstrap_stages(
        account == "level2",
        side,
        stocklink_ver=load_local_board_stocklink_ver(),
    )
    return [login] + [frame for stage in stages for frame in stage]


def build_session(
    account: str,
    side: str,
) -> bytes:
    """Encode the built frame list into one C2S raw stream (FD + LF each)."""
    from thspypc.protocol import encode_frame

    return b"".join(encode_frame(frame) + b"\n" for frame in built_frames(account, side))


def load_dumps(dump_dir: Path) -> list[dict]:
    dumps = []
    for meta_path in sorted(dump_dir.glob("*/*_meta.json")):
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        prefix = meta_path.name[: -len("meta.json")]
        c2s_path = meta_path.with_name(f"{prefix}c2s.bin")
        s2c_path = meta_path.with_name(f"{prefix}s2c.bin")
        dumps.append(
            {
                "meta": meta,
                "c2s": c2s_path.read_bytes(),
                "s2c": s2c_path.read_bytes(),
            }
        )
    return dumps


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dump-dir", type=Path)
    parser.add_argument(
        "--build",
        choices=("normal", "level2"),
        help="offline: compare current builders against clean captures",
    )
    parser.add_argument(
        "--pcap",
        choices=("normal", "level2"),
        help="force capture kind (default: inferred)",
    )
    parser.add_argument(
        "--level",
        choices=("stream", "frames", "nested", "all"),
        default="all",
    )
    parser.add_argument("--max-diff", type=int, default=6)
    args = parser.parse_args()
    levels = {"stream", "frames", "nested"} if args.level == "all" else {args.level}

    pairs: list[tuple[str, bytes, bytes, str, str]] = []
    if args.build:
        account = args.build
        streams = constituent_streams(PCAPS[account])
        for side, captured in sorted(streams.items()):
            mine = build_session(account, side)
            label = f"[{account} side={side} built]"
            pairs.append((label, mine, b"", account, side))
    if args.dump_dir:
        for dump in load_dumps(args.dump_dir):
            meta = dump["meta"]
            role = str(meta["role"])
            if not role.startswith("board_constituent_"):
                continue
            account = args.pcap or ("level2" if meta.get("level2") else "normal")
            side = role.rsplit("_", 1)[-1]
            if account == "normal" and side != "sh":
                continue
            label = (
                f"[dump role={role} host={meta.get('host')} "
                f"login_ok={meta.get('login_ok')}]"
            )
            pairs.append((label, dump["c2s"], dump["s2c"], account, side))

    if not pairs:
        parser.error("need --dump-dir or --build")

    for label, mine_c2s, mine_s2c, account, side in pairs:
        streams = constituent_streams(PCAPS[account])
        captured = streams.get(side)
        if captured is None:
            print(f"{label}: no {side} constituent stream in {PCAPS[account]}")
            continue
        compare_pair(
            label,
            mine_c2s,
            mine_s2c,
            captured,
            levels=levels,
            max_diff=args.max_diff,
        )
    return 0


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    raise SystemExit(main())
