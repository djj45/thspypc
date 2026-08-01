#!/usr/bin/env python
"""Compare bootstrap/login roles of the clean board-page TCP streams."""
from __future__ import annotations

import hashlib
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "tests"), str(ROOT / "src")]

import capture_system_blocks as capture  # noqa: E402
from _analyze_clean_constituents import nested_frames, outer_frames  # noqa: E402


def masked_login(body: bytes) -> bytes:
    return re.sub(b"Passport64=[^\r\n]*", b"Passport64=<masked>", body)


def endpoints(path: Path) -> dict[str, tuple[str, str]]:
    run = subprocess.run(
        [
            capture.TSHARK, "-r", str(path),
            "-Y", "tcp.dstport==8901 and tcp.flags.syn==1",
            "-T", "fields", "-e", "tcp.stream", "-e", "ip.dst",
        ],
        capture_output=True, timeout=120, check=True,
    )
    result = {}
    for line in run.stdout.decode().splitlines():
        parts = line.split("\t")
        if len(parts) >= 2:
            result[parts[0]] = (parts[1], "8901")
    return result


def summarize(filename: str, detail_page: bytes) -> None:
    path = ROOT / "captures_live" / filename
    eps = endpoints(path)
    print(f"\n=== {filename} ===")
    for sid, client, server in capture._tshark_streams(str(path), 8901):
        frames = outer_frames(client)
        detail_index = next(
            (index for index, body in enumerate(frames) if detail_page in body),
            None,
        )
        login = next((body for body in frames if b"Ask=login" in body), b"")
        masked = masked_login(login)
        fields = masked.decode("gbk", errors="replace")
        identity = "manual" if "UserName=__manual" in fields else "board"
        pageids = {}
        landmarks = {}
        for index, body in enumerate(frames):
            text = body.decode("gbk", errors="replace")
            for pageid in re.findall(r"pageid=(\d+)", text):
                pageids[pageid] = pageids.get(pageid, 0) + 1
            for name, marker in (
                ("subreal", b"method=subreal"),
                ("market-init", b"MarketCode="),
                ("qureal", b"method=qureal"),
                ("classify", b"DataType=[5],[55]"),
                ("stockname", b"StockNameVer="),
            ):
                if marker in body:
                    landmarks.setdefault(name, index)
        nested_routes = []
        if detail_index is not None:
            for item in nested_frames(frames[detail_index]):
                nested_routes.append(
                    f"{item['subtype']:x}@{item['route']:x}"
                )
        print(
            f"stream={sid} peer={eps.get(sid)} cli={len(client)} srv={len(server)} "
            f"frames={len(frames)} login={len(login)}B/{identity}/"
            f"{hashlib.sha256(masked).hexdigest()[:10]} detail={detail_index} "
            f"routes={nested_routes}"
        )
        print(f"  landmarks={landmarks} pageids={pageids}")


if __name__ == "__main__":
    summarize("system_blocks_20260801_163756.pcap", b"pageid=4180")
    summarize("system_blocks_20260801_164040.pcap", b"pageid=6000")
