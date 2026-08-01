#!/usr/bin/env python
"""Compare a clean captured constituent transaction with current builders."""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests")]

import capture_system_blocks as capture  # noqa: E402
from _analyze_clean_constituents import nested_frames, outer_frames  # noqa: E402
from thspypc.client import THSClient  # noqa: E402
from thspypc.codecs.framing import encode_frame  # noqa: E402
from thspypc.features.system_blocks_protocol import (  # noqa: E402
    build_board_constituents_sort_query,
    build_board_constituents_page_transition,
    parse_board_constituents_response,
    parse_board_constituents_selection_response,
)


def load_env(path: Path) -> dict[str, str]:
    result = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            result[key.strip()] = value.strip().strip("\"'")
    return result


def codelist(text: str) -> tuple[list[str], dict[str, str]]:
    line = next(line for line in text.splitlines() if line.startswith("CodeList="))
    codes = []
    markets = {}
    for market, values in re.findall(r"(-?\d+)\(([^)]*)\)", line):
        for code in (value for value in values.split(",") if value):
            codes.append(code)
            markets[code] = market
    return codes, markets


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--env", choices=("normal", "l2"), default="normal")
    args = parser.parse_args()
    env = load_env(ROOT / (".env.normal" if args.env == "normal" else ".env"))
    client = THSClient(
        env["THS_USERNAME"], env["THS_PASSWORD"],
        imei=env.get("THS_IMEI") or None,
    )
    result = client.connect()
    print("main", result.success, result.server)
    if not result.success:
        return 1
    board_open = len(client.board_quotes(["881121"], timeout=15))
    print("board-open", board_open)
    if not board_open:
        client.disconnect()
        return 2

    if args.env == "l2":
        streams = capture._tshark_streams(
            str(ROOT / "captures_live" / "system_blocks_20260801_164040.pcap"),
            8901,
        )
        for sid, outer_index in (("0", 127), ("1", 103)):
            _sid, client_bytes, _server_bytes = next(
                stream for stream in streams if stream[0] == sid
            )
            captured = encode_frame(outer_frames(client_bytes)[outer_index])
            rows = client._board_service._request_sequence(
                (build_board_constituents_page_transition(True), captured),
                parsers=(parse_board_constituents_response,),
                timeout=8.0,
                accept=lambda result: any(
                    len(str(record.get("code", ""))) == 6
                    for record in result
                ),
                interval=0.0,
            )
            print(
                f"raw-clean-l2-stream-{sid}", len(rows),
                [row.get("code") for row in rows[:3]],
            )
        client.disconnect()
        return 0

    streams = capture._tshark_streams(
        str(ROOT / "captures_live" / "system_blocks_20260801_163756.pcap"),
        8901,
    )
    _sid, client_bytes, _server_bytes = next(
        stream for stream in streams if stream[0] == "0"
    )
    captured_body = outer_frames(client_bytes)[165]
    captured_sort = next(
        item for item in nested_frames(captured_body)
        if item["subtype"] == 0x0F
    )
    universe, markets = codelist(captured_sort["text"])
    print("captured-universe", len(universe), {
        market: sum(value == market for value in markets.values())
        for market in sorted(set(markets.values()))
    })

    wanted = set(universe)
    accept = lambda rows: any(row.get("code") in wanted for row in rows)
    rows = client._board_service._request(
        encode_frame(captured_body),
        parsers=(parse_board_constituents_selection_response,),
        timeout=4.0,
        accept=accept,
    )
    print("raw-clean-sort", len(rows), [row.get("code") for row in rows[:3]])

    visible, _ = codelist(next(nested_frames(captured_body))["text"])
    for route in (0x44, 0x46, 0x5C, 0x19):
        request = build_board_constituents_sort_query(
            universe,
            visible_codes=visible,
            route_base=route,
            markets=markets,
            seq=0x10A7,
        )
        rows = client._board_service._request(
            request,
            parsers=(parse_board_constituents_selection_response,),
            timeout=3.0,
            accept=accept,
        )
        print(f"built-route-{route:02x}", len(rows), [row.get("code") for row in rows[:3]])
        if rows:
            break
    client.disconnect()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
