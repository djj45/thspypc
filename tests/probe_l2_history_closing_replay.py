"""Replay the minimal cold-start path for Level2 historical closing auction.

This diagnostic intentionally reuses only request bodies observed in a known
PC-client capture.  The login passport is always freshly generated from
``.env``; credentials and passport contents are never printed or persisted.

Example:
    py tests/probe_l2_history_closing_replay.py \
        captures_live/auction_20260729_225956.pcap
"""
from __future__ import annotations

import argparse
import os
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from thspypc import THSClient
from thspypc.codecs.framing import FRAME_MAGIC, encode_frame, read_frame
from thspypc.features.auction_protocol import (
    parse_closing_auction_response,
)
from thspypc.features.auth_protocol import LoginIdentity


DEFAULT_TSHARK = Path(
    r"D:\software\Wireshark_4.6.7_Portable\Wireshark"
    r"\WiresharkPortable64\App\Wireshark\tshark.exe"
)


def load_env() -> None:
    for line in (ROOT / ".env").read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip("\"'"))


def extract_client_bodies(
    pcap: Path,
    *,
    stream: int,
    tshark: Path,
) -> list[bytes]:
    result = subprocess.run(
        [
            str(tshark),
            "-r",
            str(pcap),
            "-Y",
            f"tcp.stream=={stream} and tcp.dstport==8901 and tcp.len>0",
            "-T",
            "fields",
            "-e",
            "tcp.payload",
        ],
        check=True,
        capture_output=True,
        timeout=120,
    )
    wire = bytes.fromhex(
        "".join(result.stdout.decode("ascii", "ignore").split())
    )
    bodies: list[bytes] = []
    cursor = 0
    while True:
        marker = wire.find(FRAME_MAGIC, cursor)
        if marker < 0 or marker + 12 > len(wire):
            break
        try:
            size = int(wire[marker + 4 : marker + 12], 16)
        except ValueError:
            cursor = marker + 4
            continue
        body_start = marker + 12
        body_end = body_start + size
        if body_end > len(wire):
            raise ValueError(
                f"truncated client frame at {marker}: "
                f"need {size}, have {len(wire) - body_start}"
            )
        bodies.append(wire[body_start:body_end])
        cursor = body_end
    return bodies


def stream_endpoints(pcap: Path, *, tshark: Path) -> dict[int, str]:
    result = subprocess.run(
        [
            str(tshark),
            "-r",
            str(pcap),
            "-Y",
            "tcp.dstport==8901 and tcp.flags.syn==1 and tcp.flags.ack==0",
            "-T",
            "fields",
            "-e",
            "tcp.stream",
            "-e",
            "ip.dst",
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    )
    endpoints = {}
    for line in result.stdout.splitlines():
        stream_text, host = line.split("\t", 1)
        endpoints[int(stream_text)] = host
    return endpoints


def drain(sock: socket.socket, *, idle: float, limit: float) -> list[bytes]:
    frames: list[bytes] = []
    deadline = time.monotonic() + limit
    while time.monotonic() < deadline:
        sock.settimeout(min(idle, max(0.05, deadline - time.monotonic())))
        try:
            frames.append(read_frame(sock))
        except socket.timeout:
            break
    return frames


def report(label: str, frames: list[bytes]) -> int:
    matches = []
    for index, frame in enumerate(frames):
        rows = parse_closing_auction_response(frame)
        if rows:
            matches.append((index, len(frame), rows))
    print(f"{label}: {len(frames)} frames")
    for index, size, rows in matches:
        print(
            f"  response[{index}] {size}B: {len(rows)} closing points, "
            f"{rows[0]['time']} .. {rows[-1]['time']}"
        )
    return len(matches)


def send_group(
    sock: socket.socket,
    bodies: list[bytes],
    *,
    label: str,
) -> list[bytes]:
    print(f"{label}: sending {len(bodies)} captured request frames")
    for body in bodies:
        sock.sendall(encode_frame(body) + b"\n")
        time.sleep(0.003)
    return drain(sock, idle=1.0, limit=12.0)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("pcap", type=Path)
    parser.add_argument("--stream", type=int, default=0)
    parser.add_argument("--host", default="8.134.98.163")
    parser.add_argument("--code", default="603118")
    parser.add_argument("--tshark", type=Path, default=DEFAULT_TSHARK)
    parser.add_argument(
        "--full-startup",
        action="store_true",
        help="replay every post-login request before the target history query",
    )
    parser.add_argument(
        "--captured-login",
        action="store_true",
        help="diagnostic only: replay the capture's original login body",
    )
    parser.add_argument(
        "--history-delay",
        type=float,
        default=0.0,
        help="wait after page-4417 setup before sending the dated query",
    )
    parser.add_argument("--startup-delay", type=float, default=0.0)
    parser.add_argument("--current-delay", type=float, default=0.0)
    parser.add_argument(
        "--sequence-offset",
        type=lambda value: int(value, 0),
        default=0,
        help="add an offset to the final page-4417 request sequence numbers",
    )
    parser.add_argument(
        "--companion-logins",
        action="store_true",
        help="also keep the capture's other 8901 market sessions logged in",
    )
    args = parser.parse_args()

    bodies = extract_client_bodies(
        args.pcap,
        stream=args.stream,
        tshark=args.tshark,
    )
    code = args.code.encode("ascii")
    init = [
        body
        for body in bodies
        if b"C-Language=2052" in body or b"StockNameVer=" in body
    ]
    current = [
        body
        for body in bodies
        if code in body and b"pageid=4214" in body
    ]
    history = [
        body
        for body in bodies
        if code in body and b"pageid=4417" in body
    ]
    print(
        f"capture selection: init={len(init)}, "
        f"page4214={len(current)}, page4417={len(history)}"
    )
    if len(init) < 2 or not current or not history:
        raise RuntimeError("capture does not contain the expected cold-start path")

    client = None
    if args.captured_login:
        login = next(body for body in bodies if b"Ask=login" in body)
    else:
        load_env()
        username = os.environ["THS_USERNAME"]
        password = os.environ["THS_PASSWORD"]
        client = THSClient(
            username,
            password,
            imei=os.environ.get("THS_IMEI") or None,
            enable_heartbeat=False,
        )
        client.authenticate(force=True)
        login = client._auth_service.login_body_for_passport(
            client._current_passport64(),
            LoginIdentity.STANDARD,
        )

    companion_sockets: list[socket.socket] = []
    if args.companion_logins:
        for stream, host in stream_endpoints(
            args.pcap,
            tshark=args.tshark,
        ).items():
            if stream == args.stream:
                continue
            stream_bodies = extract_client_bodies(
                args.pcap,
                stream=stream,
                tshark=args.tshark,
            )
            stream_login = next(
                body for body in stream_bodies if b"Ask=login" in body
            )
            companion = socket.create_connection((host, 8901), timeout=15.0)
            companion.sendall(encode_frame(stream_login) + b"\n")
            companion.settimeout(8.0)
            reply = read_frame(companion)
            if b"VerifyCode=0" not in reply:
                companion.close()
                raise RuntimeError(
                    f"captured companion login rejected: stream={stream}"
                )
            companion_sockets.append(companion)
        print(f"companion sessions: {len(companion_sockets)} logged in")

    sock = socket.create_connection((args.host, 8901), timeout=15.0)
    try:
        sock.sendall(encode_frame(login) + b"\n")
        sock.settimeout(8.0)
        reply = read_frame(sock)
        if b"VerifyCode=0" not in reply:
            raise RuntimeError("fresh Level2 login was rejected")
        print(f"login accepted by {args.host}:8901")

        if args.full_startup:
            first_current = next(
                index
                for index, body in enumerate(bodies)
                if code in body and b"pageid=4214" in body
            )
            first_history = next(
                index
                for index, body in enumerate(bodies)
                if code in body and b"pageid=4417" in body
            )
            final_history = next(
                index
                for index, body in enumerate(bodies)
                if (
                    code in body
                    and b"pageid=4417" in body
                    and b"DateTime=8192(" in body
                )
            )
            report(
                "startup",
                send_group(
                    sock,
                    bodies[1:first_current],
                    label="startup",
                ),
            )
            if args.startup_delay:
                print(f"startup: waiting {args.startup_delay:g}s")
                time.sleep(args.startup_delay)
            report(
                "current page",
                send_group(
                    sock,
                    bodies[first_current:first_history],
                    label="current page",
                ),
            )
            if args.current_delay:
                print(f"current page: waiting {args.current_delay:g}s")
                time.sleep(args.current_delay)
            report(
                "history setup",
                send_group(
                    sock,
                    bodies[first_history:final_history],
                    label="history setup",
                ),
            )
            if args.history_delay:
                print(
                    f"history setup: waiting {args.history_delay:g}s "
                    "to match PC page dwell time"
                )
                time.sleep(args.history_delay)
            final_bodies = bodies[final_history:]
            if args.sequence_offset:
                adjusted = []
                for body in final_bodies:
                    mutable = bytearray(body)
                    if len(mutable) >= 7 and mutable[0] == 0x09:
                        sequence = struct.unpack_from("<H", mutable, 5)[0]
                        struct.pack_into(
                            "<H",
                            mutable,
                            5,
                            (sequence + args.sequence_offset) & 0xFFFF,
                        )
                    adjusted.append(bytes(mutable))
                final_bodies = adjusted
            history_frames = send_group(
                sock,
                final_bodies,
                label="history query",
            )
        else:
            report("init", send_group(sock, init, label="init"))
            report(
                "current page",
                send_group(sock, current, label="current page"),
            )
            history_frames = send_group(sock, history, label="history page")
        matches = report("history page", history_frames)
        return 0 if matches else 2
    finally:
        sock.close()
        for companion in companion_sockets:
            companion.close()
        if client is not None:
            client.disconnect()


if __name__ == "__main__":
    raise SystemExit(main())
