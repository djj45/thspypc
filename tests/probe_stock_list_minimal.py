"""Find the minimum startup sequence that triggers the full stock table.

Each invocation opens a fresh MAIN connection so state from one candidate
cannot make a later candidate appear sufficient.

Examples::

    uv run python tests/probe_stock_list_minimal.py --case single-trigger
    uv run python tests/probe_stock_list_minimal.py --case short-trigger
    uv run python tests/probe_stock_list_minimal.py --case subreal-trigger
    uv run python tests/probe_stock_list_minimal.py --case full-replay
"""
from __future__ import annotations

import argparse
import os
import socket
import struct
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from thspypc import THSClient  # noqa: E402
from thspypc import protocol  # noqa: E402
import thspypc.client as client_module  # noqa: E402
from thspypc.codecs.framing import FRAME_MAGIC, encode_frame, read_frame  # noqa: E402
from thspypc.features.stock_list_protocol import (  # noqa: E402
    build_full_stock_list_query,
    build_init_query,
    parse_init_response,
    parse_stock_list_replay,
)


def _load_env() -> None:
    path = ROOT / ".env"
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip("\"'"))


def _split_envelopes(segment: bytes) -> tuple[bytes, ...]:
    frames: list[bytes] = []
    offset = 0
    while offset < len(segment):
        while (
            offset < len(segment)
            and segment[offset] in b" \t\r\n"
        ):
            offset += 1
        if offset == len(segment):
            break
        if segment[offset : offset + 4] != FRAME_MAGIC:
            raise ValueError(f"replay magic mismatch at {offset}")
        size = int(segment[offset + 4 : offset + 12], 16)
        end = offset + 12 + size
        if end > len(segment):
            raise ValueError("replay envelope is truncated")
        frames.append(segment[offset:end])
        offset = end
    return tuple(frames)


def _split_subframes(envelope: bytes) -> tuple[bytes, ...]:
    body = envelope[12:]
    if not body.startswith(b"\x09"):
        raise ValueError("expected a nested 0x09 envelope")
    subframes: list[bytes] = []
    offset = 1
    while offset < len(body):
        if offset + 22 > len(body):
            raise ValueError("nested subframe header is truncated")
        text_size = int.from_bytes(
            body[offset + 18 : offset + 22],
            "little",
        )
        end = offset + 22 + text_size
        if end > len(body):
            # The captured TCP chunk ends after the final CR; the following
            # chunk supplied its LF.  Earlier complete subframes remain valid
            # minimization candidates.
            if end != len(body) + 1 or not body.endswith(b"\r"):
                raise ValueError("nested subframe body is truncated")
            end = len(body)
        subframes.append(body[offset:end])
        offset = end
    return tuple(subframes)


def _replay_frames() -> tuple[tuple[bytes, ...], ...]:
    path = ROOT / "src" / "thspypc" / "data" / "stock_list_replay.bin"
    return tuple(
        _split_envelopes(segment)
        for segment in parse_stock_list_replay(path.read_bytes())
    )


def _candidate(name: str) -> tuple[bytes, ...]:
    if name == "dt5-empty-markets":
        return (build_full_stock_list_query() + b"\n",)

    replay_path = (
        ROOT / "src" / "thspypc" / "data" / "stock_list_replay.bin"
    )
    replay_segments = parse_stock_list_replay(replay_path.read_bytes())
    replay = tuple(
        _split_envelopes(segment)
        for segment in replay_segments
    )
    subreal = replay[1][:8]
    subreal_twice = replay[1][:16]
    short_trigger = replay[1][16]
    trigger_subframes = [
        subframe
        for subframe in _split_subframes(short_trigger)
        if b"CodeList=16(1B0987,);" in subframe
    ]
    if not trigger_subframes:
        raise RuntimeError("captured short trigger has no 1B0987 subframe")
    single_trigger = encode_frame(b"\x09" + trigger_subframes[0])
    segment3_groups = (
        b"\n".join(replay[2][0:9]) + b"\n",
        replay[2][9] + b"\n",
        b"\n".join(replay[2][10:19]) + b"\n",
        replay[2][19] + b"\n",
        replay[2][20] + b"\n",
        b"\n".join(replay[2][21:30]) + b"\n",
        b"\n".join(replay[2][30:39]) + b"\n",
    )
    dt5_query = replay[2][9]
    dt5_body = dt5_query[12:]
    dt5_header = dt5_body[1:23]

    def build_dt5_variant(
        *,
        datatype: str = "[5],[55]",
        codelist: str | None,
    ) -> bytes:
        lines = [f"DataType={datatype}"]
        if codelist is not None:
            lines.append(f"CodeList={codelist}")
        lines.extend(("DateTime=0", "pageid=5716"))
        text = ("\r\n".join(lines) + "\r\n").encode("gbk")
        header = bytearray(dt5_header)
        struct.pack_into("<I", header, 18, len(text))
        return encode_frame(b"\x09" + bytes(header) + text)

    empty_markets = (
        "16();17();19();20();144();145();146();147();150();151();"
    )

    candidates = {
        "single-trigger": (single_trigger + b"\n",),
        "dt5-query": (dt5_query + b"\n",),
        "dt5-no-codelist": (
            build_dt5_variant(codelist=None) + b"\n",
        ),
        "dt5-empty-markets": (
            build_dt5_variant(codelist=empty_markets) + b"\n",
        ),
        "dt5-one-code": (
            build_dt5_variant(codelist="17(600000,);") + b"\n",
        ),
        "dt5-empty-16": (
            build_dt5_variant(codelist="16();") + b"\n",
        ),
        "dt5-only": (
            build_dt5_variant(
                datatype="[5]",
                codelist=empty_markets,
            )
            + b"\n",
        ),
        "dt55-only": (
            build_dt5_variant(
                datatype="[55]",
                codelist=empty_markets,
            )
            + b"\n",
        ),
        "trigger-dt5-query": (
            single_trigger + b"\n",
            dt5_query + b"\n",
        ),
        "subreal-trigger-dt5-query": (
            *tuple(frame + b"\n" for frame in subreal),
            single_trigger + b"\n",
            dt5_query + b"\n",
        ),
        "short-trigger": (short_trigger + b"\n",),
        "subreal-trigger": tuple(
            frame + b"\n"
            for frame in (*subreal, single_trigger)
        ),
        "subreal-short-trigger": tuple(
            frame + b"\n"
            for frame in (*subreal, short_trigger)
        ),
        "trigger-init": (
            single_trigger + b"\n",
            build_init_query() + b"\n",
        ),
        "init-trigger": (
            build_init_query() + b"\n",
            single_trigger + b"\n",
        ),
        "subreal-trigger-init": (
            *tuple(frame + b"\n" for frame in subreal),
            single_trigger + b"\n",
            build_init_query() + b"\n",
        ),
        "subreal-short-trigger-init": (
            *tuple(frame + b"\n" for frame in subreal),
            short_trigger + b"\n",
            build_init_query() + b"\n",
        ),
        "subreal16-short-trigger-init": (
            *tuple(frame + b"\n" for frame in subreal_twice),
            short_trigger + b"\n",
            build_init_query() + b"\n",
        ),
        "captured-init-chain": tuple(
            frame + b"\n"
            for frame in replay[1][:18]
        ),
        "segment1-captured-init-chain": (
            replay_segments[0],
            *tuple(frame + b"\n" for frame in replay[1][:18]),
        ),
        "trace-replay": replay_segments,
        "trace-segment3": (
            replay_segments[0],
            replay_segments[1],
            *segment3_groups,
        ),
        "full-replay": replay_segments,
    }
    return candidates[name]


def _read_full_table(
    sock,
    *,
    timeout: float,
    settle_timeout: float = 1.5,
) -> tuple[list[dict], int]:
    deadline = time.monotonic() + timeout
    full_at: float | None = None
    best: list[dict] = []
    frames_read = 0
    while time.monotonic() < deadline:
        if full_at is not None and time.monotonic() - full_at >= settle_timeout:
            break
        sock.settimeout(min(1.0, max(0.1, deadline - time.monotonic())))
        try:
            response = read_frame(sock)
        except socket.timeout:
            continue
        except ValueError:
            continue
        frames_read += 1
        metadata = parse_init_response(response)
        stocks = metadata["stocks"]
        if len(stocks) > len(best):
            best = stocks
        if any(
            frame["unk"] == 0x18 and frame["dc"] > 5000
            for frame in metadata["hd31_frames"]
        ):
            full_at = time.monotonic()
    return best, frames_read


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--case",
        required=True,
        choices=(
            "single-trigger",
            "dt5-query",
            "dt5-no-codelist",
            "dt5-empty-markets",
            "dt5-one-code",
            "dt5-empty-16",
            "dt5-only",
            "dt55-only",
            "trigger-dt5-query",
            "subreal-trigger-dt5-query",
            "short-trigger",
            "subreal-trigger",
            "subreal-short-trigger",
            "trigger-init",
            "init-trigger",
            "subreal-trigger-init",
            "subreal-short-trigger-init",
            "subreal16-short-trigger-init",
            "captured-init-chain",
            "segment1-captured-init-chain",
            "trace-replay",
            "trace-segment3",
            "full-replay",
        ),
    )
    parser.add_argument("--timeout", type=float, default=12.0)
    parser.add_argument(
        "--host",
        help="force one MAIN 8901 host for server-capability comparison",
    )
    args = parser.parse_args()

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    _load_env()
    username = os.environ.get("THS_USERNAME", "").strip()
    password = os.environ.get("THS_PASSWORD", "").strip()
    if not username or not password:
        raise RuntimeError(".env 缺少 THS_USERNAME/THS_PASSWORD")
    if args.host:
        protocol.MARKET_HOSTS[:] = [args.host]
        client_module.MARKET_HOSTS[:] = [args.host]
        client_module.resolve_market_hosts = lambda _passport: [args.host]

    packets = _candidate(args.case)
    client = THSClient(
        username,
        password,
        imei=os.environ.get("THS_IMEI", "").strip() or None,
        enable_heartbeat=False,
    )
    try:
        login = client.connect()
        if not login.success or client._sock is None:
            raise RuntimeError(f"登录失败: {login.error or login.detail}")
        started = time.monotonic()
        with client._sock_lock:
            if args.case.startswith("trace-"):
                stocks = []
                frames_read = 0
                for index, packet in enumerate(packets, 1):
                    client._sock.sendall(packet)
                    phase_stocks, phase_frames = _read_full_table(
                        client._sock,
                        timeout=3.0,
                        settle_timeout=0.5,
                    )
                    frames_read += phase_frames
                    if len(phase_stocks) > len(stocks):
                        stocks = phase_stocks
                    print(
                        f"PHASE={index} frames_read={phase_frames} "
                        f"stocks={len(phase_stocks)}"
                    )
            else:
                for index, packet in enumerate(packets):
                    client._sock.sendall(packet)
                    if (
                        args.case == "full-replay"
                        and index + 1 < len(packets)
                    ):
                        time.sleep(0.3)
                stocks, frames_read = _read_full_table(
                    client._sock,
                    timeout=args.timeout,
                )
        elapsed = time.monotonic() - started
        try:
            healthy = bool(
                client.list_quotes(
                    ["600000", "600519"],
                    market=17,
                    timeout=4.0,
                )
            )
        except (OSError, TimeoutError):
            healthy = False
        success = len(stocks) > 5000
        print(
            f"CASE={args.case} server={login.server} "
            f"packets={len(packets)} "
            f"bytes={sum(len(packet) for packet in packets)} "
            f"frames_read={frames_read} stocks={len(stocks)} "
            f"elapsed={elapsed:.2f}s healthy={healthy} "
            f"success={success}"
        )
        return 0 if success else 1
    finally:
        client.disconnect()


if __name__ == "__main__":
    raise SystemExit(main())
