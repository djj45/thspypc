"""Socket-level diagnostic for the Level2 historical closing-auction replay.

Unlike ``probe_l2_history_closing_replay.py`` (which only counts frames that
parse into closing points), this script records, for EVERY received frame, the
raw byte count, cmd byte, echoed seq, and whether it carries an hd1.0/hd3.1
table. This distinguishes four failure modes the probe cannot:

  1. socket silence (server ignores the request);
  2. TCP FIN / connection reset (login-state problem);
  3. a short empty-ACK frame (session/permission problem);
  4. a long data frame that returns 0 points (parser bug, not session).

Privacy: credentials are loaded from ``.env`` and never printed. Only frame
sizes, cmd/seq bytes, and structural markers are reported.
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
from thspypc.features.auction_protocol import parse_closing_auction_response
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


def extract_client_bodies(pcap: Path, *, stream: int, tshark: Path) -> list[bytes]:
    result = subprocess.run(
        [str(tshark), "-r", str(pcap), "-Y",
         f"tcp.stream=={stream} and tcp.dstport==8901 and tcp.len>0",
         "-T", "fields", "-e", "tcp.payload"],
        check=True, capture_output=True, timeout=120,
    )
    wire = bytes.fromhex("".join(result.stdout.decode("ascii", "ignore").split()))
    bodies: list[bytes] = []
    cursor = 0
    while True:
        marker = wire.find(FRAME_MAGIC, cursor)
        if marker < 0 or marker + 12 > len(wire):
            break
        try:
            size = int(wire[marker + 4:marker + 12], 16)
        except ValueError:
            cursor = marker + 4
            continue
        bodies.append(wire[marker + 12:marker + 12 + size])
        cursor = marker + 12 + size
    return bodies


def summarize_frame(frame: bytes, index: int) -> str:
    """Describe one received frame without exposing credentials."""
    seq = ""
    if len(frame) > 7 and frame[0] == 0x09:
        seq = " seq=0x%04x" % struct.unpack_from("<H", frame, 5)[0]
    cmd = "0x%02x" % frame[0] if frame else "??"
    markers = []
    for tag in (b"hd1.0", b"hd3.1", b"MarketTime", b"VerifyCode", b"603118"):
        if frame.find(tag) >= 0:
            markers.append(tag.decode("ascii", "replace"))
    try:
        pts = len(parse_closing_auction_response(frame))
    except Exception:
        pts = 0
    pts_tag = f" pts={pts}" if pts else ""
    marker_tag = (" [" + ",".join(markers) + "]") if markers else ""
    return (f"  frame[{index}] {len(frame):5}B cmd={cmd}{seq}{marker_tag}"
            f"{pts_tag}")


def send_and_trace(sock: socket.socket, bodies: list[bytes], *, label: str,
                   idle: float = 1.5, limit: float = 12.0) -> list[bytes]:
    """Send request bodies, then capture every reply frame with diagnostics."""
    print(f"\n=== {label}: sending {len(bodies)} request frame(s) ===")
    for body in bodies:
        sock.sendall(encode_frame(body) + b"\n")
        time.sleep(0.003)

    frames: list[bytes] = []
    deadline = time.monotonic() + limit
    closing_state = "open"
    while time.monotonic() < deadline:
        sock.settimeout(min(idle, max(0.05, deadline - time.monotonic())))
        try:
            frames.append(read_frame(sock))
        except socket.timeout:
            break
        except ConnectionError as exc:
            closing_state = f"FIN/CLOSED ({exc})"
            break
        except OSError as exc:
            closing_state = f"socket-error ({exc})"
            break
    print(f"{label}: received {len(frames)} reply frame(s); socket={closing_state}")
    for i, frame in enumerate(frames):
        print(summarize_frame(frame, i))
    return frames


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("pcap", type=Path)
    parser.add_argument("--stream", type=int, default=19)
    parser.add_argument("--host", default="8.134.115.123")
    parser.add_argument("--code", default="603118")
    parser.add_argument("--tshark", type=Path, default=DEFAULT_TSHARK)
    parser.add_argument(
        "--mode", choices=["current_only", "history_only", "full"],
        default="full",
        help="current_only: replay current 4214 then stop; "
             "history_only: replay only history 4417; "
             "full: startup + current + history (default)",
    )
    parser.add_argument(
        "--dump", type=Path, default=None,
        help="optional path to write the LAST received reply frame for "
             "offline decoding (no credentials are sent, only server data)",
    )
    args = parser.parse_args()

    bodies = extract_client_bodies(
        args.pcap, stream=args.stream, tshark=args.tshark,
    )
    code = args.code.encode("ascii")
    init = [b for b in bodies
            if b"C-Language=2052" in b or b"StockNameVer=" in b]
    current = [b for b in bodies
               if code in b and b"pageid=4214" in b
               and b"DateTime=7424" in b]
    history = [b for b in bodies
               if code in b and b"pageid=4417" in b
               and b"DateTime=7424(" in b]
    print(f"capture selection: init={len(init)}, "
          f"current4214={len(current)}, history4417={len(history)}")

    load_env()
    client = THSClient(
        os.environ["THS_USERNAME"],
        os.environ["THS_PASSWORD"],
        imei=os.environ.get("THS_IMEI") or None,
        enable_heartbeat=False,
    )
    client.authenticate(force=True)
    login = client._auth_service.login_body_for_passport(
        client._current_passport64(), LoginIdentity.STANDARD,
    )

    sock = socket.create_connection((args.host, 8901), timeout=15.0)
    try:
        sock.sendall(encode_frame(login) + b"\n")
        sock.settimeout(8.0)
        try:
            reply = read_frame(sock)
        except (socket.timeout, ConnectionError) as exc:
            print(f"LOGIN FAILED: {type(exc).__name__}: {exc}")
            return 3
        ok = b"VerifyCode=0" in reply
        print(f"login to {args.host}:8901 -> VerifyCode={'0 (OK)' if ok else 'NON-ZERO'}")
        if not ok:
            # report only the non-sensitive VerifyCode line
            idx = reply.find(b"VerifyCode=")
            print("  ", reply[idx:idx + 20].decode("gbk", "replace"))
            return 3

        if args.mode in ("full",):
            send_and_trace(sock, bodies[1:next(i for i, b in enumerate(bodies)
                          if code in b and b"pageid=4214" in b)],
                          label="startup")
        if args.mode in ("current_only", "full") and current:
            frames = send_and_trace(
                sock, current, label="CURRENT 4214 (today 14:57-15:00)")
            if args.dump and frames:
                args.dump.write_bytes(frames[-1])
                print(f"  dumped last reply frame -> {args.dump}")
        if args.mode in ("history_only", "full") and history:
            frames = send_and_trace(
                sock, history, label="HISTORY 4417 (2026-07-24 14:57-15:00)")
            if args.dump and frames:
                args.dump.write_bytes(frames[-1])
                print(f"  dumped last reply frame -> {args.dump}")
    finally:
        sock.close()
        client.disconnect()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
