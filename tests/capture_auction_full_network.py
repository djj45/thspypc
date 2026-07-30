"""Capture the cold Hexin auction flow without restricting it to port 8901.

The earlier auction capture proved that the historical closing response is
delivered on 8901, but an additional session trigger is missing from an
independent replay.  This capture intentionally includes all TCP ports so the
trigger can be found.

Use ``--market sz`` to capture a Shenzhen (深市) closing-auction flow instead
of the default Shanghai (沪市) one; the on-screen guidance and output filename
adjust accordingly.

Privacy note: close browsers, mail clients, chat clients, and other networked
applications first.  This pcap can contain plaintext application data.
"""
from __future__ import annotations

import argparse
import datetime as dt
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CAPTURE_DIR = ROOT / "captures_live"
WIRESHARK_DIR = Path(
    r"D:\software\Wireshark_4.6.7_Portable\Wireshark"
    r"\WiresharkPortable64\App\Wireshark"
)
DUMPCAP = WIRESHARK_DIR / "dumpcap.exe"
TSHARK = WIRESHARK_DIR / "tshark.exe"
MAX_KIB = 256 * 1024


def interfaces() -> list[tuple[str, str]]:
    result = subprocess.run(
        [str(TSHARK), "-D"],
        check=True,
        capture_output=True,
        encoding="gbk",
        errors="replace",
        timeout=15,
    )
    rows = []
    for line in result.stdout.splitlines():
        number, separator, description = line.partition(". ")
        if separator and number.isdigit():
            rows.append((number, description))
    return rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--duration", type=int, default=60)
    parser.add_argument("--interface")
    parser.add_argument(
        "--market", choices=["sh", "sz"], default="sh",
        help="which market to capture: sh=Shanghai (603118), sz=Shenzhen (000001)",
    )
    args = parser.parse_args()
    if not DUMPCAP.exists():
        raise FileNotFoundError(DUMPCAP)
    if not 1 <= args.duration <= 60:
        raise ValueError("duration must be between 1 and 60 seconds")

    available = interfaces()
    for number, description in available:
        print(f"{number}. {description}")
    selected = args.interface
    if selected is None:
        wlan = next(
            (
                number
                for number, description in available
                if "WLAN" in description
            ),
            available[0][0],
        )
        selected = input(f"Interface [{wlan}]: ").strip() or wlan

    CAPTURE_DIR.mkdir(exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    output = CAPTURE_DIR / f"auction_full_{args.market}_{stamp}.pcapng"
    sample_code = "000001" if args.market == "sz" else "603118"
    market_name = "Shenzhen (深市)" if args.market == "sz" else "Shanghai (沪市)"
    print()
    print("Before continuing, fully exit Hexin and other networked apps.")
    print("During capture:")
    print(f"  1. Start Hexin and log in with the Level2 account.")
    print(f"  2. Open {sample_code} ({market_name}) current timeline and wait 3 seconds.")
    print(f"  3. Select a past trading day (e.g. 2026-07-24) and wait 5 seconds.")
    print(f"  4. Move the cursor over 14:57-15:00 (closing auction), then leave it open.")
    print()
    input("Press Enter to begin the full TCP capture...")
    subprocess.run(
        [
            str(DUMPCAP),
            "-i",
            selected,
            "-f",
            "tcp",
            "-w",
            str(output),
            "-a",
            f"duration:{args.duration}",
            "-a",
            f"filesize:{MAX_KIB}",
        ],
        check=True,
    )
    print(f"Capture complete: {output} ({output.stat().st_size:,} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
