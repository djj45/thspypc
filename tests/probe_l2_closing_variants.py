"""Probe Level2 historical closing-auction responses across SH/SZ stocks.

Sends a fresh-login historical closing-auction request (pageid=4417,
period=7424, 14:57-15:00) for each requested code, dumps every reply frame,
and reports structural diagnostics: frame size, hd1.0/hd3.1 presence, flag,
record_size, field_count, field list, and the byte-budget deficit of the
record region (positive = trailing truncation). This characterizes whether
the trailing-truncation seen on 603118 is a universal variant or stock-specific.

Privacy: credentials come from ``.env`` and are never printed. Only structural
metadata and per-stock closing prices (public market data) are reported.
"""
from __future__ import annotations

import argparse
import os
import socket
import struct
import sys
import time
from datetime import date
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from thspypc import THSClient
from thspypc.codecs.framing import encode_frame, read_frame
from thspypc.codecs.hd import _parse_hd_field_table
from thspypc.features.auction_protocol import (
    build_l2_closing_auction_query,
    parse_closing_auction_response,
)
from thspypc.features.auth_protocol import LoginIdentity


# A spread of SH (6xxxxx, 688xxx) and SZ (000xxx, 300xxx) liquid names.
DEFAULT_CODES = [
    ("603118", 17),   # SH main board
    ("600519", 17),   # SH main board (Moutai)
    ("688981", 17),   # SH STAR
    ("000001", 33),   # SZ main board (Pingan Bank)
    ("000938", 33),   # SZ main board (Intech)
    ("300033", 33),   # SZ ChiNext (Tonghuashun)
]


def load_env() -> None:
    for line in (ROOT / ".env").read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip("\"'"))


def analyze(frame: bytes) -> dict:
    info: dict = {"size": len(frame), "cmd": frame[0] if frame else None}
    for mk in (b"hd1.0", b"hd3.1"):
        idx = frame.find(mk)
        if idx < 0:
            continue
        base = idx + 6
        if len(frame) < base + 10:
            continue
        rc, flag, rs, fc = struct.unpack_from("<IHHH", frame, base)
        count = rc & 0xFFFF
        fields = _parse_hd_field_table(frame, base + 10, fc) if 0 < fc < 64 else []
        shell = base + 10 + fc * 4
        need = count * rs
        avail = len(frame) - shell
        info.update({
            "marker": mk.decode(), "flag": flag, "rec_size": rs,
            "field_count": fc, "record_count": count, "fields": fields,
            "deficit": need - avail,
        })
        break
    try:
        info["parsed_pts"] = len(parse_closing_auction_response(frame))
    except Exception:
        info["parsed_pts"] = 0
    return info


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="122.9.202.190")
    p.add_argument("--date", default="2026-07-24")
    p.add_argument("--dump-dir", default="captures_live/_variant_dump")
    p.add_argument("--codes", nargs="*", default=None,
                   help="override default code list as CODE:MARKET pairs")
    args = p.parse_args()

    trade_date = date.fromisoformat(args.date)
    codes = (DEFAULT_CODES if args.codes is None else
             [(c.split(":")[0], int(c.split(":")[1])) for c in args.codes])
    dump = Path(args.dump_dir)
    dump.mkdir(parents=True, exist_ok=True)

    load_env()
    client = THSClient(
        os.environ["THS_USERNAME"], os.environ["THS_PASSWORD"],
        imei=os.environ.get("THS_IMEI") or None, enable_heartbeat=False,
    )
    client.authenticate(force=True)
    login = client._auth_service.login_body_for_passport(
        client._current_passport64(), LoginIdentity.STANDARD,
    )

    sock = socket.create_connection((args.host, 8901), timeout=15.0)
    try:
        sock.sendall(encode_frame(login) + b"\n")
        sock.settimeout(8.0)
        reply = read_frame(sock)
        if b"VerifyCode=0" not in reply:
            print(f"login rejected on {args.host} (VerifyCode!=0) — try another host")
            return 3
        print(f"login OK on {args.host}:8901\n")

        for code, market in codes:
            q = build_l2_closing_auction_query(
                code, market=market, trade_date=trade_date, historical=True,
                seq=0x0123,
            )
            sock.sendall(q + b"\n")
            time.sleep(0.05)
            sock.settimeout(3.0)
            frames = []
            try:
                while len(frames) < 6:
                    frames.append(read_frame(sock))
            except socket.timeout:
                pass
            except (ConnectionError, OSError) as exc:
                print(f"{code} (mkt {market}): socket {type(exc).__name__}: {exc}")
                continue
            # Prefer the first frame that actually parses into closing points;
            # fall back to the first frame carrying an hd table. A bare hd1.0
            # ack (short ServerCost/subscription frame, common on SZ) must not
            # shadow the real data frame that follows it.
            info = None
            chosen_index = -1
            for i, fr in enumerate(frames):
                inf = analyze(fr)
                if inf.get("parsed_pts", 0) and inf.get("marker"):
                    info = inf
                    chosen_index = i
                    break
            if info is None:
                for i, fr in enumerate(frames):
                    inf = analyze(fr)
                    if inf.get("marker"):
                        info = inf
                        chosen_index = i
                        break
            if info is None:
                info = analyze(frames[0]) if frames else {"size": 0}
                chosen_index = 0
            if frames:
                (dump / f"{code}_f{chosen_index}.bin").write_bytes(frames[chosen_index])
            pts = info.get("parsed_pts", 0)
            print(f"{code} (mkt {market}): {len(frames)} reply frame(s); "
                  f"size={info['size']} pts={pts}")
            if "marker" in info:
                print(f"  {info['marker']} flag=0x{info['flag']:04x} "
                      f"rec_size={info['rec_size']} count={info['record_count']} "
                      f"fields={info['fields']} deficit={info['deficit']}")
            print()
    finally:
        sock.close()
        client.disconnect()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
