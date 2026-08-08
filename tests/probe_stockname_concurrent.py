#!/usr/bin/env python
"""Concurrent long-lived stock-name sync probe (hexin-style).

Logs into all level2 market groups concurrently (one socket each), keeps the
connections alive with 3s 8901 heartbeats, then replays each group bootstrap
and collects name segments. Mirrors the hexin cold-start pattern to avoid
VerifyCode=-1 from repeated serial logins.
"""
from __future__ import annotations

import os
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_dotenv(path: Path) -> None:
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        if key.strip() and key.strip() not in os.environ:
            os.environ[key.strip()] = value.strip().strip('"').strip("'")


def resolve_ips(domain: str) -> list[str]:
    try:
        return sorted(
            {a[4][0] for a in socket.getaddrinfo(domain, 8901, socket.AF_INET)}
        )
    except OSError:
        return []


def login_one(login_body: bytes, domain: str) -> tuple[str, socket.socket]:
    from thspypc.codecs.framing import encode_frame, read_frame

    ips = resolve_ips(domain)
    last_err = None
    for ip in ips:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.0)
        try:
            s.connect((ip, 8901))
            s.sendall(encode_frame(login_body) + b"\n")
            s.settimeout(3.0)
            end = time.time() + 3
            while time.time() < end:
                try:
                    reply = read_frame(s)
                except socket.timeout:
                    break
                except (OSError, ValueError):
                    break
                if reply and b"VerifyCode=0" in reply:
                    return ip, s
        except OSError as exc:
            last_err = exc
        try:
            s.close()
        except OSError:
            pass
    raise RuntimeError(f"login failed for {domain}: {last_err}")


def main() -> int:
    load_dotenv(ROOT / ".env")
    from thspypc import THSClient
    from thspypc.features.stock_name_bootstrap import STOCK_NAME_GROUPS, build_group_frames, stock_name_group
    from thspypc.features.stock_name_protocol import decode_name_frame
    from thspypc.codecs.framing import encode_frame, read_frame
    from thspypc.protocol import build_heartbeat_8901

    client = THSClient(os.environ["THS_USERNAME"], os.environ["THS_PASSWORD"])
    res = client.connect()
    if not res.success:
        print("login failed", res.error, res.detail)
        return 1
    material = client._auth_service.require_current()
    login_body = client._auth_service.login_body_for_passport(material.passport64)
    groups = STOCK_NAME_GROUPS["level2"]
    print("concurrent login of", len(groups), "groups...")

    sessions: dict[str, tuple[str, socket.socket]] = {}
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=len(groups)) as pool:
        futures = {
            pool.submit(login_one, login_body, stock_name_group(g)["domain"]): g
            for g in groups
        }
        for fut in as_completed(futures):
            g = futures[fut]
            try:
                ip, sock = fut.result()
            except Exception as exc:
                print("  !!", g, "failed:", exc)
                continue
            sessions[g] = (ip, sock)
            print("  login", g, ip, f"{time.time()-t0:.1f}s")
    print("logged in", len(sessions), "of", len(groups), "elapsed", f"{time.time()-t0:.1f}s")

    if not sessions:
        return 1

    stop = threading.Event()

    def heartbeat(ip: str, sock: socket.socket):
        seq = 0
        while not stop.wait(3.0):
            try:
                sock.sendall(encode_frame(build_heartbeat_8901(seq)) + b"\n")
                seq += 1
            except OSError:
                return

    for g, (ip, sock) in sessions.items():
        threading.Thread(target=heartbeat, args=(ip, sock), daemon=True).start()
    print("heartbeat threads started")

    totals: dict[str, int] = {}
    for g, (ip, sock) in sessions.items():
        frames = build_group_frames(g)
        try:
            for i, body in enumerate(frames):
                sock.sendall(encode_frame(body) + b"\n")
                if i % 4 == 0:
                    time.sleep(0.02)
            sock.settimeout(3.0)
            end = time.time() + 30
            last_name = time.time()
            seen = 0
            while time.time() < end:
                try:
                    item = read_frame(sock)
                except socket.timeout:
                    if seen and time.time() - last_name >= 3:
                        break
                    continue
                except (OSError, ValueError):
                    break
                if not item:
                    continue
                if b"[name_" in item:
                    decoded = decode_name_frame(item)
                    totals[g] = len(decoded["names"])
                    last_name = time.time()
                    seen += 1
        except OSError as exc:
            print("  !!", g, "send/read error:", exc)
    print("name totals:", totals)

    print("keeping connections alive for 8s to verify heartbeats...")
    time.sleep(8)
    alive = 0
    for g, (ip, sock) in sessions.items():
        try:
            sock.settimeout(0.5)
            sock.sendall(b"")
            alive += 1
        except OSError:
            pass
    print("connections still usable:", alive, "of", len(sessions))

    stop.set()
    for g, (ip, sock) in sessions.items():
        try:
            sock.close()
        except OSError:
            pass
    client.disconnect()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())