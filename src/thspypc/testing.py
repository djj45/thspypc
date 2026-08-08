"""Low-level 8901 login helpers for test/diagnostic scripts.

Tests must not hand-roll a serial ``for ip in ips: connect(...)`` loop. A
single unreachable DNS batch can turn a 3s timeout into minutes. These
helpers mirror hexin's own strategy: resolve every candidate domain, probe
TCP reachability in parallel, then log in concurrently to the fastest hosts
and keep the first ``VerifyCode=0`` socket.

The same process should also reuse one authenticated ``THSClient`` instead
of creating a fresh client and logging in again on every script round.
"""
from __future__ import annotations

import logging
import os
import socket
import threading
import time
from collections.abc import Iterable
from pathlib import Path

from .codecs.framing import encode_frame, read_frame
from .protocol import MARKET_PORT

logger = logging.getLogger(__name__)

class LoginFailed(RuntimeError):
    """All candidate hosts failed to produce a ``VerifyCode=0`` login."""

_clients: dict[str, object] = {}
_clients_lock = threading.Lock()

def load_env(path: str | os.PathLike[str] | None = ".env") -> Path:
    """Load one ``.env`` file into ``os.environ`` without overriding live env."""
    env_path = Path(path).resolve() if path else Path.cwd() / ".env"
    if not env_path.exists():
        return env_path
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if key and key not in os.environ:
            os.environ[key] = value.strip().strip('"').strip("'")
    return env_path

def _dedupe(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out

def resolve_ips(domains: Iterable[str], port: int = MARKET_PORT) -> list[str]:
    """Resolve every domain and return a deduplicated IPv4 list."""
    ips: list[str] = []
    seen: set[str] = set()
    for domain in _dedupe(domains):
        try:
            addrs = socket.getaddrinfo(
                domain, port, socket.AF_INET, socket.SOCK_STREAM
            )
        except OSError:
            continue
        for addr in addrs:
            ip = addr[4][0]
            if ip not in seen:
                seen.add(ip)
                ips.append(ip)
    return ips

def probe_hosts(
    hosts: Iterable[str],
    *,
    port: int = MARKET_PORT,
    timeout: float = 1.0,
) -> list[str]:
    """Concurrently TCP-probe hosts and return reachable ones, fastest first."""
    candidates = _dedupe(hosts)
    if len(candidates) <= 1:
        return candidates

    results: list[tuple[float, str]] = []

    def _probe(host: str) -> None:
        started = time.monotonic()
        try:
            with socket.create_connection((host, port), timeout=timeout):
                rtt = time.monotonic() - started
                results.append((rtt, host))
        except OSError:
            pass

    threads = [
        threading.Thread(target=_probe, args=(host,), daemon=True)
        for host in candidates
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=timeout + 0.2)

    results.sort(key=lambda item: item[0])
    return [host for _rtt, host in results]

def login_socket(
    login_body: bytes,
    hosts: Iterable[str],
    *,
    port: int = MARKET_PORT,
    probe_timeout: float = 1.0,
    login_timeout: float = 3.0,
    overall_timeout: float = 12.0,
    max_concurrent: int = 7,
    probe: bool = True,
) -> tuple[str, socket.socket]:
    """Open the first host whose login reply contains ``VerifyCode=0``.

    Returns ``(host, connected_socket)``. Raises :class:`LoginFailed` when
    every candidate fails or the overall deadline expires.
    """
    candidates = _dedupe(hosts)
    if not candidates:
        raise LoginFailed("no host candidates")

    if probe:
        reachable = probe_hosts(candidates, port=port, timeout=probe_timeout)
        if reachable:
            candidates = reachable
    if len(candidates) > max_concurrent:
        candidates = candidates[:max_concurrent]

    done = threading.Event()
    results: dict[str, socket.socket] = {}
    errors: dict[str, str] = {}

    def _try_login(host: str) -> None:
        sock: socket.socket | None = None
        try:
            sock = socket.create_connection(
                (host, port), timeout=min(login_timeout, overall_timeout)
            )
            if done.is_set():
                return
            sock.settimeout(min(login_timeout, max(0.1, overall_timeout)))
            sock.sendall(encode_frame(login_body) + b"\n")
            deadline = time.monotonic() + login_timeout
            while time.monotonic() < deadline:
                try:
                    reply = read_frame(sock)
                except socket.timeout:
                    continue
                except (OSError, ValueError) as exc:
                    errors[host] = str(exc)
                    return
                if not reply:
                    continue
                if b"VerifyCode=0" in reply:
                    if not done.is_set():
                        results[host] = sock
                        done.set()
                    return
                if b"VerifyCode=" in reply:
                    errors[host] = "login rejected"
                    return
            errors[host] = "no VerifyCode=0 before timeout"
        except OSError as exc:
            errors[host] = str(exc)
        finally:
            if sock is not None and host not in results:
                try:
                    sock.close()
                except OSError:
                    pass

    threads = [
        threading.Thread(target=_try_login, args=(host,), daemon=True)
        for host in candidates
    ]
    for thread in threads:
        thread.start()

    deadline = time.monotonic() + overall_timeout
    while not done.is_set() and time.monotonic() < deadline:
        done.wait(timeout=0.1)

    for thread in threads:
        thread.join(timeout=0.5)

    if results:
        host, sock = next(iter(results.items()))
        logger.info("robust login succeeded on %s:%d", host, port)
        return host, sock

    detail = "; ".join(f"{host}={err}" for host, err in errors.items())
    raise LoginFailed(
        f"all {len(candidates)} hosts failed after {overall_timeout:.1f}s: {detail}"
    )

def login_socket_for_domains(
    login_body: bytes,
    domains: Iterable[str],
    *,
    fallback_hosts: Iterable[str] = (),
    port: int = MARKET_PORT,
    **kwargs,
) -> tuple[str, socket.socket]:
    """Resolve domains and call :func:`login_socket`.

    ``fallback_hosts`` is used only when DNS returns nothing, so a hardcoded
    IP list never replaces a live DNS answer.
    """
    hosts = resolve_ips(domains, port=port)
    if not hosts:
        hosts = list(fallback_hosts)
    return login_socket(login_body, hosts, port=port, **kwargs)

def get_client(env_path: str | os.PathLike[str] = ".env"):
    """Return a cached, connected :class:`thspypc.THSClient`.

    A second call in the same process reuses the existing client and does not
    log in again while the MAIN connection is still alive.
    """
    from .client import THSClient

    key = str(Path(env_path).resolve())
    load_env(env_path)
    with _clients_lock:
        client = _clients.get(key)
        if client is None:
            username = os.environ.get("THS_USERNAME", "").strip()
            password = os.environ.get("THS_PASSWORD", "").strip()
            if not username or not password:
                raise LoginFailed(
                    f"THS_USERNAME/THS_PASSWORD missing in {env_path}"
                )
            client = THSClient(username, password)
            _clients[key] = client
        if not client.is_connected:
            result = client.connect()
            if not result.success:
                raise LoginFailed(
                    f"THSClient connect failed: {result.error}: {result.detail}"
                )
        return client

def get_login_body(
    env_path: str | os.PathLike[str] = ".env",
    *,
    identity: str = "standard",
) -> bytes:
    """Return a login body built from the cached client's current passport."""
    from .features.auth_protocol import LoginIdentity

    client = get_client(env_path)
    material = client._auth_service.require_current()
    return client._auth_service.login_body_for_passport(
        material.passport64,
        LoginIdentity(identity),
    )

def close_all_clients() -> None:
    """Disconnect and forget every cached client (test teardown helper)."""
    with _clients_lock:
        for client in _clients.values():
            try:
                client.disconnect()
            except Exception:
                pass
        _clients.clear()
