"""Incremental stock-name synchronization over MAIN."""
from __future__ import annotations

import socket
import time
from collections.abc import Callable

from .._transport import ConnectionManager, ConnectionRole, SocketLike
from ..codecs.framing import encode_frame, read_frame
from ..features.account_profile import AccountEvidenceRecorder
from ..features.stock_name_bootstrap import (
    LEVEL2_BOOTSTRAP_FRAMES,
    LEVEL2_VERSIONED_BOOTSTRAP_FRAMES,
    STANDARD_BOOTSTRAP_FRAMES,
    STOCK_NAME_DOMAINS,
    STOCK_NAME_GROUPS,
    build_group_frames,
    stock_name_group,
)
from ..features.stock_name_cache import (
    build_version_value,
    extract_config_vers,
    group_cache_path,
    load_name_cache,
    save_name_cache,
)
from ..features.stock_name_protocol import (
    build_stock_name_ver_frame,
    build_upstockname_request,
    decode_name_frame,
)
from ..models import AccountKind, Capability


FrameReader = Callable[[SocketLike], bytes]
Clock = Callable[[], float]

_NAME_GROUPS = {
    "level2": ("16;144;208;", 5716),
    "standard": ("32;208;", 392),
}


def empty_name_result() -> dict:
    return {
        "names": {},
        "by_segment": {},
        "skipped": [],
        "segments": [],
    }


def _connect_and_login(login_body: bytes, ips: list[str]):
    """Try each resolved IP until VerifyCode=0; return socket or None."""
    for target in ips:
        candidate = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        candidate.settimeout(3.0)
        try:
            candidate.connect((target, 8901))
            candidate.sendall(encode_frame(login_body) + b"\n")
            candidate.settimeout(3.0)
            deadline = time.time() + 3
            while time.time() < deadline:
                try:
                    reply = read_frame(candidate)
                except socket.timeout:
                    break
                except (OSError, ValueError):
                    break
                if reply and b"VerifyCode=0" in reply:
                    return candidate
        except OSError:
            pass
        try:
            candidate.close()
        except OSError:
            pass
    return None


def download_stock_name_group(
    login_body: bytes,
    group_key: str,
    *,
    timeout: float = 45.0,
    settle_timeout: float = 3.0,
    cache_path: str | None = None,
) -> dict:
    """Download one market group's names over a fresh 123ths session.

    Replays the captured cold-start frames for the group (``StockNameVer=;;``
    full download), merges every ``[name_*]`` frame received, and stores the
    group cache. Pure Python/TCP, no Windows client files.
    """
    if group_key == "standard_16":
        domain = "main.123ths.com"
        markets = "32;208;"
        pageid = 392
        bootstrap = list(STANDARD_BOOTSTRAP_FRAMES)
    else:
        meta = stock_name_group(group_key)
        domain = meta["domain"]
        markets = meta["markets"]
        pageid = meta["pageid"]
        bootstrap = list(build_group_frames(group_key))

    try:
        ips = sorted(
            {
                addr[4][0]
                for addr in socket.getaddrinfo(domain, 8901, socket.AF_INET)
            }
        )
    except OSError:
        ips = []
    sock = _connect_and_login(login_body, ips) if ips else None
    if sock is None:
        return empty_name_result()

    cached = load_name_cache(cache_path) if cache_path else None
    cached_names = cached[1] if cached else {}
    cached_vers = cached[0] if cached else {}

    result: dict = {
        "names": dict(cached_names),
        "by_segment": {},
        "skipped": [],
        "segments": [],
    }
    config_vers: dict[str, str] = dict(cached_vers)
    try:
        for index, body in enumerate(bootstrap):
            sock.sendall(encode_frame(body) + b"\n")
            if index % 4 == 0:
                time.sleep(0.05)
        sock.settimeout(3.0)
        deadline = time.time() + timeout
        last_name_at = time.time()
        while time.time() < deadline:
            try:
                item = read_frame(sock)
            except socket.timeout:
                if result["names"] and time.time() - last_name_at >= settle_timeout:
                    break
                continue
            except (OSError, ValueError):
                break
            if not item:
                continue
            if b"[name_" in item:
                decoded = decode_name_frame(item)
                result["names"].update(decoded["names"])
                result["by_segment"].update(decoded["by_segment"])
                result["skipped"].extend(decoded["skipped"])
                result["segments"].extend(decoded["segments"])
                config_vers.update(extract_config_vers(item))
                last_name_at = time.time()
        if cache_path and config_vers:
            save_name_cache(result["names"], config_vers, cache_path)
        return result
    finally:
        try:
            sock.close()
        except OSError:
            pass


def download_full_stock_names(
    login_body: bytes,
    *,
    account_kind: AccountKind = AccountKind.STANDARD,
    timeout: float = 45.0,
    cache_path: str | None = None,
) -> dict:
    """Download the full name_16_16 list over a fresh 123ths.com session.

    Opens a new socket to the account-specific domain (shlv2 for level2,
    main for standard), logs in with ``login_body``, replays the captured
    cold-start bootstrap ending in the ``0x001c StockNameVer=;;`` trigger,
    then decodes the name_16_16 response. Pure Python/TCP, no Windows client
    files required.

    Returns the same dict shape as :func:`decode_name_frame`; empty result on
    failure.
    """
    key = account_kind.value if isinstance(account_kind, AccountKind) else "standard"
    domain = STOCK_NAME_DOMAINS.get(key, "main.123ths.com")
    bootstrap = (
        LEVEL2_BOOTSTRAP_FRAMES if key == "level2" else STANDARD_BOOTSTRAP_FRAMES
    )
    try:
        ips = sorted(
            {
                addr[4][0]
                for addr in socket.getaddrinfo(domain, 8901, socket.AF_INET)
            }
        )
    except OSError:
        ips = []
    if not ips:
        return empty_name_result()

    cached = load_name_cache(cache_path) if cache_path else None
    cached_config_vers = cached[0] if cached else {}
    cached_names = cached[1] if cached else {}
    markets, pageid = _NAME_GROUPS.get(key, ("16;144;208;", 5716))
    if cached_config_vers:
        trigger = build_stock_name_ver_frame(
            markets=markets,
            stock_name_ver=build_version_value(cached_config_vers, markets),
            pageid=pageid,
        )
        versioned = (
            LEVEL2_VERSIONED_BOOTSTRAP_FRAMES
            if key == "level2"
            else None
        )
        base = versioned if versioned else bootstrap
        bootstrap = list(base[:-1]) + [trigger]
    else:
        bootstrap = list(bootstrap)

    sock = None
    login_ok = False
    for target in ips:
        candidate = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        candidate.settimeout(3.0)
        try:
            candidate.connect((target, 8901))
            candidate.sendall(encode_frame(login_body) + b"\n")
            candidate.settimeout(3.0)
            deadline = time.time() + 3
            while time.time() < deadline:
                try:
                    reply = read_frame(candidate)
                except socket.timeout:
                    break
                except (OSError, ValueError):
                    break
                if reply and b"VerifyCode=0" in reply:
                    login_ok = True
                    sock = candidate
                    break
        except OSError:
            pass
        if login_ok:
            break
        try:
            candidate.close()
        except OSError:
            pass
    if sock is None or not login_ok:
        return empty_name_result()

    try:
        for index, body in enumerate(bootstrap):
            sock.sendall(encode_frame(body) + b"\n")
            if index % 4 == 0:
                time.sleep(0.05)

        sock.settimeout(3.0)
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                item = read_frame(sock)
            except socket.timeout:
                continue
            except (OSError, ValueError):
                break
            if not item:
                continue
            if b"[name_16_16]" in item:
                result = decode_name_frame(item)
                if cache_path:
                    response_vers = extract_config_vers(item)
                    config_vers = dict(cached_config_vers)
                    config_vers.update(response_vers)
                    if cached_names:
                        merged = dict(cached_names)
                        merged.update(result["names"])
                        save_name_cache(merged, config_vers, cache_path)
                        result["names"] = merged
                    else:
                        save_name_cache(result["names"], config_vers, cache_path)
                return result
        if cached_names:
            return {
                "names": cached_names,
                "by_segment": {},
                "skipped": [],
                "segments": [],
            }
        return empty_name_result()
    except OSError:
        return empty_name_result()
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def download_all_stock_names(
    login_body: bytes,
    account_kind: AccountKind = AccountKind.LEVEL2,
    *,
    timeout: float = 45.0,
    settle_timeout: float = 3.0,
) -> dict:
    """Download every market group's names (external manual entry).

    Iterates the account-specific 123ths market groups and merges their
    ``[name_*]`` segments into one result, using per-group txt caches
    (``~/.thspypc/stockname/``). Call this after login to refresh the full
    stock-name list.
    """
    key = (
        account_kind.value
        if isinstance(account_kind, AccountKind)
        else "standard"
    )
    groups = STOCK_NAME_GROUPS.get(key, STOCK_NAME_GROUPS["standard"])
    result = {
        "names": {},
        "by_segment": {},
        "skipped": [],
        "segments": [],
    }
    for group_key in groups:
        part = download_stock_name_group(
            login_body,
            group_key,
            timeout=timeout,
            settle_timeout=settle_timeout,
            cache_path=str(group_cache_path(group_key)),
        )
        result["names"].update(part["names"])
        result["by_segment"].update(part["by_segment"])
        result["skipped"].extend(part["skipped"])
        result["segments"].extend(part["segments"])
    return result


class StockNameService:
    """Fetch currently available upstockname increments on MAIN."""

    def __init__(
        self,
        connections: ConnectionManager,
        *,
        frame_reader: FrameReader = read_frame,
        max_frames: int = 256,
        evidence: AccountEvidenceRecorder | None = None,
        clock: Clock = time.monotonic,
    ) -> None:
        self._connections = connections
        self._read_frame = frame_reader
        self._max_frames = max_frames
        self._evidence = evidence
        self._clock = clock

    def fetch(
        self,
        *,
        market: str = "URS",
        stock_name_ver: str = ";;",
        timeout: float = 10.0,
        settle_timeout: float = 2.0,
    ) -> dict:
        """Send one incremental request and merge recognized response sections."""
        request = build_upstockname_request(market, stock_name_ver)
        connection = self._connections.acquire(
            ConnectionRole.MAIN,
            capability=Capability.BASIC_QUOTE,
        )
        result = empty_name_result()
        started_at = self._clock()
        first_name_at: float | None = None
        request_timeout = min(2.0, max(timeout, 0.1))

        with connection.request(
            request,
            timeout=request_timeout,
            trailing_newline=False,
        ) as sock:
            for _ in range(self._max_frames):
                now = self._clock()
                if (
                    first_name_at is not None
                    and now - first_name_at >= settle_timeout
                ):
                    break
                if (
                    first_name_at is None
                    and now - started_at >= timeout
                ):
                    break
                try:
                    response = self._read_frame(sock)
                except socket.timeout:
                    continue
                except OSError:
                    break
                except ValueError:
                    continue
                if not response:
                    continue
                if not any(
                    marker in response
                    for marker in (b"[name_", b"upnametype", b"MarketCode")
                ):
                    continue
                if first_name_at is None:
                    first_name_at = self._clock()
                decoded = decode_name_frame(response)
                result["names"].update(decoded["names"])
                result["by_segment"].update(decoded["by_segment"])
                result["skipped"].extend(decoded["skipped"])
                result["segments"].extend(decoded["segments"])

        if self._evidence is not None and result["segments"]:
            self._evidence.record_main_ready()
        return result


__all__ = [
    "StockNameService",
    "download_all_stock_names",
    "download_full_stock_names",
    "download_stock_name_group",
    "empty_name_result",
]
