"""Incremental stock-name synchronization over MAIN."""
from __future__ import annotations

import logging
import socket
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed

from .._transport import ConnectionManager, ConnectionRole, SocketLike
from ..codecs.framing import FRAME_MAGIC, encode_frame, read_frame
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
    name_cache_is_fresh,
    save_name_cache,
)
from ..features.stock_name_protocol import (
    build_stock_name_ver_frame,
    build_upstockname_request,
    decode_name_frame,
)
from ..models import AccountKind, Capability
from ..protocol import build_heartbeat_8901
from ..testing import LoginFailed, login_socket

logger = logging.getLogger(__name__)

FrameReader = Callable[[SocketLike], bytes]
Clock = Callable[[], float]

_NAME_GROUPS = {
    "level2": ("16;144;208;", 5716),
    "standard": ("32;208;", 392),
}

# The 120/104 market ignores StockNameVer=;;. The 2026-08-09 00:07:56
# capture shows hexin triggers it with MarketCode=104; plus the real 104_*
# ConfigVer list; the server then returns both [name_120_120] and
# [name_104_104]. These versions are real but stale, so the same value is
# reused to force a full refresh of the small (~30KB) group.
_IFINDH_104_STALE_VERSION_VALUE = (
    "^bname_104_104^B^r^nConfigVer^e20260807_3540849890^r^n"
    "^bname_104_106^B^r^nConfigVer^e20260807_3788050668^r^n"
    "^bname_104_107^B^r^nConfigVer^e20260807_2431211407^r^n"
    "^bname_104_108^B^r^nConfigVer^e20260807_4002580065^r^n"
    "^bname_104_109^B^r^nConfigVer^e20260807_795885416^r^n"
    "^bname_104_110^B^r^nConfigVer^e20260807_2709822740^r^n;;"
)

def empty_name_result() -> dict:
    return {
        "names": {},
        "by_segment": {},
        "skipped": [],
        "segments": [],
    }

def _connect_and_login(login_body: bytes, ips: list[str]):
    """Open one robust 8901 session across every resolved IP."""
    try:
        _host, sock = login_socket(
            login_body,
            ips,
            probe_timeout=1.0,
            login_timeout=3.0,
            overall_timeout=6.0,
            max_concurrent=min(7, len(ips) or 1),
        )
        return sock
    except LoginFailed:
        return None

def _resolve_ips(domain: str) -> list[str]:
    try:
        return sorted(
            {
                addr[4][0]
                for addr in socket.getaddrinfo(domain, 8901, socket.AF_INET)
            }
        )
    except OSError:
        return []

def _send_frame(
    sock: socket.socket,
    body: bytes,
    lock: threading.Lock | None = None,
) -> None:
    """Send a raw bootstrap body, or a pre-framed 0x001c trigger as-is."""
    if body.startswith(FRAME_MAGIC):
        payload = body + b"\n"
    else:
        payload = encode_frame(body) + b"\n"
    if lock is not None:
        with lock:
            sock.sendall(payload)
    else:
        sock.sendall(payload)

def _login_one(login_body_factory: Callable[[str], bytes], group_key: str) -> socket.socket | None:
    domain = stock_name_group(group_key)["domain"]
    ips = _resolve_ips(domain)
    if not ips:
        return None
    return _connect_and_login(login_body_factory(group_key), ips)

def _login_sessions(
    login_body_factory: Callable[[str], bytes],
    groups: list[str],
) -> dict[str, tuple[socket.socket, threading.Lock]]:
    """Log in to every market group concurrently (hexin cold-start style).

    每组用 login_body_factory(group_key) 生成各自的 login body——不同域名
    需要不同 LoginIdentity（standard/manual/l2），共用一份会登录失败。
    """
    sessions: dict[str, tuple[socket.socket, threading.Lock]] = {}
    with ThreadPoolExecutor(max_workers=max(1, len(groups))) as pool:
        futures = {
            pool.submit(_login_one, login_body_factory, group_key): group_key
            for group_key in groups
        }
        for future in as_completed(futures):
            group_key = futures[future]
            try:
                sock = future.result()
            except Exception:
                sock = None
            if sock is not None:
                sessions[group_key] = (sock, threading.Lock())
    return sessions

def _start_heartbeat(sock: socket.socket, lock: threading.Lock) -> threading.Event:
    stop = threading.Event()

    def beat() -> None:
        seq = 0
        while not stop.wait(3.0):
            try:
                _send_frame(sock, build_heartbeat_8901(seq), lock)
                seq += 1
            except OSError:
                return

    threading.Thread(
        target=beat,
        name=f"stockname-heartbeat-{id(sock)}",
        daemon=True,
    ).start()
    return stop

def _collect_group(
    sock: socket.socket,
    group_key: str,
    *,
    timeout: float = 45.0,
    settle_timeout: float = 3.0,
    no_name_timeout: float = 20.0,
    cache_path: str | None = None,
    send_lock: threading.Lock | None = None,
) -> dict:
    """Replay one market group's bootstrap on an already-logged-in socket."""
    meta = stock_name_group(group_key)
    markets = meta["markets"]
    pageid = meta["pageid"]
    bootstrap = list(build_group_frames(group_key))

    cached = load_name_cache(cache_path) if cache_path else None
    cached_names = cached[1] if cached else {}
    cached_vers = cached[0] if cached else {}

    # ifindhq 120/104 ignores StockNameVer=;;; hexin triggers it through
    # MarketCode=104; plus the real 104_* ConfigVer list (2026-08-09 capture).
    if "ifindhq" in group_key:
        trigger = build_stock_name_ver_frame(
            markets="104;",
            stock_name_ver=_IFINDH_104_STALE_VERSION_VALUE,
            pageid=pageid,
        )
        bootstrap = bootstrap[:-1] + [trigger]

    result: dict = {
        "names": dict(cached_names),
        "by_segment": {},
        "skipped": [],
        "segments": [],
    }
    config_vers: dict[str, str] = dict(cached_vers)
    for index, body in enumerate(bootstrap):
        _send_frame(sock, body, send_lock)
        if index % 4 == 0:
            time.sleep(0.05)

    sock.settimeout(3.0)
    deadline = time.time() + timeout
    last_name_at = time.time()
    last_activity_at = time.time()
    while time.time() < deadline:
        try:
            item = read_frame(sock)
        except socket.timeout:
            if result["names"] and time.time() - last_name_at >= settle_timeout:
                break
            if (
                not result["names"]
                and time.time() - last_activity_at >= no_name_timeout
            ):
                break
            continue
        except (OSError, ValueError):
            break
        if not item:
            continue
        last_activity_at = time.time()
        decoded = decode_name_frame(item)
        if decoded["names"] or decoded["segments"]:
            result["names"].update(decoded["names"])
            result["by_segment"].update(decoded["by_segment"])
            result["skipped"].extend(decoded["skipped"])
            result["segments"].extend(decoded["segments"])
            config_vers.update(extract_config_vers(item))
            last_name_at = time.time()
            continue
        # 非名称帧。盘中沪深 L2 组的连接上有持续行情推送，socket 永不静默，
        # ``except socket.timeout`` 分支里的 settle 检查永远走不到；此处对
        # 推送帧同样判定：名称已到齐且超过 settle_timeout 没有新名称帧
        # 即收工，否则每组都要干等到 45s deadline（实测 33k 名称 0.6s 传
        # 完、却等满 45s）。
        if result["names"] and time.time() - last_name_at >= settle_timeout:
            break
        if (
            not result["names"]
            and time.time() - last_activity_at >= no_name_timeout
        ):
            break

    if cache_path and config_vers:
        save_name_cache(result["names"], config_vers, cache_path)
    return result

def download_stock_name_group(
    login_body_factory: Callable[[str], bytes],
    group_key: str,
    *,
    timeout: float = 45.0,
    settle_timeout: float = 3.0,
    no_name_timeout: float = 20.0,
    cache_path: str | None = None,
) -> dict:
    """Download one market group's names over a fresh 123ths session."""
    meta = stock_name_group(group_key)
    domain = meta["domain"]
    ips = _resolve_ips(domain)
    sock = _connect_and_login(login_body_factory(group_key), ips) if ips else None
    if sock is None:
        return empty_name_result()
    try:
        return _collect_group(
            sock,
            group_key,
            timeout=timeout,
            settle_timeout=settle_timeout,
            no_name_timeout=no_name_timeout,
            cache_path=cache_path,
        )
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
    # 当日已拉取过名称，直接复用缓存，不再走 8901 登录 + 引导 + 全量下载。
    if cached_names and name_cache_is_fresh(cache_path):
        logger.info(
            "download_full_stock_names: 命中当日名称缓存 (%d 条)",
            len(cached_names),
        )
        return {
            "names": dict(cached_names),
            "by_segment": {},
            "skipped": [],
            "segments": [],
        }
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

    sock = _connect_and_login(login_body, ips)
    if sock is None:
        return empty_name_result()

    try:
        for index, body in enumerate(bootstrap):
            _send_frame(sock, body)
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
            decoded = decode_name_frame(item)
            if "16_16" in decoded["by_segment"]:
                result = decoded
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

def _merge_cached_group_names(groups: list[str]) -> dict[str, str] | None:
    """所有组的当日缓存都存在且新鲜时合并返回；否则返回 None。"""
    merged: dict[str, str] = {}
    for group_key in groups:
        path = group_cache_path(group_key)
        cached = load_name_cache(path)
        if cached is None or not name_cache_is_fresh(path):
            return None
        merged.update(cached[1])
    return merged


def download_all_stock_names(
    login_body_factory: Callable[[str], bytes],
    account_kind: AccountKind = AccountKind.LEVEL2,
    *,
    timeout: float = 45.0,
    settle_timeout: float = 3.0,
    no_name_timeout: float = 20.0,
) -> dict:
    """Download every market group's names (external manual entry).

    Logs into all account-specific 123ths market groups concurrently (one
    socket per group), keeps the sessions alive with 3s 8901 heartbeats, then
    replays every group's bootstrap concurrently and merges every
    ``[name_*]`` segment.
    Per-group txt caches live under ``~/.thspypc/stockname/``.
    """
    key = (
        account_kind.value
        if isinstance(account_kind, AccountKind)
        else "standard"
    )
    groups = STOCK_NAME_GROUPS.get(key, STOCK_NAME_GROUPS["standard"])
    cached = _merge_cached_group_names(groups)
    if cached:
        logger.info(
            "download_all_stock_names: 命中当日组缓存 (%d 条)",
            len(cached),
        )
        return {
            "names": cached,
            "by_segment": {},
            "skipped": [],
            "segments": [],
        }
    result = {
        "names": {},
        "by_segment": {},
        "skipped": [],
        "segments": [],
    }
    sessions = _login_sessions(login_body_factory, groups)
    heartbeats: list[tuple[threading.Event, socket.socket]] = []
    try:
        for group_key, (sock, lock) in sessions.items():
            heartbeats.append((_start_heartbeat(sock, lock), sock))

        # 各组收集并行（hexin 冷启动同为并发）：每组传输 <1s，瓶颈是
        # 3s settle 静默等待；串行时 8 组逐个排队要 ~45s，并行后总时长
        # ≈ 最慢一组。每组独立 socket + send_lock，无共享状态。
        alive_groups = [g for g in groups if g in sessions]

        def collect(group_key: str) -> dict:
            sock, lock = sessions[group_key]
            return _collect_group(
                sock,
                group_key,
                timeout=timeout,
                settle_timeout=settle_timeout,
                no_name_timeout=no_name_timeout,
                cache_path=str(group_cache_path(group_key)),
                send_lock=lock,
            )

        with ThreadPoolExecutor(max_workers=max(1, len(alive_groups))) as pool:
            # pool.map 保序：合并顺序与原串行循环一致（后组覆盖前组）。
            parts = list(pool.map(collect, alive_groups))
        for part in parts:
            result["names"].update(part["names"])
            result["by_segment"].update(part["by_segment"])
            result["skipped"].extend(part["skipped"])
            result["segments"].extend(part["segments"])
        return result
    finally:
        for stop, _sock in heartbeats:
            stop.set()
        for sock, _lock in sessions.values():
            try:
                sock.close()
            except OSError:
                pass

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
