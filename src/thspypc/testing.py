"""Helpers for test/diagnostic scripts: login, env loading, trade calendar.

登录 helper（遵守 AGENTS.md 登录规则）:
- ``load_env()``              — 从 .env 加载 THS_USERNAME/THS_PASSWORD
- ``resolve_ips()``           — 并发 DNS 解析，返回去重 IPv4 列表
- ``probe_hosts()``           — 并发 TCP 测速，返回可达 IP（最快优先）
- ``login_socket()``          — 并发竞速登录，保留首个 VerifyCode=0 的 socket
- ``login_socket_for_domains()`` — resolve + login_socket 的组合
- ``get_client()``            — 复用已认证的 THSClient（不重复登录）
- ``get_login_body()``        — 从缓存 client 拿当前 passport 的 login body
- ``close_all_clients()``     — 断开并清空所有缓存 client

禁止手写串行 ``for ip in ips: connect(...)``——一批不可达 IP 会逐个等 3 秒。
这些 helper 复刻 hexin 策略：解析全部候选域名、并发测速、并发登录最快节点、
保留首个 ``VerifyCode=0`` 的连接。

A 股交易日历:
- ``latest_trade_date()`` — 返回当前时刻对应的最新交易日（9:15 分界）
  数据源优先级：a-trade-calendar 包 CSV（可选依赖，纯本地含节假日）
  > 深交所 API（运行时联网）> 跳周末兜底。
"""
from __future__ import annotations

import datetime as _dt
import json
import logging
import os
import random
import socket
import threading
import time
from collections.abc import Iterable
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import Request, urlopen

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


# ── A 股交易日历 ──
# 数据源优先级：
#   1. a-trade-calendar 包的 CSV（纯本地，标准库 csv 读取，不走 pandas）
#   2. 深交所官网 API（按月缓存）
#   3. 跳周末粗略判断（不识别节假日）

_trade_days_cache: list[_dt.date] | None = None


def _load_trade_days() -> list[_dt.date]:
    """加载完整交易日列表（升序），结果缓存。

    优先从 a-trade-calendar 包读 CSV（不经 pandas），失败则用深交所 API。
    """
    global _trade_days_cache
    if _trade_days_cache is not None:
        return _trade_days_cache

    days = _load_trade_days_from_csv()
    source = "a-trade-calendar CSV"
    if days is None:
        days = _load_trade_days_from_api()
        source = "深交所 API"
    if not days:
        return []  # 调用方走 fallback

    _trade_days_cache = days
    logger.debug("交易日历加载 %d 天 (%s~%s) 来源=%s",
                 len(days), days[0], days[-1], source)
    return days


def _load_trade_days_from_csv() -> list[_dt.date] | None:
    """从 a-trade-calendar 包读 CSV（标准库 csv，不走 pandas）。"""
    import csv

    # 尝试直接定位包内的 CSV 文件（不经 pandas / 不触发 updater 联网）
    for candidate in (
        "a_trade_calendar/a_trade_calendar.csv",
        "a_trade_calendar.csv",
    ):
        try:
            import importlib
            pkg = importlib.import_module("a_trade_calendar")
            pkg_dir = os.path.dirname(pkg.__file__)
        except Exception:  # noqa: BLE001
            return None
        csv_path = os.path.join(pkg_dir, "a_trade_calendar.csv")
        if os.path.isfile(csv_path):
            break
    else:
        return None

    try:
        with open(csv_path, newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
            next(reader, None)  # skip header (dt)
            days = []
            for row in reader:
                if row and row[0].strip():
                    days.append(_dt.date.fromisoformat(row[0].strip()))
        return sorted(days) if days else None
    except Exception:  # noqa: BLE001
        return None


def _load_trade_days_from_api() -> list[_dt.date]:
    """从深交所官网拉当月+上月交易日（回退数据源）。"""
    today = _dt.date.today()
    days: list[_dt.date] = []
    for offset in (0, -1):  # 当月 + 上月
        d = today.replace(day=1)
        for _ in range(-offset):
            d = d - _dt.timedelta(days=1)
        days.extend(_fetch_month_from_api(d.year, d.month))
    return sorted(set(days))


def _fetch_month_from_api(year: int, month: int) -> list[_dt.date]:
    """从深交所 API 拉一个月的交易日（无缓存，供 _load_trade_days_from_api 用）。"""
    key = f"{year:04d}-{month:02d}"
    params = urlencode({"month": key, "random": random.random()})
    req = Request(
        f"https://www.szse.cn/api/report/exchange/onepersistenthour/monthList?{params}",
        headers={"User-Agent": "Mozilla/5.0", "Referer": "https://www.szse.cn/"},
    )
    with urlopen(req, timeout=5) as resp:
        data = json.load(resp)
    return [
        _dt.date.fromisoformat(d["jyrq"])
        for d in data.get("data", [])
        if d.get("jybz") == "1"
    ]


def latest_trade_date(now: _dt.datetime | None = None) -> _dt.date:
    """返回当前时刻对应的最新 A 股交易日。

    - 交易日 9:15（含）后 → 当天
    - 交易日 9:15 前 / 周末 / 节假日 → 上一个最近的交易日

    数据源优先级：a-trade-calendar 包 CSV（纯本地）> 深交所 API > 跳周末。
    """
    now = now or _dt.datetime.now()
    today = now.date()
    cutoff = today if now.time() >= _dt.time(9, 15) else today - _dt.timedelta(days=1)

    try:
        days = _load_trade_days()
        eligible = [d for d in days if d <= cutoff]
        if eligible:
            return eligible[-1]
    except Exception as exc:  # noqa: BLE001
        logger.warning("交易日历不可用，退化到跳周末: %s", exc)

    # fallback：只跳周末，不识别节假日
    d = cutoff
    while d.weekday() >= 5:  # 周六=5 周日=6
        d -= _dt.timedelta(days=1)
    return d
    d = today if now.time() >= _dt.time(9, 15) else today - _dt.timedelta(days=1)
    while d.weekday() >= 5:  # 周六=5 周日=6
        d -= _dt.timedelta(days=1)
    return d
