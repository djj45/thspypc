"""单用户 THS 运行态：持有唯一 THSClient 并协调连接生命周期。"""
from __future__ import annotations

import logging
import os
import threading
import time
from collections.abc import Callable
from pathlib import Path

from ..client import THSClient, LoginResult
from .._transport.timing import add_request_timing

logger = logging.getLogger(__name__)


def load_env(path: str | Path | None = None) -> dict[str, str]:
    """加载 .env（默认仓库根目录），已存在的环境变量优先。"""
    if path is None:
        path = Path(__file__).resolve().parents[3] / ".env"
    result: dict[str, str] = {}
    if Path(path).exists():
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            result[key.strip()] = value.strip().strip('"').strip("'")
    return result


class ThsRuntime:
    """进程内唯一 THSClient 的运行态（单用户）。"""

    def __init__(
        self,
        *,
        env_path: str | Path | None = None,
        client_factory: Callable[[str, str, str | None], THSClient] | None = None,
    ) -> None:
        # 这里只保护 client 创建和首次登录。业务调用不能持有这把锁：
        # THSClient 下层已经按 MAIN/SH_L2/SZ_L2 等连接分别执行 single-flight，
        # 再加一把跨角色全局锁会把本可并行的页面请求全部串行化。
        self._lifecycle_lock = threading.RLock()
        self._client: THSClient | None = None
        self._connected_once = False
        self._client_factory = client_factory
        self._env = load_env(env_path)
        self._preheat_thread: threading.Thread | None = None
        self._preheat_state: dict[str, object] = {
            "state": "not_started",
            "markets": {},
        }

    @property
    def env(self) -> dict[str, str]:
        return dict(self._env)

    def _create_client(self) -> THSClient:
        username = self._env.get("THS_USERNAME") or os.environ.get("THS_USERNAME")
        password = self._env.get("THS_PASSWORD") or os.environ.get("THS_PASSWORD")
        if not username or not password:
            raise RuntimeError("缺少 THS_USERNAME/THS_PASSWORD（.env 或环境变量）")
        imei = self._env.get("THS_IMEI") or os.environ.get("THS_IMEI") or None
        if self._client_factory is not None:
            return self._client_factory(username, password, imei)
        return THSClient(username=username, password=password, imei=imei)

    def _get_client(self) -> THSClient:
        if self._client is None:
            self._client = self._create_client()
        return self._client

    def status(self) -> dict:
        with self._lifecycle_lock:
            client = self._get_client()
            profile = getattr(client, "observed_account_profile", None)
            kind = profile.kind.value if profile is not None else None
            preheat = {
                **self._preheat_state,
                "markets": dict(self._preheat_state.get("markets", {})),
            }
            return {
                "connected": bool(client.is_connected),
                "server": getattr(client, "_connected_ip", None),
                "account_kind": kind,
                "credentials": bool(self._env.get("THS_USERNAME")),
                "preheat": preheat,
            }

    def connect(self) -> dict:
        with self._lifecycle_lock:
            client = self._get_client()
            result: LoginResult = client.connect()
            if result.success:
                self._connected_once = True
            return {
                "success": bool(result.success),
                "server": getattr(result, "server", None),
                "error": getattr(result, "error", None),
            }

    def call(self, operation: Callable[[THSClient], object]) -> object:
        """确保首次登录后执行调用；并发安全由各连接的 session 负责。"""
        # 热路径不再调用 client.is_connected。该检查需要取得 MAIN 请求锁，
        # 会让纯 L2 请求被正在执行的 quote/depth 阻塞。各业务方法已经负责其
        # 所属连接的失败/重试；runtime 只协调进程内第一次登录。
        if self._client is not None and self._connected_once:
            operation_started = time.perf_counter()
            try:
                return operation(self._client)
            except OSError:
                # 只在传输异常后做一次真实 socket 健康检查；正常热请求不碰
                # MAIN 锁。若 MAIN 已断，下一次调用重新走受锁保护的登录流程。
                if not self._client.is_connected:
                    with self._lifecycle_lock:
                        self._connected_once = False
                raise
            finally:
                add_request_timing(
                    "app",
                    (time.perf_counter() - operation_started) * 1000,
                )

        waiting_started = time.perf_counter()
        self._lifecycle_lock.acquire()
        acquired = time.perf_counter()
        add_request_timing(
            "lifecycle_wait",
            (acquired - waiting_started) * 1000,
        )
        try:
            client = self._get_client()
            if not self._connected_once:
                result = client.connect()
                if not result.success:
                    raise RuntimeError(
                        f"登录失败: {getattr(result, 'error', '?')}"
                    )
                self._connected_once = True
        finally:
            add_request_timing(
                "lifecycle",
                (time.perf_counter() - acquired) * 1000,
            )
            self._lifecycle_lock.release()
        operation_started = time.perf_counter()
        try:
            return operation(client)
        except OSError:
            if not client.is_connected:
                with self._lifecycle_lock:
                    self._connected_once = False
            raise
        finally:
            add_request_timing(
                "app",
                (time.perf_counter() - operation_started) * 1000,
            )

    def start_preheat(self) -> bool:
        """后台登录 MAIN 并预建 SH/SZ L2；重复调用不会创建第二个任务。"""
        with self._lifecycle_lock:
            if self._preheat_thread is not None and self._preheat_thread.is_alive():
                return False
            if self._preheat_state.get("state") in {"ready", "skipped"}:
                return False
            self._preheat_state = {"state": "running", "markets": {}}
            thread = threading.Thread(
                target=self._preheat_worker,
                name="ths-server-preheat",
                daemon=True,
            )
            self._preheat_thread = thread
            thread.start()
            return True

    def _connect_with_retry(self, client: THSClient) -> LoginResult:
        """登录 MAIN；all_hosts_failed 时等待后重试（服务器会话释放需要时间）。

        首次失败后不立刻连打同一批 IP。常见触发场景：旧后端刚被关闭，
        服务端还挂着旧会话，立即重启会让所有 8901 IP 直接关闭新登录连接。
        等待一段时间再重试可显著降低“账号被临时限制”后反复撞墙的概率。

        连接动作始终在 ``_lifecycle_lock`` 内执行（与其他首次登录调用互斥），
        等待重试时释放锁，避免阻塞并发的 /api/status 或业务请求。
        """
        # 不要连续多轮轰炸：all_hosts_failed 通常是服务端会话限制，
        # 等 30 秒再试一次；仍失败就交由后续 API 调用按需重连。
        delays = (0.0, 30.0)
        last: LoginResult | None = None
        for attempt, delay in enumerate(delays):
            if delay > 0:
                logger.warning(
                    "MAIN 登录失败，%d 秒后重试（第 %d 次）...",
                    int(delay), attempt + 1,
                )
                time.sleep(delay)
            with self._lifecycle_lock:
                if self._connected_once:
                    return LoginResult(
                        success=True,
                        error="already_connected",
                        server=str(getattr(client, "_connected_ip", "") or ""),
                    )
                last = client.connect()
                if last.success:
                    self._connected_once = True
            if last.success:
                return last
            if getattr(last, "error", "") != "all_hosts_failed":
                return last
        if last is not None:
            return last
        return LoginResult(
            success=False,
            error="all_hosts_failed",
            detail="unknown login failure",
        )

    def _preheat_worker(self) -> None:
        started = time.perf_counter()
        try:
            with self._lifecycle_lock:
                client = self._get_client()
            if not self._connected_once:
                result = self._connect_with_retry(client)
                if not result.success:
                    raise RuntimeError(
                        f"登录失败: {getattr(result, 'error', '?')}"
                    )
            preheat = getattr(client, "preheat_service_connections", None)
            if preheat is None:
                preheat = getattr(client, "preheat_l2_connections", None)
            if preheat is None:
                markets = {}
                state = "skipped"
            else:
                markets = preheat()
                if markets and all(
                    bool(item.get("skipped"))
                    for item in markets.values()
                ):
                    state = "skipped"
                elif markets and all(
                    bool(item.get("ready")) or bool(item.get("skipped"))
                    for item in markets.values()
                ):
                    state = "ready"
                else:
                    state = "partial"
            with self._lifecycle_lock:
                self._preheat_state = {
                    "state": state,
                    "elapsed_ms": round(
                        (time.perf_counter() - started) * 1000,
                        1,
                    ),
                    "markets": markets,
                }
        except Exception as exc:
            with self._lifecycle_lock:
                self._preheat_state = {
                    "state": "error",
                    "elapsed_ms": round(
                        (time.perf_counter() - started) * 1000,
                        1,
                    ),
                    "markets": {},
                    "error": f"{type(exc).__name__}: {exc}",
                }


__all__ = ["ThsRuntime", "load_env"]
