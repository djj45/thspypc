"""单用户 THS 运行态：持有唯一 THSClient 并串行化访问。"""
from __future__ import annotations

import os
import threading
from collections.abc import Callable
from pathlib import Path

from ..client import THSClient, LoginResult


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
        self._lock = threading.RLock()
        self._client: THSClient | None = None
        self._client_factory = client_factory
        self._env = load_env(env_path)

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
        with self._lock:
            client = self._get_client()
            profile = getattr(client, "observed_account_profile", None)
            kind = profile.kind.value if profile is not None else None
            return {
                "connected": bool(client.is_connected),
                "server": getattr(client, "_connected_ip", None),
                "account_kind": kind,
                "credentials": bool(self._env.get("THS_USERNAME")),
            }

    def connect(self) -> dict:
        with self._lock:
            client = self._get_client()
            result: LoginResult = client.connect()
            return {
                "success": bool(result.success),
                "server": getattr(result, "server", None),
                "error": getattr(result, "error", None),
            }

    def call(self, operation: Callable[[THSClient], object]) -> object:
        """持锁执行一个业务调用；未连接时先按需连接。"""
        with self._lock:
            client = self._get_client()
            if not client.is_connected:
                result = client.connect()
                if not result.success:
                    raise RuntimeError(
                        f"登录失败: {getattr(result, 'error', '?')}"
                    )
            return operation(client)


__all__ = ["ThsRuntime", "load_env"]
