"""Capability-gated connection registry."""
from __future__ import annotations

import threading
from dataclasses import dataclass
from collections.abc import Callable, Mapping

from ..errors import (
    CapabilityUnavailableError,
    ChannelUnavailableError,
    UnsupportedAccountFeatureError,
)
from ..models import AccountKind, AccountProfile, Capability, Support
from .connection import (
    CONNECTION_SPECS,
    CloseableSocket,
    ConnectionRole,
    ConnectionSpec,
    ManagedConnection,
)


@dataclass(frozen=True)
class OpenedConnection:
    """A role-ready socket plus lifecycle metadata supplied by an opener."""

    socket: CloseableSocket
    owns_socket: bool = True
    initialized: bool = True
    request_lock: threading.RLock | None = None


ConnectionOpener = Callable[
    [ConnectionSpec],
    CloseableSocket | OpenedConnection,
]


class ConnectionManager:
    """Acquire role-specific connections only after capability checks."""

    def __init__(
        self,
        profile: AccountProfile,
        opener: ConnectionOpener,
        *,
        specs: Mapping[ConnectionRole, ConnectionSpec] = CONNECTION_SPECS,
    ) -> None:
        self._profile = profile
        self._opener = opener
        self._specs = dict(specs)
        self._connections: dict[ConnectionRole, ManagedConnection] = {}
        self._lock = threading.RLock()

    @property
    def profile(self) -> AccountProfile:
        """Return the current immutable routing profile."""
        with self._lock:
            return self._profile

    @staticmethod
    def _profile_allows_role(
        profile: AccountProfile,
        role: ConnectionRole,
    ) -> bool:
        if role in (
            ConnectionRole.SH_L2,
            ConnectionRole.SZ_L2,
            ConnectionRole.BOARD_CONSTITUENT_SZ,
        ):
            return (
                profile.kind is AccountKind.LEVEL2
                and profile.support(Capability.L2_MARKET_ACCESS)
                is Support.YES
            )
        if role is ConnectionRole.REALORDER:
            return profile.support(Capability.REALORDER) is Support.YES
        return True

    def update_profile(self, profile: AccountProfile) -> None:
        """Atomically replace capability evidence and retire invalid roles."""
        stale: list[ManagedConnection] = []
        with self._lock:
            self._profile = profile
            for role, connection in list(self._connections.items()):
                if not self._profile_allows_role(profile, role):
                    del self._connections[role]
                    stale.append(connection)

        # Closing takes the per-socket request lock and waits for active work.
        for connection in stale:
            connection.close()

    def _require(
        self,
        capability: Capability,
        *,
        feature: str,
    ) -> None:
        support = self._profile.support(capability)
        if support is Support.YES:
            return
        if support is Support.NO:
            raise CapabilityUnavailableError(capability, feature)
        raise UnsupportedAccountFeatureError(
            feature,
            self._profile.kind,
            f"能力证据未知: {capability.value}",
        )

    def _validate_role(
        self,
        role: ConnectionRole,
        *,
        capability: Capability | None = None,
    ) -> ConnectionSpec:
        spec = self._specs[role]
        feature = f"connection:{role.value}"

        if role in (
            ConnectionRole.SH_L2,
            ConnectionRole.SZ_L2,
            ConnectionRole.BOARD_CONSTITUENT_SZ,
        ):
            if self._profile.kind is AccountKind.STANDARD:
                raise CapabilityUnavailableError(
                    Capability.L2_MARKET_ACCESS,
                    feature,
                )
            if self._profile.kind is AccountKind.UNKNOWN:
                raise UnsupportedAccountFeatureError(
                    feature,
                    self._profile.kind,
                    "账号类型未知，禁止尝试 Level2 通道",
                )
        if spec.required_capability is not None:
            self._require(spec.required_capability, feature=feature)
        if capability is not None:
            self._require(capability, feature=feature)
        return spec

    def acquire(
        self,
        role: ConnectionRole,
        *,
        capability: Capability | None = None,
    ) -> ManagedConnection:
        stale: ManagedConnection | None = None
        with self._lock:
            spec = self._validate_role(role, capability=capability)
            current = self._connections.get(role)
            if current is not None and current.active:
                if current.is_alive:
                    return current
                # 服务器已关闭该连接（例如 L2 预热 socket 空闲后被 FIN），
                # 本地 socket 对象仍在；移除后走 opener 重建，避免业务请求
                # 发到死连接上。
                self._connections.pop(role, None)
                stale = current
            try:
                opened = self._opener(spec)
            except Exception as exc:
                if stale is not None:
                    stale.close()
                raise ChannelUnavailableError(
                    role.value, str(exc)
                ) from exc
            if isinstance(opened, OpenedConnection):
                sock = opened.socket
                owns_socket = opened.owns_socket
                initialized = opened.initialized
                request_lock = opened.request_lock
            else:
                sock = opened
                owns_socket = True
                initialized = True
                request_lock = None
            if sock is None:
                raise ChannelUnavailableError(
                    role.value, "连接工厂未返回 socket"
                )
            # The opener contract returns a fully authenticated, role-ready
            # socket. Adopted legacy sockets carry explicit init evidence.
            connection = ManagedConnection(
                spec,
                sock,
                request_lock=request_lock,
                owns_socket=owns_socket,
                initialized=initialized,
            )
            self._connections[role] = connection
        if stale is not None:
            stale.close()
        return connection

    def adopt(
        self,
        role: ConnectionRole,
        sock: CloseableSocket,
        *,
        capability: Capability | None = None,
        request_lock: threading.RLock | None = None,
        owns_socket: bool = False,
        initialized: bool = False,
    ) -> ManagedConnection:
        """Register an already authenticated socket without opening a new one."""
        with self._lock:
            spec = self._validate_role(role, capability=capability)
            for current_role, current in self._connections.items():
                if (
                    current_role is not role
                    and current.active
                    and current.socket is sock
                ):
                    raise ChannelUnavailableError(
                        role.value,
                        f"同一 socket 已绑定角色: {current_role.value}",
                    )

            current = self._connections.get(role)
            if current is not None and current.active:
                if current.socket is not sock:
                    raise ChannelUnavailableError(
                        role.value,
                        "角色已有活动连接",
                    )
                if current.owns_socket != owns_socket:
                    raise ChannelUnavailableError(
                        role.value,
                        "重复收编的 socket 所有权设置不一致",
                    )
                if initialized:
                    current.mark_initialized()
                return current

            connection = ManagedConnection(
                spec,
                sock,
                request_lock=request_lock,
                owns_socket=owns_socket,
                initialized=initialized,
            )
            self._connections[role] = connection
            return connection

    def peek(self, role: ConnectionRole) -> ManagedConnection | None:
        with self._lock:
            connection = self._connections.get(role)
            if connection is None or not connection.active:
                return None
            return connection

    def close(self, role: ConnectionRole) -> None:
        with self._lock:
            connection = self._connections.pop(role, None)
        if connection is not None:
            connection.close()

    def close_all(self) -> None:
        with self._lock:
            connections = list(self._connections.values())
            self._connections.clear()
        for connection in connections:
            connection.close()
