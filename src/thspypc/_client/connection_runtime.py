"""Connection creation and background lifecycle for :class:`THSClient`.

The public client remains the compatibility facade.  This module owns the
role-aware connection opening policy, MAIN login orchestration, and background
thread lifecycle so protocol services no longer need a three-thousand-line
object as their runtime composition root.
"""
from __future__ import annotations

import logging
import socket
import threading
import time
from collections.abc import Callable
from typing import Any

from ..transport import ConnectionRole, OpenedConnection

logger = logging.getLogger(__name__)


class ConnectionFactory:
    """Create authenticated, initialized sockets for service connection roles."""

    def __init__(
        self,
        *,
        result_type: type,
        is_connected: Callable[[], bool],
        last_connect_ts: Callable[[], float],
        connect_cooldown: float,
        authenticate: Callable[..., Any],
        do_tcp_login: Callable[[dict], Any],
        main_socket: Callable[[], Any],
        connect_main: Callable[[], Any],
        main_lock: Any,
        current_auth: Callable[[], dict | None],
        drop_main: Callable[[], None],
        open_manual: Callable[[int], Any],
        push_sockets: dict,
        push_lock: Any,
        push_initialized: set,
        push_request_locks: dict,
        connect_realorder: Callable[[], None],
        realorder_socket: Callable[[], Any],
        realorder_lock: Any,
    ) -> None:
        self._result_type = result_type
        self._is_connected = is_connected
        self._last_connect_ts = last_connect_ts
        self._connect_cooldown = connect_cooldown
        self._authenticate = authenticate
        self._do_tcp_login = do_tcp_login
        self._main_socket = main_socket
        self._connect_main = connect_main
        self._main_lock = main_lock
        self._current_auth = current_auth
        self._drop_main = drop_main
        self._open_manual = open_manual
        self._push_sockets = push_sockets
        self._push_lock = push_lock
        self._push_initialized = push_initialized
        self._push_request_locks = push_request_locks
        self._connect_realorder = connect_realorder
        self._realorder_socket = realorder_socket
        self._realorder_lock = realorder_lock

    def connect_main(self, *, refresh_auth: bool = False):
        """Authenticate on demand and establish the ordinary MAIN channel."""
        if (
            self._last_connect_ts()
            and self._is_connected()
            and (
                time.time() - self._last_connect_ts()
                < self._connect_cooldown
            )
        ):
            elapsed = time.time() - self._last_connect_ts()
            logger.info(
                "connect(): 当前连接仍活着（%.1fs 前），复用避免重复 login 触发 -1",
                elapsed,
            )
            return self._result_type(
                success=True,
                verify_code="0",
                server="(reused)",
                error="reused_existing_connection",
            )

        try:
            material = self._authenticate(force=refresh_auth)
            passport_fields = dict(material.passport_fields)
            logger.debug(
                "passport 关键字段: account=%s, userclass=%s, level2=%s",
                passport_fields.get("account", "?"),
                passport_fields.get("userclass", "?"),
                passport_fields.get("level2", "?"),
            )
        except Exception as exc:
            logger.error("HTTP 鉴权失败: %s", exc)
            return self._result_type(
                success=False,
                error="http_auth_failed",
                detail=str(exc),
            )

        return self._do_tcp_login(passport_fields)

    def open(self, spec) -> OpenedConnection:
        """Open one role-ready socket while the facade retains socket ownership."""
        if spec.role is ConnectionRole.MAIN:
            if self._main_socket() is None:
                result = self._connect_main()
                if not result.success or self._main_socket() is None:
                    raise OSError(
                        f"MAIN 登录失败: {result.error or result.detail}"
                    )
            return OpenedConnection(
                socket=self._main_socket(),
                owns_socket=False,
                initialized=True,
                request_lock=self._main_lock,
            )

        l2_role = {
            ConnectionRole.SH_L2: ("sh", 17),
            ConnectionRole.SZ_L2: ("sz", 33),
        }.get(spec.role)
        if l2_role is not None:
            key, market = l2_role
            with self._push_lock:
                current = self._push_sockets.get(key)
                initialized = key in self._push_initialized
            if current is None:
                if self._current_auth() is None:
                    try:
                        self._authenticate()
                    except Exception as exc:
                        raise OSError(f"L2 HTTP 鉴权失败: {exc}") from exc
                self._drop_main()
                opened = self._open_manual(market)
                if opened is None:
                    raise OSError(f"__manual[{key}] 建连或 init 失败")
                with self._push_lock:
                    current = self._push_sockets.get(key)
                    if current is None:
                        self._push_sockets[key] = opened
                        self._push_initialized.add(key)
                        current = opened
                    else:
                        opened.close()
                    initialized = key in self._push_initialized
            return OpenedConnection(
                socket=current,
                owns_socket=False,
                initialized=initialized,
                request_lock=self._push_request_locks[key],
            )

        if spec.role is ConnectionRole.REALORDER:
            if self._realorder_socket() is None:
                self._connect_realorder()
            if self._realorder_socket() is None:
                raise OSError("realorder 建连失败")
            return OpenedConnection(
                socket=self._realorder_socket(),
                owns_socket=False,
                initialized=True,
                request_lock=self._realorder_lock,
            )

        raise OSError(f"不支持的连接角色: {spec.role.value}")


class ConnectionRuntime:
    """Own heartbeat, push-reader, and shutdown lifecycle."""

    def __init__(
        self,
        *,
        enable_heartbeat: bool,
        main_socket: Callable[[], Any],
        realorder_socket: Callable[[], Any],
        market_session: Any,
        realorder_lock: Any,
        realorder_service: Callable[[], Any],
        push_sockets: dict,
        push_lock: Any,
        push_request_locks: dict,
        push_initialized: set,
        preheat_threads: dict,
        service_connections: Callable[[], Any],
        close_owned_sockets: Callable[[], None],
    ) -> None:
        self.enable_heartbeat = enable_heartbeat
        self._main_socket = main_socket
        self._realorder_socket = realorder_socket
        self._market_session = market_session
        self._realorder_lock = realorder_lock
        self._realorder_service = realorder_service
        self._push_sockets = push_sockets
        self._push_lock = push_lock
        self._push_request_locks = push_request_locks
        self._push_initialized = push_initialized
        self._preheat_threads = preheat_threads
        self._service_connections = service_connections
        self._close_owned_sockets = close_owned_sockets

        self.heartbeat_thread: threading.Thread | None = None
        self.heartbeat_stop = threading.Event()
        self.heartbeat_seq_main = 0
        self.heartbeat_seq_realorder = 0
        self.snapshot_thread: threading.Thread | None = None
        self.snapshot_stop = threading.Event()
        self.snapshot_codes: set[str] = set()
        self.snapshot_callback = None
        self.latest_prices: dict[str, float] = {}

    def start_heartbeat(self) -> None:
        if not self.enable_heartbeat:
            return
        if self.heartbeat_thread and self.heartbeat_thread.is_alive():
            return
        self.heartbeat_stop.clear()
        self.heartbeat_thread = threading.Thread(
            target=self.heartbeat_loop,
            name="ths-heartbeat",
            daemon=True,
        )
        self.heartbeat_thread.start()
        logger.debug("心跳线程已启动")

    def stop_heartbeat(self) -> None:
        self.heartbeat_stop.set()
        if self.heartbeat_thread and self.heartbeat_thread.is_alive():
            self.heartbeat_thread.join(timeout=5)
        self.heartbeat_thread = None

    def activate_snapshot(self, code: str, market: int, callback) -> None:
        self.snapshot_codes.add(code)
        if callback is not None:
            self.snapshot_callback = callback
        if self.snapshot_thread is None or not self.snapshot_thread.is_alive():
            self.snapshot_stop.clear()
            self.snapshot_thread = threading.Thread(
                target=self.snapshot_loop,
                name="ths-snapshot",
                daemon=True,
            )
            self.snapshot_thread.start()
            logger.debug("分时推送读取线程已启动")
        logger.info("snapshot_subscribe: 已订阅 %s（market=%d）", code, market)

    def stop_snapshot(self) -> None:
        self.snapshot_stop.set()
        if self.snapshot_thread and self.snapshot_thread.is_alive():
            self.snapshot_thread.join(timeout=3)
        self.snapshot_thread = None
        for key, sock in list(self._push_sockets.items()):
            with self._push_request_locks[key]:
                try:
                    sock.close()
                except OSError:
                    pass
        self._push_sockets.clear()
        self._push_initialized.clear()
        self._preheat_threads.clear()
        manager = self._service_connections()
        if manager is not None:
            manager.close(ConnectionRole.SH_L2)
            manager.close(ConnectionRole.SZ_L2)

    def snapshot_loop(
        self,
        read_frame: Callable[[Any], bytes] | None = None,
        is_snapshot_push: Callable[[bytes], bool] | None = None,
        parse_snapshot_push: Callable[[bytes], dict | None] | None = None,
    ) -> None:
        import select
        from ..protocol import (
            is_snapshot_push as default_is_snapshot_push,
            parse_snapshot_push as default_parse_snapshot_push,
            read_frame as default_read_frame,
        )

        read = read_frame or default_read_frame
        matches = is_snapshot_push or default_is_snapshot_push
        parse = parse_snapshot_push or default_parse_snapshot_push
        while not self.snapshot_stop.is_set():
            with self._push_lock:
                socket_items = [
                    (key, sock)
                    for key, sock in self._push_sockets.items()
                    if sock is not None
                ]
            sockets = [sock for _, sock in socket_items]
            if not sockets:
                if self.snapshot_stop.wait(1.0):
                    break
                continue
            try:
                readable, _, _ = select.select(sockets, [], [], 1.0)
            except (OSError, ValueError):
                if self.snapshot_stop.wait(1.0):
                    break
                continue
            for sock in readable:
                key = next(
                    (
                        candidate_key
                        for candidate_key, candidate in socket_items
                        if candidate is sock
                    ),
                    None,
                )
                if key is None:
                    continue
                with self._push_request_locks[key]:
                    with self._push_lock:
                        if self._push_sockets.get(key) is not sock:
                            continue
                    try:
                        sock.settimeout(2.0)
                        body = read(sock)
                    except (socket.timeout, OSError, ValueError):
                        continue
                if not matches(body):
                    continue
                record = parse(body)
                if record is None:
                    continue
                self.latest_prices[record["code"]] = record["price"]
                if self.snapshot_callback is not None:
                    try:
                        self.snapshot_callback(
                            record["code"],
                            record["market"],
                            record["price"],
                            record["volume"],
                        )
                    except Exception as exc:
                        logger.warning("snapshot 回调异常: %s", exc)

    def heartbeat_loop(
        self,
        build_main_heartbeat: Callable[[int], bytes] | None = None,
        build_realorder_heartbeat: Callable[[int], bytes] | None = None,
    ) -> None:
        from ..protocol import (
            build_heartbeat_8901,
            build_heartbeat_9601,
        )

        build_main = build_main_heartbeat or build_heartbeat_8901
        build_realorder = (
            build_realorder_heartbeat or build_heartbeat_9601
        )
        tick = 0
        while not self.heartbeat_stop.is_set():
            if self.heartbeat_stop.wait(3.0):
                break
            tick += 1
            if self._main_socket():
                try:
                    self.heartbeat_seq_main += 1
                    sent = self._market_session.try_send(
                        build_main(self.heartbeat_seq_main)
                    )
                    if not sent:
                        logger.debug("8901 连接正在处理业务请求，跳过本轮心跳")
                except OSError as exc:
                    logger.debug("8901 心跳发送失败（不影响查询）: %s", exc)
            if tick % 10 == 0 and self._realorder_socket():
                try:
                    self.heartbeat_seq_realorder += 1
                    service = self._realorder_service()
                    if service is not None:
                        sent = service.send_heartbeat(
                            self.heartbeat_seq_realorder
                        )
                        if not sent:
                            logger.debug("9601 连接正在处理业务请求，跳过本轮心跳")
                    else:
                        with self._realorder_lock:
                            sock = self._realorder_socket()
                            if sock:
                                sock.sendall(
                                    build_realorder(
                                        self.heartbeat_seq_realorder
                                    )
                                    + b"\n"
                                )
                except OSError as exc:
                    logger.debug("9601 心跳发送失败（不影响查询）: %s", exc)

    def disconnect(self) -> None:
        self.stop_heartbeat()
        self.stop_snapshot()
        manager = self._service_connections()
        if manager is not None:
            manager.close_all()
        self._close_owned_sockets()
        logger.info("连接已关闭")
