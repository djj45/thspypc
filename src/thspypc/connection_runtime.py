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

from .models import Capability
from .transport import ConnectionRole, OpenedConnection

logger = logging.getLogger(__name__)


class ConnectionFactory:
    """Create authenticated, initialized sockets for service connection roles."""

    def __init__(self, client: Any, result_type: type) -> None:
        self._client = client
        self._result_type = result_type

    def connect_main(self, *, refresh_auth: bool = False):
        """Authenticate on demand and establish the ordinary MAIN channel."""
        client = self._client
        if (
            client._last_connect_ts
            and client.is_connected
            and (
                time.time() - client._last_connect_ts
                < client._CONNECT_COOLDOWN
            )
        ):
            elapsed = time.time() - client._last_connect_ts
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
            material = client.authenticate(force=refresh_auth)
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

        return client._do_tcp_login(passport_fields)

    def open(self, spec) -> OpenedConnection:
        """Open one role-ready socket while the facade retains socket ownership."""
        client = self._client
        if spec.role is ConnectionRole.MAIN:
            if client._sock is None:
                result = client.connect_main()
                if not result.success or client._sock is None:
                    raise OSError(
                        f"MAIN 登录失败: {result.error or result.detail}"
                    )
            return OpenedConnection(
                socket=client._sock,
                owns_socket=False,
                initialized=True,
                request_lock=client._sock_lock,
            )

        l2_role = {
            ConnectionRole.SH_L2: ("sh", 17),
            ConnectionRole.SZ_L2: ("sz", 33),
        }.get(spec.role)
        if l2_role is not None:
            key, market = l2_role
            with client._push_lock:
                current = client._push_socks.get(key)
                initialized = key in client._push_initialized
            if current is None:
                if client._auth is None:
                    try:
                        client.authenticate()
                    except Exception as exc:
                        raise OSError(f"L2 HTTP 鉴权失败: {exc}") from exc
                client._drop_connection()
                opened = client._open_manual_push_connection(market)
                if opened is None:
                    raise OSError(f"__manual[{key}] 建连或 init 失败")
                with client._push_lock:
                    current = client._push_socks.get(key)
                    if current is None:
                        client._push_socks[key] = opened
                        client._push_initialized.add(key)
                        current = opened
                    else:
                        opened.close()
                    initialized = key in client._push_initialized
            return OpenedConnection(
                socket=current,
                owns_socket=False,
                initialized=initialized,
                request_lock=client._push_request_locks[key],
            )

        if spec.role is ConnectionRole.REALORDER:
            if client._realorder_sock is None:
                client._connect_realorder_server()
            if client._realorder_sock is None:
                raise OSError("realorder 建连失败")
            return OpenedConnection(
                socket=client._realorder_sock,
                owns_socket=False,
                initialized=True,
                request_lock=client._realorder_lock,
            )

        raise OSError(f"不支持的连接角色: {spec.role.value}")


class ConnectionRuntime:
    """Own heartbeat, push-reader, and shutdown lifecycle."""

    def __init__(self, client: Any) -> None:
        self._client = client

    def start_heartbeat(self) -> None:
        client = self._client
        if not client.enable_heartbeat:
            return
        if client._heartbeat_thread and client._heartbeat_thread.is_alive():
            return
        client._heartbeat_stop.clear()
        client._heartbeat_thread = threading.Thread(
            target=client._heartbeat_loop,
            name="ths-heartbeat",
            daemon=True,
        )
        client._heartbeat_thread.start()
        logger.debug("心跳线程已启动")

    def stop_heartbeat(self) -> None:
        client = self._client
        client._heartbeat_stop.set()
        if client._heartbeat_thread and client._heartbeat_thread.is_alive():
            client._heartbeat_thread.join(timeout=5)
        client._heartbeat_thread = None

    def activate_snapshot(self, code: str, market: int, callback) -> None:
        client = self._client
        client._snapshot_codes.add(code)
        if callback is not None:
            client._snapshot_cb = callback
        if client._snapshot_thread is None or not client._snapshot_thread.is_alive():
            client._snapshot_stop.clear()
            client._snapshot_thread = threading.Thread(
                target=client._snapshot_loop,
                name="ths-snapshot",
                daemon=True,
            )
            client._snapshot_thread.start()
            logger.debug("分时推送读取线程已启动")
        logger.info("snapshot_subscribe: 已订阅 %s（market=%d）", code, market)

    def stop_snapshot(self) -> None:
        client = self._client
        client._snapshot_stop.set()
        if client._snapshot_thread and client._snapshot_thread.is_alive():
            client._snapshot_thread.join(timeout=3)
        client._snapshot_thread = None
        for key, sock in list(client._push_socks.items()):
            with client._push_request_locks[key]:
                try:
                    sock.close()
                except OSError:
                    pass
        client._push_socks.clear()
        client._push_initialized.clear()
        client._preheat_threads.clear()
        if client._service_connections is not None:
            client._service_connections.close(ConnectionRole.SH_L2)
            client._service_connections.close(ConnectionRole.SZ_L2)

    def snapshot_loop(
        self,
        read_frame: Callable[[Any], bytes],
        is_snapshot_push: Callable[[bytes], bool],
        parse_snapshot_push: Callable[[bytes], dict | None],
    ) -> None:
        import select

        client = self._client
        while not client._snapshot_stop.is_set():
            with client._push_lock:
                socket_items = [
                    (key, sock)
                    for key, sock in client._push_socks.items()
                    if sock is not None
                ]
            sockets = [sock for _, sock in socket_items]
            if not sockets:
                if client._snapshot_stop.wait(1.0):
                    break
                continue
            try:
                readable, _, _ = select.select(sockets, [], [], 1.0)
            except (OSError, ValueError):
                if client._snapshot_stop.wait(1.0):
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
                with client._push_request_locks[key]:
                    with client._push_lock:
                        if client._push_socks.get(key) is not sock:
                            continue
                    try:
                        sock.settimeout(2.0)
                        body = read_frame(sock)
                    except (socket.timeout, OSError, ValueError):
                        continue
                if not is_snapshot_push(body):
                    continue
                record = parse_snapshot_push(body)
                if record is None:
                    continue
                client._latest_price[record["code"]] = record["price"]
                if client._snapshot_cb is not None:
                    try:
                        client._snapshot_cb(
                            record["code"],
                            record["market"],
                            record["price"],
                            record["volume"],
                        )
                    except Exception as exc:
                        logger.warning("snapshot 回调异常: %s", exc)

    def heartbeat_loop(
        self,
        build_main_heartbeat: Callable[[int], bytes],
        build_realorder_heartbeat: Callable[[int], bytes],
    ) -> None:
        client = self._client
        tick = 0
        while not client._heartbeat_stop.is_set():
            if client._heartbeat_stop.wait(3.0):
                break
            tick += 1
            if client._sock:
                try:
                    client._hb_seq_8901 += 1
                    sent = client._market_session.try_send(
                        build_main_heartbeat(client._hb_seq_8901)
                    )
                    if not sent:
                        logger.debug("8901 连接正在处理业务请求，跳过本轮心跳")
                except OSError as exc:
                    logger.debug("8901 心跳发送失败（不影响查询）: %s", exc)
            if tick % 10 == 0 and client._realorder_sock:
                try:
                    client._hb_seq_9601 += 1
                    if client._realorder_service is not None:
                        sent = client._realorder_service.send_heartbeat(
                            client._hb_seq_9601
                        )
                        if not sent:
                            logger.debug("9601 连接正在处理业务请求，跳过本轮心跳")
                    else:
                        with client._realorder_lock:
                            if client._realorder_sock:
                                client._realorder_sock.sendall(
                                    build_realorder_heartbeat(
                                        client._hb_seq_9601
                                    )
                                    + b"\n"
                                )
                except OSError as exc:
                    logger.debug("9601 心跳发送失败（不影响查询）: %s", exc)

    def disconnect(self) -> None:
        client = self._client
        client.stop_heartbeat()
        client.stop_snapshot()
        if client._service_connections is not None:
            client._service_connections.close_all()
        for attr, lock in (
            ("_sock", client._sock_lock),
            ("_realorder_sock", client._realorder_lock),
        ):
            with lock:
                sock = getattr(client, attr, None)
                if sock:
                    try:
                        sock.close()
                    except OSError:
                        pass
                    setattr(client, attr, None)
        logger.info("连接已关闭")
