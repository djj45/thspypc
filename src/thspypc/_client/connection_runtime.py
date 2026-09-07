"""Connection creation and background lifecycle for :class:`THSClient`.

The public client remains the compatibility facade.  This module owns the
role-aware connection opening policy, MAIN login orchestration, and background
thread lifecycle so protocol services no longer need a three-thousand-line
object as their runtime composition root.
"""
from __future__ import annotations

import logging
import queue
import socket
import threading
import time
from collections.abc import Callable
from typing import Any

from ..codecs.framing import (
    read_frame,
    register_frame_observer,
    unregister_frame_observer,
)
from ..features.heartbeat_protocol import (
    build_heartbeat_probe,
    is_heartbeat_ack,
)
from ..transport import (
    ConnectionRole,
    DispatchDecision,
    DispatchRequest,
    OpenedConnection,
    probe_socket_alive,
)
from .heartbeat_monitor import HeartbeatMonitor

logger = logging.getLogger(__name__)


def _real_socket_alive(sock: Any) -> bool:
    """Probe a real TCP socket without consuming data; doubles count as alive."""
    return probe_socket_alive(sock)


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
        open_manual: Callable[[int, Any], Any],
        push_sockets: dict,
        push_lock: Any,
        push_initialized: set,
        push_request_locks: dict,
        connect_realorder: Callable[[], None],
        realorder_socket: Callable[[], Any],
        realorder_lock: Any,
        board_socket: Callable[[], Any],
        set_board_socket: Callable[[Any], None],
        open_board: Callable[[], Any],
        board_lock: Any,
        open_board_constituent: Callable[[str], Any],
        connect_board_stats: Callable[[], None],
        board_stats_socket: Callable[[], Any],
        board_stats_lock: Any,
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
        # 保留注入参数兼容现有组合根；L2 建连已不再需要拆掉健康 MAIN。
        self._drop_main = drop_main
        self._open_manual = open_manual
        self._push_sockets = push_sockets
        self._push_lock = push_lock
        self._push_initialized = push_initialized
        self._push_request_locks = push_request_locks
        self._connect_realorder = connect_realorder
        self._realorder_socket = realorder_socket
        self._realorder_lock = realorder_lock
        self._board_socket = board_socket
        self._set_board_socket = set_board_socket
        self._open_board = open_board
        self._board_lock = board_lock
        self._open_board_constituent = open_board_constituent
        self._connect_board_stats = connect_board_stats
        self._board_stats_socket = board_stats_socket
        self._board_stats_lock = board_stats_lock

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
            if current is not None and not _real_socket_alive(current):
                logger.warning(
                    "L2[%s] 预热 socket 已被服务端关闭，丢弃并重建", key
                )
                with self._push_lock:
                    if self._push_sockets.get(key) is current:
                        self._push_sockets.pop(key, None)
                        self._push_initialized.discard(key)
                try:
                    current.close()
                except OSError:
                    pass
                current = None
                initialized = False
            if current is None:
                # 一个 Passport64 在首次成功登录后即视为已消费。MAIN、SH_L2、
                # SZ_L2 每条新 socket 都使用独立的新一代通行证；刷新 HTTP 鉴权
                # 不影响已经登录并保持心跳的 MAIN socket。
                try:
                    material = self._authenticate(force=True)
                except Exception as exc:
                    raise OSError(f"L2 HTTP 鉴权失败: {exc}") from exc
                # 将这一代不可变材料直接交给建连函数。若这里只刷新全局
                # current 后再让 opener 读取，并发建连可能在两步之间覆盖它，
                # 导致两条 socket 误用同一 Passport64。
                opened = self._open_manual(market, material)
                if opened is None:
                    raise OSError(f"L2[{key}] 建连或 init 失败")
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

        if spec.role is ConnectionRole.BOARD:
            if self._board_socket() is None:
                opened = self._open_board()
                with self._board_lock:
                    current = self._board_socket()
                    if current is None:
                        self._set_board_socket(opened)
                    else:
                        opened.close()
            sock = self._board_socket()
            if sock is None:
                raise OSError("板块通道建连失败")
            return OpenedConnection(
                socket=sock,
                owns_socket=False,
                initialized=True,
                request_lock=self._board_lock,
            )

        constituent_side = {
            ConnectionRole.BOARD_CONSTITUENT_SH: "sh",
            ConnectionRole.BOARD_CONSTITUENT_SZ: "sz",
        }.get(spec.role)
        if constituent_side is not None:
            sock = self._open_board_constituent(constituent_side)
            if sock is None:
                raise OSError(
                    f"板块成分股[{constituent_side}]通道建连失败"
                )
            # This socket is not mirrored by a legacy facade attribute.  The
            # ConnectionManager owns and closes it directly.
            return OpenedConnection(
                socket=sock,
                owns_socket=True,
                initialized=True,
            )

        if spec.role is ConnectionRole.BOARD_STATS:
            # statscalc 走独立统计节点（8.132.233.77:9601），与 REALORDER seed
            # 不同服；懒建连，失败抛 OSError 由服务层捕获后返回空列表。
            if self._board_stats_socket() is None:
                self._connect_board_stats()
            sock = self._board_stats_socket()
            if sock is None:
                raise OSError("板块统计(statscalc)通道建连失败")
            return OpenedConnection(
                socket=sock,
                owns_socket=False,
                initialized=True,
                request_lock=self._board_stats_lock,
            )

        raise OSError(f"不支持的连接角色: {spec.role.value}")


class ConnectionRuntime:
    """Own heartbeat, push-reader, and shutdown lifecycle."""

    # The official desktop client emits this response-bearing short probe on
    # a 60-second cadence.  Sending it every 30 seconds makes the server reply
    # to alternating probes and creates a deterministic false ``suspect``.
    HEARTBEAT_PROBE_INTERVAL_TICKS = 20
    HEARTBEAT_RESPONSE_TIMEOUT = 12.0
    HEARTBEAT_MISS_THRESHOLD = 2

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
        board_stats_socket: Callable[[], Any] | None = None,
        board_stats_lock: Any = None,
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
        self._board_stats_socket = board_stats_socket
        self._board_stats_lock = board_stats_lock

        self.heartbeat_thread: threading.Thread | None = None
        self.heartbeat_stop = threading.Event()
        self.heartbeat_seq_main = 0
        self.heartbeat_seq_realorder = 0
        self.heartbeat_seq_board_stats = 0
        self.heartbeat_seq_push: dict[str, int] = {}
        self._heartbeat_monitor = HeartbeatMonitor(
            response_timeout=self.HEARTBEAT_RESPONSE_TIMEOUT,
            miss_threshold=self.HEARTBEAT_MISS_THRESHOLD,
        )
        self.snapshot_thread: threading.Thread | None = None
        self.snapshot_stop = threading.Event()
        self.snapshot_codes: set[str] = set()
        self.snapshot_callback = None
        self.latest_prices: dict[str, float] = {}
        self.latest_depth: dict[str, dict] = {}
        self.depth_codes: set[str] = set()
        self.depth_callbacks: dict[str, Callable[[dict], None]] = {}
        self.ranking_depth_codes: set[str] = set()
        self.ranking_depth_callbacks: dict[str, Callable[[dict], None]] = {}
        self.depth_events: queue.Queue[dict] = queue.Queue(maxsize=1024)
        self.market_event_codes: set[str] = set()
        self.market_event_callbacks: dict[str, Callable[[dict], None]] = {}
        self.market_events: queue.Queue[dict] = queue.Queue(maxsize=4096)

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

    def heartbeat_status(self) -> dict[str, object]:
        """Return a lock-only heartbeat snapshot suitable for ``/api/status``."""
        return {
            "enabled": bool(self.enable_heartbeat),
            # First deployment is deliberately diagnostic-only.  It proves
            # ACK timing and false-positive rate before connection retirement
            # is allowed to trigger a fresh Passport/login lifecycle.
            "mode": "observe_only",
            "probe_interval_seconds": (
                self.HEARTBEAT_PROBE_INTERVAL_TICKS * 3
            ),
            "response_timeout_seconds": self.HEARTBEAT_RESPONSE_TIMEOUT,
            "miss_threshold": self.HEARTBEAT_MISS_THRESHOLD,
            "lanes": self._heartbeat_monitor.snapshot(),
        }

    def _bind_heartbeat_lane(self, lane: str, sock: Any) -> None:
        self._heartbeat_monitor.bind(lane, sock)
        register_frame_observer(
            sock,
            lambda observed_sock, body, lane_name=lane: (
                self._heartbeat_monitor.observe(
                    lane_name,
                    observed_sock,
                    body,
                )
            ),
        )

    def _probe_consumer(
        self,
        lane: str,
        sock: Any,
        probe_id: int,
        unsolicited: Callable[[bytes], Any] | None,
    ):
        def consume(body: bytes, observed_sock: Any) -> DispatchDecision:
            # Production readers notify centrally before returning the body.
            # The fallback keeps injected test readers and custom readers
            # observable without double-counting production frames.
            if self._heartbeat_monitor.has_pending(
                lane,
                observed_sock,
                probe_id,
            ):
                self._heartbeat_monitor.observe(lane, observed_sock, body)
            ack = is_heartbeat_ack(body)
            if unsolicited is not None and not ack:
                try:
                    unsolicited(body)
                except Exception as exc:
                    logger.debug(
                        "%s 心跳探针转交下行帧失败: %s",
                        lane,
                        exc,
                    )
            return DispatchDecision(matched=True, done=True, value=ack)

        return consume

    def _finish_probe_future(
        self,
        lane: str,
        sock: Any,
        probe_id: int,
        future: Any,
    ) -> None:
        try:
            future.result()
        except Exception as exc:
            state = self._heartbeat_monitor.fail_probe(
                lane,
                sock,
                probe_id,
            )
            if isinstance(exc, OSError) and not isinstance(exc, TimeoutError):
                if self._heartbeat_monitor.note_transport_failure(lane, sock):
                    state = "unresponsive"
            if state is not None:
                log = logger.warning if state == "unresponsive" else logger.debug
                log("%s 心跳探针无下行响应（%s）: %s", lane, state, exc)

    def _schedule_dispatch_probe(
        self,
        lane: str,
        sock: Any,
        owner: Any,
        frame: bytes,
        frame_reader: Callable[[Any], bytes],
        *,
        unsolicited: Callable[[bytes], Any] | None = None,
    ) -> bool:
        self._bind_heartbeat_lane(lane, sock)
        probe_id = self._heartbeat_monitor.begin_probe(lane, sock)
        if probe_id is None:
            return False
        request = DispatchRequest(
            frame=frame,
            consume=self._probe_consumer(
                lane,
                sock,
                probe_id,
                unsolicited,
            ),
            name=f"heartbeat:{lane}",
            trailing_newline=False,
        )
        try:
            future = owner.try_dispatch(
                request,
                frame_reader=frame_reader,
                timeout=self.HEARTBEAT_RESPONSE_TIMEOUT,
                max_frames=256,
            )
        except Exception as exc:
            state = self._heartbeat_monitor.fail_probe(lane, sock, probe_id)
            if isinstance(exc, OSError) and not isinstance(exc, TimeoutError):
                if self._heartbeat_monitor.note_transport_failure(lane, sock):
                    state = "unresponsive"
            logger.debug("%s 心跳探针发送失败（%s）: %s", lane, state, exc)
            return False
        if future is None:
            self._heartbeat_monitor.cancel_probe(lane, sock, probe_id)
            self._heartbeat_monitor.note_skipped(lane, sock)
            return False
        future.add_done_callback(
            lambda completed, lane_name=lane, lane_sock=sock, pid=probe_id: (
                self._finish_probe_future(
                    lane_name,
                    lane_sock,
                    pid,
                    completed,
                )
            )
        )
        return True

    def _expire_raw_probes(self) -> None:
        for lane, _sock, _probe_id, state in self._heartbeat_monitor.expire():
            logger.debug("%s 心跳探针无下行响应（%s）", lane, state)

    def activate_snapshot(self, code: str, market: int, callback) -> None:
        self.snapshot_codes.add(code)
        if callback is not None:
            self.snapshot_callback = callback
        self._ensure_snapshot_reader()
        logger.info("snapshot_subscribe: 已订阅 %s（market=%d）", code, market)

    def activate_depth(self, code: str, market: int, callback) -> None:
        """Activate local delivery for one successfully registered depth code."""
        with self._push_lock:
            self.depth_codes.add(code)
            if callback is not None:
                self.depth_callbacks[code] = callback
        self._ensure_snapshot_reader()
        logger.info("depth_subscribe: 已订阅 %s（market=%d）", code, market)

    def activate_ranking_depth(self, code: str, market: int, callback) -> None:
        """Activate list-bucket delivery without stealing per-code ownership."""
        with self._push_lock:
            self.ranking_depth_codes.add(code)
            if callback is not None:
                self.ranking_depth_callbacks[code] = callback
        self._ensure_snapshot_reader()
        logger.info("ranking_depth: 已订阅 %s（market=%d）", code, market)

    def activate_market_events(self, code: str, market: int, callback) -> None:
        """Activate normalized trade/depth/queue/cancel event delivery."""
        with self._push_lock:
            self.market_event_codes.add(code)
            if callback is not None:
                self.market_event_callbacks[code] = callback
        self._ensure_snapshot_reader()
        logger.info("market_events: 已订阅 %s（market=%d）", code, market)

    def deactivate_depth(self, code: str, *, clear_latest: bool = True) -> bool:
        """Stop local depth delivery; close L2 readers when no consumer remains.

        The captured 4214 protocol has no verified per-code wire unsubscribe.  A
        single-code removal is therefore a local filter.  Once the last snapshot
        and depth consumer leaves, closing the channels is the unambiguous server-
        side unsubscribe operation.
        """
        with self._push_lock:
            active = code in self.depth_codes
            self.depth_codes.discard(code)
            self.depth_callbacks.pop(code, None)
            if clear_latest:
                self.latest_depth.pop(code, None)
            should_stop = (
                not self.depth_codes
                and not self.ranking_depth_codes
                and not self.snapshot_codes
                and not self.market_event_codes
            )
        if should_stop:
            self.stop_snapshot()
        return active

    def deactivate_ranking_depth(
        self,
        code: str,
        *,
        clear_latest: bool = True,
    ) -> bool:
        """Stop list-bucket delivery while preserving per-code subscriptions."""
        with self._push_lock:
            active = code in self.ranking_depth_codes
            self.ranking_depth_codes.discard(code)
            self.ranking_depth_callbacks.pop(code, None)
            if clear_latest and code not in self.depth_codes:
                self.latest_depth.pop(code, None)
            should_stop = (
                not self.depth_codes
                and not self.ranking_depth_codes
                and not self.snapshot_codes
                and not self.market_event_codes
            )
        if should_stop:
            self.stop_snapshot()
        return active

    def deactivate_market_events(self, code: str) -> bool:
        """Stop normalized event delivery for one code."""
        with self._push_lock:
            active = code in self.market_event_codes
            self.market_event_codes.discard(code)
            self.market_event_callbacks.pop(code, None)
            should_stop = (
                not self.depth_codes
                and not self.ranking_depth_codes
                and not self.snapshot_codes
                and not self.market_event_codes
            )
        if should_stop:
            self.stop_snapshot()
        return active

    def receive_depth(self, timeout: float | None = None) -> dict | None:
        """Return the next event for a currently active depth subscription."""
        deadline = None if timeout is None else time.monotonic() + max(timeout, 0.0)
        while True:
            remaining = None if deadline is None else max(deadline - time.monotonic(), 0.0)
            try:
                record = self.depth_events.get(timeout=remaining)
            except queue.Empty:
                return None
            with self._push_lock:
                if (
                    record.get("code") in self.depth_codes
                    or record.get("code") in self.ranking_depth_codes
                ):
                    return record
            if deadline is not None and time.monotonic() >= deadline:
                return None

    def receive_market_event(
        self,
        timeout: float | None = None,
    ) -> dict | None:
        """Return the next event for an active normalized subscription."""
        deadline = None if timeout is None else time.monotonic() + max(timeout, 0.0)
        while True:
            remaining = (
                None
                if deadline is None
                else max(deadline - time.monotonic(), 0.0)
            )
            try:
                record = self.market_events.get(timeout=remaining)
            except queue.Empty:
                return None
            with self._push_lock:
                if record.get("code") in self.market_event_codes:
                    return record
            if deadline is not None and time.monotonic() >= deadline:
                return None

    def _ensure_snapshot_reader(self) -> None:
        if self.snapshot_thread is None or not self.snapshot_thread.is_alive():
            self.snapshot_stop.clear()
            self.snapshot_thread = threading.Thread(
                target=self.snapshot_loop,
                name="ths-snapshot",
                daemon=True,
            )
            self.snapshot_thread.start()
            logger.debug("分时推送读取线程已启动")

    def stop_snapshot(self) -> None:
        self.snapshot_stop.set()
        if self.snapshot_thread and self.snapshot_thread.is_alive():
            if self.snapshot_thread is not threading.current_thread():
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
        with self._push_lock:
            self.snapshot_codes.clear()
            self.snapshot_callback = None
            self.depth_codes.clear()
            self.depth_callbacks.clear()
            self.ranking_depth_codes.clear()
            self.ranking_depth_callbacks.clear()
            self.market_event_codes.clear()
            self.market_event_callbacks.clear()
            while True:
                try:
                    self.depth_events.get_nowait()
                except queue.Empty:
                    break
            while True:
                try:
                    self.market_events.get_nowait()
                except queue.Empty:
                    break
        manager = self._service_connections()
        if manager is not None:
            manager.close(ConnectionRole.SH_L2)
            manager.close(ConnectionRole.SZ_L2)

    def snapshot_loop(
        self,
        read_frame: Callable[[Any], bytes] | None = None,
        is_snapshot_push: Callable[[bytes], bool] | None = None,
        parse_snapshot_push: Callable[[bytes], dict | None] | None = None,
        is_depth_push: Callable[[bytes], bool] | None = None,
        parse_depth_push: Callable[[bytes], dict | None] | None = None,
        parse_depth_push_records: Callable[[bytes], list[dict]] | None = None,
    ) -> None:
        import select
        from ..protocol import read_frame as default_read_frame

        read = read_frame or default_read_frame
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
                self.deliver_market_push(
                    body,
                    is_snapshot_push=is_snapshot_push,
                    parse_snapshot_push=parse_snapshot_push,
                    is_depth_push=is_depth_push,
                    parse_depth_push=parse_depth_push,
                    parse_depth_push_records=parse_depth_push_records,
                )

    def deliver_market_push(
        self,
        body: bytes,
        *,
        is_snapshot_push: Callable[[bytes], bool] | None = None,
        parse_snapshot_push: Callable[[bytes], dict | None] | None = None,
        is_depth_push: Callable[[bytes], bool] | None = None,
        parse_depth_push: Callable[[bytes], dict | None] | None = None,
        parse_depth_push_records: Callable[[bytes], list[dict]] | None = None,
    ) -> bool:
        """Parse and deliver one unsolicited 8901 market-data body.

        Request coordinators call this when a depth frame arrives before their
        matching ACK/response, so changing a list bucket does not silently drop
        a concurrent ``0x0f7f`` update.
        """
        from ..protocol import (
            is_depth_push as default_is_depth_push,
            is_order_cancel_batch_push,
            is_order_cancel_push,
            is_order_queue_push,
            is_snapshot_push as default_is_snapshot_push,
            is_trade_tick_batch_push,
            parse_depth_push_records as default_parse_depth_push_records,
            parse_order_cancel_batch_push,
            parse_order_cancel_push,
            parse_order_queue_push,
            parse_snapshot_push as default_parse_snapshot_push,
            parse_trade_tick_batch_push,
        )

        matches = is_snapshot_push or default_is_snapshot_push
        parse = parse_snapshot_push or default_parse_snapshot_push
        depth_matches = is_depth_push or default_is_depth_push
        depth_parse_records = (
            parse_depth_push_records or default_parse_depth_push_records
        )
        # 优先匹配批量/单笔成交（旧71B/0x7f或新0x60-04）；否则尝试
        # 0x0f7f 十档盘口推送。批量帧必须展开成逐条记录再交给相同回调链。
        if is_trade_tick_batch_push(body):
            batch = parse_trade_tick_batch_push(body)
            records = batch.get("records", []) if batch is not None else []
        elif matches(body):
            record = parse(body)
            records = [record] if record is not None else []
        elif is_order_cancel_batch_push(body):
            batch = parse_order_cancel_batch_push(body)
            records = batch.get("records", []) if batch is not None else []
        elif is_order_cancel_push(body):
            record = parse_order_cancel_push(body)
            records = [record] if record is not None else []
        elif is_order_queue_push(body):
            record = parse_order_queue_push(body)
            records = [record] if record is not None else []
        elif depth_matches(body):
            if parse_depth_push_records is not None or parse_depth_push is None:
                records = depth_parse_records(body)
            else:
                record = parse_depth_push(body)
                records = [record] if record is not None else []
        else:
            return False
        for record in records:
            if record.get("event") == "order_cancel":
                # The browser stream uses a compact event vocabulary while
                # keeping the wire parser's name available for diagnostics.
                # The 0x60 push parser and the 7170/7171 replay parser
                # describe the same cancel concepts under different field
                # names (placed_at/cancelled_at/lifetime_seconds vs
                # placed_time/cancelled_time/elapsed_seconds).  Alias the
                # replay vocabulary here so both sources reach the browser
                # with one shared naming; the original fields stay for
                # diagnostics.
                record = {
                    **record,
                    "event": "cancel",
                    "source_event": "order_cancel",
                    "cancelled_time": record.get("cancelled_at"),
                    "placed_time": record.get("placed_at"),
                    "cancelled_ts": record.get("cancelled_timestamp"),
                    "placed_ts": record.get("placed_timestamp"),
                    "elapsed_seconds": record.get("lifetime_seconds"),
                }
            code = record["code"]
            event = record.get("event")
            is_depth_record = "bids" in record or record.get("phase") == "auction"
            if is_depth_record and event is None:
                # 深度解析器历史上只用 bids/asks/phase 表示类型；统一市场事件
                # WebSocket 依赖 event 字段分流，不补标签会导致十档推送已经到达
                # 后端却被浏览器静默过滤。
                record["event"] = "depth"
                event = "depth"
            updates_latest_price = (
                "price" in record
                and (is_depth_record or event in (None, "trade"))
            )
            if updates_latest_price:
                self.latest_prices[code] = record["price"]
            with self._push_lock:
                depth_active = is_depth_record and (
                    code in self.depth_codes or code in self.ranking_depth_codes
                )
                cache_depth = is_depth_record and (
                    code in self.depth_codes
                    or code in self.ranking_depth_codes
                    or code in self.snapshot_codes
                )
                depth_callback = self.depth_callbacks.get(code)
                ranking_callback = self.ranking_depth_callbacks.get(code)
                snapshot_active = (
                    code in self.snapshot_codes
                    or self.snapshot_callback is not None
                )
                market_event_active = code in self.market_event_codes
                market_event_callback = self.market_event_callbacks.get(code)
            if cache_depth:
                self.latest_depth[code] = record
            if depth_active:
                try:
                    self.depth_events.put_nowait(record)
                except queue.Full:
                    try:
                        self.depth_events.get_nowait()
                    except queue.Empty:
                        pass
                    try:
                        self.depth_events.put_nowait(record)
                    except queue.Full:
                        pass
                callbacks = []
                for callback in (depth_callback, ranking_callback):
                    if callback is not None and all(
                        callback is not current for current in callbacks
                    ):
                        callbacks.append(callback)
                for callback in callbacks:
                    try:
                        callback(record)
                    except Exception as exc:
                        logger.warning("depth 回调异常: %s", exc)
            if market_event_active:
                try:
                    self.market_events.put_nowait(record)
                except queue.Full:
                    try:
                        self.market_events.get_nowait()
                    except queue.Empty:
                        pass
                    try:
                        self.market_events.put_nowait(record)
                    except queue.Full:
                        pass
                if market_event_callback is not None:
                    try:
                        market_event_callback(record)
                    except Exception as exc:
                        logger.warning("market event 回调异常: %s", exc)
            if (
                snapshot_active
                and self.snapshot_callback is not None
                and (is_depth_record or event in (None, "trade"))
            ):
                try:
                    self.snapshot_callback(
                        code,
                        record["market"],
                        record.get("price", 0.0),
                        record.get("volume", 0),
                    )
                except Exception as exc:
                    logger.warning("snapshot 回调异常: %s", exc)
        return bool(records)

    def heartbeat_loop(
        self,
        build_main_heartbeat: Callable[[int], bytes] | None = None,
        build_realorder_heartbeat: Callable[[int], bytes] | None = None,
        build_probe_heartbeat: Callable[[int], bytes] | None = None,
    ) -> None:
        from ..features.board_stats_protocol import read_frame_board_stats
        from ..features.realorder_protocol import read_frame_realorder
        from ..protocol import (
            build_heartbeat_8901,
            build_heartbeat_9601,
        )

        build_main = build_main_heartbeat or build_heartbeat_8901
        build_realorder = (
            build_realorder_heartbeat or build_heartbeat_9601
        )
        build_probe = build_probe_heartbeat or build_heartbeat_probe
        tick = 0
        while not self.heartbeat_stop.is_set():
            if self.heartbeat_stop.wait(3.0):
                break
            tick += 1
            self._expire_raw_probes()
            manager = self._service_connections()
            main_sock = self._main_socket()
            if main_sock:
                self._bind_heartbeat_lane("main", main_sock)
                main_connection = (
                    manager.peek(ConnectionRole.MAIN)
                    if manager is not None
                    else None
                )
                main_owner = (
                    main_connection
                    if main_connection is not None
                    and main_connection.socket is main_sock
                    else self._market_session
                )
                try:
                    self.heartbeat_seq_main += 1
                    sent = main_owner.try_send(
                        build_main(self.heartbeat_seq_main)
                    )
                    if sent:
                        self._heartbeat_monitor.note_keepalive(
                            "main",
                            main_sock,
                        )
                    else:
                        self._heartbeat_monitor.note_skipped("main", main_sock)
                        logger.debug("8901 连接正在处理业务请求，跳过本轮心跳")
                except OSError as exc:
                    self._heartbeat_monitor.note_transport_failure(
                        "main",
                        main_sock,
                    )
                    logger.debug("8901 心跳发送失败（不影响查询）: %s", exc)
                if tick % self.HEARTBEAT_PROBE_INTERVAL_TICKS == 0:
                    self.heartbeat_seq_main += 1
                    probe_token = int(time.monotonic() * 1000)
                    self._schedule_dispatch_probe(
                        "main",
                        main_sock,
                        main_owner,
                        build_probe(probe_token),
                        read_frame,
                        unsolicited=self.deliver_market_push,
                    )
            if manager is not None:
                kline = manager.peek(ConnectionRole.KLINE_FAST)
                if kline is not None:
                    kline_sock = kline.socket
                else:
                    kline_sock = None
                if kline is not None and kline_sock is not None:
                    self._bind_heartbeat_lane("kline_fast", kline_sock)
                    try:
                        self.heartbeat_seq_main += 1
                        sent = kline.try_send(build_main(self.heartbeat_seq_main))
                        if sent:
                            self._heartbeat_monitor.note_keepalive(
                                "kline_fast",
                                kline_sock,
                            )
                        else:
                            self._heartbeat_monitor.note_skipped(
                                "kline_fast",
                                kline_sock,
                            )
                    except OSError as exc:
                        self._heartbeat_monitor.note_transport_failure(
                            "kline_fast",
                            kline_sock,
                        )
                        logger.debug(
                            "KLINE_FAST heartbeat failed: %s",
                            exc,
                        )
                    if tick % self.HEARTBEAT_PROBE_INTERVAL_TICKS == 0:
                        self.heartbeat_seq_main += 1
                        probe_token = int(time.monotonic() * 1000)
                        self._schedule_dispatch_probe(
                            "kline_fast",
                            kline_sock,
                            kline,
                            build_probe(probe_token),
                            read_frame,
                            unsolicited=self.deliver_market_push,
                        )
            # 预热出来的 SH_L2/SZ_L2 也是裸 socket，之前没有心跳，服务器会
            # 在空闲几十秒后主动 FIN；业务再使用时 4214 注册自然拿不到
            # CodeListSize。现在与 MAIN/KLINE 一样每 3 秒保活，并检测死连接。
            dead_l2: list[tuple[str, Any]] = []
            for key, role in (
                ("sh", ConnectionRole.SH_L2),
                ("sz", ConnectionRole.SZ_L2),
            ):
                with self._push_lock:
                    sock = self._push_sockets.get(key)
                if sock is None:
                    continue
                lane = f"{key}_l2"
                self._bind_heartbeat_lane(lane, sock)
                # probe_socket_alive() temporarily calls setblocking(False) on
                # Windows.  Probe and heartbeat write must share the same lane
                # lock as business recv; otherwise recv can fail with 10035.
                request_lock = self._push_request_locks[key]
                if not request_lock.acquire(blocking=False):
                    # An active request/reader owns the lane; skip this beat.
                    self._heartbeat_monitor.note_skipped(lane, sock)
                    continue
                seq = self.heartbeat_seq_push.get(key, 0) + 1
                self.heartbeat_seq_push[key] = seq
                try:
                    if not _real_socket_alive(sock):
                        self._heartbeat_monitor.note_transport_failure(lane, sock)
                        dead_l2.append((key, sock))
                        continue
                    sock.sendall(build_main(seq) + b"\n")
                    self._heartbeat_monitor.note_keepalive(lane, sock)
                    reader_active = bool(
                        self.snapshot_thread
                        and self.snapshot_thread.is_alive()
                    )
                    if (
                        reader_active
                        and tick % self.HEARTBEAT_PROBE_INTERVAL_TICKS == 0
                    ):
                        seq += 1
                        self.heartbeat_seq_push[key] = seq
                        probe_token = int(time.monotonic() * 1000)
                        probe_id = self._heartbeat_monitor.begin_probe(
                            lane,
                            sock,
                        )
                        if probe_id is not None:
                            try:
                                # The captured short probe has no trailing LF.
                                sock.sendall(build_probe(probe_token))
                            except OSError:
                                self._heartbeat_monitor.fail_probe(
                                    lane,
                                    sock,
                                    probe_id,
                                )
                                self._heartbeat_monitor.note_transport_failure(
                                    lane,
                                    sock,
                                )
                                raise
                except OSError as exc:
                    self._heartbeat_monitor.note_transport_failure(lane, sock)
                    logger.debug("L2[%s] 心跳发送失败：%s", key, exc)
                    dead_l2.append((key, sock))
                finally:
                    request_lock.release()
            for key, sock in dead_l2:
                with self._push_lock:
                    if self._push_sockets.get(key) is sock:
                        self._push_sockets.pop(key, None)
                        self._push_initialized.discard(key)
                try:
                    sock.close()
                except OSError:
                    pass
                if manager is not None:
                    manager.close(
                        ConnectionRole.SH_L2
                        if key == "sh"
                        else ConnectionRole.SZ_L2
                    )
            if (
                tick % self.HEARTBEAT_PROBE_INTERVAL_TICKS == 0
                and self._realorder_socket()
            ):
                try:
                    self.heartbeat_seq_realorder += 1
                    realorder_sock = self._realorder_socket()
                    self._bind_heartbeat_lane("realorder", realorder_sock)
                    service = self._realorder_service()
                    connection = (
                        manager.peek(ConnectionRole.REALORDER)
                        if manager is not None
                        else None
                    )
                    if connection is not None:
                        unsolicited = getattr(
                            service,
                            "observe_unsolicited",
                            None,
                        )
                        self._schedule_dispatch_probe(
                            "realorder",
                            realorder_sock,
                            connection,
                            build_probe(int(time.monotonic() * 1000)),
                            read_frame_realorder,
                            unsolicited=unsolicited,
                        )
                    else:
                        # Compatibility fallback before the service registry is
                        # configured: preserve keepalive without taking recv.
                        with self._realorder_lock:
                            sock = self._realorder_socket()
                            if sock:
                                sock.sendall(
                                    build_realorder(
                                        self.heartbeat_seq_realorder
                                    )
                                    + b"\n"
                                )
                                self._heartbeat_monitor.note_keepalive(
                                    "realorder",
                                    sock,
                                )
                except OSError as exc:
                    realorder_sock = self._realorder_socket()
                    if realorder_sock is not None:
                        self._heartbeat_monitor.note_transport_failure(
                            "realorder",
                            realorder_sock,
                        )
                    logger.debug("9601 心跳发送失败（不影响查询）: %s", exc)
            # statscalc 独立统计节点（9601）心跳：与 realorder 同为 5 字节 9601 心跳，
            # 但走独立 socket/lock。仅在连接已建立时发送。
            if (
                tick % self.HEARTBEAT_PROBE_INTERVAL_TICKS == 0
                and self._board_stats_socket is not None
                and self._board_stats_socket() is not None
                and self._board_stats_lock is not None
            ):
                try:
                    self.heartbeat_seq_board_stats += 1
                    sock = self._board_stats_socket()
                    if sock:
                        self._bind_heartbeat_lane("board_stats", sock)
                    connection = (
                        manager.peek(ConnectionRole.BOARD_STATS)
                        if manager is not None
                        else None
                    )
                    if sock and connection is not None:
                        self._schedule_dispatch_probe(
                            "board_stats",
                            sock,
                            connection,
                            build_probe(int(time.monotonic() * 1000)),
                            read_frame_board_stats,
                        )
                    elif sock:
                        with self._board_stats_lock:
                            sock.sendall(
                                build_realorder(self.heartbeat_seq_board_stats)
                                + b"\n"
                            )
                            self._heartbeat_monitor.note_keepalive(
                                "board_stats",
                                sock,
                            )
                except OSError as exc:
                    sock = self._board_stats_socket()
                    if sock is not None:
                        self._heartbeat_monitor.note_transport_failure(
                            "board_stats",
                            sock,
                        )
                    logger.debug(
                        "statscalc 9601 心跳发送失败（不影响查询）: %s", exc
                    )

    def disconnect(self) -> None:
        self.stop_heartbeat()
        self.stop_snapshot()
        for sock in self._heartbeat_monitor.bound_sockets():
            unregister_frame_observer(sock)
        self._heartbeat_monitor.clear()
        manager = self._service_connections()
        if manager is not None:
            manager.close_all()
        self._close_owned_sockets()
        logger.info("连接已关闭")
