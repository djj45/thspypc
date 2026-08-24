"""Connection-scoped Level2 pageid=4214 registration."""
from __future__ import annotations

import re
import socket
import threading
import time
import weakref
from collections.abc import Callable

from .._transport import ManagedConnection, SocketLike
from ..codecs.framing import read_frame
from ..errors import ChannelUnavailableError, ProtocolError
from ..features.snapshot_protocol import build_snapshot_subscribe
from ..features.account_profile import AccountEvidenceRecorder
from ..models import Capability, Support


FrameReader = Callable[[SocketLike], bytes]
UnsolicitedHandler = Callable[[bytes], None]
_CODE_LIST_SIZE = re.compile(rb"CodeListSize=(\d+)")


class L2SubscriptionCoordinator:
    """Remember successful code registrations for each live connection."""

    def __init__(
        self,
        *,
        frame_reader: FrameReader = read_frame,
        max_frames: int = 5,
        evidence: AccountEvidenceRecorder | None = None,
        unsolicited: UnsolicitedHandler | None = None,
    ) -> None:
        self._read_frame = frame_reader
        self._max_frames = max_frames
        self._evidence = evidence
        self._unsolicited = unsolicited
        self._registered = weakref.WeakKeyDictionary()
        self._connection_locks = weakref.WeakKeyDictionary()
        self._state_lock = threading.RLock()

    def ensure_registered(
        self,
        connection: ManagedConnection,
        code: str,
        *,
        market: int,
        timeout: float = 5.0,
    ) -> bool:
        """Register once; return ``True`` when a frame was sent."""
        if not connection.init_complete:
            raise ChannelUnavailableError(
                connection.role.value,
                "L2 连接尚未完成 init",
            )
        key = (market, code)
        with self._state_lock:
            registration_lock = self._connection_locks.setdefault(
                connection,
                threading.RLock(),
            )

        with registration_lock:
            with self._state_lock:
                registered = self._registered.setdefault(
                    connection,
                    set(),
                )
                if key in registered:
                    return False
            last_error: ProtocolError | None = None
            # 新建连接/切换股票时，注册响应前可能夹着任意数量的 init 遗留帧
            # 和实时行情推送。不能用固定帧数判断 ACK 缺失：活跃股票在 24 帧
            # 之后才返回 CodeListSize 很常见。每次尝试改为以截止时间为准，
            # 中间帧全部交给统一推送分发器。
            frame = build_snapshot_subscribe(code, market=market, seq=0)
            for attempt in range(2):
                saw_status = False
                zero_statuses = 0
                deadline = time.monotonic() + timeout
                try:
                    with connection.request(frame, timeout=timeout) as sock:
                        while True:
                            remaining = deadline - time.monotonic()
                            if remaining <= 0:
                                break
                            sock.settimeout(remaining)
                            try:
                                response = self._read_frame(sock)
                            except socket.timeout:
                                break
                            match = _CODE_LIST_SIZE.search(response)
                            if match is None:
                                self.deliver_unsolicited(response)
                                continue
                            saw_status = True
                            if int(match.group(1)) >= 1:
                                with self._state_lock:
                                    registered.add(key)
                                if self._evidence is not None:
                                    self._evidence.record_feature(
                                        Capability.L2_SNAPSHOT_PUSH,
                                        Support.YES,
                                    )
                                return True
                            # 某些服务器在有效 ACK 前先发一次 size=0；继续等后续
                            # 状态。但连续两次明确为 0 可视作本次注册被拒绝，
                            # 无需把整个 timeout 消耗在重复状态上。
                            zero_statuses += 1
                            if zero_statuses >= 2:
                                break
                except (socket.timeout, OSError) as exc:
                    last_error = ProtocolError(
                        f"4214 注册请求网络异常: {exc}"
                    )
                if saw_status:
                    last_error = ProtocolError(
                        "4214 订阅注册被拒绝: CodeListSize=0"
                    )
                else:
                    last_error = ProtocolError(
                        "4214 订阅未返回 CodeListSize"
                    )
                if attempt == 0:
                    time.sleep(0.05)

        raise last_error or ProtocolError("4214 订阅未返回 CodeListSize")

    def deliver_unsolicited(self, body: bytes) -> None:
        """Forward a frame which does not belong to the synchronous request."""
        if self._unsolicited is not None:
            self._unsolicited(body)

    def is_registered(
        self,
        connection: ManagedConnection,
        code: str,
        *,
        market: int,
    ) -> bool:
        with self._state_lock:
            return (market, code) in self._registered.get(
                connection,
                (),
            )

    def forget(self, connection: ManagedConnection) -> None:
        with self._state_lock:
            self._registered.pop(connection, None)
            self._connection_locks.pop(connection, None)
