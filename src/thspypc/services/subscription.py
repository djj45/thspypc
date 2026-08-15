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
_CODE_LIST_SIZE = re.compile(rb"CodeListSize=(\d+)")


class L2SubscriptionCoordinator:
    """Remember successful code registrations for each live connection."""

    def __init__(
        self,
        *,
        frame_reader: FrameReader = read_frame,
        max_frames: int = 5,
        evidence: AccountEvidenceRecorder | None = None,
    ) -> None:
        self._read_frame = frame_reader
        self._max_frames = max_frames
        self._evidence = evidence
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
            # 新建连接/切换股票时，注册响应前可能还有 init 遗留帧；实测偶尔
            # 连续 5 帧都不是 CodeListSize。放宽读取上限并重试一次，避免
            # 首次 intraday/timeline 偶发 502。
            frame = build_snapshot_subscribe(code, market=market, seq=0)
            for attempt in range(2):
                saw_status = False
                try:
                    with connection.request(frame, timeout=timeout) as sock:
                        for _ in range(max(self._max_frames, 24)):
                            try:
                                response = self._read_frame(sock)
                            except socket.timeout:
                                break
                            match = _CODE_LIST_SIZE.search(response)
                            if match is None:
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
