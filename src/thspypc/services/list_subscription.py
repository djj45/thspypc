"""Connection-scoped pageid list buckets and ranking depth subscriptions.

The coordinator owns no socket.  It serializes through an existing
``ManagedConnection`` and remembers only state acknowledged by the server.
This is important for Level2 accounts: callers reuse the already authenticated
SH_L2/SZ_L2 lanes instead of consuming another Passport64 or opening a second
client session.
"""
from __future__ import annotations

import socket
import threading
import weakref
from collections.abc import Callable, Iterable, Mapping

from .._transport import ManagedConnection, SocketLike
from ..codecs.framing import read_frame
from ..errors import ChannelUnavailableError, ProtocolError
from ..features.list_subscription_protocol import (
    LIST_MODE_GROUP_0,
    LIST_SUBTYPE_MANAGE,
    LIST_SUBTYPE_QUERY,
    ListSubscriptionResponse,
    build_list_subscription_clear,
    build_list_subscription_codes,
    build_list_subscription_delta,
    build_list_subscription_query,
    parse_list_subscription_response,
)


FrameReader = Callable[[SocketLike], bytes]
UnsolicitedHandler = Callable[[bytes], None]
BucketKey = tuple[int, int, int]  # command, pageid, group mode


def _normalized_groups(
    groups: Mapping[int, Iterable[str]],
) -> dict[int, tuple[str, ...]]:
    normalized: dict[int, tuple[str, ...]] = {}
    for market, raw_codes in groups.items():
        codes = tuple(dict.fromkeys(str(code).strip() for code in raw_codes))
        if not codes or any(not code.isdigit() for code in codes):
            raise ValueError(f"market={market!r} 的代码集合为空或含非数字代码")
        normalized[int(market)] = codes
    if not normalized:
        raise ValueError("代码集合不能为空")
    return normalized


class ListBucketCoordinator:
    """Manage acknowledged CodeList state on already logged-in connections."""

    def __init__(
        self,
        *,
        frame_reader: FrameReader = read_frame,
        unsolicited: UnsolicitedHandler | None = None,
        max_frames: int = 32,
    ) -> None:
        self._frame_reader = frame_reader
        self._unsolicited = unsolicited
        self._max_frames = max_frames
        self._states = weakref.WeakKeyDictionary()
        self._state_lock = threading.RLock()

    @staticmethod
    def _require_ready(connection: ManagedConnection) -> None:
        if not connection.init_complete:
            raise ChannelUnavailableError(
                connection.role.value,
                "列表桶连接尚未完成 init",
            )

    def _exchange(
        self,
        connection: ManagedConnection,
        frame: bytes,
        *,
        timeout: float,
        matches: Callable[[ListSubscriptionResponse], bool],
        description: str,
    ) -> ListSubscriptionResponse:
        self._require_ready(connection)
        try:
            with connection.request(frame, timeout=timeout) as sock:
                for _ in range(self._max_frames):
                    try:
                        body = self._frame_reader(sock)
                    except socket.timeout:
                        break
                    for response in parse_list_subscription_response(body):
                        if matches(response):
                            return response
                    if self._unsolicited is not None:
                        self._unsolicited(body)
        except (socket.timeout, OSError) as exc:
            raise ProtocolError(f"{description}网络异常: {exc}") from exc
        raise ProtocolError(f"{description}未收到匹配响应")

    def replace_codes(
        self,
        connection: ManagedConnection,
        groups: Mapping[int, Iterable[str]],
        *,
        command: int,
        pageid: int,
        mode: int = LIST_MODE_GROUP_0,
        timeout: float = 5.0,
    ) -> int:
        """Replace one CodeList group and return acknowledged total size."""
        normalized = _normalized_groups(groups)
        frame = build_list_subscription_codes(
            command,
            normalized,
            mode=mode,
            pageid=pageid,
        )
        response = self._exchange(
            connection,
            frame,
            timeout=timeout,
            matches=lambda item: (
                item.command == command
                and item.mode_raw == mode
                and item.subtype == LIST_SUBTYPE_MANAGE
                and item.code_list_size is not None
            ),
            description="列表桶替换",
        )
        size = int(response.code_list_size or 0)
        if size < 1:
            raise ProtocolError("列表桶替换被拒绝: CodeListSize=0")
        with self._state_lock:
            states = self._states.setdefault(connection, {})
            states[(command, pageid, mode)] = normalized
        return size

    def apply_delta(
        self,
        connection: ManagedConnection,
        *,
        command: int,
        pageid: int,
        add: Mapping[int, Iterable[str]],
        remove: Mapping[int, Iterable[str]],
        target_mode: int = LIST_MODE_GROUP_0,
        timeout: float = 5.0,
    ) -> int:
        """Apply captured mode-5 AddCode/DelCode to one local group."""
        add_groups = _normalized_groups(add) if add else {}
        remove_groups = _normalized_groups(remove) if remove else {}
        frame = build_list_subscription_delta(
            command,
            add=add_groups,
            remove=remove_groups,
            pageid=pageid,
        )
        response = self._exchange(
            connection,
            frame,
            timeout=timeout,
            matches=lambda item: (
                item.command == command
                and item.mode_raw == 5
                and item.subtype == LIST_SUBTYPE_MANAGE
                and item.code_list_size is not None
            ),
            description="列表桶增量",
        )
        size = int(response.code_list_size or 0)
        with self._state_lock:
            states = self._states.setdefault(connection, {})
            key = (command, pageid, target_mode)
            current = {
                market: list(codes)
                for market, codes in states.get(key, {}).items()
            }
            for market, codes in remove_groups.items():
                removed = set(codes)
                current[market] = [
                    code for code in current.get(market, ()) if code not in removed
                ]
                if not current[market]:
                    current.pop(market, None)
            for market, codes in add_groups.items():
                current[market] = list(
                    dict.fromkeys([*current.get(market, ()), *codes])
                )
            states[key] = {
                market: tuple(codes) for market, codes in current.items()
            }
        return size

    def query(
        self,
        connection: ManagedConnection,
        groups: Mapping[int, Iterable[str]],
        datatype: Iterable[int],
        *,
        command: int,
        pageid: int,
        wire_seq: int,
        datetime: str = "0(0-0)",
        lack_time: str = "0,0,0,0,0,0,0,0",
        timeout: float = 5.0,
    ) -> ListSubscriptionResponse:
        """Issue one subtype-09 field query on the same list bucket."""
        normalized = _normalized_groups(groups)
        frame = build_list_subscription_query(
            command,
            normalized,
            datatype,
            wire_seq=wire_seq,
            pageid=pageid,
            datetime=datetime,
            lack_time=lack_time,
        )
        return self._exchange(
            connection,
            frame,
            timeout=timeout,
            matches=lambda item: (
                item.command == command
                and item.subtype == LIST_SUBTYPE_QUERY
                and item.wire_seq == wire_seq
            ),
            description="列表桶字段查询",
        )

    def clear(
        self,
        connection: ManagedConnection,
        *,
        command: int,
        pageid: int,
        timeout: float = 5.0,
    ) -> tuple[int, set[str]]:
        """Clear one command/page and return ``(ack_size, prior_codes)``."""
        frame = build_list_subscription_clear(command, pageid=pageid)
        response = self._exchange(
            connection,
            frame,
            timeout=timeout,
            matches=lambda item: (
                item.command == command
                and item.mode_raw == 4
                and item.subtype == LIST_SUBTYPE_MANAGE
                and item.code_list_size is not None
            ),
            description="列表桶清空",
        )
        with self._state_lock:
            states = self._states.setdefault(connection, {})
            keys = [
                key for key in states if key[0] == command and key[1] == pageid
            ]
            prior = {
                code
                for key in keys
                for codes in states[key].values()
                for code in codes
            }
            for key in keys:
                states.pop(key, None)
        return int(response.code_list_size or 0), prior

    def codes(
        self,
        connection: ManagedConnection,
        *,
        command: int,
        pageid: int,
        mode: int | None = None,
    ) -> set[str]:
        """Return the acknowledged local code set for one bucket."""
        with self._state_lock:
            states = self._states.get(connection, {})
            return {
                code
                for (item_command, item_pageid, item_mode), groups in states.items()
                if item_command == command
                and item_pageid == pageid
                and (mode is None or item_mode == mode)
                for codes in groups.values()
                for code in codes
            }

    def forget(self, connection: ManagedConnection) -> None:
        with self._state_lock:
            self._states.pop(connection, None)


__all__ = ["ListBucketCoordinator"]
