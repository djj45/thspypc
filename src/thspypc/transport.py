"""TCP 传输层的最小同步会话抽象。

当前 8901 协议没有可直接用于并发请求分发的 request id。一个请求的响应还可能
夹在 CodeListSize、MarketTime 等通知帧之后，因此在建立单 reader 分发器之前，
必须把一次完整的“发送 → 读取/匹配响应”视为不可分割事务。
"""
from __future__ import annotations

import threading
from contextlib import contextmanager
from typing import Callable, Iterator, Protocol


class SocketLike(Protocol):
    """MarketSession 实际使用的 socket 最小接口，便于离线测试。"""

    def settimeout(self, value: float | None) -> None: ...

    def sendall(self, data: bytes) -> None: ...


class MarketSession:
    """串行化 8901 请求生命周期。

    ``request()`` 在进入时取得连接锁，设置超时并发送请求；调用方完成全部响应
    读取后退出上下文才释放锁。后台心跳使用 ``try_send()``，业务请求进行中会
    跳过本轮心跳，防止心跳响应混入业务帧。
    """

    def __init__(
        self,
        socket_getter: Callable[[], SocketLike | None],
        request_lock: threading.RLock,
    ) -> None:
        self._socket_getter = socket_getter
        self._request_lock = request_lock

    @contextmanager
    def request(
        self,
        frame: bytes,
        *,
        timeout: float,
        trailing_newline: bool = True,
    ) -> Iterator[SocketLike]:
        """发送请求并在上下文存续期间独占该连接的收发。"""
        with self._request_lock:
            sock = self._socket_getter()
            if sock is None:
                raise ConnectionError("连接已关闭")
            sock.settimeout(timeout)
            sock.sendall(frame + (b"\n" if trailing_newline else b""))
            yield sock

    def try_send(self, frame: bytes, *, trailing_newline: bool = True) -> bool:
        """连接空闲时发送单向帧；连接忙或已关闭时返回 ``False``。"""
        if not self._request_lock.acquire(blocking=False):
            return False
        try:
            sock = self._socket_getter()
            if sock is None:
                return False
            sock.sendall(frame + (b"\n" if trailing_newline else b""))
            return True
        finally:
            self._request_lock.release()
