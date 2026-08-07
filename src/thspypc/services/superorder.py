"""超级盘口 / 逐笔成交回放工作流（period=7169，Level2 市场连接专用）。"""
from __future__ import annotations

import logging
import socket
from collections.abc import Callable

from .._transport import ConnectionManager, ConnectionRole, SocketLike
from ..codecs.framing import read_frame
from ..errors import (
    CapabilityUnavailableError,
    ProtocolError,
    UnsupportedAccountFeatureError,
)
from ..features.account_profile import AccountEvidenceRecorder
from ..features.superorder_protocol import (
    build_snapshot_replay_query,
    build_superorder_query,
    parse_snapshot_replay_response,
    parse_superorder_response,
)
from ..models import AccountKind, Capability, Support
from .subscription import L2SubscriptionCoordinator

logger = logging.getLogger(__name__)
FrameReader = Callable[[SocketLike], bytes]


def _superorder_l2_role(market: int) -> ConnectionRole:
    """7169 走对应市场的 Level2 连接（沪 shlv2 / 深 szlv2）。"""
    if market in (16, 17, 144):
        return ConnectionRole.SH_L2
    if market in (32, 33):
        return ConnectionRole.SZ_L2
    raise ValueError(f"7169 逐笔回放暂不支持市场码: {market}")


class SuperorderService:
    """在持有 L2 连接请求锁的前提下执行一次 7169 逐笔成交回放请求。

    仅 Level2 账号可用（普通账号无 L2 通道）。走市场专用 L2 连接，先 4214 注册
    （与十档盘口 depth_ten 同一套注册机制），再发 7169 区间请求。

    响应模式（2026-08-05 抓包确认）：**一个区间请求 → 一个响应帧**。服务端按请求的
    DateTime 区间一次性返回该段全部逐笔（单帧可达 2.5MB / 15 万条，TCP 拆包由
    read_frame 自动重组）。``max_frames`` 是兜底（防异常分页），正常只读 1 帧。
    """

    def __init__(
        self,
        connections: ConnectionManager,
        *,
        frame_reader: FrameReader = read_frame,
        max_frames: int = 32,
        subscriptions: L2SubscriptionCoordinator | None = None,
        evidence: AccountEvidenceRecorder | None = None,
    ) -> None:
        self._connections = connections
        self._read_frame = frame_reader
        self._max_frames = max_frames
        self._subscriptions = subscriptions
        self._evidence = evidence

    def superorder(
        self,
        code: str,
        *,
        market: int,
        start_ts: int,
        end_ts: int,
        pageid: int = 4214,
        timeout: float = 12.0,
    ) -> list[dict]:
        """请求并解析 7169 逐笔成交回放，返回逐笔记录列表。

        Args:
            code: 股票代码。
            market: 市场码（17=沪, 33=深）。
            start_ts/end_ts: 回放区间的 unix 时间戳（秒）。
            pageid: 4214（逐笔面板）或 4260（超级盘口）。
            timeout: 单次 read_frame 超时（秒）。
        """
        profile = self._connections.profile
        if profile.kind is AccountKind.STANDARD:
            raise CapabilityUnavailableError(
                Capability.L2_TIMELINE,
                "superorder",
            )
        if profile.kind is AccountKind.UNKNOWN:
            raise UnsupportedAccountFeatureError(
                "superorder",
                profile.kind,
                "账号类型未知，不能推断 L2 逐笔通道",
            )

        role = _superorder_l2_role(market)
        connection = self._connections.acquire(
            role,
            capability=Capability.L2_TIMELINE,
        )
        # 先 4214 注册（与十档盘口同一套机制；7169 复用 4214 通道）
        if self._subscriptions is not None:
            self._subscriptions.ensure_registered(
                connection,
                code,
                market=market,
                timeout=min(timeout, 5.0),
            )

        request = build_superorder_query(
            code,
            market=market,
            start_ts=start_ts,
            end_ts=end_ts,
            pageid=pageid,
        )
        records: list[dict] = []
        saw_frame = False

        with connection.request(request, timeout=timeout) as sock:
            for _ in range(self._max_frames):
                try:
                    response = self._read_frame(sock)
                except socket.timeout:
                    if records:
                        break
                    raise
                except ValueError:
                    recv = getattr(sock, "recv", None)
                    if recv is not None:
                        try:
                            recv(8192)
                        except OSError as exc:
                            raise ConnectionError("连接已关闭") from exc
                    if records:
                        break
                    continue

                # 7169 帧：normalize 前以 0x0a 开头，normalize 后含 hd1.0
                if response.startswith(b"\x0a") or b"hd1.0" in response:
                    parsed = parse_superorder_response(response)
                    if parsed:
                        records.extend(parsed)
                        sock.settimeout(2.0)
                        saw_frame = True
                        continue
                    if b"hd1.0" in response:
                        saw_frame = True
                if records:
                    break

        if records:
            if self._evidence is not None:
                self._evidence.record_feature(
                    Capability.L2_TIMELINE,
                    Support.YES,
                )
            return records
        if saw_frame:
            raise ProtocolError("收到 7169 逐笔帧但无法解析")
        return []

    def snapshot_replay(
        self,
        code: str,
        *,
        market: int,
        timeout: float = 30.0,
    ) -> list[dict]:
        """请求并解析 4096 盘口快照回放（pageid=4260，超级盘口分时曲线）。

        返回全天每 ~3 秒一个完整盘口快照（~4927 点），每条记录含十档买卖价量。
        响应是标准 hd1.0 行主序（flag=0x00FE），非 BitRLE。

        Args:
            code: 股票代码（如 ``"000938"``）。
            market: 市场码（17=沪, 33=深）。
            timeout: 单次 read_frame 超时（秒）。全天数据 ~500KB，需较长超时。
        """
        profile = self._connections.profile
        if profile.kind is AccountKind.STANDARD:
            raise CapabilityUnavailableError(
                Capability.L2_TIMELINE,
                "snapshot_replay",
            )
        if profile.kind is AccountKind.UNKNOWN:
            raise UnsupportedAccountFeatureError(
                "snapshot_replay",
                profile.kind,
                "账号类型未知，不能推断 L2 通道",
            )

        role = _superorder_l2_role(market)
        connection = self._connections.acquire(
            role,
            capability=Capability.L2_TIMELINE,
        )
        if self._subscriptions is not None:
            self._subscriptions.ensure_registered(
                connection,
                code,
                market=market,
                timeout=min(timeout, 5.0),
            )

        request = build_snapshot_replay_query(code, market=market)
        records: list[dict] = []
        saw_frame = False

        with connection.request(request, timeout=timeout) as sock:
            for _ in range(self._max_frames):
                try:
                    response = self._read_frame(sock)
                except socket.timeout:
                    if records:
                        break
                    raise
                except ValueError:
                    recv = getattr(sock, "recv", None)
                    if recv is not None:
                        try:
                            recv(8192)
                        except OSError as exc:
                            raise ConnectionError("连接已关闭") from exc
                    if records:
                        break
                    continue

                if response.startswith(b"\x0a") or b"hd1.0" in response:
                    parsed = parse_snapshot_replay_response(response)
                    if parsed:
                        records.extend(parsed)
                        sock.settimeout(2.0)
                        saw_frame = True
                        continue
                    if b"hd1.0" in response:
                        saw_frame = True
                if records:
                    break

        if records:
            if self._evidence is not None:
                self._evidence.record_feature(
                    Capability.L2_TIMELINE,
                    Support.YES,
                )
            return records
        if saw_frame:
            raise ProtocolError("收到 4096 盘口快照帧但无法解析")
        return []


__all__ = ["SuperorderService"]
