"""Capability-gated call-auction workflow."""
from __future__ import annotations

from collections.abc import Callable

from .._transport import ConnectionManager, ConnectionRole, SocketLike
from ..codecs.framing import read_frame
from ..errors import (
    CapabilityUnavailableError,
    ProtocolError,
    UnsupportedAccountFeatureError,
)
from ..features.auction_protocol import (
    build_auction_query,
    parse_auction_response,
)
from ..features.account_profile import AccountEvidenceRecorder
from ..models import AccountKind, Capability, Support
from .subscription import L2SubscriptionCoordinator


FrameReader = Callable[[SocketLike], bytes]


def _auction_role(market: int) -> ConnectionRole:
    if market == 17:
        return ConnectionRole.SH_L2
    if market == 33:
        return ConnectionRole.SZ_L2
    raise ValueError(f"集合竞价暂不支持市场码: {market}")


class AuctionService:
    """Run Level2 call-auction requests on the market-specific connection."""

    def __init__(
        self,
        connections: ConnectionManager,
        *,
        frame_reader: FrameReader = read_frame,
        max_frames: int = 8,
        subscriptions: L2SubscriptionCoordinator | None = None,
        evidence: AccountEvidenceRecorder | None = None,
    ) -> None:
        self._connections = connections
        self._read_frame = frame_reader
        self._max_frames = max_frames
        self._subscriptions = (
            subscriptions
            or L2SubscriptionCoordinator(frame_reader=frame_reader)
        )
        self._evidence = evidence

    def auction(
        self,
        code: str,
        *,
        market: int,
        trade_date=None,
        timeout: float = 12.0,
    ) -> list[dict]:
        profile = self._connections.profile
        if profile.kind is AccountKind.STANDARD:
            raise CapabilityUnavailableError(
                Capability.L2_AUCTION,
                "auction",
            )
        if profile.kind is not AccountKind.LEVEL2:
            raise UnsupportedAccountFeatureError(
                "auction",
                profile.kind,
                "账号类型未知，禁止尝试 Level2 竞价通道",
            )

        support = profile.support(Capability.L2_AUCTION)
        if support is Support.NO:
            raise CapabilityUnavailableError(
                Capability.L2_AUCTION,
                "auction",
            )
        if support is Support.UNKNOWN:
            raise UnsupportedAccountFeatureError(
                "auction",
                profile.kind,
                "能力证据未知: l2_auction",
            )

        role = _auction_role(market)
        frame = build_auction_query(
            code,
            market=market,
            trade_date=trade_date,
        )
        connection = self._connections.acquire(
            role,
            capability=Capability.L2_AUCTION,
        )
        self._subscriptions.ensure_registered(
            connection,
            code,
            market=market,
            timeout=min(timeout, 5.0),
        )

        saw_auction_frame = False
        with connection.request(frame, timeout=timeout) as sock:
            for _ in range(self._max_frames):
                response = self._read_frame(sock)
                if (
                    not response.startswith(b"\x0a")
                    and b"hd1.0" not in response
                ):
                    continue
                saw_auction_frame = True
                records = parse_auction_response(response)
                if records:
                    if self._evidence is not None:
                        self._evidence.record_feature(
                            Capability.L2_AUCTION,
                            Support.YES,
                        )
                    return records

        if saw_auction_frame:
            raise ProtocolError("收到集合竞价帧但无法解析")
        return []
