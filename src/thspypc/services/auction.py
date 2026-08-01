"""Capability-gated call-auction workflow."""
from __future__ import annotations

from collections.abc import Callable
from datetime import date, datetime, timedelta

from .._transport import ConnectionManager, ConnectionRole, SocketLike
from ..codecs.framing import read_frame
from ..errors import (
    CapabilityUnavailableError,
    ProtocolError,
    UnsupportedAccountFeatureError,
)
from ..features.auction_protocol import (
    build_auction_query,
    build_basic_auction_query,
    build_l2_closing_auction_query,
    build_l2_history_auction_query,
    parse_auction_response,
    parse_closing_auction_response,
)
from ..features.account_profile import AccountEvidenceRecorder
from ..features.history_timeline_protocol import (
    build_history_timeline_query,
)
from ..models import AccountKind, Capability, Support
from .subscription import L2SubscriptionCoordinator


FrameReader = Callable[[SocketLike], bytes]


def _auction_role(market: int) -> ConnectionRole:
    if market == 17:
        return ConnectionRole.SH_L2
    if market == 33:
        return ConnectionRole.SZ_L2
    raise ValueError(f"集合竞价暂不支持市场码: {market}")


def _build_l2_history_auction_bundle(
    code: str,
    *,
    market: int,
    trade_date,
) -> bytes:
    """Prime page 4417 exactly as the PC client before auction companions."""
    benchmark = {
        17: (16, "1A0002"),
        33: (32, "399002"),
    }.get(market)
    if benchmark is None:
        raise ValueError(f"历史集合竞价暂不支持市场码: {market}")
    history = build_history_timeline_query(
        code,
        date=trade_date,
        market=market,
        benchmark_market=benchmark[0],
        benchmark_code=benchmark[1],
        seq=0x10EC,
    )
    closing = build_l2_closing_auction_query(
        code,
        market=market,
        trade_date=trade_date,
        historical=True,
        seq=0x00EF,
    )
    opening = build_l2_history_auction_query(
        code,
        market=market,
        trade_date=trade_date,
        seq=0x00F1,
    )
    # Each encoded outer frame is one 8901 request.  MarketSession appends
    # the final LF; retain the two inter-frame delimiters that separate the
    # three pipelined requests in the PC capture.
    return b"\n".join((history, closing, opening))


class AuctionService:
    """Run account-specific opening and closing call-auction requests."""

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
            capability = Capability.BASIC_AUCTION
            role = ConnectionRole.MAIN
            historical = _is_historical_date(trade_date)
            frame = build_basic_auction_query(
                code,
                market=market,
                trade_date=trade_date,
                historical=historical,
            )
        elif profile.kind is AccountKind.LEVEL2:
            capability = Capability.L2_AUCTION
            role = _auction_role(market)
            if _is_historical_date(trade_date):
                frame = _build_l2_history_auction_bundle(
                    code,
                    market=market,
                    trade_date=trade_date,
                )
            else:
                frame = build_auction_query(
                    code,
                    market=market,
                    trade_date=trade_date,
                )
        else:
            raise UnsupportedAccountFeatureError(
                "auction",
                profile.kind,
                "账号类型未知，不能选择普通或 Level2 竞价协议",
            )

        support = profile.support(capability)
        if support is Support.NO:
            raise CapabilityUnavailableError(
                capability,
                "auction",
            )
        if support is Support.UNKNOWN:
            raise UnsupportedAccountFeatureError(
                "auction",
                profile.kind,
                f"能力证据未知: {capability.value}",
            )

        connection = self._connections.acquire(
            role,
            capability=capability,
        )
        if role is not ConnectionRole.MAIN:
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
                    if (
                        self._evidence is not None
                        and capability is Capability.L2_AUCTION
                    ):
                        self._evidence.record_feature(
                            Capability.L2_AUCTION,
                            Support.YES,
                        )
                    return records

        if saw_auction_frame:
            raise ProtocolError("收到集合竞价帧但无法解析")
        return []

    def closing_auction(
        self,
        code: str,
        *,
        market: int,
        trade_date=None,
        timeout: float = 12.0,
    ) -> list[dict]:
        """Return the 14:57-15:00 closing-auction companion series."""
        profile = self._connections.profile
        if profile.kind is AccountKind.STANDARD:
            capability = Capability.BASIC_AUCTION
            role = ConnectionRole.MAIN
            frame = build_basic_auction_query(
                code,
                market=market,
                trade_date=trade_date,
                closing=True,
                historical=_is_historical_date(trade_date),
            )
        elif profile.kind is AccountKind.LEVEL2:
            capability = Capability.L2_AUCTION
            role = _auction_role(market)
            if _is_historical_date(trade_date):
                frame = _build_l2_history_auction_bundle(
                    code,
                    market=market,
                    trade_date=trade_date,
                )
            else:
                frame = build_l2_closing_auction_query(
                    code,
                    market=market,
                    trade_date=trade_date,
                )
        else:
            raise UnsupportedAccountFeatureError(
                "closing_auction",
                profile.kind,
                "账号类型未知，不能选择普通或 Level2 尾盘竞价协议",
            )
        support = profile.support(capability)
        if support is Support.NO:
            raise CapabilityUnavailableError(
                capability,
                "closing_auction",
            )
        if support is Support.UNKNOWN:
            raise UnsupportedAccountFeatureError(
                "closing_auction",
                profile.kind,
                f"能力证据未知: {capability.value}",
            )

        connection = self._connections.acquire(
            role,
            capability=capability,
        )
        if role is not ConnectionRole.MAIN:
            self._subscriptions.ensure_registered(
                connection,
                code,
                market=market,
                timeout=min(timeout, 5.0),
            )
        saw_frame = False
        with connection.request(frame, timeout=timeout) as sock:
            for _ in range(self._max_frames):
                response = self._read_frame(sock)
                if (
                    not response.startswith(b"\x0a")
                    and b"hd1.0" not in response
                    and b"hd3.1" not in response
                ):
                    continue
                saw_frame = True
                records = parse_closing_auction_response(response)
                if records:
                    if (
                        self._evidence is not None
                        and capability is Capability.L2_AUCTION
                    ):
                        self._evidence.record_feature(
                            Capability.L2_AUCTION,
                            Support.YES,
                        )
                    return records

        if saw_frame:
            raise ProtocolError("收到尾盘集合竞价帧但无法解析")
        return []


def _is_historical_date(value) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        value = date.fromisoformat(value)
    elif isinstance(value, datetime):
        value = value.date()
    return value != date.today()
