"""Capability-gated call-auction workflow."""
from __future__ import annotations

import socket
from collections.abc import Callable
from datetime import date, datetime, time

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
    build_index_auction_context_query,
    build_index_auction_query,
    build_l2_closing_auction_query,
    build_l2_history_auction_query,
    parse_auction_response,
    resolve_trade_date,
    parse_closing_auction_response,
    parse_index_auction_response,
)
from ..features.account_profile import AccountEvidenceRecorder
from ..features.history_timeline_protocol import (
    build_history_timeline_query,
    history_timeline_request_codes,
    parse_history_timeline_response,
)
from ..features.trade_calendar import latest_trade_date
from ..models import AccountKind, Capability, Support
from .subscription import L2SubscriptionCoordinator


FrameReader = Callable[[SocketLike], bytes]


_OPENING_PHASE = "opening_auction"
_CONTINUOUS_PHASE = "continuous"
_CLOSING_PHASE = "closing_auction"
_L2_BUNDLE_READ_TIMEOUT = 2.0


def _auction_role(market: int) -> ConnectionRole:
    if market in (16, 17):
        return ConnectionRole.SH_L2
    if market in (32, 33):
        return ConnectionRole.SZ_L2
    raise ValueError(f"集合竞价暂不支持市场码: {market}")


def _build_l2_history_auction_bundle(
    code: str,
    *,
    market: int,
    trade_date,
    phases: tuple[str, ...] | None = None,
) -> bytes:
    """Prime page 4417 exactly as the PC client before auction companions."""
    if trade_date is None:
        trade_date = resolve_trade_date(None)
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
    phases = phases or (
        _OPENING_PHASE,
        _CONTINUOUS_PHASE,
        _CLOSING_PHASE,
    )
    requests = [history]
    if _CLOSING_PHASE in phases:
        requests.append(build_l2_closing_auction_query(
            code,
            market=market,
            trade_date=trade_date,
            historical=True,
            seq=0x00EF,
        ))
    if _OPENING_PHASE in phases:
        requests.append(build_l2_history_auction_query(
            code,
            market=market,
            trade_date=trade_date,
            seq=0x00F1,
        ))
    # Each encoded outer frame is one 8901 request.  MarketSession appends
    # the final LF; retain the two inter-frame delimiters that separate the
    # three pipelined requests in the PC capture.
    return b"\n".join(requests)


def _build_index_closing_auction_bundle(
    code: str,
    *,
    market: int,
) -> bytes:
    """Prime the index auction context before requesting CloseAuction."""
    opening = build_index_auction_context_query(
        code,
        market=market,
        seq=0x0176,
    )
    closing = build_index_auction_query(
        code,
        market=market,
        closing=True,
        seq=0x0177,
    )
    return b"\n".join((opening, closing))


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

    def intraday(
        self,
        code: str,
        *,
        market: int,
        trade_date=None,
        timeout: float = 12.0,
    ) -> list[dict]:
        """Return the three stock intraday phases from one Level2 workflow.

        Outside the live opening-auction window the PC client pipelines the
        page-4417 history, closing-auction and opening-auction requests on the
        market Level2 connection.  Consume all three responses here so no
        caller has to issue the same bundle three times.

        A phase that has not been produced yet (for example closing auction at
        noon) is simply absent.  Once any data response is received, only a
        short trailing read is used because all companion requests were
        already sent in the same pipeline.
        """
        now = _now()
        target_date = (
            latest_trade_date(now)
            if trade_date is None
            else _coerce_date(trade_date)
        )
        current_day = target_date == now.date()
        expected_phases = (
            _current_intraday_phases(now)
            if current_day
            else (_OPENING_PHASE, _CONTINUOUS_PHASE, _CLOSING_PHASE)
        )
        # Only an explicit request for today before 09:15 reaches this empty
        # branch.  The default request has already selected the previous
        # trading day above.
        if not expected_phases:
            return []

        profile = self._connections.profile
        if profile.kind is not AccountKind.LEVEL2:
            raise UnsupportedAccountFeatureError(
                "intraday",
                profile.kind,
                "单次三段分时读取只适用于 Level2 连接",
            )
        if market in (16, 32):
            raise ValueError("指数不支持 Level2 三段历史分时 bundle")

        for capability in (
            Capability.L2_AUCTION,
            Capability.L2_HISTORY_TIMELINE,
        ):
            support = profile.support(capability)
            if support is Support.NO:
                raise CapabilityUnavailableError(capability, "intraday")
            if support is Support.UNKNOWN:
                raise UnsupportedAccountFeatureError(
                    "intraday",
                    profile.kind,
                    f"能力证据未知: {capability.value}",
                )

        if current_day and _in_auction_session(now):
            opening = self.auction(
                code,
                market=market,
                trade_date=None,
                timeout=timeout,
            )
            return [
                {"phase": _OPENING_PHASE, **record}
                for record in opening
            ]

        phases = self._request_l2_intraday_bundle(
            code,
            market=market,
            trade_date=target_date,
            timeout=timeout,
            expected_phases=expected_phases,
            allow_partial_continuous=current_day,
        )
        result: list[dict] = []
        for phase in (
            _OPENING_PHASE,
            _CONTINUOUS_PHASE,
            _CLOSING_PHASE,
        ):
            if phase not in expected_phases:
                continue
            result.extend(
                {"phase": phase, **record}
                for record in phases[phase]
            )
        return result

    def intraday_auctions(
        self,
        code: str,
        *,
        market: int,
        trade_date=None,
        timeout: float = 12.0,
    ) -> list[dict]:
        """Return only opening/closing auctions for staged screen loading.

        The page-4417 history request is retained as the date/context primer,
        but its continuous table is not exposed or parsed as a result.  This
        lets callers render the live 1334/8192 timeline first and append the
        two auction phases afterwards without downloading the public
        ``intraday()`` result twice.
        """
        now = _now()
        target_date = (
            latest_trade_date(now)
            if trade_date is None
            else _coerce_date(trade_date)
        )
        current_day = target_date == now.date()
        available = (
            _current_intraday_phases(now)
            if current_day
            else (_OPENING_PHASE, _CONTINUOUS_PHASE, _CLOSING_PHASE)
        )
        expected_phases = tuple(
            phase
            for phase in (_OPENING_PHASE, _CLOSING_PHASE)
            if phase in available
        )
        if not expected_phases:
            return []

        profile = self._connections.profile
        if profile.kind is not AccountKind.LEVEL2:
            raise UnsupportedAccountFeatureError(
                "intraday_auctions",
                profile.kind,
                "分阶段竞价补全只适用于 Level2 连接",
            )
        if market in (16, 32):
            raise ValueError("指数不支持 Level2 分阶段竞价补全")
        for capability in (
            Capability.L2_AUCTION,
            Capability.L2_HISTORY_TIMELINE,
        ):
            support = profile.support(capability)
            if support is Support.NO:
                raise CapabilityUnavailableError(
                    capability,
                    "intraday_auctions",
                )
            if support is Support.UNKNOWN:
                raise UnsupportedAccountFeatureError(
                    "intraday_auctions",
                    profile.kind,
                    f"能力证据未知: {capability.value}",
                )

        if current_day and _in_auction_session(now):
            opening = self.auction(
                code,
                market=market,
                trade_date=None,
                timeout=timeout,
            )
            return [
                {"phase": _OPENING_PHASE, **record}
                for record in opening
            ]

        phases = self._request_l2_intraday_bundle(
            code,
            market=market,
            trade_date=target_date,
            timeout=timeout,
            expected_phases=expected_phases,
        )
        result: list[dict] = []
        for phase in (_OPENING_PHASE, _CLOSING_PHASE):
            if phase not in expected_phases:
                continue
            result.extend(
                {"phase": phase, **record}
                for record in phases[phase]
            )
        return result

    def _request_l2_intraday_bundle(
        self,
        code: str,
        *,
        market: int,
        trade_date,
        timeout: float,
        stop_after: str | None = None,
        expected_phases: tuple[str, ...] | None = None,
        allow_partial_continuous: bool = False,
    ) -> dict[str, list[dict]]:
        """Send page 4417 once and dispatch every companion response."""
        role = _auction_role(market)
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

        benchmark = {
            17: (16, "1A0002"),
            33: (32, "399002"),
        }[market]
        requested_codes, _, _ = history_timeline_request_codes(
            code,
            market=market,
            benchmark_market=benchmark[0],
            benchmark_code=benchmark[1],
        )
        phases: dict[str, list[dict]] = {
            _OPENING_PHASE: [],
            _CONTINUOUS_PHASE: [],
            _CLOSING_PHASE: [],
        }
        expected_phases = expected_phases or (
            _OPENING_PHASE,
            _CONTINUOUS_PHASE,
            _CLOSING_PHASE,
        )
        saw_data_frame = False
        frame = _build_l2_history_auction_bundle(
            code,
            market=market,
            trade_date=trade_date,
            phases=expected_phases,
        )
        read_timeout = min(timeout, _L2_BUNDLE_READ_TIMEOUT)
        with connection.request(frame, timeout=read_timeout) as sock:
            for _ in range(max(self._max_frames, 16)):
                try:
                    response = self._read_frame(sock)
                except (socket.timeout, StopIteration):
                    break
                if (
                    not response.startswith(b"\x0a")
                    and b"hd1.0" not in response
                    and b"hd3.1" not in response
                ):
                    continue
                saw_data_frame = True
                sock.settimeout(min(timeout, 0.25))

                if (
                    _CONTINUOUS_PHASE in expected_phases
                    and not phases[_CONTINUOUS_PHASE]
                ):
                    phases[_CONTINUOUS_PHASE] = (
                        parse_history_timeline_response(
                            response,
                            code=code,
                            requested_codes=requested_codes,
                            allow_partial=allow_partial_continuous,
                        )
                    )
                if (
                    _OPENING_PHASE in expected_phases
                    and not phases[_OPENING_PHASE]
                ):
                    phases[_OPENING_PHASE] = parse_auction_response(response)
                if (
                    _CLOSING_PHASE in expected_phases
                    and not phases[_CLOSING_PHASE]
                ):
                    phases[_CLOSING_PHASE] = (
                        parse_closing_auction_response(response)
                    )

                if all(phases[phase] for phase in expected_phases):
                    break
                if stop_after is not None and phases[stop_after]:
                    break
                if any(phases.values()):
                    # Pipelined companion frames arrive back-to-back.  Do not
                    # hold the shared runtime lock for the public 12s timeout
                    # just because a currently expected phase is empty.
                    sock.settimeout(min(timeout, 0.25))

        if self._evidence is not None:
            if phases[_CONTINUOUS_PHASE]:
                self._evidence.record_feature(
                    Capability.L2_HISTORY_TIMELINE,
                    Support.YES,
                )
            if phases[_OPENING_PHASE] or phases[_CLOSING_PHASE]:
                self._evidence.record_feature(
                    Capability.L2_AUCTION,
                    Support.YES,
                )
        if saw_data_frame and not any(phases.values()):
            raise ProtocolError("收到 Level2 分时伴随帧但三段数据均无法解析")
        return phases

    def auction(
        self,
        code: str,
        *,
        market: int,
        trade_date=None,
        timeout: float = 12.0,
    ) -> list[dict]:
        profile = self._connections.profile
        index_auction = market in (16, 32)
        if index_auction and _is_historical_date(trade_date):
            raise ValueError("指数 T_URL 竞价接口只提供当前交易日")
        if profile.kind is AccountKind.STANDARD:
            capability = Capability.BASIC_AUCTION
            role = ConnectionRole.MAIN
            historical = _is_historical_date(trade_date)
            frame = (
                build_index_auction_context_query(code, market=market)
                if index_auction
                else build_basic_auction_query(
                    code,
                    market=market,
                    trade_date=trade_date,
                    historical=historical,
                )
            )
        elif profile.kind is AccountKind.LEVEL2:
            capability = Capability.L2_AUCTION
            role = _auction_role(market)
            if index_auction:
                frame = build_index_auction_context_query(
                    code,
                    market=market,
                )
            elif _is_historical_date(trade_date) or not _in_auction_session():
                # 非竞价时段(9:25 之后当日竞价已完整生成)或显式历史日期:
                # 走 L2 历史路径 pageid=4417,拿当日完整竞价序列(实测 ~39ms)。
                # 实时路径 pageid=1334 在非竞价时段会死等 timeout(盘后偶发 12s+)。
                frame = _build_l2_history_auction_bundle(
                    code,
                    market=market,
                    trade_date=trade_date,
                )
            else:
                # 9:15-9:25 实时竞价时段:走 L2 实时路径,拿实时撮合
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

        if (
            profile.kind is AccountKind.LEVEL2
            and not index_auction
            and (_is_historical_date(trade_date) or not _in_auction_session())
        ):
            return self._request_l2_intraday_bundle(
                code,
                market=market,
                trade_date=_resolve_l2_intraday_date(trade_date),
                timeout=timeout,
                stop_after=_OPENING_PHASE,
            )[_OPENING_PHASE]

        connection = self._connections.acquire(
            role,
            capability=capability,
        )
        if role is not ConnectionRole.MAIN and not index_auction:
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
                    and b'{"Auction"' not in response
                    and b'{"CloseAuction"' not in response
                ):
                    continue
                saw_auction_frame = True
                records = (
                    parse_index_auction_response(response)
                    if index_auction
                    else parse_auction_response(response)
                )
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
        index_auction = market in (16, 32)
        if index_auction and _is_historical_date(trade_date):
            raise ValueError("指数 T_URL 竞价接口只提供当前交易日")
        if profile.kind is AccountKind.STANDARD:
            capability = Capability.BASIC_AUCTION
            role = ConnectionRole.MAIN
            frame = (
                _build_index_closing_auction_bundle(
                    code,
                    market=market,
                )
                if index_auction
                else build_basic_auction_query(
                    code,
                    market=market,
                    trade_date=trade_date,
                    closing=True,
                    historical=_is_historical_date(trade_date),
                )
            )
        elif profile.kind is AccountKind.LEVEL2:
            capability = Capability.L2_AUCTION
            role = _auction_role(market)
            if index_auction:
                frame = _build_index_closing_auction_bundle(
                    code,
                    market=market,
                )
            elif _is_historical_date(trade_date):
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
        if role is not ConnectionRole.MAIN and not index_auction:
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
                    and b'{"Auction"' not in response
                    and b'{"CloseAuction"' not in response
                ):
                    continue
                saw_frame = True
                records = (
                    parse_index_auction_response(response)
                    if index_auction
                    else parse_closing_auction_response(response)
                )
                if (
                    index_auction
                    and records
                    and records[0].get("auction_type") != "closing"
                ):
                    continue
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


def _coerce_date(value) -> date:
    if isinstance(value, str):
        return date.fromisoformat(value)
    if isinstance(value, datetime):
        return value.date()
    return value


def _now() -> datetime:
    return datetime.now()


def _current_intraday_phases(now: datetime) -> tuple[str, ...]:
    """Return phases that can legitimately exist at *now* on a trade day."""
    current = now.time()
    if now.weekday() >= 5 or current < time(9, 15):
        return ()
    if current < time(9, 30):
        return (_OPENING_PHASE,)
    if current < time(14, 57):
        return (_OPENING_PHASE, _CONTINUOUS_PHASE)
    return (_OPENING_PHASE, _CONTINUOUS_PHASE, _CLOSING_PHASE)


# 沪深 A 股集合竞价时段(9:15-9:25)。此时段内服务端推送实时撮合,应走实时路径;
# 时段外发实时请求会死等 timeout(盘后偶发 12s+),应改走历史路径(11ms,完整序列)。
def _resolve_l2_intraday_date(value=None) -> date:
    """Resolve the trading date displayed by the Level2 intraday page."""
    if value is not None:
        return resolve_trade_date(value)
    return latest_trade_date(_now())


AUCTION_SESSION_START = time(9, 15)
AUCTION_SESSION_END = time(9, 25)


def _in_auction_session(now: datetime | None = None) -> bool:
    """当前是否在 9:15-9:25 集合竞价时段(周一到周五)。"""
    now = now or _now()
    if now.weekday() >= 5:
        return False
    return AUCTION_SESSION_START <= now.time() < AUCTION_SESSION_END
