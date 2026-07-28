"""Account-aware request planning for intraday timelines."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from collections.abc import Callable

from .._transport import ConnectionManager, ConnectionRole, SocketLike
from ..codecs.framing import read_frame
from ..errors import (
    CapabilityUnavailableError,
    ChannelUnavailableError,
    ProtocolError,
    UnsupportedAccountFeatureError,
)
from ..features.timeline_protocol import (
    build_timeline_l2_query,
    build_timeline_query,
    parse_timeline_l2_response,
)
from ..features.history_timeline_protocol import (
    build_history_timeline_query,
    parse_history_timeline_response,
)
from ..features.account_profile import AccountEvidenceRecorder
from ..models import AccountKind, AccountProfile, Capability, Support
from .subscription import L2SubscriptionCoordinator


class TimelineMode(str, Enum):
    AUTO = "auto"
    BASIC = "basic"
    LEVEL2 = "level2"


@dataclass(frozen=True)
class TimelinePlan:
    mode: TimelineMode
    role: ConnectionRole
    capability: Capability

    @property
    def level2(self) -> bool:
        return self.mode is TimelineMode.LEVEL2


def _require(
    profile: AccountProfile,
    capability: Capability,
    *,
    feature: str,
) -> None:
    support = profile.support(capability)
    if support is Support.YES:
        return
    if support is Support.NO:
        raise CapabilityUnavailableError(capability, feature)
    raise UnsupportedAccountFeatureError(
        feature,
        profile.kind,
        f"能力证据未知: {capability.value}",
    )


def _l2_role(market: int) -> ConnectionRole:
    if market == 17:
        return ConnectionRole.SH_L2
    if market == 33:
        return ConnectionRole.SZ_L2
    raise ValueError(f"分时暂不支持市场码: {market}")


def select_timeline_plan(
    profile: AccountProfile,
    market: int,
    mode: TimelineMode | str = TimelineMode.AUTO,
) -> TimelinePlan:
    """Choose account-specific transport and wire protocol without I/O."""
    mode = TimelineMode(mode)
    if mode is TimelineMode.BASIC:
        _require(
            profile,
            Capability.BASIC_TIMELINE,
            feature="timeline:basic",
        )
        return TimelinePlan(
            mode=TimelineMode.BASIC,
            role=ConnectionRole.MAIN,
            capability=Capability.BASIC_TIMELINE,
        )

    if mode is TimelineMode.LEVEL2:
        if profile.kind is AccountKind.STANDARD:
            raise CapabilityUnavailableError(
                Capability.L2_TIMELINE,
                "timeline:level2",
            )
        _require(
            profile,
            Capability.L2_TIMELINE,
            feature="timeline:level2",
        )
        return TimelinePlan(
            mode=TimelineMode.LEVEL2,
            role=_l2_role(market),
            capability=Capability.L2_TIMELINE,
        )

    if profile.kind is AccountKind.STANDARD:
        return select_timeline_plan(profile, market, TimelineMode.BASIC)
    if profile.kind is AccountKind.LEVEL2:
        return select_timeline_plan(profile, market, TimelineMode.LEVEL2)
    raise UnsupportedAccountFeatureError(
        "timeline:auto",
        profile.kind,
        "账号类型未知，不能推断 basic 或 level2 请求",
    )


def build_timeline_request(
    plan: TimelinePlan,
    code: str,
    *,
    market: int,
    seq: int | None = None,
) -> bytes:
    """Build the exact wire request selected by a timeline plan."""
    if not plan.level2:
        kwargs = {"market": market}
        if seq is not None:
            kwargs["seq"] = seq
        return build_timeline_query(code, **kwargs)

    benchmark = {
        17: "16(1A0002,);",
        33: "32(399002,);",
    }.get(market)
    if benchmark is None:
        raise ValueError(f"分时暂不支持市场码: {market}")
    kwargs = {
        "market": market,
        "extra_codelist": benchmark,
    }
    if seq is not None:
        kwargs["seq"] = seq
    return build_timeline_l2_query(code, **kwargs)


FrameReader = Callable[[SocketLike], bytes]


class TimelineService:
    """Execute timeline plans while preserving per-connection read ownership."""

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

    def timeline(
        self,
        code: str,
        *,
        market: int,
        mode: TimelineMode | str = TimelineMode.AUTO,
        timeout: float = 12.0,
    ) -> list[dict]:
        plan = select_timeline_plan(
            self._connections.profile,
            market,
            mode,
        )
        if not plan.level2:
            raise UnsupportedAccountFeatureError(
                "timeline:basic_response",
                self._connections.profile.kind,
                "pageid=9354 响应协议缺少普通账号脱敏语料",
            )

        frame = build_timeline_request(plan, code, market=market)
        connection = self._connections.acquire(
            plan.role,
            capability=plan.capability,
        )
        self._subscriptions.ensure_registered(
            connection,
            code,
            market=market,
            timeout=min(timeout, 5.0),
        )
        saw_timeline_frame = False
        with connection.request(frame, timeout=timeout) as sock:
            for _ in range(self._max_frames):
                response = self._read_frame(sock)
                if b"hd3.1\x00" not in response:
                    continue
                saw_timeline_frame = True
                records = parse_timeline_l2_response(response)
                if records:
                    if self._evidence is not None:
                        self._evidence.record_feature(
                            Capability.L2_TIMELINE,
                            Support.YES,
                        )
                    return records

        if saw_timeline_frame:
            raise ProtocolError("收到 Level2 分时帧但无法解析")
        return []

    def history_timeline(
        self,
        code: str,
        *,
        market: int,
        date=None,
        bar_start: int | None = None,
        timeout: float = 12.0,
        benchmark_market: int | None = None,
        benchmark_code: str | None = None,
    ) -> list[dict]:
        profile = self._connections.profile
        if profile.kind is not AccountKind.LEVEL2:
            raise UnsupportedAccountFeatureError(
                "history_timeline",
                profile.kind,
                "普通账号 4417 协议尚未获得脱敏实测",
            )
        _require(
            profile,
            Capability.L2_HISTORY_TIMELINE,
            feature="history_timeline",
        )
        role = _l2_role(market)
        frame = build_history_timeline_query(
            code,
            bar_start=bar_start,
            date=date,
            market=market,
            benchmark_market=benchmark_market,
            benchmark_code=benchmark_code,
        )
        connection = self._connections.acquire(
            role,
            capability=Capability.L2_HISTORY_TIMELINE,
        )
        if not connection.init_complete:
            raise ChannelUnavailableError(
                role.value,
                "L2 连接尚未完成 init",
            )

        saw_history_frame = False
        with connection.request(frame, timeout=timeout) as sock:
            for _ in range(self._max_frames):
                response = self._read_frame(sock)
                if (
                    not response.startswith(b"\x0a")
                    and b"hd1.0" not in response
                ):
                    continue
                saw_history_frame = True
                records = parse_history_timeline_response(
                    response,
                    code=code,
                )
                if records:
                    if self._evidence is not None:
                        self._evidence.record_feature(
                            Capability.L2_HISTORY_TIMELINE,
                            Support.YES,
                        )
                    return records

        if saw_history_frame:
            raise ProtocolError("收到历史分时帧但无法安全恢复")
        return []
