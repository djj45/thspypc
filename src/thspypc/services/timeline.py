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
    is_index_timeline,
    parse_index_timeline_response,
    parse_timeline_l2_response,
    parse_timeline_response,
)
from ..features.history_timeline_protocol import (
    build_beijing_index_timeline_query,
    build_beijing_timeline_query,
    build_history_timeline_query,
    build_index_history_timeline_query,
    build_normal_history_timeline_query,
    history_timeline_request_codes,
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
    capability: Capability | None

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
    if market in (16, 17, 144):
        return ConnectionRole.SH_L2
    if market in (32, 33):
        return ConnectionRole.SZ_L2
    raise ValueError(f"分时暂不支持市场码: {market}")


def select_timeline_plan(
    profile: AccountProfile,
    market: int,
    mode: TimelineMode | str = TimelineMode.AUTO,
    code: str = "",
) -> TimelinePlan:
    """Choose account-specific transport and wire protocol without I/O."""
    mode = TimelineMode(mode)
    # 北交所（BSE）专用 pageid：普通账号走 MAIN，Level2 账号走沪 L2（shlv2）。
    # 2026-08-15 抓包确认 Level2 客户端把 920083 的 1334/10443 请求全部发在
    # shlv2 连接上（MAIN/ifindhq 不响应北交所 151）。
    if market == 151 or (market == 144 and code.startswith("899")):
        role = (
            ConnectionRole.SH_L2
            if profile.kind is AccountKind.LEVEL2
            else ConnectionRole.MAIN
        )
        return TimelinePlan(
            mode=TimelineMode.BASIC,
            role=role,
            capability=None,  # MAIN 不需要能力校验；SH_L2 由 acquire 校验 L2 权限
        )
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


def _enrich_buy_sell_force(records: list[dict]) -> None:
    """给分时记录加主动买卖力量字段（红绿柱数据）。

    主动买卖累计量用 **dt14/dt15**（fmt=0x70 ths_float，严格单调递增，
    ``dt14 + dt15 ≈ dt13``）。普通账号 9355 和 Level2 1334 的 DataType 都
    含 14/15，字段值完全一致（同数据源）。

    dt22/dt23 经实测**不是累计主动买卖量**（全天窄幅波动、非单调、与 dt14/dt15
    无数值关系），不能用于买卖力量。

    逐分钟相减得到每分钟增量：
    - ``buy_force``：本分钟主动买入量
    - ``sell_force``：本分钟主动卖出量
    - ``net_force``：买卖净力量（正=红柱/买强，负=绿柱/卖强）

    对应同花顺指数分时图零轴上下的红绿柱：同一分钟柱子只能红或绿，
    由 net_force 正负决定。首条无前值时三个字段均为 0。
    """
    prev_buy = None
    prev_sell = None
    for r in records:
        buy = r.get("dt14")
        sell = r.get("dt15")
        if isinstance(buy, (int, float)) and isinstance(sell, (int, float)):
            if prev_buy is not None:
                b = buy - prev_buy
                s = sell - prev_sell
                r["buy_force"] = b
                r["sell_force"] = s
                r["net_force"] = b - s
            else:
                r["buy_force"] = 0
                r["sell_force"] = 0
                r["net_force"] = 0
            prev_buy, prev_sell = buy, sell
        else:
            r["buy_force"] = 0
            r["sell_force"] = 0
            r["net_force"] = 0


def build_timeline_request(
    plan: TimelinePlan,
    code: str,
    *,
    market: int,
    seq: int | None = None,
) -> bytes:
    """Build the exact wire request selected by a timeline plan."""
    # 北交所（BSE）走专用 pageid（10443 个股 / 11695 指数），不分 BASIC/LEVEL2，
    # 均走 MAIN 连接（2026-08-06 抓包确认两种账号都在 MAIN 上请求）。
    if market == 151:
        return build_beijing_timeline_query(code, market=market)
    if market == 144 and code.startswith("899"):
        return build_beijing_index_timeline_query(code, market=market)

    if not plan.level2:
        # 2026-08-06 抓包修正：普通账号当日分时走 pageid=9355（同历史分时），
        # 非 9354（已废弃，服务端不响应）。today=True 用 DateTime=8192(0-0)。
        return build_normal_history_timeline_query(code, market=market, today=True)

    # 2026-08-05 抓包对齐：Level2 分时主体用 pageid=1334（DataType 含大单字段不变）
    if is_index_timeline(code, market):
        kwargs = {"market": market, "pageid": 1334}
        if seq is not None:
            kwargs["seq"] = seq
        return build_timeline_l2_query(code, **kwargs)

    benchmark = {
        17: "16(1A0002,);",
        33: "32(399002,);",
    }.get(market)
    if benchmark is None:
        raise ValueError(f"分时暂不支持市场码: {market}")
    kwargs = {
        "market": market,
        "extra_codelist": benchmark,
        "pageid": 1334,
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
            code=code,
        )

        frame = build_timeline_request(plan, code, market=market)
        connection = self._connections.acquire(
            plan.role,
            capability=plan.capability,
        )
        if plan.level2 and not is_index_timeline(code, market):
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
                if (
                    not response.startswith(b"\x0a")
                    and b"hd3.1\x00" not in response
                ):
                    continue
                saw_timeline_frame = True
                parser = (
                    parse_timeline_l2_response
                    if plan.level2
                    else parse_index_timeline_response
                )
                records = parser(response)
                if records:
                    # 指数分时的买卖力量（红绿柱）：用 dt14/dt15（累计主动买/卖）。
                    # 普通账号 9355 和 Level2 1334 的 DataType 都含 14/15。
                    if any(
                        isinstance(r.get("dt14"), (int, float))
                        and isinstance(r.get("dt15"), (int, float))
                        for r in records
                    ):
                        _enrich_buy_sell_force(records)
                    if self._evidence is not None and plan.level2:
                        self._evidence.record_feature(
                            Capability.L2_TIMELINE,
                            Support.YES,
                        )
                    return records

        if saw_timeline_frame:
            label = "Level2" if plan.level2 else "普通账号"
            raise ProtocolError(f"收到{label}分时帧但无法解析")
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
        index_timeline = is_index_timeline(code, market)
        if profile.kind is AccountKind.STANDARD:
            capability = Capability.BASIC_HISTORY_TIMELINE
            role = ConnectionRole.MAIN
            requested_codes = (code,)
            if index_timeline:
                frame = build_index_history_timeline_query(
                    code,
                    bar_start=bar_start,
                    date=date,
                    market=market,
                )
            else:
                frame = build_normal_history_timeline_query(
                    code,
                    bar_start=bar_start,
                    date=date,
                    market=market,
                )
        elif profile.kind is AccountKind.LEVEL2:
            capability = Capability.L2_HISTORY_TIMELINE
            role = _l2_role(market)
            if index_timeline:
                requested_codes = (code,)
                frame = build_index_history_timeline_query(
                    code,
                    bar_start=bar_start,
                    date=date,
                    market=market,
                )
            else:
                requested_codes, _, _ = history_timeline_request_codes(
                    code,
                    market=market,
                    benchmark_market=benchmark_market,
                    benchmark_code=benchmark_code,
                )
                frame = build_history_timeline_query(
                    code,
                    bar_start=bar_start,
                    date=date,
                    market=market,
                    benchmark_market=benchmark_market,
                    benchmark_code=benchmark_code,
                )
        else:
            raise UnsupportedAccountFeatureError(
                "history_timeline",
                profile.kind,
                "账号类型未知，不能选择普通或 Level2 历史分时协议",
            )
        _require(
            profile,
            capability,
            feature="history_timeline",
        )
        connection = self._connections.acquire(
            role,
            capability=capability,
        )
        if role is not ConnectionRole.MAIN and not connection.init_complete:
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
                    and b"hd3.1" not in response
                ):
                    continue
                saw_history_frame = True
                records = parse_history_timeline_response(
                    response,
                    code=code,
                    requested_codes=requested_codes,
                )
                if records:
                    if (
                        self._evidence is not None
                        and capability
                        is Capability.L2_HISTORY_TIMELINE
                    ):
                        self._evidence.record_feature(
                            Capability.L2_HISTORY_TIMELINE,
                            Support.YES,
                        )
                    return records

        if saw_history_frame:
            raise ProtocolError("收到历史分时帧但无法安全恢复")
        return []
