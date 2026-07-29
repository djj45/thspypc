"""公开业务结果的类型定义。

运行时仍使用字典以保持兼容；TypedDict 用于明确稳定字段，协议原始 ``dt<N>``
字段则保留在各结果的 ``fields`` 中。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Literal, Mapping, TypedDict


class AccountKind(str, Enum):
    """Coarse account classification; feature routing uses capabilities."""

    STANDARD = "standard"
    LEVEL2 = "level2"
    UNKNOWN = "unknown"


class Capability(str, Enum):
    """Granular permissions used when selecting request plans."""

    BASIC_QUOTE = "basic_quote"
    BASIC_TIMELINE = "basic_timeline"
    BASIC_HISTORY_TIMELINE = "basic_history_timeline"
    BASIC_AUCTION = "basic_auction"
    L2_MARKET_ACCESS = "l2_market_access"
    L2_TIMELINE = "l2_timeline"
    L2_AUCTION = "l2_auction"
    L2_SNAPSHOT_PUSH = "l2_snapshot_push"
    L2_HISTORY_TIMELINE = "l2_history_timeline"
    REALORDER = "realorder"
    REALORDER_BASIC_ANOMALIES = "realorder_basic_anomalies"
    REALORDER_LEVEL2_ANOMALIES = "realorder_level2_anomalies"


class Support(str, Enum):
    """Tri-state capability evidence."""

    YES = "yes"
    NO = "no"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class AccountEvidence:
    """Independent, auditable observations used to build an account profile."""

    main_market_access: Support = Support.UNKNOWN
    l2_entitlement: Support = Support.UNKNOWN
    manual_login: Support = Support.UNKNOWN
    l2_market_init: Support = Support.UNKNOWN
    l2_timeline: Support = Support.UNKNOWN
    l2_auction: Support = Support.UNKNOWN
    l2_snapshot_push: Support = Support.UNKNOWN
    l2_history_timeline: Support = Support.UNKNOWN
    realorder: Support = Support.UNKNOWN
    passport_fields: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "passport_fields",
            MappingProxyType(dict(self.passport_fields)),
        )


@dataclass(frozen=True)
class AccountProfile:
    """Account capabilities derived from explicit, separately stored evidence."""

    kind: AccountKind = AccountKind.UNKNOWN
    capabilities: Mapping[Capability, Support] = field(default_factory=dict)
    passport_fields: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "capabilities",
            MappingProxyType(dict(self.capabilities)),
        )
        object.__setattr__(
            self,
            "passport_fields",
            MappingProxyType(dict(self.passport_fields)),
        )

    def support(self, capability: Capability) -> Support:
        """Return explicit support evidence, defaulting to ``UNKNOWN``."""
        return self.capabilities.get(capability, Support.UNKNOWN)

    def supports(self, capability: Capability) -> bool:
        """Return whether a capability is explicitly supported."""
        return self.support(capability) is Support.YES


class DepthLevel(TypedDict):
    """单档盘口。"""

    level: str
    price: float
    qty: float
    amount: float


class DepthQuote(TypedDict, total=False):
    """五档盘口结果；空字典表示服务器未返回可识别盘口帧。"""

    code: str
    buy: list[DepthLevel]
    sell: list[DepthLevel]
    seal_amount: float
    seal_type: Literal["涨停", "跌停"] | None
    fields: dict[str, float]
