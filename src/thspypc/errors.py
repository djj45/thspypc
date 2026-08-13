"""Shared error taxonomy for authentication, transport, and feature services."""
from __future__ import annotations

from .models import AccountKind, Capability


class THSPyPCError(Exception):
    """Base class for errors exposed by the refactored service layers."""


class CapabilityUnavailableError(THSPyPCError):
    """The authenticated account explicitly lacks a required capability."""

    def __init__(self, capability: Capability, detail: str = "") -> None:
        self.capability = capability
        self.detail = detail
        message = f"账号不具备能力: {capability.value}"
        if detail:
            message = f"{message} ({detail})"
        super().__init__(message)


class UnsupportedAccountFeatureError(THSPyPCError):
    """The protocol for this feature/account combination is not implemented."""

    def __init__(
        self,
        feature: str,
        account_kind: AccountKind,
        detail: str = "",
    ) -> None:
        self.feature = feature
        self.account_kind = account_kind
        self.detail = detail
        message = f"{account_kind.value} 账号暂不支持功能: {feature}"
        if detail:
            message = f"{message} ({detail})"
        super().__init__(message)


class ChannelUnavailableError(THSPyPCError):
    """The account has permission, but the required channel is unavailable."""

    def __init__(self, channel: str, detail: str = "") -> None:
        self.channel = channel
        self.detail = detail
        message = f"行情通道不可用: {channel}"
        if detail:
            message = f"{message} ({detail})"
        super().__init__(message)


class ProtocolError(THSPyPCError):
    """A response was received but could not be recognized or decoded."""


class SupersededError(THSPyPCError):
    """A newer request superseded this one before it reached the socket.

    Raised by latest-wins connection requests: the request was queued behind the
    connection lock and a more recent request arrived first, so this one was
    dropped without being sent.
    """

