"""Offline contracts for account capability and error models."""

import pytest

from thspypc.errors import (
    CapabilityUnavailableError,
    ChannelUnavailableError,
    ProtocolError,
    THSPyPCError,
    UnsupportedAccountFeatureError,
)
from thspypc.models import AccountKind, AccountProfile, Capability, Support


def test_unknown_profile_does_not_guess_capabilities():
    profile = AccountProfile(passport_fields={"level2": ""})

    assert profile.kind is AccountKind.UNKNOWN
    assert profile.support(Capability.BASIC_QUOTE) is Support.UNKNOWN
    assert not profile.supports(Capability.BASIC_QUOTE)
    assert (
        profile.support(Capability.REALORDER_BASIC_ANOMALIES)
        is Support.UNKNOWN
    )
    assert (
        profile.support(Capability.REALORDER_LEVEL2_ANOMALIES)
        is Support.UNKNOWN
    )
    assert profile.passport_fields["level2"] == ""


def test_profile_copies_and_freezes_evidence_mappings():
    capabilities = {Capability.BASIC_QUOTE: Support.YES}
    fields = {"userclass": "sample"}
    profile = AccountProfile(
        kind=AccountKind.STANDARD,
        capabilities=capabilities,
        passport_fields=fields,
    )

    capabilities[Capability.BASIC_QUOTE] = Support.NO
    fields["userclass"] = "changed"

    assert profile.supports(Capability.BASIC_QUOTE)
    assert profile.passport_fields["userclass"] == "sample"
    with pytest.raises(TypeError):
        profile.capabilities[Capability.BASIC_TIMELINE] = Support.YES
    with pytest.raises(TypeError):
        profile.passport_fields["level2"] = "1"


def test_capability_and_channel_errors_remain_distinct():
    capability_error = CapabilityUnavailableError(
        Capability.L2_TIMELINE,
        "ordinary account",
    )
    unsupported_error = UnsupportedAccountFeatureError(
        "history_timeline",
        AccountKind.STANDARD,
    )
    channel_error = ChannelUnavailableError("sz_l2", "DNS failed")

    assert isinstance(capability_error, THSPyPCError)
    assert capability_error.capability is Capability.L2_TIMELINE
    assert unsupported_error.account_kind is AccountKind.STANDARD
    assert channel_error.channel == "sz_l2"
    assert issubclass(ProtocolError, THSPyPCError)

