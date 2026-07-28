"""Evidence-to-profile matrix for ordinary and Level2 accounts."""

import pytest

from thspypc import (
    AccountEvidence,
    AccountEvidenceRecorder,
    AccountKind,
    Capability,
    Support,
    build_account_profile,
)


def test_unknown_passport_fields_do_not_guess_account_type():
    profile = build_account_profile(
        AccountEvidence(passport_fields={"level2": "", "userclass": "x"})
    )

    assert profile.kind is AccountKind.UNKNOWN
    assert profile.support(Capability.L2_MARKET_ACCESS) is Support.UNKNOWN
    assert profile.passport_fields["level2"] == ""


def test_explicit_ordinary_entitlement_disables_only_l2_capabilities():
    profile = build_account_profile(
        AccountEvidence(
            main_market_access=Support.YES,
            l2_entitlement=Support.NO,
            realorder=Support.UNKNOWN,
        )
    )

    assert profile.kind is AccountKind.STANDARD
    assert profile.supports(Capability.BASIC_QUOTE)
    assert profile.supports(Capability.BASIC_TIMELINE)
    assert profile.support(Capability.L2_MARKET_ACCESS) is Support.NO
    assert profile.support(Capability.L2_TIMELINE) is Support.NO
    assert profile.support(Capability.L2_AUCTION) is Support.NO
    assert profile.support(Capability.REALORDER) is Support.UNKNOWN


def test_l2_init_and_feature_success_promote_only_observed_capabilities():
    profile = build_account_profile(
        AccountEvidence(
            main_market_access=Support.YES,
            manual_login=Support.YES,
            l2_market_init=Support.YES,
            l2_timeline=Support.YES,
        )
    )

    assert profile.kind is AccountKind.LEVEL2
    assert profile.supports(Capability.L2_MARKET_ACCESS)
    assert profile.supports(Capability.L2_TIMELINE)
    assert profile.support(Capability.L2_AUCTION) is Support.UNKNOWN
    assert (
        profile.support(Capability.L2_HISTORY_TIMELINE)
        is Support.UNKNOWN
    )


def test_manual_login_success_alone_does_not_claim_level2_access():
    profile = build_account_profile(
        AccountEvidence(manual_login=Support.YES)
    )

    assert profile.kind is AccountKind.UNKNOWN
    assert profile.support(Capability.L2_MARKET_ACCESS) is Support.UNKNOWN
    assert profile.support(Capability.L2_TIMELINE) is Support.UNKNOWN


@pytest.mark.parametrize(
    "evidence",
    [
        AccountEvidence(
            l2_entitlement=Support.NO,
            manual_login=Support.YES,
        ),
        AccountEvidence(
            manual_login=Support.NO,
            l2_market_init=Support.YES,
        ),
        AccountEvidence(
            manual_login=Support.NO,
            l2_timeline=Support.YES,
        ),
        AccountEvidence(
            l2_market_init=Support.NO,
            l2_auction=Support.YES,
        ),
    ],
)
def test_contradictory_l2_evidence_is_rejected(evidence):
    with pytest.raises(ValueError, match="矛盾"):
        build_account_profile(evidence)


def test_recorder_promotes_main_and_l2_success_evidence():
    recorder = AccountEvidenceRecorder()

    recorder.record_main_ready({"userclass": "captured"})
    recorder.record_manual_login(Support.YES)
    recorder.record_l2_init(Support.YES)
    recorder.record_feature(Capability.L2_AUCTION, Support.YES)
    profile = recorder.profile()

    assert profile.kind is AccountKind.LEVEL2
    assert profile.supports(Capability.BASIC_QUOTE)
    assert profile.supports(Capability.L2_MARKET_ACCESS)
    assert profile.supports(Capability.L2_AUCTION)
    assert profile.passport_fields["userclass"] == "captured"


def test_recorder_explicit_ordinary_entitlement_sets_l2_no():
    recorder = AccountEvidenceRecorder()
    recorder.record_main_ready()
    recorder.record_l2_entitlement(Support.NO)

    profile = recorder.profile()

    assert profile.kind is AccountKind.STANDARD
    assert profile.support(Capability.L2_TIMELINE) is Support.NO


def test_transient_failure_never_downgrades_evidence():
    recorder = AccountEvidenceRecorder(
        AccountEvidence(
            l2_entitlement=Support.YES,
            l2_market_init=Support.YES,
            l2_timeline=Support.YES,
        )
    )
    before = recorder.snapshot()

    after = recorder.record_transient_failure()

    assert after is before
    assert recorder.profile().supports(Capability.L2_TIMELINE)


def test_contradictory_recorder_update_is_atomic():
    recorder = AccountEvidenceRecorder()
    recorder.record_l2_init(Support.YES)
    before = recorder.snapshot()

    with pytest.raises(ValueError, match="矛盾"):
        recorder.record_l2_entitlement(Support.NO)

    assert recorder.snapshot() is before
    assert recorder.profile().kind is AccountKind.LEVEL2


def test_recorder_rejects_non_business_capability():
    recorder = AccountEvidenceRecorder()

    with pytest.raises(ValueError, match="不由业务响应证据更新"):
        recorder.record_feature(Capability.BASIC_QUOTE, Support.YES)
