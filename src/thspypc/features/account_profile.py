"""Pure conversion from explicit account evidence to routing capabilities."""
from __future__ import annotations

import threading
from dataclasses import replace
from collections.abc import Mapping

from ..models import (
    AccountEvidence,
    AccountKind,
    AccountProfile,
    Capability,
    Support,
)


_L2_FEATURE_EVIDENCE = {
    Capability.L2_TIMELINE: "l2_timeline",
    Capability.L2_AUCTION: "l2_auction",
    Capability.L2_SNAPSHOT_PUSH: "l2_snapshot_push",
    Capability.L2_HISTORY_TIMELINE: "l2_history_timeline",
}


def _validate_evidence(evidence: AccountEvidence) -> None:
    feature_values = [
        getattr(evidence, field)
        for field in _L2_FEATURE_EVIDENCE.values()
    ]
    if evidence.l2_entitlement is Support.NO and any(
        value is Support.YES
        for value in (
            evidence.manual_login,
            evidence.l2_market_init,
            *feature_values,
        )
    ):
        raise ValueError("L2 entitlement=NO 与 L2 成功证据矛盾")
    if evidence.manual_login is Support.NO and (
        evidence.l2_market_init is Support.YES
        or any(value is Support.YES for value in feature_values)
    ):
        raise ValueError("manual_login=NO 与 L2 成功证据矛盾")
    if evidence.l2_market_init is Support.NO and any(
        value is Support.YES for value in feature_values
    ):
        raise ValueError("l2_market_init=NO 与 L2 业务成功证据矛盾")


def _market_support(evidence: AccountEvidence) -> Support:
    if evidence.l2_market_init is not Support.UNKNOWN:
        return evidence.l2_market_init
    if (
        evidence.manual_login is Support.NO
        or evidence.l2_entitlement is Support.NO
    ):
        return Support.NO
    return Support.UNKNOWN


def _feature_support(
    direct: Support,
    *,
    entitlement: Support,
    market: Support,
) -> Support:
    if direct is not Support.UNKNOWN:
        return direct
    if entitlement is Support.NO or market is Support.NO:
        return Support.NO
    return Support.UNKNOWN


def build_account_profile(evidence: AccountEvidence) -> AccountProfile:
    """Build a conservative profile without interpreting passport field text."""
    _validate_evidence(evidence)
    market_support = _market_support(evidence)
    feature_values = {
        capability: _feature_support(
            getattr(evidence, field),
            entitlement=evidence.l2_entitlement,
            market=market_support,
        )
        for capability, field in _L2_FEATURE_EVIDENCE.items()
    }

    l2_success = (
        evidence.l2_entitlement is Support.YES
        or evidence.l2_market_init is Support.YES
        or any(value is Support.YES for value in feature_values.values())
    )
    if l2_success:
        kind = AccountKind.LEVEL2
    elif evidence.l2_entitlement is Support.NO:
        kind = AccountKind.STANDARD
    else:
        kind = AccountKind.UNKNOWN

    realorder_basic = evidence.realorder
    if evidence.realorder is Support.NO:
        realorder_level2 = Support.NO
    elif evidence.l2_entitlement is Support.NO:
        realorder_level2 = Support.NO
    elif (
        evidence.realorder is Support.YES
        and evidence.l2_entitlement is Support.YES
    ):
        realorder_level2 = Support.YES
    else:
        realorder_level2 = Support.UNKNOWN

    capabilities = {
        Capability.BASIC_QUOTE: evidence.main_market_access,
        Capability.BASIC_TIMELINE: evidence.main_market_access,
        Capability.BASIC_HISTORY_TIMELINE: evidence.main_market_access,
        Capability.BASIC_AUCTION: evidence.main_market_access,
        Capability.L2_MARKET_ACCESS: market_support,
        **feature_values,
        Capability.REALORDER: evidence.realorder,
        Capability.REALORDER_BASIC_ANOMALIES: realorder_basic,
        Capability.REALORDER_LEVEL2_ANOMALIES: realorder_level2,
    }
    return AccountProfile(
        kind=kind,
        capabilities=capabilities,
        passport_fields=evidence.passport_fields,
    )


_FEATURE_FIELDS = {
    **_L2_FEATURE_EVIDENCE,
    Capability.REALORDER: "realorder",
}


def infer_l2_entitlement(
    passport_fields: Mapping[str, str],
) -> Support:
    """Classify only the paired passport signatures verified in live accounts.

    A single ``userclass`` or ``level2`` value is not sufficient evidence.
    Unknown combinations remain UNKNOWN so new server-side account classes do
    not get routed to a privileged channel by accident.
    """
    userclass = passport_fields.get("userclass", "").strip()
    level2 = passport_fields.get("level2", "").strip()
    if userclass == "30002" and level2 == "16;32;48":
        return Support.YES
    if userclass == "10000" and level2 == "255":
        return Support.NO
    return Support.UNKNOWN


class AccountEvidenceRecorder:
    """Atomically evolve evidence while preserving conservative semantics."""

    def __init__(
        self,
        initial: AccountEvidence | None = None,
    ) -> None:
        self._evidence = initial or AccountEvidence()
        build_account_profile(self._evidence)
        self._lock = threading.RLock()

    def snapshot(self) -> AccountEvidence:
        with self._lock:
            return self._evidence

    def profile(self) -> AccountProfile:
        with self._lock:
            return build_account_profile(self._evidence)

    def _update(self, **changes) -> AccountEvidence:
        with self._lock:
            candidate = replace(self._evidence, **changes)
            build_account_profile(candidate)
            self._evidence = candidate
            return candidate

    def record_main_ready(
        self,
        passport_fields: Mapping[str, str] | None = None,
    ) -> AccountEvidence:
        with self._lock:
            fields = dict(self._evidence.passport_fields)
            if passport_fields is not None:
                fields.update(passport_fields)
            return self._update(
                main_market_access=Support.YES,
                passport_fields=fields,
            )

    def record_l2_entitlement(
        self,
        support: Support,
    ) -> AccountEvidence:
        return self._update(l2_entitlement=Support(support))

    def record_passport_fields(
        self,
        passport_fields: Mapping[str, str],
    ) -> AccountEvidence:
        """Record passport metadata and any verified account-class signature."""
        with self._lock:
            fields = dict(self._evidence.passport_fields)
            fields.update(passport_fields)
            inferred = infer_l2_entitlement(fields)
            entitlement = self._evidence.l2_entitlement
            if inferred is not Support.UNKNOWN:
                entitlement = inferred
            return self._update(
                passport_fields=fields,
                l2_entitlement=entitlement,
            )

    def record_manual_login(
        self,
        support: Support,
    ) -> AccountEvidence:
        return self._update(manual_login=Support(support))

    def record_l2_init(
        self,
        support: Support,
    ) -> AccountEvidence:
        return self._update(l2_market_init=Support(support))

    def record_feature(
        self,
        capability: Capability,
        support: Support,
    ) -> AccountEvidence:
        try:
            field = _FEATURE_FIELDS[capability]
        except KeyError as exc:
            raise ValueError(
                f"该能力不由业务响应证据更新: {capability.value}"
            ) from exc
        return self._update(**{field: Support(support)})

    def record_transient_failure(self) -> AccountEvidence:
        """Leave evidence unchanged for timeout, DNS, RST, or parser failures."""
        return self.snapshot()
