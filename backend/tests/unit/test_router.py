"""Exhaustive routing-matrix test — the safety net for the routing layer.

Every branch of every router is covered by an independently-derived expectation
(double-entry: the expected value is computed from the spec text, not from the
router under test). If a routing rule ever changes, this table breaks loudly.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.agent.router import (
    MEDIUM_RETRIEVE_MIN_SCORE,
    route_after_classify,
    route_after_enrich,
    route_after_reason,
    route_after_recommend,
    route_after_retrieve,
)
from app.agent.state import TriageState
from app.schemas import NormalizedAlert, Severity

ALL_SEVERITIES = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]
SCORES = [None, 0, 39, 40, 79, 80, 100]


def _alert(has_iocs: bool) -> NormalizedAlert:
    return NormalizedAlert(
        id="a1",
        timestamp=datetime(2026, 7, 25, tzinfo=UTC),
        source="suricata",
        signature="test signature",
        src_ip="45.13.2.99",
        dst_ip="10.0.0.5",
        extracted_iocs=["45.13.2.99"] if has_iocs else [],
    )


def _state(
    severity: Severity,
    *,
    has_iocs: bool = False,
    max_ioc_score: int | None = None,
    enrich_low_severity: bool = False,
    reasoning: str | None = None,
) -> TriageState:
    return {
        "alert": _alert(has_iocs),
        "severity": severity,
        "max_ioc_score": max_ioc_score,
        "reasoning": reasoning,
        "config": {"enrich_low_severity": enrich_low_severity},
    }


# route_after_classify — full matrix of severity x has_iocs x enrich_low_severity


def _expected_after_classify(sev: Severity, has_iocs: bool, els: bool) -> str:
    if sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM):
        return "enrich"
    if sev in (Severity.LOW, Severity.INFO) and has_iocs and els:
        return "enrich"
    return "finalize"


@pytest.mark.parametrize("severity", ALL_SEVERITIES)
@pytest.mark.parametrize("has_iocs", [True, False])
@pytest.mark.parametrize("enrich_low_severity", [True, False])
def test_route_after_classify_matrix(
    severity: Severity, has_iocs: bool, enrich_low_severity: bool
) -> None:
    state = _state(
        severity, has_iocs=has_iocs, enrich_low_severity=enrich_low_severity
    )
    expected = _expected_after_classify(severity, has_iocs, enrich_low_severity)
    assert route_after_classify(state) == expected


def test_route_after_classify_low_with_iocs_needs_flag() -> None:
    def r(has_iocs: bool, els: bool) -> str:
        return route_after_classify(
            _state(Severity.LOW, has_iocs=has_iocs, enrich_low_severity=els)
        )

    # low + iocs + flag ON -> enrich; flag OFF -> finalize (the whole cost saving)
    assert r(True, True) == "enrich"
    assert r(True, False) == "finalize"
    # low + flag ON but NO iocs -> finalize (nothing to enrich)
    assert r(False, True) == "finalize"


# route_after_enrich — full matrix of (post-upgrade) severity x max_ioc_score


def _expected_after_enrich(sev: Severity, score: int | None) -> str:
    if sev in (Severity.CRITICAL, Severity.HIGH):
        return "retrieve"
    if sev == Severity.MEDIUM and (score or 0) >= MEDIUM_RETRIEVE_MIN_SCORE:
        return "retrieve"
    return "finalize"


@pytest.mark.parametrize("severity", ALL_SEVERITIES)
@pytest.mark.parametrize("score", SCORES)
def test_route_after_enrich_matrix(severity: Severity, score: int | None) -> None:
    state = _state(severity, max_ioc_score=score)
    expected = _expected_after_enrich(severity, score)
    assert route_after_enrich(state) == expected


def test_route_after_enrich_medium_threshold_boundary() -> None:
    assert route_after_enrich(_state(Severity.MEDIUM, max_ioc_score=39)) == "finalize"
    assert route_after_enrich(_state(Severity.MEDIUM, max_ioc_score=40)) == "retrieve"


def test_route_after_enrich_critical_high_always_retrieve() -> None:
    for sev in (Severity.CRITICAL, Severity.HIGH):
        for score in SCORES:
            assert route_after_enrich(_state(sev, max_ioc_score=score)) == "retrieve"


def test_route_after_retrieve_always_reason() -> None:
    assert route_after_retrieve(_state(Severity.LOW)) == "reason"
    assert route_after_retrieve(_state(Severity.CRITICAL)) == "reason"


def test_route_after_reason_needs_narrative() -> None:
    def r(reasoning: str | None) -> str:
        return route_after_reason(_state(Severity.HIGH, reasoning=reasoning))

    assert r("Active brute force (T1110).") == "recommend"
    assert r("") == "finalize"
    assert r("   ") == "finalize"
    assert r(None) == "finalize"


def test_route_after_recommend_always_finalize() -> None:
    assert route_after_recommend(_state(Severity.CRITICAL)) == "finalize"


def test_routers_are_pure_no_mutation() -> None:
    state = _state(Severity.MEDIUM, max_ioc_score=80, has_iocs=True)
    before = dict(state)
    route_after_classify(state)
    route_after_enrich(state)
    route_after_reason(state)
    assert state == before
