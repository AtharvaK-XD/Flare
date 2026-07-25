"""Conditional control flow — the highest-risk code in the phase.

Every function here is PURE: state in, edge-name string out. No I/O, no logging,
no mutation. That purity is exactly what makes the routing matrix exhaustively
unit-testable, and the exhaustive test is the safety net for the whole phase.

The only external input a router reads is a boolean tunable
(``enrich_low_severity``), resolved from ``state["config"]`` first (so tests are
hermetic) and otherwise from settings.
"""

from __future__ import annotations

from app.agent.state import TriageState, config_flag
from app.schemas import Severity

_ENRICH_SEVERITIES = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)
_RETRIEVE_SEVERITIES = (Severity.CRITICAL, Severity.HIGH)
_LOW_SEVERITIES = (Severity.LOW, Severity.INFO)

# A medium alert only earns retrieval if its worst IOC clears this bar.
MEDIUM_RETRIEVE_MIN_SCORE = 40


def _has_public_iocs(state: TriageState) -> bool:
    alert = state.get("alert")
    return bool(alert is not None and alert.extracted_iocs)


def route_after_classify(state: TriageState) -> str:
    """classify -> enrich | finalize."""
    severity = state.get("severity")

    if severity in _ENRICH_SEVERITIES:
        return "enrich"

    if (
        severity in _LOW_SEVERITIES
        and _has_public_iocs(state)
        and config_flag(state, "enrich_low_severity", False)
    ):
        return "enrich"

    return "finalize"


def route_after_enrich(state: TriageState) -> str:
    """enrich -> retrieve | finalize (severity is post-upgrade here)."""
    severity = state.get("severity")

    if severity in _RETRIEVE_SEVERITIES:
        return "retrieve"

    max_score = state.get("max_ioc_score") or 0
    if severity == Severity.MEDIUM and max_score >= MEDIUM_RETRIEVE_MIN_SCORE:
        return "retrieve"

    return "finalize"


def route_after_retrieve(state: TriageState) -> str:
    """retrieve -> reason (always)."""
    return "reason"


def route_after_reason(state: TriageState) -> str:
    """reason -> recommend if a narrative exists, else finalize."""
    reasoning = state.get("reasoning")
    if reasoning and reasoning.strip():
        return "recommend"
    return "finalize"


def route_after_recommend(state: TriageState) -> str:
    """recommend -> finalize (always)."""
    return "finalize"


__all__ = [
    "route_after_classify",
    "route_after_enrich",
    "route_after_retrieve",
    "route_after_reason",
    "route_after_recommend",
    "MEDIUM_RETRIEVE_MIN_SCORE",
]
