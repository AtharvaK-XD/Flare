"""enrich node — attach IOC reputation and let real intel outrank the model.

Pulls the alert's public indicators, fans them out through the IntelAggregator,
and records the worst score. Two hard rules:

* A rate-limited / quota-exhausted lookup is EXPECTED on free tiers — it yields
  empty IOCs and a trace note, never an error state.
* If the worst IOC score is at or above ``settings.ioc_escalation_score`` and the
  model's severity is below ``high``, upgrade to ``high`` and record it. Ground
  truth from threat intel beats a language model's first impression.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from app.agent.state import TriageState, aggregator_for, severity_rank
from app.agent.trace import NodeTrace, traced
from app.api.errors import RateLimitedError
from app.config import get_settings
from app.core.logging import get_logger
from app.intel.models import IndicatorType
from app.schemas import AlertStatus, Severity

log = get_logger(__name__)


def _indicator_type(indicator: str) -> IndicatorType:
    try:
        ipaddress.ip_address(indicator)
        return "ip"
    except ValueError:
        return "hash"


@traced("enrich")
async def enrich(state: TriageState, tr: NodeTrace) -> dict[str, Any]:
    alert = state["alert"]
    indicators = list(alert.extracted_iocs or [])

    if not indicators:
        tr.note = "no public IOCs to enrich"
        return {"iocs": [], "max_ioc_score": None, "status": AlertStatus.ENRICHED}

    pairs: list[tuple[str, IndicatorType]] = [(i, _indicator_type(i)) for i in indicators]

    try:
        aggregator = aggregator_for(state)
        verdicts = await aggregator.lookup_many(pairs)
    except RateLimitedError as exc:
        # Expected on free tier — degrade quietly, do NOT poison the alert.
        log.info("agent.enrich_rate_limited", error=str(exc))
        tr.note = "intel rate-limited; enrichment skipped (no reputation available)"
        return {"iocs": [], "max_ioc_score": None, "status": AlertStatus.ENRICHED}
    except Exception as exc:  # noqa: BLE001 — degrade, never raise out of a node
        log.warning("agent.enrich_failed", error=str(exc))
        tr.mark_failed(f"enrichment failed: {exc}")
        return {
            "iocs": [],
            "max_ioc_score": None,
            "status": AlertStatus.ENRICHED,
            "errors": [f"enrich: {exc}"],
        }

    iocs = [v for v in verdicts if v is not None]
    max_score: int | None = int(round(max((v.score for v in iocs), default=0.0))) if iocs else None

    out: dict[str, Any] = {
        "iocs": iocs,
        "max_ioc_score": max_score,
        "status": AlertStatus.ENRICHED,
    }

    note = f"{len(iocs)} indicator(s) enriched"
    if max_score is not None:
        note += f", worst score {max_score}"

    current = state.get("severity")
    threshold = get_settings().ioc_escalation_score
    if (
        max_score is not None
        and max_score >= threshold
        and severity_rank(current) < severity_rank(Severity.HIGH)
    ):
        out["severity"] = Severity.HIGH
        prev = current.value if current else "unknown"
        note += f"; severity upgraded {prev} -> high (IOC score {max_score} >= {threshold})"
        log.info("agent.severity_upgraded", from_severity=prev, to="high", score=max_score)

    tr.note = note
    return out


__all__ = ["enrich"]
