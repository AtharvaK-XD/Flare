"""classify node — fast-tier severity + attack-type tagging.

The first stage: sub-second, cheap, runs on every alert. On any failure it must
degrade to ``medium``/``unknown`` — never ``critical`` (a broken classifier must
not flood the critical queue) and never silently (an error is always recorded).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import Field

from app.agent.state import TriageState, provider_for
from app.agent.trace import NodeTrace, traced
from app.core.logging import get_logger
from app.schemas import AlertStatus, AttackType, FlareModel, ProviderTier, Severity

log = get_logger(__name__)

_PROMPT = (Path(__file__).parent.parent / "prompts" / "classify.md").read_text(encoding="utf-8")

_RAW_EXCERPT_MAX = 800


class ClassificationResult(FlareModel):
    """Strict classifier output — the fast tier must return exactly this."""

    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    attack_type: AttackType
    rationale: str = ""


def _alert_block(alert: Any) -> str:
    raw_excerpt = json.dumps(alert.raw, default=str)[:_RAW_EXCERPT_MAX]
    return (
        "Alert to classify:\n"
        f"- signature: {alert.signature}\n"
        f"- src_ip: {alert.src_ip}  src_port: {alert.src_port}\n"
        f"- dst_ip: {alert.dst_ip}  dst_port: {alert.dst_port}\n"
        f"- protocol: {alert.protocol}\n"
        f"- source: {alert.source}\n"
        f"- raw excerpt: {raw_excerpt}"
    )


@traced("classify")
async def classify(state: TriageState, tr: NodeTrace) -> dict[str, Any]:
    alert = state["alert"]
    prompt = f"{_PROMPT}\n\n{_alert_block(alert)}"

    try:
        provider = provider_for(state, ProviderTier.FAST)
        result = await provider.complete(
            prompt,
            max_tokens=300,
            temperature=0.1,
            response_model=ClassificationResult,
            node="classify",  # type: ignore[call-arg]
        )
        parsed: ClassificationResult = result.parsed  # type: ignore[assignment]
        tr.from_completion(result)
        tr.note = (parsed.rationale or "")[:200] or None
        return {
            "severity": parsed.severity,
            "confidence": parsed.confidence,
            "attack_type": parsed.attack_type,
            "status": AlertStatus.CLASSIFIED,
        }
    except Exception as exc:  # noqa: BLE001 — degrade, never raise out of a node
        log.warning("agent.classify_failed", error=str(exc))
        tr.mark_failed(f"classification failed, defaulted to medium/unknown: {exc}")
        return {
            "severity": Severity.MEDIUM,
            "confidence": 0.0,
            "attack_type": AttackType.UNKNOWN,
            "status": AlertStatus.CLASSIFIED,
            "errors": [f"classify: {exc}"],
        }


__all__ = ["classify", "ClassificationResult"]
