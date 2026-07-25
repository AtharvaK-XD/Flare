"""recommend node — quality-tier remediation playbook with a hallucination guard.

The model returns a strict ``Remediation`` object. Two post-validations are
mandatory before we trust it:

* Drop every technique the model cites that was NOT retrieved into
  ``state["techniques"]``. Models reliably emit plausible-looking but fabricated
  T-numbers; a fake technique ID on the judges' screen is indefensible. The kept
  techniques are re-hydrated from OUR retrieved objects (authoritative name/url),
  never from the model's copy.
* Renumber the surviving steps sequentially so ``order`` is always 1..N with no
  gaps, regardless of what the model emitted.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.agent.state import TriageState, provider_for
from app.agent.trace import NodeTrace, traced
from app.core.logging import get_logger
from app.schemas import (
    AlertStatus,
    MitreTechnique,
    ProviderTier,
    Remediation,
    RemediationStep,
)

log = get_logger(__name__)

_MAX_TOKENS = 800
_TEMPERATURE = 0.2

_PROMPT = (Path(__file__).parent.parent / "prompts" / "recommend.md").read_text(encoding="utf-8")


def _context_block(state: TriageState) -> str:
    alert = state["alert"]
    reasoning = state.get("reasoning") or "(no analysis narrative available)"
    techniques = state.get("techniques") or []
    tech_lines = (
        "\n".join(f"- {t.id} {t.name} [{t.tactic}]" for t in techniques)
        if techniques
        else "(none — return an empty techniques list)"
    )
    return (
        "Alert:\n"
        f"- signature: {alert.signature}\n"
        f"- src_ip: {alert.src_ip}:{alert.src_port} -> dst_ip: {alert.dst_ip}:{alert.dst_port}\n"
        f"- protocol: {alert.protocol}\n\n"
        f"Analysis narrative:\n{reasoning}\n\n"
        f"Available ATT&CK techniques (cite only these IDs):\n{tech_lines}"
    )


def _sanitize(
    parsed: Remediation, available: list[MitreTechnique], duration_ms: int
) -> Remediation:
    by_id = {t.id: t for t in available}
    cited = {t.id for t in parsed.techniques}
    # Keep only techniques that were both cited AND actually retrieved; use our
    # authoritative objects so name/url/excerpt cannot be fabricated.
    kept = [by_id[tid] for tid in by_id if tid in cited]

    steps = [
        RemediationStep(
            order=i + 1,
            action=s.action,
            detail=s.detail,
            urgency=s.urgency,
        )
        for i, s in enumerate(parsed.steps)
    ]

    return Remediation(
        summary=parsed.summary,
        steps=steps,
        techniques=kept,
        generated_at=datetime.now(UTC),
        duration_ms=duration_ms,
    )


@traced("recommend")
async def recommend(state: TriageState, tr: NodeTrace) -> dict[str, Any]:
    prompt = f"{_PROMPT}\n\n{_context_block(state)}"
    available = state.get("techniques") or []

    try:
        provider = provider_for(state, ProviderTier.QUALITY)
        result = await provider.complete(
            prompt,
            max_tokens=_MAX_TOKENS,
            temperature=_TEMPERATURE,
            response_model=Remediation,
            node="recommend",  # type: ignore[call-arg]
        )
        parsed: Remediation = result.parsed  # type: ignore[assignment]
        tr.from_completion(result)
    except Exception as exc:  # noqa: BLE001 — degrade, never raise out of a node
        log.warning("agent.recommend_failed", error=str(exc))
        tr.mark_failed(f"remediation generation failed: {exc}")
        return {
            "remediation": None,
            "status": AlertStatus.REASONED,
            "errors": [f"recommend: {exc}"],
        }

    remediation = _sanitize(parsed, available, int(result.latency_ms))

    dropped = len(parsed.techniques) - len(remediation.techniques)
    note = f"{len(remediation.steps)} step(s), {len(remediation.techniques)} technique(s)"
    if dropped > 0:
        note += f"; dropped {dropped} hallucinated/absent technique id(s)"
        log.info("agent.recommend_dropped_techniques", dropped=dropped)
    tr.note = note

    return {"remediation": remediation, "status": AlertStatus.REASONED}


__all__ = ["recommend"]
