"""reason node — quality-tier grounded analysis narrative.

Runs the slow, better model to write the analyst-facing story, grounded in the
IOC verdicts and retrieved ATT&CK chunks. If the quality tier fails, it retries
ONCE on the fast tier: a degraded narrative beats no narrative, and the trace
records which tier actually served the text so the transparency panel is honest.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from app.agent.state import TriageState, provider_for
from app.agent.trace import NodeTrace, traced
from app.core.logging import get_logger
from app.providers.base import CompletionResult
from app.schemas import IocVerdict, MitreTechnique, ProviderTier

log = get_logger(__name__)

#: Same thinking-budget rule as classify.py: the quality tier is a REASONING
#: model, so the output allowance is spent on hidden reasoning tokens before a
#: single narrative token is emitted. At 800 a long IOC/ATT&CK context could burn
#: the entire budget thinking and return an empty narrative — which this node
#: then correctly reports as "model returned an empty narrative", hiding the real
#: cause. 2048 leaves room for ~400 tokens of prose after typical thinking
#: overhead. RE-MEASURE AFTER ANY MODEL SWAP.
_MAX_TOKENS = 2048
_TEMPERATURE = 0.3

_PROMPT = (Path(__file__).parent.parent / "prompts" / "reason.md").read_text(encoding="utf-8")


def _iocs_block(iocs: list[IocVerdict]) -> str:
    if not iocs:
        return "IOC reputation: none available (no public indicators returned data)."
    lines = ["IOC reputation verdicts:"]
    for v in iocs:
        cats = ", ".join(sorted({c for s in v.sources for c in s.categories})) or "n/a"
        vendors = ", ".join(s.source.value for s in v.sources) or "n/a"
        lines.append(
            f"- {v.indicator} ({v.indicator_type}): score {v.score:.0f}/100, "
            f"malicious={v.malicious}, sources=[{vendors}], categories=[{cats}]"
        )
    return "\n".join(lines)


def _techniques_block(techniques: list[MitreTechnique]) -> str:
    if not techniques:
        return "ATT&CK context: no techniques retrieved. Do not cite any technique IDs."
    lines = ["ATT&CK context (cite these IDs only):"]
    for t in techniques:
        lines.append(f"- {t.id} {t.name} [{t.tactic}]: {t.excerpt}")
    return "\n".join(lines)


def _prompt_for(state: TriageState) -> str:
    alert = state["alert"]
    severity = state.get("severity")
    attack_type = state.get("attack_type")
    header = (
        "Alert under analysis:\n"
        f"- signature: {alert.signature}\n"
        f"- src_ip: {alert.src_ip}:{alert.src_port} -> dst_ip: {alert.dst_ip}:{alert.dst_port}\n"
        f"- protocol: {alert.protocol}\n"
        f"- classified severity: {severity.value if severity else 'unknown'}\n"
        f"- classified attack_type: {attack_type.value if attack_type else 'unknown'}"
    )
    iocs = state.get("iocs") or []
    techniques = state.get("techniques") or []
    return (
        f"{_PROMPT}\n\n{header}\n\n{_iocs_block(iocs)}\n\n{_techniques_block(techniques)}"
    )


async def _complete(state: TriageState, tier: ProviderTier, prompt: str) -> CompletionResult:
    provider = provider_for(state, tier)
    return await provider.complete(
        prompt,
        max_tokens=_MAX_TOKENS,
        temperature=_TEMPERATURE,
        node="reason",  # type: ignore[call-arg]
    )


@traced("reason")
async def reason(state: TriageState, tr: NodeTrace) -> dict[str, Any]:
    prompt = _prompt_for(state)

    try:
        result = await _complete(state, ProviderTier.QUALITY, prompt)
        tr.from_completion(result)
    except Exception as quality_exc:  # noqa: BLE001 — one degraded retry on the fast tier
        log.warning("agent.reason_quality_failed", error=str(quality_exc))
        try:
            result = await _complete(state, ProviderTier.FAST, prompt)
            tr.from_completion(result)
            tr.note = "quality tier failed; narrative served by fast tier (degraded)"
        except Exception as fast_exc:  # noqa: BLE001 — both tiers down
            log.warning("agent.reason_fast_failed", error=str(fast_exc))
            tr.mark_failed(f"reasoning failed on both tiers: {fast_exc}")
            return {"reasoning": None, "errors": [f"reason: {fast_exc}"]}

    reasoning = (result.text or "").strip() or None
    if reasoning is None:
        tr.status = "failed"
        tr.note = "model returned an empty narrative"
        return {"reasoning": None, "errors": ["reason: empty narrative"]}

    return {"reasoning": reasoning}


__all__ = ["reason"]
