"""retrieve node — attack-type-filtered MITRE ATT&CK lookup for grounding.

Feeds the reason/recommend stages with real technique text so their citations
are grounded rather than invented. An empty result is a valid outcome (the
retriever degrades silently on a missing/empty index) — the pipeline continues
with ``techniques=[]``.
"""

from __future__ import annotations

from typing import Any

from app.agent.state import TriageState, retriever_for
from app.agent.trace import NodeTrace, traced
from app.core.logging import get_logger
from app.schemas import AttackType

log = get_logger(__name__)

_RETRIEVE_K = 4


@traced("retrieve")
async def retrieve(state: TriageState, tr: NodeTrace) -> dict[str, Any]:
    alert = state["alert"]
    attack_type = state.get("attack_type")
    at_label = attack_type.value if isinstance(attack_type, AttackType) else ""
    query = f"{alert.signature} {at_label}".strip()

    try:
        retriever = retriever_for(state)
        techniques = await retriever.retrieve(query, attack_type, k=_RETRIEVE_K)
    except Exception as exc:  # noqa: BLE001 — degrade, never raise out of a node
        log.warning("agent.retrieve_failed", error=str(exc))
        tr.mark_failed(f"retrieval failed: {exc}")
        return {"techniques": [], "errors": [f"retrieve: {exc}"]}

    if not techniques:
        tr.note = "no matching ATT&CK techniques"
    else:
        tr.note = "retrieved " + ", ".join(t.id for t in techniques)
    return {"techniques": techniques}


__all__ = ["retrieve"]
