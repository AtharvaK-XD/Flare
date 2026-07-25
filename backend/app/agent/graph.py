"""The compiled triage graph and its wall-clock-bounded runner.

Isolation contract (load-bearing): this module imports NO db, NO event bus, NO
queue, and NO FastAPI. It takes a ``NormalizedAlert`` and returns a
``TriageState``. That is what lets Phase 9 wire workers around it and Phase 11
replay eval traffic through the identical code path without a rewrite.

The graph is compiled once (``build_graph`` memoizes) and reused for every alert.
There is deliberately no checkpointer — triage is stateless per alert — but the
node/edge structure is checkpointer-ready, so one can be added later without
touching a single node.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator
from typing import Any, cast

from langgraph.graph import END, StateGraph

from app.agent.nodes import classify, enrich, reason, recommend, retrieve
from app.agent.router import (
    route_after_classify,
    route_after_enrich,
    route_after_reason,
)
from app.agent.state import PIPELINE_NODES, TriageState
from app.config import get_settings
from app.core.logging import get_logger
from app.schemas import AlertStatus, NormalizedAlert, Severity, TraceNode

log = get_logger(__name__)


def _skip_reason(node: str, state: TriageState) -> str:
    """Human-readable 'why didn't this run' for a bypassed node (frontend-facing)."""
    severity = state.get("severity")
    sev = severity.value if isinstance(severity, Severity) else "unknown"
    score = state.get("max_ioc_score")

    if node == "classify":
        return "classification did not run"
    if node == "enrich":
        return f"enrichment skipped: severity '{sev}' did not qualify for IOC lookup"
    if node == "retrieve":
        detail = f"severity '{sev}'"
        if score is not None:
            detail += f", worst IOC score {score}"
        return f"retrieval skipped: {detail} below the reasoning threshold"
    if node == "reason":
        return "reasoning skipped: alert did not reach the analysis stage"
    if node == "recommend":
        if not (state.get("reasoning") or "").strip():
            return "remediation skipped: no analysis narrative was produced"
        return "remediation skipped: alert did not reach the remediation stage"
    return "node skipped"


async def finalize(state: TriageState) -> dict[str, Any]:
    """Terminal node: stamp done, backfill skipped traces, normalize severity.

    Not a pipeline node — it emits no TraceNode of its own (``finalize`` is not a
    valid trace node literal). Instead it synthesizes a ``skipped`` entry for
    every pipeline node that never ran, each with a human-readable reason.
    """
    ran = {t.node for t in state.get("trace", [])}
    skipped = [
        TraceNode(
            node=node,  # type: ignore[arg-type]
            status="skipped",
            duration_ms=0,
            note=_skip_reason(node, state),
        )
        for node in PIPELINE_NODES
        if node not in ran
    ]

    severity = state.get("severity")
    if not isinstance(severity, Severity):
        severity = Severity.MEDIUM

    started_at = state.get("started_at")
    total_duration_ms = (
        int((time.monotonic() - started_at) * 1000) if started_at is not None else None
    )

    out: dict[str, Any] = {
        "status": AlertStatus.DONE,
        "severity": severity,
        "total_duration_ms": total_duration_ms,
    }
    if skipped:
        out["trace"] = skipped
    return out


_compiled: Any = None
_compiled_enrich: Any = None


def _add_pipeline_nodes(graph: StateGraph, names: tuple[str, ...]) -> None:
    # The @traced-wrapped nodes carry an alias type LangGraph's overloads don't
    # structurally recognize; runtime accepts these plain coroutine callables.
    fns = {
        "classify": classify,
        "enrich": enrich,
        "retrieve": retrieve,
        "reason": reason,
        "recommend": recommend,
    }
    for name in names:
        graph.add_node(name, fns[name])  # type: ignore[call-overload]
    graph.add_node("finalize", finalize)


def build_graph() -> Any:
    """Compile the full triage graph once; subsequent calls return the same object."""
    global _compiled
    if _compiled is not None:
        return _compiled

    graph = StateGraph(TriageState)
    _add_pipeline_nodes(graph, ("classify", "enrich", "retrieve", "reason", "recommend"))

    graph.set_entry_point("classify")
    graph.add_conditional_edges(
        "classify", route_after_classify, {"enrich": "enrich", "finalize": "finalize"}
    )
    graph.add_conditional_edges(
        "enrich", route_after_enrich, {"retrieve": "retrieve", "finalize": "finalize"}
    )
    graph.add_edge("retrieve", "reason")
    graph.add_conditional_edges(
        "reason", route_after_reason, {"recommend": "recommend", "finalize": "finalize"}
    )
    graph.add_edge("recommend", "finalize")
    graph.add_edge("finalize", END)

    _compiled = graph.compile()
    return _compiled


def build_enrich_graph() -> Any:
    """Compile the enrich-onward subgraph (entry = enrich) for worker resume.

    Nodes are pure functions of state, so resuming = invoking this subgraph with
    the state the classify stage produced. No checkpointer needed; the same nodes
    and routers back both graphs.
    """
    global _compiled_enrich
    if _compiled_enrich is not None:
        return _compiled_enrich

    graph = StateGraph(TriageState)
    _add_pipeline_nodes(graph, ("enrich", "retrieve", "reason", "recommend"))

    graph.set_entry_point("enrich")
    graph.add_conditional_edges(
        "enrich", route_after_enrich, {"retrieve": "retrieve", "finalize": "finalize"}
    )
    graph.add_edge("retrieve", "reason")
    graph.add_conditional_edges(
        "reason", route_after_reason, {"recommend": "recommend", "finalize": "finalize"}
    )
    graph.add_edge("recommend", "finalize")
    graph.add_edge("finalize", END)

    _compiled_enrich = graph.compile()
    return _compiled_enrich


def _initial_state(
    alert: NormalizedAlert, config: dict[str, Any] | None, started_at: float
) -> TriageState:
    return {
        "alert": alert,
        "trace": [],
        "errors": [],
        "status": AlertStatus.INGESTED,
        "started_at": started_at,
        "config": config or {},
    }


def _ran(snapshot: TriageState, node: str) -> bool:
    return any(t.node == node for t in snapshot.get("trace", []))


async def run_triage(
    alert: NormalizedAlert,
    config: dict[str, Any] | None = None,
    stop_after: str | None = None,
) -> TriageState:
    """Run one alert through the graph under a total wall-clock budget.

    ``stop_after`` halts streaming once the named node has run and returns the
    (non-finalized) state — the triage worker uses ``stop_after="classify"`` to
    classify without dragging enrichment onto the fast path. With ``stop_after``
    unset the graph runs to ``finalize``.

    On budget exhaustion the partially-accumulated state is returned with
    ``status=done`` and a timeout error appended — a hung alert must never block a
    worker forever. State is streamed so the partial reflects completed nodes.
    """
    graph = build_graph()
    started_at = time.monotonic()
    initial = _initial_state(alert, config, started_at)
    budget = get_settings().triage_timeout_seconds

    last: TriageState = cast(TriageState, dict(initial))

    async def _drive() -> TriageState:
        nonlocal last
        stream = graph.astream(initial, stream_mode="values")
        try:
            async for snapshot in stream:
                last = cast(TriageState, snapshot)
                if stop_after is not None and _ran(last, stop_after):
                    break
        finally:
            await stream.aclose()
        return last

    try:
        return await asyncio.wait_for(_drive(), timeout=budget)
    except TimeoutError:
        partial: TriageState = cast(TriageState, dict(last))
        errors = list(partial.get("errors") or [])
        errors.append(f"triage exceeded {budget}s wall-clock budget")
        partial["errors"] = errors
        partial["status"] = AlertStatus.DONE
        partial["total_duration_ms"] = int((time.monotonic() - started_at) * 1000)
        log.warning("agent.triage_timeout", alert_id=getattr(alert, "id", None), budget=budget)
        return partial


async def stream_resume(
    state: TriageState, config: dict[str, Any] | None = None
) -> AsyncIterator[TriageState]:
    """Resume the pipeline from enrich, yielding the full state after each node.

    Feeds the enrich worker: it persists and publishes each stage as it lands
    (enriched, then reasoned/done), giving the dashboard its progressive fill.
    """
    graph = build_enrich_graph()
    initial: dict[str, Any] = dict(state)
    initial["config"] = config if config is not None else (state.get("config") or {})
    if initial.get("started_at") is None:
        initial["started_at"] = time.monotonic()

    stream = graph.astream(initial, stream_mode="values")
    try:
        async for snapshot in stream:
            yield cast(TriageState, snapshot)
    finally:
        await stream.aclose()


__all__ = [
    "build_graph",
    "build_enrich_graph",
    "run_triage",
    "stream_resume",
    "finalize",
]
