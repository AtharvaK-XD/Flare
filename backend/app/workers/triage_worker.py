"""Triage worker pool — the fast path that keeps the live feed responsive.

Each task consumes ``triage_q``: persist the ingested alert, run only the
classify stage of the graph (``stop_after="classify"`` — no enrichment on the
fast path), persist + publish ``alert.new``, then either hand off to ``enrich_q``
or finalize immediately for low-severity alerts.

One alert's failure must never kill the task: every exception is caught, logged
with the alert id, the alert is marked ``failed``, and the loop continues.
"""

from __future__ import annotations

from app.agent.graph import finalize
from app.agent.router import route_after_classify
from app.agent.state import TriageState
from app.core.logging import bind_request_context, get_logger
from app.schemas import (
    AlertNewEvent,
    AlertStatus,
    AlertUpdatedEvent,
    AttackType,
    NormalizedAlert,
    Severity,
)
from app.workers import EnrichJob, WorkerContext

log = get_logger(__name__)


async def _publish_summary(ctx: WorkerContext, alert_id: str, new: bool) -> None:
    async with ctx.session_factory() as session:
        detail = await ctx.repo.get(session, alert_id)
    if detail is None:  # pragma: no cover - row must exist here
        return
    summary = detail.to_summary()
    event = AlertNewEvent(data=summary) if new else AlertUpdatedEvent(data=summary)
    ctx.bus.publish(event)


async def _finalize_now(ctx: WorkerContext, alert_id: str, state: TriageState) -> None:
    """Low-severity path: run the graph's finalize, persist skips + done."""
    fin = await finalize(state)
    async with ctx.session_factory() as session:
        for trace in fin.get("trace", []):
            await ctx.repo.add_trace(session, alert_id, trace)
        await ctx.repo.mark_done(session, alert_id, fin.get("total_duration_ms"))
        await session.commit()
    await _publish_summary(ctx, alert_id, new=False)


async def process_triage(alert: NormalizedAlert, ctx: WorkerContext) -> None:
    alert_id = alert.id
    bind_request_context(alert_id=alert_id)
    try:
        async with ctx.session_factory() as session:
            await ctx.repo.create(session, alert)
            await session.commit()

        # classify only — the fast path never drags enrichment along
        state = await ctx.classify_fn(alert, config=ctx.graph_config, stop_after="classify")
        severity = state.get("severity") or Severity.MEDIUM
        confidence = state.get("confidence") or 0.0
        attack_type = state.get("attack_type") or AttackType.UNKNOWN

        async with ctx.session_factory() as session:
            await ctx.repo.update_classification(
                session, alert_id, severity, confidence, attack_type
            )
            for trace in state.get("trace", []):
                await ctx.repo.add_trace(session, alert_id, trace)
            await session.commit()
        await _publish_summary(ctx, alert_id, new=True)

        if route_after_classify(state) == "enrich":
            if not ctx.enrich_q.put(EnrichJob(state=state)):
                # enrich_q saturated — don't strand the alert, finalize it
                log.warning("worker.enrich_q_full", alert_id=alert_id)
                await _finalize_now(ctx, alert_id, state)
        else:
            await _finalize_now(ctx, alert_id, state)
    except Exception as exc:  # noqa: BLE001 — never let one alert kill the worker
        log.error("worker.triage_failed", alert_id=alert_id, error=str(exc))
        await _mark_failed(ctx, alert_id)


async def _mark_failed(ctx: WorkerContext, alert_id: str) -> None:
    try:
        async with ctx.session_factory() as session:
            await ctx.repo.set_status(session, alert_id, AlertStatus.FAILED)
            await session.commit()
    except Exception as exc:  # noqa: BLE001 - best-effort; already in an error path
        log.error("worker.mark_failed_failed", alert_id=alert_id, error=str(exc))


async def triage_loop(ctx: WorkerContext) -> None:
    """Consume ``triage_q`` forever; exits only on cancellation."""
    while True:
        alert = await ctx.triage_q.get()
        try:
            await process_triage(alert, ctx)
        finally:
            ctx.triage_q.task_done()


__all__ = ["process_triage", "triage_loop"]
