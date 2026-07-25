"""Enrich worker pool — the rate-capped slow path (default concurrency 1).

One task by design: VirusTotal permits ~4 req/min, so extra concurrency here
buys only 429s. Each job resumes the graph from enrich through recommend and
persists + publishes each stage AS IT LANDS (enriched, then reasoned/done) so
the dashboard visibly upgrades cards in place — the progressive fill is the
demo's best moment.

On RateLimitedError a job is requeued exactly ONCE (after a delay); a second hit
finalizes the alert without enrichment and notes it in the trace. A poisoned item
always exits the system — never an infinite requeue.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from app.agent.state import TriageState
from app.api.errors import RateLimitedError
from app.core.logging import bind_request_context, get_logger
from app.schemas import (
    AlertUpdatedEvent,
    Enrichment,
    TraceNode,
)
from app.workers import EnrichJob, WorkerContext
from app.workers.triage_worker import _mark_failed

log = get_logger(__name__)


def _stage_ms(snap: TriageState, node: str) -> int:
    for trace in snap.get("trace", []):
        if trace.node == node:
            return trace.duration_ms
    return 0


async def _publish_updated(ctx: WorkerContext, alert_id: str) -> None:
    async with ctx.session_factory() as session:
        detail = await ctx.repo.get(session, alert_id)
    if detail is not None:
        ctx.bus.publish(AlertUpdatedEvent(data=detail.to_summary()))


async def _persist_enriched(ctx: WorkerContext, alert_id: str, snap: TriageState) -> None:
    iocs = snap.get("iocs") or []
    if not iocs:
        return  # nothing landed to attach; finalize handles the terminal state
    enrichment = Enrichment(
        iocs=iocs, enriched_at=datetime.now(UTC), duration_ms=_stage_ms(snap, "enrich")
    )
    severity = snap.get("severity")
    attack_type = snap.get("attack_type")
    async with ctx.session_factory() as session:
        # persist any enrichment-driven severity upgrade before the enrichment row
        if severity is not None and attack_type is not None:
            await ctx.repo.update_classification(
                session, alert_id, severity, snap.get("confidence") or 0.0, attack_type
            )
        await ctx.repo.attach_enrichment(session, alert_id, enrichment)
        await session.commit()
    await _publish_updated(ctx, alert_id)


async def _persist_remediation(ctx: WorkerContext, alert_id: str, snap: TriageState) -> None:
    remediation = snap.get("remediation")
    if remediation is None:
        return
    async with ctx.session_factory() as session:
        await ctx.repo.attach_remediation(
            session, alert_id, remediation, reasoning=snap.get("reasoning")
        )
        await session.commit()
    await _publish_updated(ctx, alert_id)


async def _finalize_without_enrichment(ctx: WorkerContext, alert_id: str) -> None:
    async with ctx.session_factory() as session:
        await ctx.repo.add_trace(
            session,
            alert_id,
            TraceNode(
                node="enrich",
                status="skipped",
                duration_ms=0,
                note="enrichment skipped: intel rate-limited after one retry",
            ),
        )
        await ctx.repo.mark_done(session, alert_id, None)
        await session.commit()
    await _publish_updated(ctx, alert_id)


async def _handle_rate_limited(job: EnrichJob, ctx: WorkerContext, alert_id: str) -> None:
    if job.attempts == 0:
        job.attempts += 1
        log.info("worker.enrich_requeue", alert_id=alert_id)
        await asyncio.sleep(ctx.settings.enrich_requeue_delay_seconds)
        if not ctx.enrich_q.put(job):  # queue saturated — don't strand it
            await _finalize_without_enrichment(ctx, alert_id)
    else:
        log.info("worker.enrich_give_up", alert_id=alert_id)
        await _finalize_without_enrichment(ctx, alert_id)


async def process_enrich(job: EnrichJob, ctx: WorkerContext) -> None:
    state = job.state
    alert_id = state["alert"].id
    bind_request_context(alert_id=alert_id)

    persisted = len(state.get("trace", []))  # classify trace already in the DB
    final_snap: TriageState | None = None
    try:
        async for snap in ctx.resume_fn(state, config=ctx.graph_config):
            final_snap = snap
            new_traces = snap.get("trace", [])[persisted:]
            if new_traces:
                async with ctx.session_factory() as session:
                    for trace in new_traces:
                        await ctx.repo.add_trace(session, alert_id, trace)
                    await session.commit()
                persisted = len(snap.get("trace", []))

            last_node = new_traces[-1].node if new_traces else None
            if last_node == "enrich":
                await _persist_enriched(ctx, alert_id, snap)
            elif last_node == "recommend":
                await _persist_remediation(ctx, alert_id, snap)

        total = final_snap.get("total_duration_ms") if final_snap else None
        async with ctx.session_factory() as session:
            await ctx.repo.mark_done(session, alert_id, total)
            await session.commit()
        await _publish_updated(ctx, alert_id)
    except RateLimitedError:
        await _handle_rate_limited(job, ctx, alert_id)
    except Exception as exc:  # noqa: BLE001 — never let one alert kill the worker
        log.error("worker.enrich_failed", alert_id=alert_id, error=str(exc))
        await _mark_failed(ctx, alert_id)


async def enrich_loop(ctx: WorkerContext) -> None:
    """Consume ``enrich_q`` forever; exits only on cancellation."""
    while True:
        job = await ctx.enrich_q.get()
        try:
            await process_enrich(job, ctx)
        finally:
            ctx.enrich_q.task_done()


__all__ = ["process_enrich", "enrich_loop"]
