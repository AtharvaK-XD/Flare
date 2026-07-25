"""Replay control (§5) — the dashboard's play/pause bar.

Illegal transitions (resume while idle, start while already running) are 409 with
a message naming the current state, never a 500 and never a silent no-op.

Every state change republishes ``replay.status`` on the bus so every connected
dashboard's transport bar updates without polling. ``queue_depth`` is filled from
the live queues here — the engine itself is dependency-inverted and knows nothing
about them.
"""

from __future__ import annotations

from fastapi import APIRouter

from app.api.errors import ConflictError
from app.core.logging import get_logger
from app.deps import BusDep, EnrichQueueDep, ReplayDep, TriageQueueDep
from app.ingestion.replay import ReplayEngine
from app.schemas import FlareModel
from app.schemas.events import ReplayState, ReplayStatus, ReplayStatusEvent
from app.workers.queue import BoundedQueue

log = get_logger(__name__)

router = APIRouter(prefix="/replay", tags=["replay"])


class ReplayStartRequest(FlareModel):
    dataset: str = "cicids2017"
    events_per_second: float | None = None
    limit: int | None = None


def _status(engine: ReplayEngine, triage_q: BoundedQueue, enrich_q: BoundedQueue) -> ReplayStatus:
    """Engine status plus the live queue depths the contract requires."""
    status = engine.status()
    return status.model_copy(
        update={"queue_depth": {"triage": triage_q.depth, "enrich": enrich_q.depth}}
    )


def _publish(bus: object, status: ReplayStatus) -> None:
    bus.publish(ReplayStatusEvent(data=status))  # type: ignore[attr-defined]


@router.post("/start", response_model=ReplayStatus)
async def start_replay(
    body: ReplayStartRequest,
    engine: ReplayDep,
    bus: BusDep,
    triage_q: TriageQueueDep,
    enrich_q: EnrichQueueDep,
) -> ReplayStatus:
    state = engine.status().state
    if state == ReplayState.RUNNING:
        raise ConflictError("replay is already running — pause or stop it first")

    # NotFoundError (unknown dataset / missing file) propagates as a 404 envelope.
    await engine.start(
        body.dataset, events_per_second=body.events_per_second, limit=body.limit
    )
    status = _status(engine, triage_q, enrich_q)
    _publish(bus, status)
    log.info("replay.started", dataset=body.dataset, eps=body.events_per_second)
    return status


@router.post("/pause", response_model=ReplayStatus)
async def pause_replay(
    engine: ReplayDep,
    bus: BusDep,
    triage_q: TriageQueueDep,
    enrich_q: EnrichQueueDep,
) -> ReplayStatus:
    state = engine.status().state
    if state != ReplayState.RUNNING:
        raise ConflictError(f"cannot pause replay while it is {state.value}")
    engine.pause()
    status = _status(engine, triage_q, enrich_q)
    _publish(bus, status)
    return status


@router.post("/resume", response_model=ReplayStatus)
async def resume_replay(
    engine: ReplayDep,
    bus: BusDep,
    triage_q: TriageQueueDep,
    enrich_q: EnrichQueueDep,
) -> ReplayStatus:
    state = engine.status().state
    if state != ReplayState.PAUSED:
        raise ConflictError(f"cannot resume replay while it is {state.value}")
    engine.resume()
    status = _status(engine, triage_q, enrich_q)
    _publish(bus, status)
    return status


@router.post("/stop", response_model=ReplayStatus)
async def stop_replay(
    engine: ReplayDep,
    bus: BusDep,
    triage_q: TriageQueueDep,
    enrich_q: EnrichQueueDep,
) -> ReplayStatus:
    state = engine.status().state
    if state == ReplayState.IDLE:
        raise ConflictError("replay is idle — nothing to stop")
    await engine.stop()
    status = _status(engine, triage_q, enrich_q)
    _publish(bus, status)
    return status


@router.get("/status", response_model=ReplayStatus)
async def replay_status(
    engine: ReplayDep,
    triage_q: TriageQueueDep,
    enrich_q: EnrichQueueDep,
) -> ReplayStatus:
    return _status(engine, triage_q, enrich_q)


__all__ = ["router", "ReplayStartRequest"]
