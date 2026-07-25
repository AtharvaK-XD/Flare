"""Evaluation routes (§5) — the judge-facing accuracy panel.

``POST /run`` answers 202 immediately and does the work in a detached task: a
200-alert eval takes minutes and must never hold a request open. Only one run may
be in flight at a time (409 otherwise) — concurrent runs would interleave LLM
calls, blow the rate limits, and produce two sets of numbers nobody can trust.

The frontend polls ``GET /runs/{id}`` every 2s while ``status=running``, so that
handler is a single indexed primary-key read and nothing else. The runner
persists partial metrics as it goes, so a poll during a run returns a real
(clearly still-``running``) report rather than an empty shell.
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter
from pydantic import Field

from app.api.errors import BadRequestError, ConflictError, NotFoundError
from app.config import get_settings
from app.core.logging import get_logger
from app.deps import BusDep, EvalRepoDep, SessionDep
from app.evaluation.runner import run_eval
from app.evaluation.staleness import stale_cutoff
from app.schemas import FlareModel, OverallMetrics
from app.schemas.evaluation import EvalRunDetail, RunStatus

log = get_logger(__name__)

router = APIRouter(prefix="/evaluation", tags=["evaluation"])

# Guards the check-then-create window: two POSTs arriving in the same tick must
# not both pass the "nothing running" test.
_launch_lock = asyncio.Lock()

# create_task keeps only a weak reference; without this the eval can be garbage
# collected mid-run.
_tasks: set[asyncio.Task[EvalRunDetail]] = set()


class EvalRunRequest(FlareModel):
    sample_size: Annotated[int | None, Field(ge=1)] = None


class EvalRunAccepted(FlareModel):
    run_id: str
    status: RunStatus


class EvalRunSummary(FlareModel):
    """List-view projection — no confusion matrix, no per-class rows."""

    run_id: str
    status: RunStatus
    sample_size: int
    started_at: datetime | None = None
    completed_at: datetime | None = None
    overall: OverallMetrics | None = None
    error: str | None = None


@router.post("/run", status_code=202, response_model=EvalRunAccepted)
async def start_evaluation(
    body: EvalRunRequest,
    session: SessionDep,
    repo: EvalRepoDep,
    bus: BusDep,
) -> EvalRunAccepted:
    settings = get_settings()
    sample_size = body.sample_size or settings.eval_sample_size
    if sample_size > settings.eval_max_sample_size:
        # 400 for a refused value, 409 for a state conflict — same split as the
        # benchmark panel.
        raise BadRequestError(
            f"sample_size {sample_size} exceeds the cap of "
            f"{settings.eval_max_sample_size}; re-run with a smaller sample"
        )

    async with _launch_lock:
        # Reap first, then check. Without this a run killed with its process
        # leaves a `running` row that 409s every future request forever — the
        # in-flight guard must only see runs that could still be alive.
        cutoff = stale_cutoff()
        reaped = await repo.reap_stale(session, cutoff)
        active = await repo.active_run_id(session, cutoff)
        if active is not None:
            raise ConflictError(
                f"evaluation run {active} is already in flight — "
                "wait for it to finish before starting another"
            )
        if reaped:
            log.warning("eval.stale_runs_reaped", run_ids=reaped)
        detail = await repo.create(session, sample_size=sample_size)
        await session.commit()

    task = asyncio.create_task(run_eval(detail.run_id, sample_size, bus=bus))
    _tasks.add(task)
    task.add_done_callback(_tasks.discard)

    log.info("eval.run_started", run_id=detail.run_id, sample_size=sample_size)
    return EvalRunAccepted(run_id=detail.run_id, status="running")


@router.get("/runs", response_model=list[EvalRunSummary])
async def list_evaluation_runs(
    session: SessionDep, repo: EvalRepoDep
) -> list[EvalRunSummary]:
    """Past runs, newest first."""
    runs = await repo.list(session)
    return [
        EvalRunSummary(
            run_id=r.run_id,
            status=r.status,
            sample_size=r.sample_size,
            started_at=r.started_at,
            completed_at=r.completed_at,
            overall=r.overall,
            error=r.error,
        )
        for r in runs
    ]


@router.get("/runs/{run_id}", response_model=EvalRunDetail)
async def get_evaluation_run(
    run_id: str, session: SessionDep, repo: EvalRepoDep
) -> EvalRunDetail:
    detail = await repo.get(session, run_id)
    if detail is None:
        raise NotFoundError(f"evaluation run not found: {run_id}")
    return detail


__all__ = ["router", "EvalRunAccepted", "EvalRunRequest", "EvalRunSummary"]
