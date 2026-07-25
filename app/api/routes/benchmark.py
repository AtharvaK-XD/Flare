"""Benchmark routes (§5) — fast tier vs quality tier, side by side.

Same lifecycle as the eval panel: 202 + detached task, one run at a time, cheap
polling reads. A sample size over the cap is refused with a message that explains
the arithmetic (every alert is run through BOTH tiers), never silently truncated
into a smaller run than the caller asked for.
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter
from pydantic import Field

from app.api.errors import ConflictError, NotFoundError
from app.config import get_settings
from app.core.logging import get_logger
from app.deps import BenchmarkRepoDep, BusDep, SessionDep
from app.evaluation.benchmark import check_sample_size, run_benchmark
from app.evaluation.staleness import stale_cutoff
from app.schemas import FlareModel
from app.schemas.evaluation import BenchmarkRunDetail, RunStatus

log = get_logger(__name__)

router = APIRouter(prefix="/benchmark", tags=["benchmark"])

_launch_lock = asyncio.Lock()
_tasks: set[asyncio.Task[BenchmarkRunDetail]] = set()


class BenchmarkRunRequest(FlareModel):
    sample_size: Annotated[int | None, Field(ge=1)] = None


class BenchmarkRunAccepted(FlareModel):
    run_id: str
    status: RunStatus


class BenchmarkRunSummary(FlareModel):
    """List-view projection — no per-tier rows, no disagreement examples."""

    run_id: str
    status: RunStatus
    sample_size: int
    started_at: datetime | None = None
    completed_at: datetime | None = None
    agreement_rate: float | None = None
    error: str | None = None


@router.post("/run", status_code=202, response_model=BenchmarkRunAccepted)
async def start_benchmark(
    body: BenchmarkRunRequest,
    session: SessionDep,
    repo: BenchmarkRepoDep,
    bus: BusDep,
) -> BenchmarkRunAccepted:
    # Validate BEFORE opening a row: a rejected request must not leave a run
    # behind that blocks the next one.
    sample_size = check_sample_size(body.sample_size or get_settings().benchmark_sample_size)

    async with _launch_lock:
        # Same crash-recovery rule as the eval panel: reap presumed-dead runs
        # before the in-flight check, or a killed process 409s this endpoint
        # permanently. See app/evaluation/staleness.py.
        cutoff = stale_cutoff()
        reaped = await repo.reap_stale(session, cutoff)
        active = await repo.active_run_id(session, cutoff)
        if active is not None:
            raise ConflictError(
                f"benchmark run {active} is already in flight — "
                "wait for it to finish before starting another"
            )
        if reaped:
            log.warning("benchmark.stale_runs_reaped", run_ids=reaped)
        detail = await repo.create(session, sample_size=sample_size)
        await session.commit()

    task = asyncio.create_task(run_benchmark(detail.run_id, sample_size, bus=bus))
    _tasks.add(task)
    task.add_done_callback(_tasks.discard)

    log.info("benchmark.run_started", run_id=detail.run_id, sample_size=sample_size)
    return BenchmarkRunAccepted(run_id=detail.run_id, status="running")


@router.get("/runs", response_model=list[BenchmarkRunSummary])
async def list_benchmark_runs(
    session: SessionDep, repo: BenchmarkRepoDep
) -> list[BenchmarkRunSummary]:
    """Past runs, newest first."""
    runs = await repo.list(session)
    return [
        BenchmarkRunSummary(
            run_id=r.run_id,
            status=r.status,
            sample_size=r.sample_size,
            started_at=r.started_at,
            completed_at=r.completed_at,
            agreement_rate=r.agreement_rate,
            error=r.error,
        )
        for r in runs
    ]


@router.get("/runs/{run_id}", response_model=BenchmarkRunDetail)
async def get_benchmark_run(
    run_id: str, session: SessionDep, repo: BenchmarkRepoDep
) -> BenchmarkRunDetail:
    detail = await repo.get(session, run_id)
    if detail is None:
        raise NotFoundError(f"benchmark run not found: {run_id}")
    return detail


__all__ = [
    "router",
    "BenchmarkRunAccepted",
    "BenchmarkRunRequest",
    "BenchmarkRunSummary",
]
