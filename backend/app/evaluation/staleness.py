"""Stale-run reaping — what makes POST /run survive a crashed process.

THE BUG THIS EXISTS FOR
-----------------------
Both ``POST /evaluation/run`` and ``POST /benchmark/run`` refuse to start while
another run is in flight (409): two concurrent runs would interleave LLM calls,
blow the rate limits, and produce two sets of numbers nobody can trust. That
guard reads the DB — a row in ``status=running``.

A run that dies with its process (Ctrl-C, OOM, a crash mid-eval) never gets to
write ``completed`` or ``failed``. Its row stays ``running`` forever, and from
then on EVERY POST /run 409s, permanently, with no way out but hand-editing the
database. That is exactly what happened in testing.

THE FIX
-------
A run whose ``started_at`` is older than ``settings.run_stale_timeout_seconds``
is presumed dead and marked ``failed`` with :data:`STALE_RUN_ERROR`. The sweep
runs at startup (so a crash is cleared before the first request) and then
periodically (so a crash mid-session clears itself without a restart), and the
in-flight check consults only rows fresh enough to still be alive.

WHY A TIMEOUT AND NOT A HEARTBEAT: a heartbeat needs the run to keep writing,
which is precisely what a crashed process cannot do. The timeout is deliberately
generous (5 min default) — a 200-alert eval that is genuinely still running keeps
its row fresh because :func:`app.evaluation.runner.run_eval` persists partial
progress every 10%, which touches the row long before the timeout elapses.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any

from app.config import get_settings
from app.core.logging import get_logger
from app.store.db import get_sessionmaker
from app.store.repositories import (
    STALE_RUN_ERROR,
    BenchmarkRunRepository,
    EvalRunRepository,
)

log = get_logger(__name__)


def stale_cutoff(timeout_seconds: float | None = None) -> datetime:
    """The instant before which a ``running`` row is presumed crashed."""
    seconds = (
        timeout_seconds
        if timeout_seconds is not None
        else get_settings().run_stale_timeout_seconds
    )
    return datetime.now(UTC) - timedelta(seconds=seconds)


async def sweep_stale_runs(
    *, session_factory: Any = None, timeout_seconds: float | None = None
) -> dict[str, list[str]]:
    """Reap stale eval AND benchmark runs. Returns the reaped ids per kind."""
    maker = session_factory or get_sessionmaker()
    cutoff = stale_cutoff(timeout_seconds)

    async with maker() as session:
        evals = await EvalRunRepository().reap_stale(session, cutoff)
        benchmarks = await BenchmarkRunRepository().reap_stale(session, cutoff)
        await session.commit()

    if evals or benchmarks:
        log.warning(
            "runs.stale_reaped",
            eval_runs=evals,
            benchmark_runs=benchmarks,
            cutoff=cutoff.isoformat(),
            error=STALE_RUN_ERROR,
            note="a crashed process left these in `running`; they no longer block new runs",
        )
    return {"eval": evals, "benchmark": benchmarks}


class StaleRunSweeper:
    """Periodic sweep, owned by the app lifespan.

    Failures are logged and the loop continues: a DB hiccup during a sweep must
    never take down the pool that keeps the endpoints usable.
    """

    def __init__(self, *, session_factory: Any = None, interval: float | None = None) -> None:
        settings = get_settings()
        self._session_factory = session_factory
        self._interval = (
            interval if interval is not None else settings.run_stale_sweep_interval_seconds
        )
        self._task: asyncio.Task[None] | None = None
        self._stopping = False

    def start(self) -> None:
        self._stopping = False
        self._task = asyncio.ensure_future(self._loop())
        self._task.set_name("stale-run-sweeper")

    async def _loop(self) -> None:
        while not self._stopping:
            try:
                await asyncio.sleep(self._interval)
            except asyncio.CancelledError:
                raise
            if self._stopping:
                break
            try:
                await sweep_stale_runs(session_factory=self._session_factory)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 — a sweep hiccup must not kill the loop
                log.warning("runs.stale_sweep_failed", error=str(exc))

    async def stop(self) -> None:
        self._stopping = True
        if self._task is None:
            return
        self._task.cancel()
        try:
            await self._task
        except asyncio.CancelledError:
            pass
        self._task = None


__all__ = ["StaleRunSweeper", "STALE_RUN_ERROR", "stale_cutoff", "sweep_stale_runs"]
