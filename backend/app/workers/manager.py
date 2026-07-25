"""WorkerManager — owns the pools, the stats pulse, and graceful shutdown.

Lifecycle:
  start()  launches the triage pool, the enrich pool, and a 2s stats publisher.
  stop()   stops accepting work, drains the queues within a timeout, cancels the
           remaining (idle) tasks, awaits them, and verifies none stay pending —
           an orphaned task after shutdown is a leak.

Supervision: a worker task that dies unexpectedly is logged at error and
restarted, capped at ``worker_restart_cap_per_min`` restarts/minute per pool;
past the cap the pool is marked degraded (surfaced later in /health/deep).
"""

from __future__ import annotations

import asyncio
import time
from collections import deque
from collections.abc import Awaitable, Callable
from typing import Any

from app.config import get_settings
from app.core.bus import get_event_bus
from app.core.logging import get_logger
from app.schemas import StatsUpdatedEvent
from app.store.repositories import AlertRepository
from app.workers import WorkerContext
from app.workers.enrich_worker import enrich_loop
from app.workers.queue import get_queue_registry
from app.workers.triage_worker import triage_loop

log = get_logger(__name__)

LoopFactory = Callable[[], Awaitable[None]]

#: Bounded settle loop for async-generator finalizers on shutdown. Two passes at
#: a second each is far more than the tick or two they actually need, and still
#: cannot turn a wedged finalizer into a hung shutdown.
_SETTLE_PASSES = 2
_SETTLE_TIMEOUT = 1.0


def default_context() -> WorkerContext:
    """Wire a context from the process-wide singletons."""
    registry = get_queue_registry()
    return WorkerContext(
        repo=AlertRepository(),
        bus=get_event_bus(),
        triage_q=registry.get("triage"),
        enrich_q=registry.get("enrich"),
        settings=get_settings(),
    )


class WorkerManager:
    def __init__(self, ctx: WorkerContext | None = None) -> None:
        self.ctx = ctx or default_context()
        s = self.ctx.settings
        self._triage_n = s.triage_worker_concurrency
        self._enrich_n = s.enrich_worker_concurrency
        self._drain_timeout = s.shutdown_drain_seconds
        self._stats_interval = s.stats_publish_interval_seconds
        self._restart_cap = s.worker_restart_cap_per_min

        self._tasks: dict[str, list[asyncio.Task[None]]] = {"triage": [], "enrich": []}
        self._stats_task: asyncio.Task[None] | None = None
        self._restarts: dict[str, deque[float]] = {"triage": deque(), "enrich": deque()}
        self._restart_totals: dict[str, int] = {"triage": 0, "enrich": 0}
        self._degraded = False
        self._stopping = False

    def start(self) -> None:
        self._stopping = False
        self._degraded = False
        self._spawn_pool("triage", self._triage_n, lambda: triage_loop(self.ctx))
        self._spawn_pool("enrich", self._enrich_n, lambda: enrich_loop(self.ctx))
        self._stats_task = asyncio.ensure_future(self._stats_publisher())
        log.info("workers.started", triage=self._triage_n, enrich=self._enrich_n)

    def _spawn_pool(self, pool: str, count: int, factory: LoopFactory) -> None:
        for i in range(count):
            task = asyncio.ensure_future(self._supervise(pool, factory))
            task.set_name(f"{pool}-worker-{i}")
            self._tasks[pool].append(task)

    async def stop(self) -> None:
        """Graceful shutdown: drain, cancel idle tasks, await, verify no leaks."""
        self._stopping = True

        remaining_triage = await self.ctx.triage_q.drain(self._drain_timeout)
        remaining_enrich = await self.ctx.enrich_q.drain(self._drain_timeout)

        all_tasks = [*self._tasks["triage"], *self._tasks["enrich"]]
        if self._stats_task is not None:
            all_tasks.append(self._stats_task)
        for task in all_tasks:
            task.cancel()
        await asyncio.gather(*all_tasks, return_exceptions=True)

        # Let async-generator finalizers finish.
        #
        # A worker cancelled INSIDE the graph's `astream(...)` runs the
        # generator's `aclose()` on the way out, and asyncio schedules that as a
        # separate `async_generator_athrow` task. The worker task is already
        # `done()` at that point, so gathering it above proves nothing about the
        # finalizer — which is still pending, still holds the graph's state, and
        # shows up as an orphan task to anything that looks. Waiting for them
        # here is what makes "zero orphan tasks after stop()" actually true
        # rather than true-if-you-check-late-enough.
        await self._settle_async_generators()

        pending = [t for t in all_tasks if not t.done()]
        dropped = remaining_triage + remaining_enrich
        log.info(
            "workers.stopped",
            dropped_at_shutdown=dropped,
            remaining_triage=remaining_triage,
            remaining_enrich=remaining_enrich,
            pending_tasks=len(pending),
        )
        assert not pending, f"{len(pending)} worker task(s) still pending after stop()"

        self._tasks = {"triage": [], "enrich": []}
        self._stats_task = None

    async def _settle_async_generators(self) -> None:
        """Wait for pending generator finalizers, bounded. Never raises."""
        current = asyncio.current_task()
        for _ in range(_SETTLE_PASSES):
            finalizers = [
                task
                for task in asyncio.all_tasks()
                if task is not current
                and not task.done()
                and "async_generator_athrow" in repr(task.get_coro())
            ]
            if not finalizers:
                return
            await asyncio.wait(finalizers, timeout=_SETTLE_TIMEOUT)
        remaining = [
            task
            for task in asyncio.all_tasks()
            if task is not current
            and not task.done()
            and "async_generator_athrow" in repr(task.get_coro())
        ]
        if remaining:
            log.warning("workers.asyncgen_finalizers_pending", count=len(remaining))

    async def _supervise(self, pool: str, factory: LoopFactory) -> None:
        while not self._stopping:
            try:
                await factory()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 — restart the pool member
                log.error("workers.crashed", pool=pool, error=str(exc))
                if self._stopping or not self._register_restart(pool):
                    self._degraded = True
                    log.error("workers.pool_degraded", pool=pool)
                    return
                await asyncio.sleep(0.05)  # avoid a tight crash-restart spin
                continue
            else:
                return  # a loop only returns cleanly on shutdown

    def _register_restart(self, pool: str) -> bool:
        """Record a restart; return False if the per-minute cap is exceeded."""
        now = time.monotonic()
        window = self._restarts[pool]
        window.append(now)
        while window and now - window[0] > 60.0:
            window.popleft()
        self._restart_totals[pool] += 1
        return len(window) <= self._restart_cap

    async def _stats_publisher(self) -> None:
        while not self._stopping:
            try:
                await asyncio.sleep(self._stats_interval)
            except asyncio.CancelledError:
                raise
            if self._stopping:
                break
            try:
                async with self.ctx.session_factory() as session:
                    stats = await self.ctx.repo.stats(session)
                self.ctx.bus.publish(StatsUpdatedEvent(data=stats))
            except Exception as exc:  # noqa: BLE001 — a stats hiccup must not crash the pool
                log.warning("workers.stats_failed", error=str(exc))

    @property
    def degraded(self) -> bool:
        return self._degraded

    def stats(self) -> dict[str, Any]:
        return {
            "triage": {
                "active": sum(1 for t in self._tasks["triage"] if not t.done()),
                "configured": self._triage_n,
                "restarts": self._restart_totals["triage"],
            },
            "enrich": {
                "active": sum(1 for t in self._tasks["enrich"] if not t.done()),
                "configured": self._enrich_n,
                "restarts": self._restart_totals["enrich"],
            },
            "queues": {
                "triage": self.ctx.triage_q.metrics(),
                "enrich": self.ctx.enrich_q.metrics(),
            },
            "degraded": self._degraded,
        }


__all__ = ["WorkerManager", "default_context"]
