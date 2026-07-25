"""Scratch acceptance demo — 300 alerts at 10 eps through the worker pools.

Fully offline: the graph's LLM/intel leaves are stubbed (heuristic classify, a
deliberately slow enrich to simulate the VT rate cap), but the WorkerManager,
dual queues, bus, backpressure, and graceful shutdown are the REAL Phase-9 code.

Shows: triage keeps up (triage_q stays near empty), enrich_q backlog grows while
input outruns the rate-capped single enrich worker and then drains once input
stops, and shutdown is clean with zero orphan tasks.

Usage: python scripts/worker_demo.py
"""

from __future__ import annotations

import asyncio
import tempfile
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import event, func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.agent.state import TriageState
from app.config import get_settings
from app.core.bus import EventBus
from app.schemas import AlertStatus, AttackType, NormalizedAlert, Severity, TraceNode
from app.store import models
from app.store.repositories import AlertRepository
from app.workers import WorkerContext
from app.workers.manager import WorkerManager
from app.workers.queue import BoundedQueue

TOTAL = 300
EPS = 10
ENRICH_SECONDS = 0.25  # simulated rate-capped enrichment (single worker => ~4/s)


# --------------------------------------------------------------------------- stubs


async def stub_classify(
    alert: NormalizedAlert, config: Any = None, stop_after: Any = None
) -> TriageState:
    # ~55% route to enrich (high/medium), ~45% finalize on the fast path (info)
    idx = int(alert.id.rsplit("-", 1)[-1])
    if idx % 20 == 0:
        severity, attack = Severity.CRITICAL, AttackType.MALWARE_C2
    elif idx % 2 == 0:
        severity, attack = Severity.HIGH, AttackType.BRUTE_FORCE
    else:
        severity, attack = Severity.INFO, AttackType.BENIGN
    return {
        "alert": alert,
        "severity": severity,
        "confidence": 0.85,
        "attack_type": attack,
        "status": AlertStatus.CLASSIFIED,
        "trace": [TraceNode(node="classify", status="ok", duration_ms=1)],
        "errors": [],
        "config": {},
        "started_at": time.monotonic(),
    }


async def stub_resume(state: TriageState, config: Any = None) -> AsyncIterator[TriageState]:
    base = state["trace"]
    await asyncio.sleep(ENRICH_SECONDS)  # the deliberate rate cap
    yield {
        **state,
        "trace": [*base, TraceNode(node="enrich", status="ok", duration_ms=1)],
        "iocs": [],
        "status": AlertStatus.ENRICHED,
    }
    yield {
        **state,
        "trace": [
            *base,
            TraceNode(node="enrich", status="ok", duration_ms=1),
            TraceNode(node="recommend", status="ok", duration_ms=1),
        ],
        "status": AlertStatus.REASONED,
        "total_duration_ms": 5,
    }


# --------------------------------------------------------------------------- db


def _alert(i: int) -> NormalizedAlert:
    return NormalizedAlert(
        id=f"demo-alert-{i}",
        timestamp=datetime(2026, 7, 25, 14, 0, tzinfo=UTC),
        source="suricata",
        signature=f"ET SIG {i}",
        src_ip="45.13.2.99",
        dst_ip="10.0.0.5",
        dst_port=22,
        protocol="TCP",
    )


@asynccontextmanager
async def _make_db() -> AsyncIterator[Any]:
    path = Path(tempfile.mkdtemp()) / "worker_demo.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{path.as_posix()}")

    @event.listens_for(engine.sync_engine, "connect")
    def _pragmas(dbapi_conn: Any, _rec: Any) -> None:
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA synchronous=OFF")
        cur.execute("PRAGMA foreign_keys=ON")
        cur.execute("PRAGMA busy_timeout=5000")
        cur.close()

    async with engine.begin() as conn:
        await conn.run_sync(models.Base.metadata.create_all)
    maker = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

    @asynccontextmanager
    async def factory() -> AsyncIterator[AsyncSession]:
        async with maker() as session:
            yield session

    try:
        yield factory
    finally:
        await engine.dispose()


async def _terminal_count(factory: Any) -> int:
    async with factory() as session:
        rows = await session.execute(
            select(func.count(models.Alert.id)).where(
                models.Alert.status.in_([AlertStatus.DONE.value, AlertStatus.FAILED.value])
            )
        )
        return int(rows.scalar_one())


# --------------------------------------------------------------------------- run


async def main() -> None:
    baseline_tasks = asyncio.all_tasks()

    async with _make_db() as factory:
        settings = get_settings().model_copy(
            update={
                "triage_worker_concurrency": 2,
                "enrich_worker_concurrency": 1,
                "shutdown_drain_seconds": 15.0,
                "stats_publish_interval_seconds": 1.0,
            }
        )
        bus = EventBus(maxsize=500)
        triage_q = BoundedQueue("triage", settings.triage_queue_maxsize)
        enrich_q = BoundedQueue("enrich", settings.enrich_queue_maxsize)
        ctx = WorkerContext(
            repo=AlertRepository(),
            bus=bus,
            triage_q=triage_q,
            enrich_q=enrich_q,
            settings=settings,
            session_factory=factory,
            classify_fn=stub_classify,
            resume_fn=stub_resume,
        )

        # count published events off the bus (proves the transport seam works)
        events = {"new": 0, "updated": 0}
        sub = bus.subscribe()

        async def drain_bus() -> None:
            async for event_obj in sub:
                name = getattr(event_obj, "event", "")
                if name == "alert.new":
                    events["new"] += 1
                elif name == "alert.updated":
                    events["updated"] += 1

        bus_task = asyncio.ensure_future(drain_bus())

        manager = WorkerManager(ctx)
        manager.start()

        interval = 1.0 / EPS
        cap = 1 / ENRICH_SECONDS
        print(f"\nReplaying {TOTAL} alerts at {EPS} eps (enrich capped ~{cap:.0f}/s)\n")
        print(f"{'t(s)':>5} {'triage_q':>9} {'enrich_q':>9} {'done+fail':>10} {'rejected':>9}")
        print("-" * 48)

        start = time.monotonic()

        async def producer() -> None:
            nxt = time.monotonic()
            for i in range(TOTAL):
                triage_q.put(_alert(i))
                nxt += interval
                await asyncio.sleep(max(0.0, nxt - time.monotonic()))

        prod = asyncio.ensure_future(producer())

        async def report() -> None:
            done = await _terminal_count(factory)
            rej = triage_q.metrics()["rejected"] + enrich_q.metrics()["rejected"]
            print(
                f"{time.monotonic() - start:5.1f} {triage_q.depth:9d} {enrich_q.depth:9d} "
                f"{done:10d} {rej:9d}"
            )

        # report while producing and while the enrich backlog drains
        while not prod.done() or (await _terminal_count(factory)) < TOTAL:
            await report()
            await asyncio.sleep(1.0)
            if time.monotonic() - start > 120:  # safety valve
                break
        await report()

        await prod
        await manager.stop()

        sub.close()
        bus_task.cancel()
        try:
            await bus_task
        except asyncio.CancelledError:
            pass

        done = await _terminal_count(factory)
        leaked = asyncio.all_tasks() - baseline_tasks
        leaked.discard(asyncio.current_task())

        print("-" * 48)
        print(
            f"\nprocessed {done}/{TOTAL} terminal | events new={events['new']} "
            f"updated={events['updated']}"
        )
        print(f"triage_q metrics: {triage_q.metrics()}")
        print(f"enrich_q metrics: {enrich_q.metrics()}")
        print(f"orphan tasks after stop(): {len(leaked)}")
        assert done == TOTAL, f"lost alerts: {done}/{TOTAL}"
        assert not leaked, f"orphan tasks: {leaked}"
        print("\nOK: triage kept up, enrich backlog drained, clean shutdown, zero orphans.")


if __name__ == "__main__":
    asyncio.run(main())
