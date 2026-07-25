"""Worker integration — stubbed graph + in-memory DB, zero network.

Covers: throughput without loss/dup, enrich concurrency=1, per-alert exception
isolation, graceful mid-flight shutdown, rate-limit requeue-once, and no task
leaks after stop().
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from datetime import UTC, datetime
from typing import Any

import pytest
import pytest_asyncio
from sqlalchemy import event, func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.api.errors import RateLimitedError
from app.config import get_settings
from app.core.bus import EventBus
from app.schemas import (
    AlertStatus,
    AttackType,
    NormalizedAlert,
    Severity,
    TraceNode,
)
from app.store import models
from app.store.repositories import AlertRepository
from app.workers import EnrichJob, WorkerContext
from app.workers.enrich_worker import process_enrich
from app.workers.manager import WorkerManager
from app.workers.queue import BoundedQueue

pytestmark = pytest.mark.asyncio

SessionFactory = Callable[[], AbstractAsyncContextManager[AsyncSession]]


@pytest_asyncio.fixture
async def session_factory(tmp_path: Any) -> AsyncIterator[SessionFactory]:
    # A temp FILE db (WAL) so concurrent worker tasks each get their own
    # connection — mirrors production, unlike the shared single-connection
    # in-memory db used elsewhere.
    url = f"sqlite+aiosqlite:///{(tmp_path / 'workers.db').as_posix()}"
    engine = create_async_engine(url)

    @event.listens_for(engine.sync_engine, "connect")
    def _pragmas(dbapi_conn: Any, _rec: Any) -> None:
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA synchronous=OFF")  # ephemeral test db — skip fsync per commit
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

    yield factory
    await engine.dispose()


def _settings(**over: Any) -> Any:
    return get_settings().model_copy(
        update={
            # SQLite serializes writes, so extra worker concurrency only thrashes
            # the WAL lock; 1 is fastest here. (Prod's split is about not blocking
            # the live feed, not DB parallelism.)
            "triage_worker_concurrency": 1,
            "enrich_worker_concurrency": 1,
            "shutdown_drain_seconds": 3.0,
            "stats_publish_interval_seconds": 30.0,  # idle during tests; avoids DB contention
            "enrich_requeue_delay_seconds": 0.0,
            **over,
        }
    )


def _alert(i: int) -> NormalizedAlert:
    return NormalizedAlert(
        id=f"alert-{i}",
        timestamp=datetime(2026, 7, 25, tzinfo=UTC),
        source="suricata",
        signature=f"sig-{i}",
        src_ip="45.13.2.99",
        dst_ip="10.0.0.5",
        dst_port=22,
        protocol="TCP",
        extracted_iocs=["45.13.2.99"],
    )


def _classified_state(alert: NormalizedAlert, severity: Severity) -> dict[str, Any]:
    return {
        "alert": alert,
        "severity": severity,
        "confidence": 0.9,
        "attack_type": AttackType.BRUTE_FORCE,
        "status": AlertStatus.CLASSIFIED,
        "trace": [TraceNode(node="classify", status="ok", duration_ms=1)],
        "errors": [],
        "config": {},
        "started_at": time.monotonic(),
    }


def _make_classify(severity: Severity, *, boom_ids: set[str] | None = None) -> Callable[..., Any]:
    boom = boom_ids or set()

    async def classify(alert: NormalizedAlert, config: Any = None, stop_after: Any = None) -> Any:
        if alert.id in boom:
            raise RuntimeError("classifier exploded")
        return _classified_state(alert, severity)

    return classify


def _ctx(
    session_factory: SessionFactory,
    *,
    classify_fn: Callable[..., Any],
    resume_fn: Callable[..., Any] | None = None,
    settings: Any = None,
) -> WorkerContext:
    return WorkerContext(
        repo=AlertRepository(),
        bus=EventBus(maxsize=1000),
        triage_q=BoundedQueue("triage", 2000),
        enrich_q=BoundedQueue("enrich", 1000),
        settings=settings or _settings(),
        session_factory=session_factory,
        classify_fn=classify_fn,
        resume_fn=resume_fn or _noop_resume,
    )


async def _noop_resume(state: dict[str, Any], config: Any = None) -> AsyncIterator[dict[str, Any]]:
    yield {
        **state,
        "trace": [*state["trace"], TraceNode(node="enrich", status="ok", duration_ms=1)],
        "iocs": [],
        "status": AlertStatus.ENRICHED,
        "total_duration_ms": 5,
    }


async def _count(session_factory: SessionFactory) -> int:
    async with session_factory() as session:
        return (await session.execute(select(func.count(models.Alert.id)))).scalar_one()


async def _status_counts(session_factory: SessionFactory) -> dict[str, int]:
    async with session_factory() as session:
        rows = await session.execute(
            select(models.Alert.status, func.count()).group_by(models.Alert.status)
        )
        return {str(k): int(v) for k, v in rows.all()}


async def _until(cond: Callable[[], Any], timeout: float = 10.0) -> None:
    started = time.monotonic()
    deadline = started + timeout
    while time.monotonic() < deadline:
        if await cond():
            return
        # 50ms, not 20ms: the poll is itself a GROUP BY on the same SQLite file,
        # so a tight loop steals write throughput from the workers under test.
        await asyncio.sleep(0.05)
    raise AssertionError(f"condition not met within {timeout}s")


async def test_200_alerts_none_lost_none_duplicated(session_factory: SessionFactory) -> None:
    # INFO severity -> triage finalizes each on the fast path (no enrich pool needed)
    ctx = _ctx(session_factory, classify_fn=_make_classify(Severity.INFO))
    manager = WorkerManager(ctx)
    manager.start()
    try:
        for i in range(200):
            assert ctx.triage_q.put(_alert(i))
        # Generous budget on purpose: this test asserts CORRECTNESS (nothing lost,
        # nothing duplicated), not speed. 200 alerts x ~5 committed transactions
        # each is inherently ~20s on SQLite, so a tight bound would make it an
        # accidental performance benchmark that flaps on a busy machine.
        await _until(lambda: _terminal_eq(session_factory, 200), timeout=90)
    finally:
        await manager.stop()

    assert await _count(session_factory) == 200
    # every alert reached a terminal state; none duplicated (unique PK) or lost
    counts = await _status_counts(session_factory)
    assert counts.get(AlertStatus.DONE.value, 0) == 200


async def test_worker_exception_does_not_stop_the_rest(session_factory: SessionFactory) -> None:
    boom = {"alert-3", "alert-7"}
    ctx = _ctx(session_factory, classify_fn=_make_classify(Severity.INFO, boom_ids=boom))
    manager = WorkerManager(ctx)
    manager.start()
    try:
        for i in range(10):
            assert ctx.triage_q.put(_alert(i))
        await _until(lambda: _terminal_eq(session_factory, 10), timeout=10)
    finally:
        await manager.stop()

    counts = await _status_counts(session_factory)
    assert counts.get(AlertStatus.FAILED.value, 0) == 2  # the two boom alerts
    assert counts.get(AlertStatus.DONE.value, 0) == 8  # the rest processed fine


async def test_enrich_concurrency_one_never_overlaps(session_factory: SessionFactory) -> None:
    active = 0
    max_active = 0

    async def tracking_resume(
        state: dict[str, Any], config: Any = None
    ) -> AsyncIterator[dict[str, Any]]:
        nonlocal active, max_active
        active += 1
        max_active = max(max_active, active)
        try:
            await asyncio.sleep(0.02)
            yield {
                **state,
                "trace": [*state["trace"], TraceNode(node="enrich", status="ok", duration_ms=1)],
                "iocs": [],
                "status": AlertStatus.ENRICHED,
                "total_duration_ms": 3,
            }
        finally:
            active -= 1

    ctx = _ctx(
        session_factory,
        classify_fn=_make_classify(Severity.HIGH),  # HIGH -> routes to enrich_q
        resume_fn=tracking_resume,
        settings=_settings(triage_worker_concurrency=4, enrich_worker_concurrency=1),
    )
    manager = WorkerManager(ctx)
    manager.start()
    try:
        for i in range(20):
            assert ctx.triage_q.put(_alert(i))
        await _until(
            lambda: _status_has(session_factory, AlertStatus.DONE.value, 20), timeout=15
        )
    finally:
        await manager.stop()

    assert max_active == 1  # single enrich worker never runs two jobs at once


async def _status_has(session_factory: SessionFactory, status: str, n: int) -> bool:
    counts = await _status_counts(session_factory)
    return counts.get(status, 0) >= n


async def _terminal_eq(session_factory: SessionFactory, n: int) -> bool:
    """True once ``n`` alerts have reached a terminal state (done or failed)."""
    counts = await _status_counts(session_factory)
    return counts.get(AlertStatus.DONE.value, 0) + counts.get(AlertStatus.FAILED.value, 0) == n


async def test_graceful_shutdown_no_half_written_rows(session_factory: SessionFactory) -> None:
    async def slow_resume(
        state: dict[str, Any], config: Any = None
    ) -> AsyncIterator[dict[str, Any]]:
        await asyncio.sleep(0.2)
        yield {
            **state,
            "trace": [*state["trace"], TraceNode(node="enrich", status="ok", duration_ms=1)],
            "iocs": [],
            "status": AlertStatus.ENRICHED,
            "total_duration_ms": 3,
        }

    ctx = _ctx(
        session_factory,
        classify_fn=_make_classify(Severity.HIGH),
        resume_fn=slow_resume,
        settings=_settings(triage_worker_concurrency=2, enrich_worker_concurrency=1),
    )
    manager = WorkerManager(ctx)
    manager.start()
    for i in range(15):
        ctx.triage_q.put(_alert(i))
    await asyncio.sleep(0.1)  # stop mid-flight, work still in progress
    await manager.stop()  # asserts internally that no task stays pending

    # every persisted row is in a VALID terminal-or-intermediate state — never
    # a corrupt/partial row (each DB write is its own committed transaction)
    valid = {s.value for s in AlertStatus}
    async with session_factory() as session:
        rows = (await session.execute(select(models.Alert))).scalars().all()
    for row in rows:
        assert row.status in valid
        if row.remediation is not None:  # remediation implies enrichment stage passed
            assert row.status in {AlertStatus.REASONED.value, AlertStatus.DONE.value}


async def test_rate_limited_requeues_once_then_finalizes(session_factory: SessionFactory) -> None:
    async def rl_resume(state: dict[str, Any], config: Any = None) -> AsyncIterator[dict[str, Any]]:
        raise RateLimitedError("VT quota exhausted")
        yield  # pragma: no cover - marks this an async generator

    ctx = _ctx(session_factory, classify_fn=_make_classify(Severity.HIGH), resume_fn=rl_resume)

    alert = _alert(1)
    async with session_factory() as session:
        await ctx.repo.create(session, alert)
        await ctx.repo.update_classification(
            session, alert.id, Severity.HIGH, 0.9, AttackType.BRUTE_FORCE
        )
        await session.commit()

    job = EnrichJob(state=_classified_state(alert, Severity.HIGH))

    # attempt 0: rate-limited -> requeued exactly once (attempts bumped to 1)
    await process_enrich(job, ctx)
    assert ctx.enrich_q.depth == 1
    requeued = await ctx.enrich_q.get()
    assert requeued.attempts == 1

    # attempt 1: rate-limited again -> finalize without enrichment, no third try
    await process_enrich(requeued, ctx)
    assert ctx.enrich_q.depth == 0

    async with session_factory() as session:
        detail = await ctx.repo.get(session, alert.id)
    assert detail is not None
    assert detail.status == AlertStatus.DONE
    assert detail.enrichment is None
    notes = " ".join(t.note or "" for t in detail.trace)
    assert "rate-limited" in notes


async def test_no_task_leaks_after_stop(session_factory: SessionFactory) -> None:
    before = asyncio.all_tasks()
    ctx = _ctx(session_factory, classify_fn=_make_classify(Severity.INFO))
    manager = WorkerManager(ctx)
    manager.start()
    for i in range(5):
        ctx.triage_q.put(_alert(i))
    await asyncio.sleep(0.1)
    await manager.stop()

    leaked = asyncio.all_tasks() - before
    leaked.discard(asyncio.current_task())  # the test's own task
    assert not leaked, f"leaked tasks: {leaked}"
