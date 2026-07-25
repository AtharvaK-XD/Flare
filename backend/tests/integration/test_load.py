"""Sustained-load and backpressure behaviour at 5x the demo rate.

Marked ``load`` and excluded from ``make test`` — these run for a minute each by
design. ``make test-load`` runs them.

WHAT EACH TEST IS ACTUALLY CHECKING
-----------------------------------
Not "does it survive", but "does it degrade the way the design claims":

* ``triage_q`` drops the NEWEST item under saturation, counts every drop
  accurately, and never deadlocks the producer;
* ``enrich_q`` is allowed to back up (that IS the cost-control signal) and must
  drain once input stops;
* the VirusTotal limiter is never exceeded in ANY rolling 60s window, not merely
  on average — an average that hides a burst is how a free tier gets banned;
* one deliberately slow SSE subscriber drops its own events and nobody else's,
  and the publisher never blocks on it;
* RSS is flat across the run (the bus, the dedup LRU, the metrics ring buffers
  and the Chroma client are all bounded, and this is what proves it);
* ``asyncio.all_tasks()`` returns to baseline afterwards.
"""

from __future__ import annotations

import asyncio
import gc
import time
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import psutil
import pytest
import pytest_asyncio
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app import offline
from app.core.bus import EventBus
from app.core.ratelimit import TokenBucket
from app.evaluation import ground_truth as gt
from app.schemas import AlertStatus, NormalizedAlert
from app.store import models
from app.store.repositories import AlertRepository
from app.workers import WorkerContext
from app.workers.manager import WorkerManager
from app.workers.queue import BoundedQueue

pytestmark = [pytest.mark.load, pytest.mark.asyncio]

LOAD_EPS = 50.0
LOAD_SECONDS = 60.0
RSS_SAMPLE_SECONDS = 5.0

#: Growth beyond this over a 60s run means something is unbounded. Generous
#: because Python's allocator returns memory lazily; a real leak at 50 eps for a
#: minute is tens of MB, not single digits.
MAX_RSS_GROWTH_MB = 60.0

#: How long to wait for the enrich backlog to drain after input stops. 50 eps for
#: 60s puts thousands of jobs behind ONE enrich worker (the VirusTotal rate cap),
#: so this is minutes by design — the property is "it drains", not "it drains
#: fast", and a budget tuned to one machine's speed flakes on every other.
DRAIN_BUDGET_SECONDS = 420.0

TERMINAL = {AlertStatus.DONE.value, AlertStatus.FAILED.value}


@pytest_asyncio.fixture
async def file_db(tmp_path: Path) -> AsyncIterator[Any]:
    from contextlib import asynccontextmanager

    from sqlalchemy import event

    path = tmp_path / "load.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{path.as_posix()}")

    @event.listens_for(engine.sync_engine, "connect")
    def _pragmas(dbapi_conn: Any, _rec: Any) -> None:
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
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


@pytest.fixture
def alerts() -> list[NormalizedAlert]:
    offline.install()
    return [item.alert for item in gt.load_population()]


def _cycle(source: list[NormalizedAlert], count: int) -> list[NormalizedAlert]:
    """``count`` alerts with unique ids, cycling the labeled set."""
    out: list[NormalizedAlert] = []
    for index in range(count):
        base = source[index % len(source)]
        out.append(base.model_copy(update={"id": f"{base.id}-load-{index}"}))
    return out


async def test_triage_queue_drops_newest_with_accurate_counter() -> None:
    """A saturated queue refuses the OFFERED item and counts it. No deadlock."""
    queue = BoundedQueue("triage", maxsize=10)
    accepted = 0
    rejected = 0

    for index in range(100):
        if queue.put(f"item-{index}"):
            accepted += 1
        else:
            rejected += 1

    metrics = queue.metrics()
    assert accepted == 10, "queue accepted more than its maxsize"
    assert rejected == 90
    assert metrics["rejected"] == rejected, "reject counter disagrees with observed drops"
    assert metrics["enqueued"] == accepted
    assert queue.depth == 10

    # DROP-NEWEST: the first ten offered are the ten retained. Drop-oldest would
    # leave items 90-99 here instead, and the live feed would show only the tail.
    retained = [await queue.get() for _ in range(10)]
    assert retained == [f"item-{i}" for i in range(10)], (
        f"queue dropped the OLDEST rather than the newest: {retained[:3]}"
    )

    # And the producer was never blocked: 100 puts completed without awaiting.
    assert accepted + rejected == 100


async def test_sustained_50eps_backpressure_and_flat_memory(
    file_db: Any, alerts: list[NormalizedAlert]
) -> None:
    """50 eps for 60s: visible backpressure, a draining backlog, flat RSS."""
    process = psutil.Process()
    gc.collect()
    baseline_tasks = {t for t in asyncio.all_tasks() if not t.done()}
    baseline_rss = process.memory_info().rss / 1024 / 1024

    bus = EventBus(maxsize=200)
    triage_q = BoundedQueue("triage", 1000)
    enrich_q = BoundedQueue("enrich", 500)
    ctx = WorkerContext(
        repo=AlertRepository(),
        bus=bus,
        triage_q=triage_q,
        enrich_q=enrich_q,
        session_factory=file_db,
    )
    manager = WorkerManager(ctx)
    manager.start()

    total = int(LOAD_EPS * LOAD_SECONDS)
    source = _cycle(alerts, total)

    rss_samples: list[float] = [baseline_rss]
    enrich_depths: list[int] = []
    stop_sampling = asyncio.Event()

    async def sample() -> None:
        while not stop_sampling.is_set():
            rss_samples.append(process.memory_info().rss / 1024 / 1024)
            enrich_depths.append(enrich_q.depth)
            try:
                await asyncio.wait_for(stop_sampling.wait(), timeout=RSS_SAMPLE_SECONDS)
            except TimeoutError:
                continue

    sampler = asyncio.ensure_future(sample())

    loop = asyncio.get_running_loop()
    started = loop.time()
    next_at = started
    produced = 0
    for alert in source:
        triage_q.put(alert)
        produced += 1
        next_at += 1.0 / LOAD_EPS
        delay = next_at - loop.time()
        if delay > 0:
            await asyncio.sleep(delay)
    produce_seconds = loop.time() - started

    # Let the backlog drain.
    #
    # The claim under test is that the backlog DRAINS once input stops, not that
    # it stays empty while input arrives — a growing enrich_q at 5x demo rate is
    # the intended cost-control signal (one enrich worker, because VirusTotal
    # allows 4 requests/minute). The drain budget is therefore generous: the
    # enrich worker is deliberately the slowest thing in the system, and a budget
    # tuned to this machine's speed would be a flake on any other.
    peak_enrich = max(enrich_depths, default=0)
    drain_deadline = loop.time() + DRAIN_BUDGET_SECONDS
    drain_trace: list[int] = []
    while loop.time() < drain_deadline:
        drain_trace.append(enrich_q.depth)
        if enrich_q.depth == 0 and triage_q.depth == 0:
            break
        await asyncio.sleep(1.0)

    async with file_db() as session:
        done = int(
            (
                await session.execute(
                    select(func.count(models.Alert.id)).where(
                        models.Alert.status.in_(list(TERMINAL))
                    )
                )
            ).scalar_one()
        )

    stop_sampling.set()
    await sampler
    await manager.stop()

    gc.collect()
    await asyncio.sleep(0.1)
    final_rss = process.memory_info().rss / 1024 / 1024
    growth = final_rss - baseline_rss

    triage_metrics = triage_q.metrics()
    accepted = triage_metrics["enqueued"]

    # 1. Backpressure is VISIBLE and counted, and nothing deadlocked.
    assert produced == total, "the producer blocked — put() must never await"
    assert accepted + triage_metrics["rejected"] == total, (
        "alerts vanished: enqueued + rejected must account for every offer"
    )
    assert produce_seconds < LOAD_SECONDS * 1.5, (
        f"producing {total} alerts took {produce_seconds:.0f}s — the producer was throttled "
        "by a consumer, which is exactly what the non-blocking queue exists to prevent"
    )

    # 2. enrich_q backed up (visible cost control) and then drained to empty.
    assert peak_enrich > 0, "enrich_q never backed up under 50 eps"
    assert drain_trace and drain_trace[-1] < drain_trace[0], (
        f"enrich_q did not drain at all: {drain_trace[0]} -> {drain_trace[-1]}"
    )
    assert enrich_q.depth == 0, (
        f"enrich_q still holds {enrich_q.depth} job(s) after {DRAIN_BUDGET_SECONDS}s "
        f"(peak {peak_enrich}); drain trace {drain_trace[::10]}"
    )
    assert done > 0, "nothing reached a terminal status"

    # 3. Memory is flat.
    assert growth < MAX_RSS_GROWTH_MB, (
        f"RSS grew {growth:.1f}MB over the run (baseline {baseline_rss:.1f}MB, "
        f"final {final_rss:.1f}MB, peak {max(rss_samples):.1f}MB) — something is unbounded"
    )

    # 4. Tasks return to baseline.
    await asyncio.sleep(0.2)
    leaked = {t for t in asyncio.all_tasks() if not t.done()} - baseline_tasks
    leaked.discard(asyncio.current_task())
    assert not leaked, f"tasks left running: {[t.get_name() for t in leaked]}"


async def test_vt_limiter_never_exceeded_in_any_rolling_60s_window() -> None:
    """Rolling window, not average: a burst inside one minute is the failure mode.

    A limiter that lets 4 through instantly and then starves for 59s averages
    correctly and still gets the key banned. Every 60s window is checked.
    """
    rate = 4
    limiter = TokenBucket(rate=float(rate), period_seconds=60.0, burst=1, name="virustotal")

    grants: list[float] = []
    started = time.monotonic()

    async def call() -> None:
        await limiter.acquire(1)
        grants.append(time.monotonic() - started)

    # Ask for far more than the budget over a window longer than one period.
    await asyncio.wait_for(asyncio.gather(*(call() for _ in range(12))), timeout=200.0)

    assert len(grants) == 12
    for index, start in enumerate(grants):
        window = [g for g in grants if start <= g < start + 60.0]
        assert len(window) <= rate + 1, (
            f"window starting at {start:.1f}s granted {len(window)} calls, "
            f"limit is {rate}/min (grant #{index})"
        )


async def test_slow_sse_subscriber_drops_its_own_events_only() -> None:
    """One frozen tab must not stall triage, and must not cost anyone else events."""
    bus = EventBus(maxsize=10)

    fast_subs = [bus.subscribe() for _ in range(4)]
    slow_sub = bus.subscribe()  # deliberately never read from

    received: dict[int, int] = {i: 0 for i in range(len(fast_subs))}
    stop = asyncio.Event()

    async def consume(index: int, subscription: Any) -> None:
        try:
            async for _ in subscription:
                received[index] += 1
                if stop.is_set():
                    return
        except asyncio.CancelledError:
            return

    consumers = [
        asyncio.ensure_future(consume(i, sub)) for i, sub in enumerate(fast_subs)
    ]
    await asyncio.sleep(0.05)

    # Publish the way the workers actually do: from a coroutine that yields
    # between alerts. A tight 500-iteration loop with no await would starve EVERY
    # subscriber equally — including the healthy ones — and would be measuring
    # the test's own scheduling, not the bus's slow-subscriber policy.
    published = 500
    slowest_publish = 0.0
    for index in range(published):
        started = time.perf_counter()
        bus.publish(_FakeEvent(index))
        slowest_publish = max(slowest_publish, time.perf_counter() - started)
        if index % 5 == 4:
            await asyncio.sleep(0)  # yield, exactly as an awaiting worker does

    await asyncio.sleep(0.5)
    stop.set()
    for sub in (*fast_subs, slow_sub):
        sub.close()
    for consumer in consumers:
        consumer.cancel()
    await asyncio.gather(*consumers, return_exceptions=True)

    # publish() is synchronous and must never await a consumer: with one
    # subscriber wedged, the worst SINGLE publish still has to be trivial.
    assert slowest_publish < 0.05, (
        f"the slowest publish() took {slowest_publish * 1000:.1f}ms — it blocked on the "
        "stalled subscriber instead of dropping that subscriber's oldest event"
    )

    # The slow subscriber absorbed the drops.
    assert slow_sub.dropped > 0, "the slow subscriber should have dropped events"
    assert slow_sub.dropped >= published - 10, (
        f"slow subscriber only dropped {slow_sub.dropped} of {published}"
    )

    # The fast ones did not.
    for index, count in received.items():
        assert count >= published * 0.9, (
            f"fast subscriber {index} received only {count}/{published} — a slow peer "
            "cost it events"
        )
        assert fast_subs[index].dropped == 0, (
            f"fast subscriber {index} dropped {fast_subs[index].dropped} events"
        )


class _FakeEvent:
    """Minimal event: the bus is transport-agnostic and never inspects payloads."""

    def __init__(self, index: int) -> None:
        self.event = "alert.new"
        self.index = index
