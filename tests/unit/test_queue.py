"""BoundedQueue — drop-newest backpressure, non-blocking producer, clean drain."""

from __future__ import annotations

import asyncio

import pytest

from app.workers.queue import BoundedQueue, QueueRegistry

pytestmark = pytest.mark.asyncio


async def test_full_queue_drops_newest_and_counts_it() -> None:
    q = BoundedQueue("triage", maxsize=3)

    accepted = [q.put(i) for i in range(5)]

    assert accepted == [True, True, True, False, False]
    assert q.depth == 3
    m = q.metrics()
    assert m["enqueued"] == 3
    assert m["rejected"] == 2

    # the three OLDEST were kept; the two newest (3, 4) were dropped
    got = [await q.get() for _ in range(3)]
    assert got == [0, 1, 2]


async def test_producer_never_blocks() -> None:
    q = BoundedQueue("triage", maxsize=1)
    # 10_000 puts into a size-1 queue must return immediately, never await
    for i in range(10_000):
        q.put(i)
    assert q.depth == 1
    assert q.metrics()["rejected"] == 9_999


async def test_drain_empties_cleanly() -> None:
    q = BoundedQueue("enrich", maxsize=10)
    for i in range(5):
        q.put(i)

    async def consume() -> None:
        for _ in range(5):
            await q.get()
            q.task_done()

    consumer = asyncio.create_task(consume())
    remaining = await q.drain(timeout=1.0)
    await consumer

    assert remaining == 0
    assert q.depth == 0
    assert q.metrics()["dequeued"] == 5


async def test_drain_reports_remaining_on_timeout() -> None:
    q = BoundedQueue("enrich", maxsize=10)
    for i in range(3):
        q.put(i)
    # nothing consumes -> drain times out with items still present
    remaining = await q.drain(timeout=0.1)
    assert remaining == 3


async def test_avg_wait_ms_tracked() -> None:
    q = BoundedQueue("triage", maxsize=10)
    q.put("a")
    await asyncio.sleep(0.03)
    await q.get()
    assert q.metrics()["avg_wait_ms"] > 0


async def test_registry_named_queues() -> None:
    reg = QueueRegistry()
    reg.register("triage", 1000)
    reg.register("enrich", 500)
    assert reg.get("triage").name == "triage"
    assert reg.get("enrich")._maxsize == 500  # type: ignore[attr-defined]
    with pytest.raises(KeyError):
        reg.get("nope")
