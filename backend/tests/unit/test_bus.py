"""EventBus — slow-subscriber drop policy, non-blocking publish, clean unsubscribe."""

from __future__ import annotations

import asyncio

import pytest

from app.core.bus import EventBus

pytestmark = pytest.mark.asyncio


async def _next(sub: object, timeout: float = 1.0) -> object:
    return await asyncio.wait_for(sub.__anext__(), timeout)  # type: ignore[attr-defined]


async def test_publish_is_non_blocking_and_fans_out_to_all() -> None:
    bus = EventBus(maxsize=10)
    subs = [bus.subscribe() for _ in range(3)]

    bus.publish("event-1")

    for sub in subs:
        assert await _next(sub) == "event-1"
    assert bus.subscriber_count == 3


async def test_slow_subscriber_drops_oldest_never_blocks() -> None:
    bus = EventBus(maxsize=2)
    sub = bus.subscribe()

    # Publish 3 into a size-2 queue. Publisher must not block; oldest is dropped.
    for i in range(3):
        bus.publish(i)

    assert sub.dropped == 1
    # queue retains the two NEWEST (1, 2); the oldest (0) was evicted
    assert await _next(sub) == 1
    assert await _next(sub) == 2

    stats = bus.stats()
    assert stats["published"] == 3
    assert stats["dropped_total"] == 1


async def test_slow_subscriber_does_not_stall_others() -> None:
    bus = EventBus(maxsize=1)
    slow = bus.subscribe()  # never consumed
    fast = bus.subscribe()

    for i in range(5):
        bus.publish(i)

    # fast subscriber still gets the newest event; slow one just drops
    assert await _next(fast) == 4
    assert slow.dropped == 4


async def test_unsubscribe_leaves_zero_subscribers() -> None:
    bus = EventBus(maxsize=10)

    sub = bus.subscribe()
    assert bus.subscriber_count == 1
    sub.close()
    assert bus.subscriber_count == 0

    async with bus.subscribe() as ctx_sub:
        assert bus.subscriber_count == 1
        bus.publish("x")
        assert await _next(ctx_sub) == "x"
    assert bus.subscriber_count == 0


async def test_close_is_idempotent() -> None:
    bus = EventBus(maxsize=4)
    sub = bus.subscribe()
    sub.close()
    sub.close()
    assert bus.subscriber_count == 0
