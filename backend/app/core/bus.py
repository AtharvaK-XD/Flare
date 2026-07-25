"""In-process async pub/sub — the seam between compute and transport.

The graph and workers publish typed events here and never learn that an HTTP/SSE
connection exists. Every subscriber gets its own bounded queue.

SLOW-SUBSCRIBER POLICY: publishing is non-blocking and never awaits a consumer.
If a subscriber's queue is full (a frozen browser tab), the OLDEST event for that
subscriber is dropped and its drop counter incremented. One stuck consumer must
never stall triage or grow memory without bound.
"""

from __future__ import annotations

import asyncio
from typing import Any

from app.config import get_settings
from app.core.logging import get_logger

log = get_logger(__name__)


class Subscription:
    """A single subscriber's bounded queue, usable as an async iterator/CM.

    Registered with the bus at creation (eagerly, so an event published before
    the first ``__anext__`` is still delivered) and removed on ``close``.
    """

    def __init__(self, bus: EventBus, maxsize: int) -> None:
        self._bus = bus
        self._queue: asyncio.Queue[Any] = asyncio.Queue(maxsize=maxsize)
        self.dropped = 0
        self._closed = False

    def _offer(self, event: Any) -> None:
        """Non-blocking enqueue; drop the oldest event on overflow."""
        try:
            self._queue.put_nowait(event)
            return
        except asyncio.QueueFull:
            pass
        try:
            self._queue.get_nowait()  # evict oldest
        except asyncio.QueueEmpty:  # pragma: no cover - race with a consumer
            pass
        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:  # pragma: no cover - consumer refilled it
            pass
        self.dropped += 1

    def __aiter__(self) -> Subscription:
        return self

    async def __anext__(self) -> Any:
        if self._closed and self._queue.empty():
            raise StopAsyncIteration
        return await self._queue.get()

    async def __aenter__(self) -> Subscription:
        return self

    async def __aexit__(self, *exc: object) -> None:
        self.close()

    async def aclose(self) -> None:
        self.close()

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._bus._remove(self)


class EventBus:
    def __init__(self, maxsize: int | None = None) -> None:
        self._maxsize = maxsize if maxsize is not None else get_settings().event_bus_maxsize
        self._subscribers: set[Subscription] = set()
        self._published = 0

    def publish(self, event: Any) -> None:
        """Fan an event out to every subscriber. Never blocks, never awaits."""
        self._published += 1
        for sub in list(self._subscribers):
            sub._offer(event)

    def subscribe(self) -> Subscription:
        """Register and return a per-subscriber async-iterator queue."""
        sub = Subscription(self, self._maxsize)
        self._subscribers.add(sub)
        return sub

    def _remove(self, sub: Subscription) -> None:
        self._subscribers.discard(sub)

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)

    def stats(self) -> dict[str, Any]:
        return {
            "subscribers": len(self._subscribers),
            "published": self._published,
            "dropped_by_subscriber": [s.dropped for s in self._subscribers],
            "dropped_total": sum(s.dropped for s in self._subscribers),
        }


_bus: EventBus | None = None


def get_event_bus() -> EventBus:
    """Process-wide bus singleton (workers publish, routes subscribe)."""
    global _bus
    if _bus is None:
        _bus = EventBus()
    return _bus


def reset_event_bus() -> None:
    """Test helper — drop the singleton so a fresh bus is built next call."""
    global _bus
    _bus = None


__all__ = ["EventBus", "Subscription", "get_event_bus", "reset_event_bus"]
