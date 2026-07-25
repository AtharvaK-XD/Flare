"""Bounded work queues with backpressure metrics.

Two named queues split the pipeline — the core architectural claim of the
project:

    triage_q  (1000)  high-throughput, keeps the live feed responsive
    enrich_q  (500)   rate-capped downstream (VirusTotal is 4 req/min)

``put`` NEVER blocks the producer. When a queue is full it DROPS THE NEWEST item
(the one being offered) and counts it — replay outrunning triage degrades
throughput, it does not deadlock the emitter. Backlog on ``enrich_q`` is the
expected, visible cost-control signal, not a bug.
"""

from __future__ import annotations

import asyncio
import time
from collections import deque
from typing import Any

from app.config import get_settings
from app.core.logging import get_logger

log = get_logger(__name__)

_WAIT_SAMPLES = 1000


class BoundedQueue:
    def __init__(self, name: str, maxsize: int) -> None:
        self.name = name
        self._maxsize = maxsize
        self._q: asyncio.Queue[tuple[float, Any]] = asyncio.Queue(maxsize=maxsize)
        self._enqueued = 0
        self._dequeued = 0
        self._rejected = 0
        self._waits: deque[float] = deque(maxlen=_WAIT_SAMPLES)

    def put(self, item: Any, block: bool = False) -> bool:
        """Enqueue without blocking. Returns False (and counts a reject) if full.

        ``block`` exists for signature completeness; producers in this system are
        never allowed to block, so a full queue always drops the newest item.
        """
        try:
            self._q.put_nowait((time.monotonic(), item))
            self._enqueued += 1
            return True
        except asyncio.QueueFull:
            self._rejected += 1
            log.debug("queue.rejected", queue=self.name, depth=self._q.qsize())
            return False

    async def get(self) -> Any:
        """Await the next item (FIFO), recording its queue-wait latency."""
        enqueued_at, item = await self._q.get()
        self._dequeued += 1
        self._waits.append((time.monotonic() - enqueued_at) * 1000.0)
        return item

    def task_done(self) -> None:
        self._q.task_done()

    @property
    def depth(self) -> int:
        return self._q.qsize()

    def empty(self) -> bool:
        return self._q.empty()

    async def drain(self, timeout: float) -> int:
        """Wait until empty or ``timeout`` elapses. Returns the remaining depth."""
        deadline = time.monotonic() + timeout
        while not self._q.empty() and time.monotonic() < deadline:
            await asyncio.sleep(0.02)
        return self._q.qsize()

    def metrics(self) -> dict[str, Any]:
        waits = list(self._waits)
        avg_wait = sum(waits) / len(waits) if waits else 0.0
        return {
            "name": self.name,
            "depth": self.depth,
            "maxsize": self._maxsize,
            "enqueued": self._enqueued,
            "dequeued": self._dequeued,
            "rejected": self._rejected,
            "avg_wait_ms": round(avg_wait, 2),
        }


class QueueRegistry:
    def __init__(self) -> None:
        self._queues: dict[str, BoundedQueue] = {}

    def register(self, name: str, maxsize: int) -> BoundedQueue:
        q = BoundedQueue(name, maxsize)
        self._queues[name] = q
        return q

    def get(self, name: str) -> BoundedQueue:
        if name not in self._queues:
            raise KeyError(f"no queue named {name!r}")
        return self._queues[name]

    def all(self) -> dict[str, BoundedQueue]:
        return dict(self._queues)

    def metrics(self) -> dict[str, dict[str, Any]]:
        return {name: q.metrics() for name, q in self._queues.items()}


_registry: QueueRegistry | None = None


def get_queue_registry() -> QueueRegistry:
    """Process-wide registry with the two named queues sized from settings."""
    global _registry
    if _registry is None:
        settings = get_settings()
        reg = QueueRegistry()
        reg.register("triage", settings.triage_queue_maxsize)
        reg.register("enrich", settings.enrich_queue_maxsize)
        _registry = reg
    return _registry


def reset_queue_registry() -> None:
    """Test helper — drop the singleton so fresh queues are built next call."""
    global _registry
    _registry = None


__all__ = [
    "BoundedQueue",
    "QueueRegistry",
    "get_queue_registry",
    "reset_queue_registry",
]
