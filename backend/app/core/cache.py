"""Async TTL caches with single-flight (stampede prevention).

``get_or_set`` guarantees that N concurrent misses on the same key trigger
exactly ONE factory call — the others await the same future. Without this, 20
alerts from one attacker IP would fire 20 VirusTotal calls at once and burn the
quota in a second. That coalescing is the most important thing in this module.
"""

from __future__ import annotations

import asyncio
import heapq
import time
from collections import OrderedDict
from collections.abc import Awaitable, Callable
from typing import Any, Protocol, runtime_checkable

from app.core.logging import get_logger

log = get_logger(__name__)

Clock = Callable[[], float]


@runtime_checkable
class AsyncTTLCache(Protocol):
    async def get(self, key: str) -> Any | None: ...
    async def set(self, key: str, value: Any, ttl: float) -> None: ...
    async def delete(self, key: str) -> None: ...
    async def clear(self) -> None: ...
    def stats(self) -> dict[str, Any]: ...


class _CacheBase:
    """Shared counters + single-flight ``get_or_set`` (uses self.get/self.set)."""

    def __init__(self, clock: Clock = time.monotonic) -> None:
        self._clock = clock
        self._hits = 0
        self._misses = 0
        self._evictions = 0
        self._coalesced = 0
        self._inflight: dict[str, asyncio.Future] = {}
        self._negatives: dict[str, tuple[BaseException, float]] = {}

    async def get_or_set(
        self,
        key: str,
        factory: Callable[[], Awaitable[Any]],
        ttl: float,
        negative_ttl: float | None = None,
    ) -> Any:
        cached = await self.get(key)  # type: ignore[attr-defined]
        if cached is not None:
            return cached

        neg = self._negatives.get(key)
        if neg is not None:
            exc, expires = neg
            if self._clock() < expires:
                raise exc
            del self._negatives[key]

        inflight = self._inflight.get(key)
        if inflight is not None:
            self._coalesced += 1
            return await inflight

        loop = asyncio.get_running_loop()
        fut: asyncio.Future = loop.create_future()
        self._inflight[key] = fut
        try:
            try:
                result = await factory()
            except BaseException as exc:  # noqa: BLE001 — propagated to all waiters via fut
                if negative_ttl is not None:
                    self._negatives[key] = (exc, self._clock() + negative_ttl)
                fut.set_exception(exc)
            else:
                await self.set(key, result, ttl)  # type: ignore[attr-defined]
                fut.set_result(result)
        finally:
            self._inflight.pop(key, None)
        return await fut

    def _base_stats(self) -> dict[str, Any]:
        total = self._hits + self._misses
        return {
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": round(self._hits / total, 4) if total else 0.0,
            "evictions": self._evictions,
            "single_flight_coalesced": self._coalesced,
        }


_SWEEP_LIMIT = 50


class InMemoryTTLCache(_CacheBase):
    def __init__(self, max_size: int = 5000, clock: Clock = time.monotonic) -> None:
        super().__init__(clock=clock)
        self._max_size = max_size
        self._store: OrderedDict[str, tuple[Any, float]] = OrderedDict()
        self._expiry_heap: list[tuple[float, str]] = []

    async def get(self, key: str) -> Any | None:
        entry = self._store.get(key)
        if entry is None:
            self._misses += 1
            return None
        value, expires = entry
        if self._clock() >= expires:
            del self._store[key]
            self._misses += 1
            return None
        self._store.move_to_end(key)
        self._hits += 1
        return value

    def _sweep(self) -> None:
        now = self._clock()
        removed = 0
        while self._expiry_heap and removed < _SWEEP_LIMIT and self._expiry_heap[0][0] <= now:
            _, key = heapq.heappop(self._expiry_heap)
            entry = self._store.get(key)
            if entry is not None and entry[1] <= now:
                del self._store[key]
                removed += 1

    async def set(self, key: str, value: Any, ttl: float) -> None:
        self._sweep()
        expires = self._clock() + ttl
        self._store[key] = (value, expires)
        self._store.move_to_end(key)
        heapq.heappush(self._expiry_heap, (expires, key))
        while len(self._store) > self._max_size:
            self._store.popitem(last=False)
            self._evictions += 1

    async def delete(self, key: str) -> None:
        self._store.pop(key, None)

    async def clear(self) -> None:
        self._store.clear()
        self._expiry_heap.clear()

    def stats(self) -> dict[str, Any]:
        return {**self._base_stats(), "size": len(self._store)}


class DbBackedCache(_CacheBase):
    """Cross-restart cache for IOC verdicts, keyed by indicator."""

    def __init__(self, session_factory: Any = None, clock: Clock = time.monotonic) -> None:
        super().__init__(clock=clock)
        if session_factory is None:
            from app.store.db import session_scope

            session_factory = session_scope
        self._session_factory = session_factory
        from app.store.repositories import IocCacheRepository

        self._repo = IocCacheRepository()

    async def get(self, key: str) -> Any | None:
        async with self._session_factory() as session:
            verdict = await self._repo.get(session, key)
        if verdict is None:
            self._misses += 1
            return None
        self._hits += 1
        return verdict

    async def set(self, key: str, value: Any, ttl: float) -> None:
        async with self._session_factory() as session:
            await self._repo.put(session, value, int(ttl))
            await session.commit()

    async def delete(self, key: str) -> None:
        from sqlalchemy import delete as sa_delete

        from app.store import models

        async with self._session_factory() as session:
            await session.execute(
                sa_delete(models.IocCache).where(models.IocCache.indicator == key)
            )
            await session.commit()

    async def clear(self) -> None:
        from sqlalchemy import delete as sa_delete

        from app.store import models

        async with self._session_factory() as session:
            await session.execute(sa_delete(models.IocCache))
            await session.commit()

    def stats(self) -> dict[str, Any]:
        return {**self._base_stats(), "size": -1}


class TieredCache(_CacheBase):
    """Read memory → fall through to db → backfill memory on hit."""

    def __init__(
        self,
        memory: InMemoryTTLCache,
        db: DbBackedCache,
        backfill_ttl: float = 3600.0,
        clock: Clock = time.monotonic,
    ) -> None:
        super().__init__(clock=clock)
        self._memory = memory
        self._db = db
        self._backfill_ttl = backfill_ttl

    async def get(self, key: str) -> Any | None:
        value = await self._memory.get(key)
        if value is not None:
            self._hits += 1
            return value
        value = await self._db.get(key)
        if value is not None:
            await self._memory.set(key, value, self._backfill_ttl)
            self._hits += 1
            return value
        self._misses += 1
        return None

    async def set(self, key: str, value: Any, ttl: float) -> None:
        await self._memory.set(key, value, ttl)
        await self._db.set(key, value, ttl)

    async def delete(self, key: str) -> None:
        await self._memory.delete(key)
        await self._db.delete(key)

    async def clear(self) -> None:
        await self._memory.clear()
        await self._db.clear()

    def stats(self) -> dict[str, Any]:
        return {
            **self._base_stats(),
            "memory": self._memory.stats(),
            "db": self._db.stats(),
        }
