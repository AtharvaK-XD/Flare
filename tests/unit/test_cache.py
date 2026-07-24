"""Cache tests — TTL, LRU, single-flight, negative caching, tiered backfill."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.cache import DbBackedCache, InMemoryTTLCache, TieredCache
from app.schemas import IocVerdict

pytestmark = pytest.mark.asyncio


class MC:
    """Manual clock."""

    def __init__(self) -> None:
        self.t = 0.0

    def __call__(self) -> float:
        return self.t


async def test_ttl_expiry() -> None:
    clock = MC()
    c = InMemoryTTLCache(clock=clock)
    await c.set("k", "v", ttl=10)
    clock.t = 5
    assert await c.get("k") == "v"
    clock.t = 11
    assert await c.get("k") is None


async def test_lru_eviction_order() -> None:
    c = InMemoryTTLCache(max_size=2)
    await c.set("a", 1, ttl=100)
    await c.set("b", 2, ttl=100)
    assert await c.get("a") == 1
    await c.set("c", 3, ttl=100)
    assert await c.get("b") is None
    assert await c.get("a") == 1
    assert await c.get("c") == 3
    assert c.stats()["evictions"] == 1


async def test_single_flight_one_factory_call() -> None:
    c = InMemoryTTLCache()
    calls = {"n": 0}

    async def factory() -> str:
        calls["n"] += 1
        await asyncio.sleep(0.01)
        return "value"

    results = await asyncio.gather(
        *[c.get_or_set("k", factory, ttl=10) for _ in range(50)]
    )
    assert calls["n"] == 1
    assert all(r == "value" for r in results)
    assert c.stats()["single_flight_coalesced"] == 49


async def test_factory_exception_propagates_and_not_cached() -> None:
    c = InMemoryTTLCache()
    calls = {"n": 0}

    async def boom() -> str:
        calls["n"] += 1
        await asyncio.sleep(0.01)
        raise ValueError("nope")

    results = await asyncio.gather(
        *[c.get_or_set("k", boom, ttl=10) for _ in range(10)], return_exceptions=True
    )
    assert all(isinstance(r, ValueError) for r in results)
    assert calls["n"] == 1
    assert await c.get("k") is None


async def test_negative_caching_off_by_default() -> None:
    c = InMemoryTTLCache()
    calls = {"n": 0}

    async def boom() -> str:
        calls["n"] += 1
        raise KeyError("404")

    with pytest.raises(KeyError):
        await c.get_or_set("k", boom, ttl=10)
    with pytest.raises(KeyError):
        await c.get_or_set("k", boom, ttl=10)
    assert calls["n"] == 2


async def test_negative_caching_when_enabled() -> None:
    clock = MC()
    c = InMemoryTTLCache(clock=clock)
    calls = {"n": 0}

    async def boom() -> str:
        calls["n"] += 1
        raise KeyError("404")

    with pytest.raises(KeyError):
        await c.get_or_set("k", boom, ttl=10, negative_ttl=30)
    with pytest.raises(KeyError):
        await c.get_or_set("k", boom, ttl=10, negative_ttl=30)
    assert calls["n"] == 1


def _session_factory(engine: Any):
    maker = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

    @asynccontextmanager
    async def factory() -> AsyncIterator[AsyncSession]:
        async with maker() as session:
            yield session

    return factory


async def test_tiered_backfills_memory_from_db(db_engine: Any) -> None:
    mem = InMemoryTTLCache()
    db = DbBackedCache(session_factory=_session_factory(db_engine))
    tier = TieredCache(mem, db)

    verdict = IocVerdict(indicator="8.8.8.8", indicator_type="ip", score=10.0, malicious=False)
    await tier.set("8.8.8.8", verdict, ttl=100)

    await mem.clear()
    got = await tier.get("8.8.8.8")
    assert got is not None
    assert got.indicator == "8.8.8.8"
    assert await mem.get("8.8.8.8") is not None
