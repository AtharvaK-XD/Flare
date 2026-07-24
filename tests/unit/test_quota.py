"""Quota tests — day rollover, persisted restart, header override."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.api.errors import RateLimitedError
from app.core.quota import QuotaTracker

pytestmark = pytest.mark.asyncio


def _session_factory(engine: Any):
    maker = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

    @asynccontextmanager
    async def factory() -> AsyncIterator[AsyncSession]:
        async with maker() as session:
            yield session

    return factory


async def test_day_rollover_resets(db_engine: Any) -> None:
    now = {"v": datetime(2026, 1, 1, 10, 0, tzinfo=UTC)}
    qt = QuotaTracker(
        "abuseipdb", limit=3, window="day",
        session_factory=_session_factory(db_engine), now=lambda: now["v"],
    )
    await qt.consume(1)
    await qt.consume(1)
    await qt.consume(1)
    assert await qt.remaining() == 0
    with pytest.raises(RateLimitedError):
        await qt.consume(1)

    now["v"] = datetime(2026, 1, 2, 0, 0, tzinfo=UTC)
    await qt.consume(1)
    assert await qt.remaining() == 2


async def test_restart_reloads_persisted_count(db_engine: Any) -> None:
    now = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
    factory = _session_factory(db_engine)
    qt1 = QuotaTracker("vt", limit=5, window="day", session_factory=factory, now=lambda: now)
    await qt1.consume(2)

    qt2 = QuotaTracker("vt", limit=5, window="day", session_factory=factory, now=lambda: now)
    assert await qt2.remaining() == 3


async def test_header_override_wins(db_engine: Any) -> None:
    now = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
    qt = QuotaTracker(
        "abuseipdb", limit=100, window="day",
        session_factory=_session_factory(db_engine), now=lambda: now,
    )
    await qt.consume(1)
    assert await qt.remaining() == 99
    await qt.update_from_headers({"X-RateLimit-Remaining": "10"})
    assert await qt.remaining() == 10


async def test_minute_window_rollover(db_engine: Any) -> None:
    now = {"v": datetime(2026, 1, 1, 12, 30, 15, tzinfo=UTC)}
    qt = QuotaTracker(
        "svc", limit=2, window="minute",
        session_factory=_session_factory(db_engine), now=lambda: now["v"],
    )
    await qt.consume(1)
    await qt.consume(1)
    with pytest.raises(RateLimitedError):
        await qt.consume(1)
    now["v"] = datetime(2026, 1, 1, 12, 31, 0, tzinfo=UTC)
    await qt.consume(1)
    assert await qt.remaining() == 1
