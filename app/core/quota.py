"""Daily/hourly/minute quota tracking, persisted so a restart never overruns.

A per-minute rate bucket does not protect a daily budget — AbuseIPDB's 1000/day
would evaporate in an hour. QuotaTracker counts against a window boundary and
persists the counter to the ``quotas`` table. Server-reported remaining quota
(via response headers) always wins over the local count.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.api.errors import RateLimitedError
from app.core.logging import get_logger
from app.store.models import Base

log = get_logger(__name__)

Window = str

_HEADER_KEYS = {
    "minute": ("x-ratelimit-remaining-minute", "x-ratelimit-remaining"),
    "hour": ("x-ratelimit-remaining-hour",),
    "day": ("x-ratelimit-remaining-day", "x-ratelimit-remaining"),
}


class Quota(Base):
    __tablename__ = "quotas"

    name: Mapped[str] = mapped_column(String(64), primary_key=True)
    window: Mapped[str] = mapped_column(String(16), primary_key=True)
    count: Mapped[int] = mapped_column(Integer, default=0)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True))


def _default_now() -> datetime:
    return datetime.now(UTC)


class QuotaTracker:
    def __init__(
        self,
        name: str,
        limit: int,
        window: Window,
        session_factory: Any = None,
        now: Callable[[], datetime] = _default_now,
    ) -> None:
        if window not in ("minute", "hour", "day"):
            raise ValueError(f"invalid window: {window}")
        self.name = name
        self.limit = limit
        self.window = window
        self._now = now
        if session_factory is None:
            from app.store.db import session_scope

            session_factory = session_scope
        self._session_factory = session_factory


    def _window_start(self, dt: datetime) -> datetime:
        if self.window == "minute":
            return dt.replace(second=0, microsecond=0)
        if self.window == "hour":
            return dt.replace(minute=0, second=0, microsecond=0)
        return dt.replace(hour=0, minute=0, second=0, microsecond=0)

    def _window_delta(self) -> timedelta:
        return {
            "minute": timedelta(minutes=1),
            "hour": timedelta(hours=1),
            "day": timedelta(days=1),
        }[self.window]

    def resets_at(self) -> datetime:
        return self._window_start(self._now()) + self._window_delta()


    async def _load_or_reset(self, session: Any, ws: datetime) -> Quota:
        row = await session.get(Quota, (self.name, self.window))
        if row is None:
            row = Quota(name=self.name, window=self.window, count=0, window_start=ws)
            session.add(row)
        else:
            start = row.window_start
            if start.tzinfo is None:
                start = start.replace(tzinfo=UTC)
            if start != ws:
                row.count = 0
                row.window_start = ws
        return row


    async def consume(self, n: int = 1) -> None:
        ws = self._window_start(self._now())
        async with self._session_factory() as session:
            row = await self._load_or_reset(session, ws)
            if row.count + n > self.limit:
                await session.commit()
                raise RateLimitedError(
                    f"{self.name} {self.window} quota exhausted "
                    f"({row.count}/{self.limit}), resets at {self.resets_at().isoformat()}"
                )
            row.count += n
            await session.commit()

    async def remaining(self) -> int:
        ws = self._window_start(self._now())
        async with self._session_factory() as session:
            row = await session.get(Quota, (self.name, self.window))
            if row is None:
                return self.limit
            start = row.window_start
            if start.tzinfo is None:
                start = start.replace(tzinfo=UTC)
            count = 0 if start != ws else row.count
            return max(self.limit - count, 0)

    async def update_from_headers(self, headers: Any) -> None:
        """Trust server-reported remaining quota over the local count."""
        remaining = self._parse_header(headers)
        if remaining is None:
            return
        ws = self._window_start(self._now())
        new_count = max(self.limit - remaining, 0)
        async with self._session_factory() as session:
            row = await self._load_or_reset(session, ws)
            row.count = new_count
            row.window_start = ws
            await session.commit()

    def _parse_header(self, headers: Any) -> int | None:
        try:
            items = headers.items()
        except AttributeError:
            items = dict(headers).items()
        lowered = {str(k).lower(): v for k, v in items}
        for candidate in _HEADER_KEYS[self.window]:
            if candidate in lowered:
                try:
                    return int(lowered[candidate])
                except (ValueError, TypeError):
                    return None
        return None

    async def snapshot(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "window": self.window,
            "limit": self.limit,
            "remaining": await self.remaining(),
            "resets_at": self.resets_at().isoformat(),
        }
