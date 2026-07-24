"""Async token-bucket rate limiter — fair, monotonic, cancellation-safe.

Refill is computed lazily from ``time.monotonic()`` deltas (no background task,
no wall clock). Waiters queue FIFO through explicit futures so a late small
request can never jump an earlier one. A cancelled/timed-out waiter returns any
tokens it was granted and wakes the next waiter.
"""

from __future__ import annotations

import asyncio
import time
from collections import deque
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from functools import wraps
from typing import Any, TypeVar

from app.api.errors import RateLimitedError
from app.config import get_settings
from app.core.logging import get_logger

log = get_logger(__name__)

T = TypeVar("T")

Clock = Callable[[], float]
Sleeper = Callable[[float], Awaitable[None]]

_EPS = 1e-9


@dataclass
class _Waiter:
    tokens: float
    future: asyncio.Future
    enqueued: float
    granted: bool = False


def _percentile(samples: list[float], pct: float) -> float:
    if not samples:
        return 0.0
    ordered = sorted(samples)
    idx = min(len(ordered) - 1, int(round((pct / 100.0) * (len(ordered) - 1))))
    return ordered[idx]


class TokenBucket:
    def __init__(
        self,
        rate: float,
        period_seconds: float,
        burst: float | None = None,
        name: str = "bucket",
        clock: Clock = time.monotonic,
        sleep: Sleeper = asyncio.sleep,
    ) -> None:
        if rate <= 0 or period_seconds <= 0:
            raise ValueError("rate and period_seconds must be positive")
        self.name = name
        self._fill_rate = rate / period_seconds
        self._capacity = float(burst if burst is not None else rate)
        self._available = self._capacity
        self._clock = clock
        self._sleep = sleep
        self._last = clock()
        self._waiters: deque[_Waiter] = deque()
        self._dispatcher: asyncio.Task | None = None
        self._acquired_total = 0
        self._rejected_total = 0
        self._wait_samples: deque[float] = deque(maxlen=1000)


    def _refill(self) -> None:
        now = self._clock()
        delta = now - self._last
        if delta > 0:
            self._available = min(self._capacity, self._available + delta * self._fill_rate)
            self._last = now

    def _drain(self) -> None:
        self._refill()
        while self._waiters:
            w = self._waiters[0]
            if w.future.done():
                self._waiters.popleft()
                continue
            if self._available + _EPS >= w.tokens:
                self._waiters.popleft()
                self._available = max(0.0, self._available - w.tokens)
                w.granted = True
                self._acquired_total += 1
                self._wait_samples.append((self._clock() - w.enqueued) * 1000.0)
                w.future.set_result(True)
            else:
                break

    def _ensure_dispatcher(self) -> None:
        if self._dispatcher is None or self._dispatcher.done():
            self._dispatcher = asyncio.ensure_future(self._dispatch())

    async def _dispatch(self) -> None:
        try:
            while self._waiters:
                self._drain()
                if not self._waiters:
                    break
                head = self._waiters[0]
                if head.future.done():
                    continue
                self._refill()
                needed = head.tokens - self._available
                if needed <= _EPS:
                    continue
                await self._sleep(needed / self._fill_rate)
        finally:
            self._dispatcher = None

    def _return(self, tokens: float) -> None:
        self._available = min(self._capacity, self._available + tokens)
        if self._waiters:
            self._ensure_dispatcher()

    def _discard(self, w: _Waiter) -> None:
        if w.granted:
            self._return(w.tokens)
        else:
            try:
                self._waiters.remove(w)
            except ValueError:
                pass
            if self._waiters:
                self._ensure_dispatcher()

    async def acquire(self, tokens: float = 1, timeout: float | None = None) -> None:
        if tokens > self._capacity:
            raise ValueError(f"requested {tokens} tokens exceeds capacity {self._capacity}")

        self._refill()
        if not self._waiters and self._available + _EPS >= tokens:
            self._available = max(0.0, self._available - tokens)
            self._acquired_total += 1
            self._wait_samples.append(0.0)
            return

        loop = asyncio.get_running_loop()
        w = _Waiter(tokens=tokens, future=loop.create_future(), enqueued=self._clock())
        self._waiters.append(w)
        self._ensure_dispatcher()

        try:
            if timeout is None:
                await w.future
            else:
                await asyncio.wait_for(asyncio.shield(w.future), timeout)
        except TimeoutError:
            self._discard(w)
            self._rejected_total += 1
            raise RateLimitedError(f"{self.name} rate limit: acquire timed out") from None
        except asyncio.CancelledError:
            self._discard(w)
            raise

    def try_acquire(self, tokens: float = 1) -> bool:
        if tokens > self._capacity:
            return False
        self._refill()
        if not self._waiters and self._available + _EPS >= tokens:
            self._available = max(0.0, self._available - tokens)
            self._acquired_total += 1
            self._wait_samples.append(0.0)
            return True
        self._rejected_total += 1
        return False

    def stats(self) -> dict[str, Any]:
        self._refill()
        return {
            "available": round(self._available, 3),
            "capacity": self._capacity,
            "waiting": len(self._waiters),
            "acquired_total": self._acquired_total,
            "rejected_total": self._rejected_total,
            "wait_p95_ms": round(_percentile(list(self._wait_samples), 95), 2),
        }


@dataclass
class LimiterRegistry:
    _limiters: dict[str, TokenBucket] = field(default_factory=dict)

    @classmethod
    def from_settings(cls) -> LimiterRegistry:
        s = get_settings()
        reg = cls()
        reg._limiters["virustotal"] = TokenBucket(
            rate=float(s.vt_rate_limit_per_min), period_seconds=60.0, burst=1, name="virustotal"
        )
        per_min = max(s.abuseipdb_rate_limit_per_day / (24 * 60), 0.1)
        reg._limiters["abuseipdb"] = TokenBucket(
            rate=per_min, period_seconds=60.0, burst=max(1.0, per_min), name="abuseipdb"
        )
        reg._limiters["groq"] = TokenBucket(rate=30, period_seconds=60.0, name="groq")
        reg._limiters["gemini"] = TokenBucket(rate=15, period_seconds=60.0, name="gemini")
        return reg

    def get(self, name: str) -> TokenBucket:
        if name not in self._limiters:
            raise KeyError(f"no limiter named {name!r}")
        return self._limiters[name]

    def register(self, name: str, bucket: TokenBucket) -> None:
        self._limiters[name] = bucket


_registry: LimiterRegistry | None = None


def get_limiter_registry() -> LimiterRegistry:
    global _registry
    if _registry is None:
        _registry = LimiterRegistry.from_settings()
    return _registry


def rate_limited(
    name: str, tokens: float = 1, timeout: float | None = None
) -> Callable[[Callable[..., Awaitable[T]]], Callable[..., Awaitable[T]]]:
    """Decorator: acquire ``tokens`` from the named limiter before the call."""

    def decorator(fn: Callable[..., Awaitable[T]]) -> Callable[..., Awaitable[T]]:
        @wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> T:
            await get_limiter_registry().get(name).acquire(tokens, timeout=timeout)
            return await fn(*args, **kwargs)

        return wrapper

    return decorator
