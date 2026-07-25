"""TokenBucket tests — deterministic via a virtual clock/scheduler."""

from __future__ import annotations

import asyncio
import heapq

import pytest

from app.api.errors import RateLimitedError
from app.core.ratelimit import LimiterRegistry, TokenBucket

pytestmark = pytest.mark.asyncio


class VClock:
    """Virtual clock + sleep so tests never wait on real time."""

    def __init__(self) -> None:
        self.t = 0.0
        self._sleepers: list[tuple[float, int, asyncio.Future]] = []
        self._seq = 0

    def now(self) -> float:
        return self.t

    async def sleep(self, d: float) -> None:
        if d <= 0:
            await asyncio.sleep(0)
            return
        loop = asyncio.get_running_loop()
        fut: asyncio.Future = loop.create_future()
        self._seq += 1
        heapq.heappush(self._sleepers, (self.t + d, self._seq, fut))
        await fut

    async def advance(self, dt: float) -> None:
        target = self.t + dt
        while self._sleepers and self._sleepers[0][0] <= target + 1e-9:
            wake, _, fut = heapq.heappop(self._sleepers)
            self.t = max(self.t, wake)
            if not fut.done():
                fut.set_result(None)
            await asyncio.sleep(0)
        self.t = target
        await asyncio.sleep(0)


async def _settle(times: int = 5) -> None:
    for _ in range(times):
        await asyncio.sleep(0)


async def test_four_per_min_then_fifth_blocks() -> None:
    vc = VClock()
    b = TokenBucket(4, 60, clock=vc.now, sleep=vc.sleep, name="vt")
    for _ in range(4):
        await b.acquire()
    assert b.stats()["available"] == 0

    fifth = asyncio.create_task(b.acquire())
    await _settle()
    assert not fifth.done()

    await vc.advance(15)
    await _settle()
    assert fifth.done()
    await fifth


async def test_100_concurrent_on_10ps() -> None:
    vc = VClock()
    b = TokenBucket(10, 1, clock=vc.now, sleep=vc.sleep, name="x")
    tasks = [asyncio.create_task(b.acquire()) for _ in range(100)]
    await _settle()

    for _ in range(200):
        if all(t.done() for t in tasks):
            break
        await vc.advance(0.1)
    await asyncio.gather(*tasks)

    assert b.stats()["acquired_total"] == 100
    assert b.stats()["available"] <= 0.001
    assert 8.5 <= vc.t <= 10.5


async def test_fifo_preserved_mixed_sizes() -> None:
    vc = VClock()
    b = TokenBucket(1, 1, burst=3, clock=vc.now, sleep=vc.sleep, name="f")
    await b.acquire(3)
    order: list[str] = []

    async def big() -> None:
        await b.acquire(3)
        order.append("A")

    async def small() -> None:
        await b.acquire(1)
        order.append("B")

    a = asyncio.create_task(big())
    await _settle()
    s = asyncio.create_task(small())
    await _settle()

    for _ in range(10):
        if a.done() and s.done():
            break
        await vc.advance(1)
    await asyncio.gather(a, s)
    assert order == ["A", "B"]


async def test_cancelled_waiter_wakes_next() -> None:
    vc = VClock()
    b = TokenBucket(1, 1, burst=1, clock=vc.now, sleep=vc.sleep, name="c")
    await b.acquire(1)

    a = asyncio.create_task(b.acquire(1))
    await _settle()
    nxt = asyncio.create_task(b.acquire(1))
    await _settle()

    a.cancel()
    with pytest.raises(asyncio.CancelledError):
        await a

    await vc.advance(1)
    await _settle()
    assert nxt.done()
    await nxt


async def test_timeout_raises_and_does_not_consume() -> None:
    vc = VClock()
    b = TokenBucket(1, 1, burst=1, clock=vc.now, sleep=vc.sleep, name="t")
    await b.acquire(1)
    before = b.stats()["acquired_total"]
    with pytest.raises(RateLimitedError):
        await b.acquire(1, timeout=0.05)
    assert b.stats()["acquired_total"] == before
    assert b.stats()["available"] <= 0.001


async def test_try_acquire_nonblocking() -> None:
    vc = VClock()
    b = TokenBucket(2, 60, clock=vc.now, sleep=vc.sleep)
    assert b.try_acquire() is True
    assert b.try_acquire() is True
    assert b.try_acquire() is False


async def test_stress_vt_never_exceeds_rate_in_rolling_window() -> None:
    vc = VClock()
    reg = LimiterRegistry.from_settings()
    vt = reg.get("virustotal")
    assert vt.stats()["capacity"] == 1
    b = TokenBucket(4, 60, burst=1, clock=vc.now, sleep=vc.sleep, name="vt")

    grants: list[float] = []

    async def run() -> None:
        await b.acquire(1)
        grants.append(vc.now())

    tasks = [asyncio.create_task(run()) for _ in range(200)]
    await _settle()
    for _ in range(400):
        if all(t.done() for t in tasks):
            break
        await vc.advance(15)
    await asyncio.gather(*tasks)

    assert len(grants) == 200
    grants.sort()
    for i, start in enumerate(grants):
        window = [g for g in grants[i:] if g < start + 60.0]
        assert len(window) <= 4, f"{len(window)} grants in 60s window at t={start}"
