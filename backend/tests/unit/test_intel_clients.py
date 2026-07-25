"""Intel client tests — respx-mocked, ZERO real network."""

from __future__ import annotations

import asyncio
import heapq

import httpx
import pytest
import respx

from app.api.errors import ProviderError, RateLimitedError
from app.core.ratelimit import TokenBucket
from app.intel.abuseipdb import AbuseIPDBClient
from app.intel.virustotal import VirusTotalClient

pytestmark = pytest.mark.asyncio

ABUSE_URL = "https://api.abuseipdb.com/api/v2/check"
VT_IP = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"
VT_FILE = "https://www.virustotal.com/api/v3/files/{h}"


@pytest.fixture(autouse=True)
def _no_backoff(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("app.core.retry.random.uniform", lambda a, b: 0.0)


def _fast_limiter() -> TokenBucket:
    return TokenBucket(1000, 1, name="test")


class VClock:
    def __init__(self) -> None:
        self.t = 0.0
        self._s: list[tuple[float, int, asyncio.Future]] = []
        self._n = 0

    def now(self) -> float:
        return self.t

    async def sleep(self, d: float) -> None:
        if d <= 0:
            await asyncio.sleep(0)
            return
        fut: asyncio.Future = asyncio.get_running_loop().create_future()
        self._n += 1
        heapq.heappush(self._s, (self.t + d, self._n, fut))
        await fut

    async def advance(self, dt: float) -> None:
        target = self.t + dt
        while self._s and self._s[0][0] <= target + 1e-9:
            wake, _, fut = heapq.heappop(self._s)
            self.t = max(self.t, wake)
            if not fut.done():
                fut.set_result(None)
            await asyncio.sleep(0)
        self.t = target
        await asyncio.sleep(0)


@respx.mock
async def test_abuseipdb_happy_path() -> None:
    respx.get(ABUSE_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "abuseConfidenceScore": 75,
                    "totalReports": 5,
                    "reports": [{"categories": [14, 18]}],
                }
            },
        )
    )
    c = AbuseIPDBClient(limiter=_fast_limiter())
    v = await c.lookup_ip("45.13.2.99")
    assert v is not None
    assert v.normalized_score == 75
    assert v.malicious is True
    assert v.categories == ["brute_force", "port_scan"]


@respx.mock
async def test_abuseipdb_threshold_boundary() -> None:
    route = respx.get(ABUSE_URL)
    route.side_effect = [
        httpx.Response(200, json={"data": {"abuseConfidenceScore": 50, "totalReports": 1}}),
        httpx.Response(200, json={"data": {"abuseConfidenceScore": 49, "totalReports": 1}}),
    ]
    c = AbuseIPDBClient(limiter=_fast_limiter())
    assert (await c.lookup_ip("1.2.3.4")).malicious is True
    assert (await c.lookup_ip("1.2.3.5")).malicious is False


@respx.mock
async def test_abuseipdb_clean_ip_returns_none() -> None:
    respx.get(ABUSE_URL).mock(
        return_value=httpx.Response(
            200, json={"data": {"abuseConfidenceScore": 0, "totalReports": 0}}
        )
    )
    c = AbuseIPDBClient(limiter=_fast_limiter())
    assert await c.lookup_ip("8.8.8.8") is None


@respx.mock
async def test_abuseipdb_401_no_retry() -> None:
    route = respx.get(ABUSE_URL).mock(return_value=httpx.Response(401, json={"errors": []}))
    c = AbuseIPDBClient(limiter=_fast_limiter())
    with pytest.raises(ProviderError) as ei:
        await c.lookup_ip("1.2.3.4")
    assert "ABUSEIPDB_API_KEY" in ei.value.message
    assert route.call_count == 1


@respx.mock
async def test_abuseipdb_429_rate_limited() -> None:
    respx.get(ABUSE_URL).mock(return_value=httpx.Response(429, text="slow down"))
    c = AbuseIPDBClient(limiter=_fast_limiter())
    with pytest.raises(RateLimitedError):
        await c.lookup_ip("1.2.3.4")


@respx.mock
async def test_abuseipdb_5xx_retried_then_raised() -> None:
    route = respx.get(ABUSE_URL).mock(return_value=httpx.Response(503, text="oops"))
    c = AbuseIPDBClient(limiter=_fast_limiter())
    with pytest.raises(ProviderError):
        await c.lookup_ip("1.2.3.4")
    assert route.call_count == 3


@respx.mock
async def test_abuseipdb_malformed_json() -> None:
    respx.get(ABUSE_URL).mock(return_value=httpx.Response(200, text="not json at all"))
    c = AbuseIPDBClient(limiter=_fast_limiter())
    with pytest.raises(ProviderError):
        await c.lookup_ip("1.2.3.4")


def _vt_ip_response(malicious: int, total: int) -> httpx.Response:
    stats = {"malicious": malicious, "harmless": total - malicious, "undetected": 0}
    return httpx.Response(
        200, json={"data": {"attributes": {"last_analysis_stats": stats, "tags": ["botnet"]}}}
    )


@respx.mock
async def test_virustotal_happy_and_threshold() -> None:
    respx.get(VT_IP.format(ip="9.9.9.9")).mock(return_value=_vt_ip_response(5, 70))
    respx.get(VT_IP.format(ip="9.9.9.8")).mock(return_value=_vt_ip_response(3, 70))
    respx.get(VT_IP.format(ip="9.9.9.7")).mock(return_value=_vt_ip_response(1, 70))
    c = VirusTotalClient(limiter=_fast_limiter())

    v = await c.lookup_ip("9.9.9.9")
    assert v is not None and v.malicious is True
    assert v.normalized_score == pytest.approx(5 / 70 * 100)
    assert (await c.lookup_ip("9.9.9.8")).malicious is True
    assert (await c.lookup_ip("9.9.9.7")).malicious is False


@respx.mock
async def test_virustotal_404_negative_cached() -> None:
    route = respx.get(VT_IP.format(ip="1.1.1.1")).mock(return_value=httpx.Response(404))
    c = VirusTotalClient(limiter=_fast_limiter())
    assert await c.lookup_ip("1.1.1.1") is None
    assert await c.lookup_ip("1.1.1.1") is None
    assert route.call_count == 1


@respx.mock
async def test_virustotal_hash_lookup() -> None:
    h = "a" * 64
    respx.get(VT_FILE.format(h=h)).mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {"attributes": {"last_analysis_stats": {"malicious": 40, "harmless": 20}}}
            },
        )
    )
    c = VirusTotalClient(limiter=_fast_limiter())
    v = await c.lookup_hash(h)
    assert v is not None and v.malicious is True
    assert v.indicator_type == "hash"


@respx.mock
async def test_virustotal_401_no_retry() -> None:
    route = respx.get(VT_IP.format(ip="1.2.3.4")).mock(return_value=httpx.Response(401))
    c = VirusTotalClient(limiter=_fast_limiter())
    with pytest.raises(ProviderError):
        await c.lookup_ip("1.2.3.4")
    assert route.call_count == 1


@respx.mock
async def test_virustotal_429_rate_limited() -> None:
    respx.get(VT_IP.format(ip="1.2.3.4")).mock(return_value=httpx.Response(429))
    c = VirusTotalClient(limiter=_fast_limiter())
    with pytest.raises(RateLimitedError):
        await c.lookup_ip("1.2.3.4")


@respx.mock
async def test_virustotal_5xx_retried() -> None:
    route = respx.get(VT_IP.format(ip="1.2.3.4")).mock(return_value=httpx.Response(500))
    c = VirusTotalClient(limiter=_fast_limiter())
    with pytest.raises(ProviderError):
        await c.lookup_ip("1.2.3.4")
    assert route.call_count == 3


@respx.mock
async def test_virustotal_limiter_hard_cap_rolling_window() -> None:
    vc = VClock()
    limiter = TokenBucket(4, 60, burst=1, clock=vc.now, sleep=vc.sleep, name="virustotal")
    times: list[float] = []

    def handler(request: httpx.Request) -> httpx.Response:
        times.append(vc.now())
        return _vt_ip_response(0, 70)

    respx.get(url__regex=r"https://www\.virustotal\.com/api/v3/ip_addresses/.*").mock(
        side_effect=handler
    )
    c = VirusTotalClient(limiter=limiter)

    tasks = [asyncio.create_task(c.lookup_ip(f"203.0.{i // 256}.{i % 256}")) for i in range(100)]
    for _ in range(10):
        await asyncio.sleep(0)
    for _ in range(400):
        if all(t.done() for t in tasks):
            break
        await vc.advance(15)
    await asyncio.gather(*tasks)

    assert len(times) == 100
    times.sort()
    for i, start in enumerate(times):
        window = [t for t in times[i:] if t < start + 60.0]
        assert len(window) <= 4
