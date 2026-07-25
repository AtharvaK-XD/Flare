"""Aggregator tests — merge rules, partial failure, single-flight, batch."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from app.core.cache import InMemoryTTLCache, TieredCache
from app.intel.aggregator import IntelAggregator
from app.intel.models import SourceVerdict
from app.providers.base import ProviderHealth
from app.schemas import IntelSource

pytestmark = pytest.mark.asyncio


def _verdict(src: IntelSource, ind: str, score: float, malicious: bool, cats: list[str]):
    return SourceVerdict(
        source=src, indicator=ind, indicator_type="ip",
        raw_score=score, normalized_score=score, malicious=malicious, categories=cats,
    )


class FakeSource:
    def __init__(self, name: str, src_enum: IntelSource, behavior) -> None:  # noqa: ANN001
        self.name = name
        self.supports = {"ip"}
        self._src = src_enum
        self._behavior = behavior
        self.calls = 0
        self.ip_calls: dict[str, int] = {}

    async def lookup_ip(self, ip: str):  # noqa: ANN201
        self.calls += 1
        self.ip_calls[ip] = self.ip_calls.get(ip, 0) + 1
        await asyncio.sleep(0.005)
        result = self._behavior(ip)
        if isinstance(result, Exception):
            raise result
        return result

    async def lookup_hash(self, h: str):  # noqa: ANN201, ARG002
        return None

    async def health(self) -> ProviderHealth:
        return ProviderHealth(status="ok", latency_ms=1.0)


def _settings() -> SimpleNamespace:
    return SimpleNamespace(
        intel_cache_ttl_seconds=3600,
        intel_source_timeout_seconds=8.0,
        intel_concurrency=5,
    )


def _cache() -> TieredCache:
    return TieredCache(InMemoryTTLCache(), InMemoryTTLCache())


async def test_merge_max_score_or_malicious_union_categories() -> None:
    a = FakeSource("abuseipdb", IntelSource.ABUSEIPDB,
                   lambda ip: _verdict(IntelSource.ABUSEIPDB, ip, 40, False, ["port_scan"]))
    b = FakeSource(
        "virustotal", IntelSource.VIRUSTOTAL,
        lambda ip: _verdict(IntelSource.VIRUSTOTAL, ip, 80, True, ["malware", "port_scan"]),
    )
    agg = IntelAggregator([a, b], _cache(), _settings())

    v = await agg.lookup("8.8.8.8", "ip")
    assert v is not None
    assert v.score == 80
    assert v.malicious is True
    assert [e.source for e in v.sources] and len(v.sources) == 2
    cats = sorted({c for e in v.sources for c in e.categories})
    assert cats == ["malware", "port_scan"]


async def test_partial_failure_returns_degraded_verdict() -> None:
    good = FakeSource("abuseipdb", IntelSource.ABUSEIPDB,
                      lambda ip: _verdict(IntelSource.ABUSEIPDB, ip, 60, True, ["ssh"]))
    bad = FakeSource("virustotal", IntelSource.VIRUSTOTAL,
                     lambda ip: RuntimeError("VT down"))
    agg = IntelAggregator([good, bad], _cache(), _settings())

    v = await agg.lookup("1.2.3.4", "ip")
    assert v is not None
    assert len(v.sources) == 1
    assert v.sources[0].source is IntelSource.ABUSEIPDB


async def test_total_failure_returns_none() -> None:
    a = FakeSource("abuseipdb", IntelSource.ABUSEIPDB, lambda ip: RuntimeError("x"))
    b = FakeSource("virustotal", IntelSource.VIRUSTOTAL, lambda ip: RuntimeError("y"))
    agg = IntelAggregator([a, b], _cache(), _settings())
    assert await agg.lookup("1.2.3.4", "ip") is None


async def test_no_data_returns_none() -> None:
    a = FakeSource("abuseipdb", IntelSource.ABUSEIPDB, lambda ip: None)
    b = FakeSource("virustotal", IntelSource.VIRUSTOTAL, lambda ip: None)
    agg = IntelAggregator([a, b], _cache(), _settings())
    assert await agg.lookup("8.8.8.8", "ip") is None


async def test_single_flight_one_call_per_source() -> None:
    a = FakeSource("abuseipdb", IntelSource.ABUSEIPDB,
                   lambda ip: _verdict(IntelSource.ABUSEIPDB, ip, 30, False, []))
    b = FakeSource("virustotal", IntelSource.VIRUSTOTAL,
                   lambda ip: _verdict(IntelSource.VIRUSTOTAL, ip, 10, False, []))
    agg = IntelAggregator([a, b], _cache(), _settings())

    results = await asyncio.gather(*[agg.lookup("8.8.8.8", "ip") for _ in range(50)])
    assert all(r is not None for r in results)
    assert a.calls == 1
    assert b.calls == 1


async def test_second_lookup_marked_cached() -> None:
    a = FakeSource("abuseipdb", IntelSource.ABUSEIPDB,
                   lambda ip: _verdict(IntelSource.ABUSEIPDB, ip, 30, False, []))
    agg = IntelAggregator([a], _cache(), _settings())

    first = await agg.lookup("8.8.8.8", "ip")
    assert first is not None and first.cached is False
    second = await agg.lookup("8.8.8.8", "ip")
    assert second is not None and second.cached is True
    assert a.calls == 1


async def test_lookup_many_dedupes_and_preserves_order() -> None:
    a = FakeSource("abuseipdb", IntelSource.ABUSEIPDB,
                   lambda ip: _verdict(IntelSource.ABUSEIPDB, ip, 50, True, []))
    agg = IntelAggregator([a], _cache(), _settings())

    items: list[tuple[str, str]] = [("1.1.1.1", "ip"), ("2.2.2.2", "ip"), ("1.1.1.1", "ip")]
    results = await agg.lookup_many(items)  # type: ignore[arg-type]

    assert len(results) == 3
    assert results[0] is not None and results[0].indicator == "1.1.1.1"
    assert results[1] is not None and results[1].indicator == "2.2.2.2"
    assert results[2] is not None and results[2].indicator == "1.1.1.1"
    assert a.ip_calls["1.1.1.1"] == 1
    assert a.ip_calls["2.2.2.2"] == 1
