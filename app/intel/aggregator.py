"""Intel aggregator — single-flight lookups, concurrent fan-out, explicit merge.

Partial failure is a first-class outcome: if VirusTotal is rate-limited and
AbuseIPDB answers, we return the AbuseIPDB verdict (degraded), not an error.
None is returned only when EVERY source failed or EVERY source had no data —
and the two are logged distinctly.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

from app.api.errors import FlareError
from app.core.cache import TieredCache
from app.core.logging import get_logger
from app.intel.base import IntelSource
from app.intel.models import IndicatorType, SourceVerdict
from app.providers.base import ProviderHealth
from app.schemas import IocVerdict

log = get_logger(__name__)


class _AllFailed(Exception):
    """Every source raised — transient, must NOT be cached."""


@dataclass
class _SourceMetrics:
    calls: int = 0
    hits: int = 0
    misses: int = 0
    failures: int = 0

    def as_dict(self) -> dict[str, Any]:
        total = self.calls
        return {
            "calls": self.calls,
            "hits": self.hits,
            "misses": self.misses,
            "failures": self.failures,
            "cache_hit_rate": round(self.hits / total, 4) if total else 0.0,
        }


@dataclass
class IntelAggregator:
    sources: list[IntelSource]
    cache: TieredCache
    settings: Any
    _metrics: dict[str, _SourceMetrics] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self._ttl = float(getattr(self.settings, "intel_cache_ttl_seconds", 86400))
        self._timeout = float(getattr(self.settings, "intel_source_timeout_seconds", 8.0))
        self._concurrency = int(getattr(self.settings, "intel_concurrency", 10))
        for s in self.sources:
            self._metrics.setdefault(s.name, _SourceMetrics())


    async def lookup(self, indicator: str, indicator_type: IndicatorType) -> IocVerdict | None:
        key = f"{indicator_type}:{indicator}"

        pre = await self.cache.get(key)
        if pre is not None:
            pre.cached = True
            return pre

        async def factory() -> IocVerdict | None:
            return await self._compute(indicator, indicator_type)

        try:
            return await self.cache.get_or_set(key, factory, self._ttl)
        except _AllFailed:
            return None

    async def _compute(
        self, indicator: str, indicator_type: IndicatorType
    ) -> IocVerdict | None:
        applicable = [s for s in self.sources if indicator_type in s.supports]
        results = await asyncio.gather(
            *(self._one(s, indicator, indicator_type) for s in applicable),
            return_exceptions=True,
        )

        verdicts: list[SourceVerdict] = []
        failures = 0
        for source, res in zip(applicable, results, strict=True):
            m = self._metrics[source.name]
            m.calls += 1
            if isinstance(res, BaseException):
                failures += 1
                m.failures += 1
                log.warning("intel.source_failed", source=source.name, error=str(res))
            elif res is None:
                m.misses += 1
            else:
                m.hits += 1
                verdicts.append(res)

        if verdicts:
            if failures:
                log.info("intel.degraded", indicator=indicator, failures=failures)
            return self._merge(indicator, indicator_type, verdicts)

        if failures:
            log.warning("intel.total_failure", indicator=indicator, sources=len(applicable))
            raise _AllFailed(indicator)

        log.info("intel.no_data", indicator=indicator)
        return None

    async def _one(
        self, source: IntelSource, indicator: str, indicator_type: IndicatorType
    ) -> SourceVerdict | None:
        coro = (
            source.lookup_ip(indicator)
            if indicator_type == "ip"
            else source.lookup_hash(indicator)
        )
        return await asyncio.wait_for(coro, timeout=self._timeout)


    def _merge(
        self,
        indicator: str,
        indicator_type: IndicatorType,
        verdicts: list[SourceVerdict],
    ) -> IocVerdict:
        score = max(v.normalized_score for v in verdicts)
        malicious = any(v.malicious for v in verdicts)
        categories: set[str] = set()
        for v in verdicts:
            categories.update(v.categories)
        cached = all(v.cached for v in verdicts)
        return IocVerdict(
            indicator=indicator,
            indicator_type=indicator_type,
            score=score,
            malicious=malicious,
            sources=[v.to_source_entry() for v in verdicts],
            cached=cached,
        )


    async def lookup_many(
        self, indicators: list[tuple[str, IndicatorType]]
    ) -> list[IocVerdict | None]:
        unique: dict[tuple[str, IndicatorType], None] = {}
        for item in indicators:
            unique.setdefault(item, None)

        sem = asyncio.Semaphore(self._concurrency)

        async def run(ind: str, itype: IndicatorType) -> IocVerdict | None:
            async with sem:
                return await self.lookup(ind, itype)

        keys = list(unique.keys())
        computed = await asyncio.gather(*(run(i, t) for i, t in keys))
        by_key = dict(zip(keys, computed, strict=True))
        return [by_key[item] for item in indicators]


    async def aclose(self) -> None:
        """Close every source that owns a connection pool. Never raises.

        Shutdown must not be able to fail: one source with a wedged transport
        would otherwise leave the others open AND surface as a shutdown error.
        """
        for source in self.sources:
            closer = getattr(source, "aclose", None)
            if closer is None:
                continue
            try:
                await closer()
            except Exception as exc:  # noqa: BLE001 — best effort, on the way out
                log.warning("intel.close_failed", source=source.name, error=str(exc))

    def metrics(self) -> dict[str, Any]:
        return {name: m.as_dict() for name, m in self._metrics.items()}

    async def health(self) -> dict[str, ProviderHealth]:
        results = await asyncio.gather(
            *(s.health() for s in self.sources), return_exceptions=True
        )
        out: dict[str, ProviderHealth] = {}
        for source, res in zip(self.sources, results, strict=True):
            if isinstance(res, ProviderHealth):
                out[source.name] = res
            elif isinstance(res, FlareError):
                out[source.name] = ProviderHealth(status="down", note=str(res.message))
            else:
                out[source.name] = ProviderHealth(status="down", note=str(res))
        return out
