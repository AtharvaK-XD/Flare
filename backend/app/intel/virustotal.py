"""VirusTotal client (IP + file hash reputation).

Normalization: ``last_analysis_stats.malicious / total_engines * 100`` is the
``normalized_score``. Malicious only when malicious_count >= the settings
threshold (default 3) — 1–2 engines flagging is noise, not a verdict.

The VT free-tier ceiling (VT_RATE_LIMIT_PER_MIN) is enforced HERE via the
"virustotal" limiter; no caller may bypass it. 404 ("not in dataset") returns
None and is negative-cached so we never spend a second unit on the same unknown.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime

import httpx

from app.api.errors import FlareError, RateLimitedError
from app.config import get_settings
from app.core.cache import InMemoryTTLCache
from app.core.logging import get_logger
from app.core.ratelimit import TokenBucket, get_limiter_registry
from app.intel.base import HttpIntelClient
from app.intel.models import IndicatorType, SourceVerdict
from app.providers.base import ProviderHealth
from app.schemas import IntelSource

log = get_logger(__name__)

BASE_URL = "https://www.virustotal.com/api/v3"


class VirusTotalClient(HttpIntelClient):
    supports: set[str] = {"ip", "hash"}

    def __init__(
        self,
        client: httpx.AsyncClient | None = None,
        limiter: TokenBucket | None = None,
    ) -> None:
        settings = get_settings()
        super().__init__(
            name="virustotal",
            limiter=limiter or get_limiter_registry().get("virustotal"),
            client=client,
            headers={"x-apikey": settings.virustotal_api_key or ""},
        )
        self.base_url = BASE_URL
        self._min_engines = int(getattr(settings, "vt_malicious_engines", 3))
        self._neg = InMemoryTTLCache(max_size=10000)
        self._neg_ttl = float(getattr(settings, "vt_negative_ttl_seconds", 300))

    async def lookup_ip(self, ip: str) -> SourceVerdict | None:
        return await self._lookup(
            ip, "ip", f"{BASE_URL}/ip_addresses/{ip}",
            f"https://www.virustotal.com/gui/ip-address/{ip}",
        )

    async def lookup_hash(self, h: str) -> SourceVerdict | None:
        return await self._lookup(
            h, "hash", f"{BASE_URL}/files/{h}",
            f"https://www.virustotal.com/gui/file/{h}",
        )

    async def _lookup(
        self, indicator: str, itype: IndicatorType, url: str, link: str
    ) -> SourceVerdict | None:
        neg_key = f"{itype}:{indicator}"
        if await self._neg.get(neg_key) is not None:
            return None

        resp = await self._get(url)
        if resp.status_code == 404:
            await self._neg.set(neg_key, True, self._neg_ttl)
            return None
        self._raise_for_terminal(resp, "VIRUSTOTAL_API_KEY")

        attrs = self._json(resp).get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {}) or {}
        malicious_count = int(stats.get("malicious", 0) or 0)
        total = sum(int(v or 0) for v in stats.values()) or 1
        normalized = malicious_count / total * 100.0

        last_seen = None
        epoch = attrs.get("last_analysis_date")
        if epoch:
            last_seen = datetime.fromtimestamp(int(epoch), tz=UTC)

        cats = {str(t) for t in (attrs.get("tags") or [])}
        label = (attrs.get("popular_threat_classification") or {}).get("suggested_threat_label")
        if label:
            cats.add(str(label))
        categories = sorted(cats)

        return SourceVerdict(
            source=IntelSource.VIRUSTOTAL,
            indicator=indicator,
            indicator_type=itype,
            raw_score=float(malicious_count),
            normalized_score=normalized,
            malicious=malicious_count >= self._min_engines,
            categories=categories,
            last_seen=last_seen,
            link=link,
        )

    async def health(self) -> ProviderHealth:
        if not get_settings().virustotal_api_key:
            return ProviderHealth(status="down", note="no VIRUSTOTAL_API_KEY")
        try:
            t0 = time.perf_counter()
            resp = await self._get(f"{BASE_URL}/ip_addresses/8.8.8.8")
            if resp.status_code != 404:
                self._raise_for_terminal(resp, "VIRUSTOTAL_API_KEY")
            remaining = resp.headers.get("x-ratelimit-remaining")
            note = f"quota_remaining={remaining}" if remaining is not None else None
            return ProviderHealth(
                status="ok", latency_ms=(time.perf_counter() - t0) * 1000, note=note
            )
        except RateLimitedError as exc:
            return ProviderHealth(status="degraded", note=str(exc.message))
        except FlareError as exc:
            return ProviderHealth(status="down", note=str(exc.message))
