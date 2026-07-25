"""AbuseIPDB client (IP reputation).

Normalization: ``abuseConfidenceScore`` is already 0–100, used directly as
``normalized_score``. Malicious when the score >= the settings threshold
(default 50).
"""

from __future__ import annotations

import time

import httpx

from app.api.errors import FlareError, RateLimitedError
from app.config import get_settings
from app.core.logging import get_logger
from app.core.quota import QuotaTracker
from app.core.ratelimit import TokenBucket, get_limiter_registry
from app.intel.base import HttpIntelClient
from app.intel.models import SourceVerdict
from app.providers.base import ProviderHealth
from app.schemas import IntelSource

log = get_logger(__name__)

BASE_URL = "https://api.abuseipdb.com/api/v2"

CATEGORY_MAP: dict[int, str] = {
    3: "fraud_orders",
    4: "ddos_attack",
    5: "ftp_brute_force",
    6: "ping_of_death",
    7: "phishing",
    9: "open_proxy",
    10: "web_spam",
    11: "email_spam",
    14: "port_scan",
    15: "hacking",
    18: "brute_force",
    19: "bad_web_bot",
    20: "exploited_host",
    21: "web_app_attack",
    22: "ssh",
    23: "iot_targeted",
}


class AbuseIPDBClient(HttpIntelClient):
    supports: set[str] = {"ip"}

    def __init__(
        self,
        client: httpx.AsyncClient | None = None,
        limiter: TokenBucket | None = None,
        quota: QuotaTracker | None = None,
    ) -> None:
        settings = get_settings()
        super().__init__(
            name="abuseipdb",
            limiter=limiter or get_limiter_registry().get("abuseipdb"),
            client=client,
            headers={"Key": settings.abuseipdb_api_key or "", "Accept": "application/json"},
        )
        self.base_url = BASE_URL
        self._quota = quota
        self._threshold = float(getattr(settings, "abuseipdb_malicious_threshold", 50))

    def _map_categories(self, reports: list[dict]) -> list[str]:
        slugs: set[str] = set()
        for report in reports:
            for cid in report.get("categories", []) or []:
                slug = CATEGORY_MAP.get(int(cid))
                if slug:
                    slugs.add(slug)
        return sorted(slugs)

    async def lookup_ip(self, ip: str) -> SourceVerdict | None:
        if self._quota is not None:
            await self._quota.consume(1)

        resp = await self._get(
            f"{BASE_URL}/check",
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
        )
        self._raise_for_terminal(resp, "ABUSEIPDB_API_KEY")

        if self._quota is not None:
            await self._quota.update_from_headers(resp.headers)

        data = self._json(resp).get("data", {})
        score = float(data.get("abuseConfidenceScore", 0) or 0)
        total_reports = int(data.get("totalReports", 0) or 0)
        if total_reports == 0 and score == 0:
            return None

        return SourceVerdict(
            source=IntelSource.ABUSEIPDB,
            indicator=ip,
            indicator_type="ip",
            raw_score=score,
            normalized_score=score,
            malicious=score >= self._threshold,
            categories=self._map_categories(data.get("reports", []) or []),
            last_seen=None,
            link=f"https://www.abuseipdb.com/check/{ip}",
        )

    async def health(self) -> ProviderHealth:
        if not get_settings().abuseipdb_api_key:
            return ProviderHealth(status="down", note="no ABUSEIPDB_API_KEY")
        try:
            t0 = time.perf_counter()
            resp = await self._get(f"{BASE_URL}/check", params={"ipAddress": "8.8.8.8"})
            self._raise_for_terminal(resp, "ABUSEIPDB_API_KEY")
            remaining = resp.headers.get("X-RateLimit-Remaining")
            note = f"quota_remaining={remaining}" if remaining is not None else None
            return ProviderHealth(
                status="ok", latency_ms=(time.perf_counter() - t0) * 1000, note=note
            )
        except RateLimitedError as exc:
            return ProviderHealth(status="degraded", note=str(exc.message))
        except FlareError as exc:
            return ProviderHealth(status="down", note=str(exc.message))
