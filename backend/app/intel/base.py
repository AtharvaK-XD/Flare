"""Intel source protocol + shared HTTP client base (rate-limit + retry).

Normalization is per-source and documented on each client. Two invariants
everywhere in this package:
  * ``None`` means "no data on this indicator" (a clean IP) — NOT a failure.
  * Exceptions are reserved for actual failures (auth, quota, 5xx, network).
Conflating the two makes every unknown IP look like an outage.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

import httpx

from app.api.errors import ProviderError, RateLimitedError
from app.core.logging import get_logger
from app.core.ratelimit import TokenBucket
from app.core.retry import http_status_of, with_retry
from app.intel.models import SourceVerdict
from app.providers.base import ProviderHealth

log = get_logger(__name__)


@runtime_checkable
class IntelSource(Protocol):
    @property
    def name(self) -> str: ...

    @property
    def supports(self) -> set[str]: ...

    async def lookup_ip(self, ip: str) -> SourceVerdict | None: ...

    async def lookup_hash(self, h: str) -> SourceVerdict | None: ...

    async def health(self) -> ProviderHealth: ...


def intel_retryable(exc: BaseException) -> bool:
    """Retry only transient transport failures — never 429 (surface it) or 4xx."""
    if isinstance(exc, (TimeoutError, httpx.TimeoutException, httpx.ConnectError)):
        return True
    status = http_status_of(exc)
    if status is not None:
        return 500 <= status < 600
    return False


class HttpIntelClient:
    """Shared HTTP plumbing: one limiter acquire per call, 5xx retried.

    OWNERSHIP: a client passed in belongs to the caller (tests, respx) and is
    never closed here; one built here is owned here and IS closed by
    :meth:`aclose`. Without that distinction shutdown either leaks a connection
    pool ("Unclosed client session" on the way out) or closes a transport a test
    still needs.
    """

    base_url: str = ""

    def __init__(
        self,
        name: str,
        limiter: TokenBucket,
        client: httpx.AsyncClient | None = None,
        headers: dict[str, str] | None = None,
        timeout: float = 15.0,
    ) -> None:
        self._name = name
        self._limiter = limiter
        self._headers = headers or {}
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(timeout=timeout)

    @property
    def name(self) -> str:
        return self._name

    async def aclose(self) -> None:
        """Release the connection pool if this client built it. Idempotent."""
        if self._owns_client and not self._client.is_closed:
            await self._client.aclose()

    async def _get(self, url: str, params: dict[str, Any] | None = None) -> httpx.Response:
        """One limiter token per logical call; 5xx/network retried, then raised."""
        await self._limiter.acquire()

        @with_retry(attempts=3, retry_on=intel_retryable, provider=self._name)
        async def _do() -> httpx.Response:
            resp = await self._client.get(url, params=params, headers=self._headers)
            if resp.status_code >= 500:
                resp.raise_for_status()
            return resp

        return await _do()

    def _raise_for_terminal(self, resp: httpx.Response, key_env: str) -> None:
        """Map terminal statuses to the right typed error (caller handles 200/404)."""
        if resp.status_code == 401 or resp.status_code == 403:
            raise ProviderError(
                f"{self._name} authentication failed — check {key_env}",
                detail=resp.text[:300],
            )
        if resp.status_code == 429:
            raise RateLimitedError(f"{self._name} rate limit hit", detail=resp.text[:300])
        if resp.status_code != 200:
            raise ProviderError(
                f"{self._name} unexpected status {resp.status_code}", detail=resp.text[:300]
            )

    @staticmethod
    def _json(resp: httpx.Response) -> dict[str, Any]:
        try:
            data = resp.json()
        except (ValueError, httpx.DecodingError):
            raise ProviderError(
                "malformed JSON from intel source", detail=resp.text[:300]
            ) from None
        if not isinstance(data, dict):
            raise ProviderError("intel source returned non-object JSON", detail=str(data)[:300])
        return data

    async def lookup_hash(self, h: str) -> SourceVerdict | None:  # noqa: ARG002
        return None

    async def lookup_ip(self, ip: str) -> SourceVerdict | None:  # pragma: no cover - overridden
        raise NotImplementedError

    async def health(self) -> ProviderHealth:  # pragma: no cover - overridden
        raise NotImplementedError
