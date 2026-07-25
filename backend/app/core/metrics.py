"""In-process metrics registry — per provider/model/node call stats.

Thread/async safe via a plain lock (gemini runs in worker threads via
``asyncio.to_thread``, so a real lock is required, not just single-threaded luck).
"""

from __future__ import annotations

import threading
from collections import deque
from dataclasses import dataclass, field

COST_PER_1K_TOKENS: dict[str, float] = {}

_MAX_SAMPLES = 1000


@dataclass
class _Bucket:
    calls: int = 0
    failures: int = 0
    retries: int = 0
    #: Retries specifically caused by a 429 / quota wait. Split out from
    #: ``retries`` because a benchmark that queued behind a free-tier limit is
    #: NOT measuring the model's speed, and must say so.
    rate_limit_retries: int = 0
    tokens_in: int = 0
    tokens_out: int = 0
    latencies: deque[float] = field(default_factory=lambda: deque(maxlen=_MAX_SAMPLES))


def percentile(samples: list[float], pct: float) -> float:
    """Nearest-rank percentile. Empty input is 0.0.

    Public because the provider benchmark reports the same percentiles over its
    own samples — percentile math must exist in exactly one place or two panels
    can quote different p95s for the same calls.
    """
    if not samples:
        return 0.0
    ordered = sorted(samples)
    idx = min(len(ordered) - 1, int(round((pct / 100.0) * (len(ordered) - 1))))
    return ordered[idx]


class MetricsRegistry:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._buckets: dict[tuple[str, str, str], _Bucket] = {}

    def _bucket(self, key: tuple[str, str, str]) -> _Bucket:
        b = self._buckets.get(key)
        if b is None:
            b = _Bucket()
            self._buckets[key] = b
        return b

    def record_call(
        self,
        provider: str,
        model: str,
        node: str,
        latency_ms: float,
        tokens_in: int,
        tokens_out: int,
        ok: bool,
    ) -> None:
        key = (provider, model, node)
        with self._lock:
            b = self._bucket(key)
            b.calls += 1
            if not ok:
                b.failures += 1
            b.tokens_in += tokens_in
            b.tokens_out += tokens_out
            b.latencies.append(latency_ms)

    def record_retry(
        self,
        provider: str,
        model: str = "-",
        node: str = "-",
        *,
        rate_limited: bool = False,
    ) -> None:
        with self._lock:
            bucket = self._bucket((provider, model, node))
            bucket.retries += 1
            if rate_limited:
                bucket.rate_limit_retries += 1

    def rate_limit_retries(self, provider: str, model: str | None = None) -> int:
        """Total 429-driven retries for a provider (optionally one model).

        The benchmark samples this before and after each tier: a non-zero delta
        means that tier's latency numbers include free-tier queueing.
        """
        with self._lock:
            return sum(
                bucket.rate_limit_retries
                for (bucket_provider, bucket_model, _), bucket in self._buckets.items()
                if bucket_provider == provider and (model is None or bucket_model == model)
            )

    def _estimated_cost(self, model: str, tokens_in: int, tokens_out: int) -> float:
        rate = COST_PER_1K_TOKENS.get(model, 0.0)
        return round(rate * (tokens_in + tokens_out) / 1000.0, 6)

    def snapshot(self) -> dict:
        with self._lock:
            keys = list(self._buckets.items())

        per_key: list[dict] = []
        totals = {
            "calls": 0,
            "failures": 0,
            "retries": 0,
            "rate_limit_retries": 0,
            "tokens_in": 0,
            "tokens_out": 0,
            "estimated_cost": 0.0,
        }
        for (provider, model, node), b in keys:
            samples = list(b.latencies)
            avg = sum(samples) / len(samples) if samples else 0.0
            cost = self._estimated_cost(model, b.tokens_in, b.tokens_out)
            per_key.append(
                {
                    "provider": provider,
                    "model": model,
                    "node": node,
                    "calls": b.calls,
                    "failures": b.failures,
                    "retries": b.retries,
                    "rate_limit_retries": b.rate_limit_retries,
                    "tokens_in": b.tokens_in,
                    "tokens_out": b.tokens_out,
                    "avg_latency_ms": round(avg, 2),
                    "p50_latency_ms": round(percentile(samples, 50), 2),
                    "p95_latency_ms": round(percentile(samples, 95), 2),
                    "failure_rate": round(b.failures / b.calls, 4) if b.calls else 0.0,
                    "estimated_cost": cost,
                }
            )
            totals["calls"] += b.calls
            totals["failures"] += b.failures
            totals["retries"] += b.retries
            totals["rate_limit_retries"] += b.rate_limit_retries
            totals["tokens_in"] += b.tokens_in
            totals["tokens_out"] += b.tokens_out
            totals["estimated_cost"] = round(totals["estimated_cost"] + cost, 6)

        totals["failure_rate"] = (
            round(totals["failures"] / totals["calls"], 4) if totals["calls"] else 0.0
        )
        return {"per_key": per_key, "totals": totals}

    def reset(self) -> None:
        with self._lock:
            self._buckets.clear()


metrics = MetricsRegistry()
