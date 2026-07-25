"""Health routes — liveness (§5 ``/health``) and per-dependency depth (§5 ``/health/deep``).

``/health`` performs zero dependency work: it is the dashboard's connection dot
and must stay fast even when every provider is down.

``/health/deep`` fans every check out concurrently under one wall-clock budget.
A check that times out or raises is reported ``degraded``/``down`` for that
service — it never fails the endpoint, because a partially-degraded system still
needs to render its status strip.
"""

from __future__ import annotations

import asyncio
import re
import time
from typing import Any

from fastapi import APIRouter
from sqlalchemy import text

from app.core.logging import get_logger
from app.deps import SessionDep, WorkerManagerDep
from app.providers.base import HealthStatus, ProviderHealth
from app.schemas import FlareModel

log = get_logger(__name__)

router = APIRouter(tags=["health"])

DEEP_BUDGET_SECONDS = 5.0

_QUOTA_NOTE_RE = re.compile(r"quota_remaining=(\d+)")

# Worst-wins ordering for the top-level rollup.
_SEVERITY = {"ok": 0, "degraded": 1, "down": 2}

_PROVIDER_SERVICES = ("groq", "gemini")
_INTEL_SERVICES = ("abuseipdb", "virustotal")


class ServiceHealth(FlareModel):
    """One service's status. Optional fields are omitted when not applicable."""

    status: HealthStatus
    latency_ms: int | None = None
    quota_remaining: int | None = None
    documents: int | None = None
    note: str | None = None


class DeepHealth(FlareModel):
    status: HealthStatus
    services: dict[str, ServiceHealth]
    workers: dict[str, Any] = {}


def _worst(statuses: list[HealthStatus]) -> HealthStatus:
    if not statuses:
        return "down"
    return max(statuses, key=lambda s: _SEVERITY.get(s, 2))


def _from_provider_health(health: ProviderHealth, *, want_quota: bool) -> ServiceHealth:
    """Adapt a ProviderHealth into the contract's per-service shape.

    Intel clients report remaining quota inside their note (``quota_remaining=N``);
    lift it into its own field, as the contract requires, and drop the redundant
    note text.
    """
    note = health.note
    quota: int | None = None
    if note:
        match = _QUOTA_NOTE_RE.search(note)
        if match is not None:
            quota = int(match.group(1))
            note = _QUOTA_NOTE_RE.sub("", note).strip(" ;,") or None
    return ServiceHealth(
        status=health.status,
        latency_ms=int(health.latency_ms) if health.latency_ms is not None else None,
        quota_remaining=quota if want_quota else None,
        note=note,
    )


# --------------------------------------------------------------------------- checks


async def _check_llm_providers() -> dict[str, ServiceHealth]:
    from app.providers.registry import get_registry

    results = await get_registry().health_all()
    return {
        name: _from_provider_health(health, want_quota=False)
        for name, health in results.items()
    }


async def _check_intel() -> dict[str, ServiceHealth]:
    from app.agent.state import get_default_aggregator

    results = await get_default_aggregator().health()
    out = {
        name: _from_provider_health(health, want_quota=True)
        for name, health in results.items()
    }
    # A client that reported no quota header still owes the contract the field;
    # fall back to the local limiter's remaining tokens.
    for name, service in out.items():
        if service.quota_remaining is None:
            service.quota_remaining = _local_quota_remaining(name)
    return out


def _local_quota_remaining(name: str) -> int | None:
    try:
        from app.core.ratelimit import get_limiter_registry

        return int(get_limiter_registry().get(name).stats()["available"])
    except (KeyError, RuntimeError):  # pragma: no cover - limiter always registered
        return None


async def _check_chroma() -> ServiceHealth:
    from app.store.chroma import collection_stats

    t0 = time.perf_counter()
    stats = await collection_stats()
    documents = int(stats.get("documents", 0))
    return ServiceHealth(
        status="ok" if documents > 0 else "degraded",
        latency_ms=int((time.perf_counter() - t0) * 1000),
        documents=documents,
        note=None if documents > 0 else "index is empty — run scripts/index_mitre.py",
    )


async def _check_database(session: Any) -> ServiceHealth:
    t0 = time.perf_counter()
    await session.execute(text("SELECT 1"))
    return ServiceHealth(status="ok", latency_ms=int((time.perf_counter() - t0) * 1000))


async def _guard(
    name: str, coro: Any, budget: float
) -> tuple[str, dict[str, ServiceHealth] | ServiceHealth | BaseException]:
    """Run one check under the budget; never propagate its failure."""
    try:
        return name, await asyncio.wait_for(coro, timeout=budget)
    except TimeoutError:
        return name, TimeoutError(f"{name} health check exceeded {budget}s")
    except Exception as exc:  # noqa: BLE001 — a broken check must not 500 the endpoint
        return name, exc


def _degraded(note: str) -> ServiceHealth:
    return ServiceHealth(status="degraded", note=note)


# --------------------------------------------------------------------------- routes


@router.get("/health")
async def health() -> dict[str, str]:
    """Liveness only — no dependency checks, always fast."""
    return {"status": "ok"}


@router.get("/health/deep", response_model=DeepHealth, response_model_exclude_none=True)
async def health_deep(session: SessionDep, workers: WorkerManagerDep) -> DeepHealth:
    budget = DEEP_BUDGET_SECONDS
    results = await asyncio.gather(
        _guard("llm", _check_llm_providers(), budget),
        _guard("intel", _check_intel(), budget),
        _guard("chroma", _check_chroma(), budget),
        _guard("database", _check_database(session), budget),
    )

    services: dict[str, ServiceHealth] = {}
    for name, outcome in results:
        if isinstance(outcome, BaseException):
            log.warning("health.check_failed", check=name, error=str(outcome))
            fallback = _degraded(str(outcome) or f"{name} check failed")
            if name == "llm":
                services.update(dict.fromkeys(_PROVIDER_SERVICES, fallback))
            elif name == "intel":
                services.update(dict.fromkeys(_INTEL_SERVICES, fallback))
            else:
                services[name] = fallback
        elif isinstance(outcome, dict):
            services.update(outcome)
        else:
            services[name] = outcome

    # Guarantee every contract-mandated key is present even if a check invented none.
    for required in (*_PROVIDER_SERVICES, *_INTEL_SERVICES, "chroma", "database"):
        services.setdefault(required, _degraded("no status reported"))

    return DeepHealth(
        status=_worst([s.status for s in services.values()]),
        services=services,
        workers=workers.stats() if workers is not None else {},
    )


__all__ = ["router", "DeepHealth", "ServiceHealth"]
