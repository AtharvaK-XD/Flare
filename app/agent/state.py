"""TriageState — the single mutable object flowing through the LangGraph.

``trace`` and ``errors`` use an ``operator.add`` reducer so every node's writes
*merge* (append) instead of clobbering. Any other key is last-write-wins, which
is what we want for scalar fields like ``severity`` (the enrich node's upgrade
must overwrite the classifier's first guess).

Dependency resolution (provider registry, intel aggregator, MITRE retriever)
lives here too, keyed off ``state["config"]``. Injecting a fake through config
is the entire test seam — the graph itself never imports the db, a bus, or
FastAPI. Real defaults are built lazily (and only then is the db touched), so an
injected run is pure compute.
"""

from __future__ import annotations

import operator
from typing import TYPE_CHECKING, Annotated, Any, TypedDict

from app.schemas import (
    AlertStatus,
    AttackType,
    IocVerdict,
    MitreTechnique,
    NormalizedAlert,
    ProviderTier,
    Remediation,
    Severity,
    TraceNode,
)

if TYPE_CHECKING:
    from app.intel.aggregator import IntelAggregator
    from app.providers.base import LLMProvider
    from app.rag.retriever import MitreRetriever


class TriageState(TypedDict, total=False):
    """The state graph payload. All keys optional — nodes fill in their own."""

    alert: NormalizedAlert
    severity: Severity
    confidence: float
    attack_type: AttackType
    iocs: list[IocVerdict]
    max_ioc_score: int | None
    techniques: list[MitreTechnique]
    reasoning: str | None
    remediation: Remediation | None
    # Append-only via reducer — NEVER overwrite these two.
    trace: Annotated[list[TraceNode], operator.add]
    errors: Annotated[list[str], operator.add]
    status: AlertStatus
    total_duration_ms: int | None
    started_at: float
    node_started_at: float
    config: dict[str, Any]


PIPELINE_NODES: tuple[str, ...] = ("classify", "enrich", "retrieve", "reason", "recommend")

SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 1,
    Severity.LOW: 2,
    Severity.MEDIUM: 3,
    Severity.HIGH: 4,
    Severity.CRITICAL: 5,
}


def severity_rank(severity: Severity | None) -> int:
    if severity is None:
        return 0
    return SEVERITY_RANK.get(severity, 0)


def config_of(state: TriageState) -> dict[str, Any]:
    return state.get("config") or {}


def config_flag(state: TriageState, key: str, default: bool) -> bool:
    """Read a boolean tunable: state config first, then settings, then default."""
    cfg = config_of(state)
    if key in cfg:
        return bool(cfg[key])
    from app.config import get_settings

    return bool(getattr(get_settings(), key, default))


def provider_for(state: TriageState, tier: ProviderTier) -> LLMProvider:
    """Resolve the LLM provider for a tier, honouring benchmark tier overrides.

    ``config["registry"]`` swaps the whole registry (tests); ``config``
    ``["tier_overrides"]`` remaps one tier onto another provider tier (benchmark
    runs forcing e.g. the fast lane through the quality model).
    """
    cfg = config_of(state)
    registry = cfg.get("registry")
    if registry is None:
        from app.providers.registry import get_registry

        registry = get_registry()
    overrides = cfg.get("tier_overrides") or {}
    mapped = overrides.get(tier.value, tier.value)
    return registry.get(ProviderTier(mapped))


def retriever_for(state: TriageState) -> MitreRetriever:
    cfg = config_of(state)
    retriever = cfg.get("retriever")
    if retriever is not None:
        return retriever
    from app.rag.retriever import MitreRetriever

    return MitreRetriever()


_default_aggregator_singleton: IntelAggregator | None = None


def aggregator_for(state: TriageState) -> IntelAggregator:
    cfg = config_of(state)
    aggregator = cfg.get("aggregator")
    if aggregator is not None:
        return aggregator
    return _build_default_aggregator()


def get_default_aggregator() -> IntelAggregator:
    """The process-wide live aggregator (shared by the graph and /health/deep)."""
    return _build_default_aggregator()


def _build_default_aggregator() -> IntelAggregator:
    """Lazily construct the real aggregator (this is the only db-touching path).

    Only reached when no aggregator is injected — i.e. a live production run,
    never a test or an injected eval replay.
    """
    global _default_aggregator_singleton
    if _default_aggregator_singleton is not None:
        return _default_aggregator_singleton

    from types import SimpleNamespace

    from app.config import get_settings
    from app.core.cache import DbBackedCache, InMemoryTTLCache, TieredCache
    from app.core.ratelimit import get_limiter_registry
    from app.intel.abuseipdb import AbuseIPDBClient
    from app.intel.aggregator import IntelAggregator
    from app.intel.virustotal import VirusTotalClient

    settings = get_settings()
    limiters = get_limiter_registry()
    abuse = AbuseIPDBClient(limiter=limiters.get("abuseipdb"))
    vt = VirusTotalClient(limiter=limiters.get("virustotal"))
    cache = TieredCache(InMemoryTTLCache(), DbBackedCache())
    agg_settings = SimpleNamespace(
        intel_cache_ttl_seconds=settings.intel_cache_ttl_seconds,
        intel_source_timeout_seconds=8.0,
        intel_concurrency=10,
    )
    _default_aggregator_singleton = IntelAggregator([abuse, vt], cache, agg_settings)
    return _default_aggregator_singleton


__all__ = [
    "TriageState",
    "PIPELINE_NODES",
    "SEVERITY_RANK",
    "severity_rank",
    "config_of",
    "config_flag",
    "provider_for",
    "retriever_for",
    "aggregator_for",
]
