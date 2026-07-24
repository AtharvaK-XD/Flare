"""Pydantic v2 schemas — the frozen API contract shapes (§3 and §4).

``FlareModel`` is defined here (before the re-export imports run) so every
submodule can ``from app.schemas import FlareModel`` without a circular import.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class FlareModel(BaseModel):
    """Base for all Flare schemas — shared model_config per the contract."""

    model_config = ConfigDict(
        populate_by_name=True,
        use_enum_values=False,
        ser_json_timedelta="float",
    )


from app.schemas.alert import (  # noqa: E402
    AlertDetail,
    AlertStats,
    AlertStatus,
    AlertSummary,
    AttackType,
    NormalizedAlert,
    RawAlert,
    Severity,
    TimelineBucket,
    TraceNode,
)
from app.schemas.enrichment import (  # noqa: E402
    Enrichment,
    IntelSource,
    IocSourceEntry,
    IocVerdict,
)
from app.schemas.evaluation import (  # noqa: E402
    BenchmarkResult,
    BenchmarkRunDetail,
    ConfusionMatrix,
    EvalRunDetail,
    OverallMetrics,
    PerClassMetric,
    ProviderTier,
)
from app.schemas.events import (  # noqa: E402
    AlertNewEvent,
    AlertUpdatedEvent,
    FlareEvent,
    ReplayState,
    ReplayStatus,
    ReplayStatusEvent,
    StatsUpdatedEvent,
    SystemNotice,
    SystemNoticeEvent,
)
from app.schemas.remediation import (  # noqa: E402
    MitreTechnique,
    Remediation,
    RemediationStep,
)

__all__ = [
    "FlareModel",
    "IntelSource",
    "IocSourceEntry",
    "IocVerdict",
    "Enrichment",
    "MitreTechnique",
    "RemediationStep",
    "Remediation",
    "Severity",
    "AlertStatus",
    "AttackType",
    "TraceNode",
    "AlertSummary",
    "AlertDetail",
    "RawAlert",
    "NormalizedAlert",
    "TimelineBucket",
    "AlertStats",
    "ProviderTier",
    "OverallMetrics",
    "PerClassMetric",
    "ConfusionMatrix",
    "EvalRunDetail",
    "BenchmarkResult",
    "BenchmarkRunDetail",
    "FlareEvent",
    "AlertNewEvent",
    "AlertUpdatedEvent",
    "StatsUpdatedEvent",
    "ReplayStatusEvent",
    "SystemNoticeEvent",
    "SystemNotice",
    "ReplayStatus",
    "ReplayState",
]
