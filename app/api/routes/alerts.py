"""Alert routes (§5) — the feed, the stat counters, and the drill-down.

Thin by design: parse and validate query params, call a repository, return the
schema. No ORM access, no business logic, no graph invocation lives here.

ROUTE ORDER IS LOAD-BEARING: ``/alerts/stats`` is declared BEFORE ``/alerts/{id}``.
Reversed, "stats" is captured as an id and every stats call 404s.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Annotated

from fastapi import APIRouter, Query

from app.api.errors import NotFoundError, ValidationError
from app.deps import AlertRepoDep, SessionDep
from app.schemas import (
    AlertDetail,
    AlertStats,
    AlertStatus,
    AlertSummary,
    AttackType,
    FlareModel,
    Severity,
)
from app.store.repositories import AlertFilters

router = APIRouter(prefix="/alerts", tags=["alerts"])

DEFAULT_LIMIT = 50
MAX_LIMIT = 200
STATS_WINDOW_MINUTES = 30

SORT_OPTIONS = ("-timestamp", "timestamp", "-severity")


class AlertListResponse(FlareModel):
    items: list[AlertSummary] = []
    total: int
    limit: int
    offset: int


def _parse_csv_enum(raw: str | None, enum_cls: type[Enum], field: str) -> list[str]:
    """Split a csv filter and validate each member against the enum.

    An unknown value is a client error, not an empty result set — surface it as
    422 with the offending value so the caller can see exactly what was rejected.
    """
    if raw is None:
        return []
    values = [part.strip() for part in raw.split(",") if part.strip()]
    allowed = {member.value for member in enum_cls}
    invalid = [value for value in values if value not in allowed]
    if invalid:
        raise ValidationError(
            f"invalid {field} value(s): {', '.join(invalid)}",
            detail={
                "field": field,
                "invalid": invalid,
                "allowed": sorted(allowed),
            },
        )
    return values


@router.get("/stats", response_model=AlertStats)
async def alert_stats(session: SessionDep, repo: AlertRepoDep) -> AlertStats:
    """Header counters + the 1-minute timeline buckets for the last 30 minutes."""
    return await repo.stats(session, window_minutes=STATS_WINDOW_MINUTES)


@router.get("", response_model=AlertListResponse)
async def list_alerts(
    session: SessionDep,
    repo: AlertRepoDep,
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
    offset: Annotated[int, Query(ge=0)] = 0,
    severity: Annotated[str | None, Query(description="csv, e.g. critical,high")] = None,
    status: Annotated[str | None, Query(description="csv")] = None,
    attack_type: Annotated[str | None, Query(description="csv")] = None,
    src_ip: Annotated[str | None, Query(description="exact match")] = None,
    malicious_only: Annotated[bool, Query()] = False,
    since: Annotated[datetime | None, Query(description="ISO-8601")] = None,
    sort: Annotated[str, Query()] = "-timestamp",
) -> AlertListResponse:
    if sort not in SORT_OPTIONS:
        raise ValidationError(
            f"invalid sort value: {sort}",
            detail={"field": "sort", "invalid": [sort], "allowed": list(SORT_OPTIONS)},
        )

    filters = AlertFilters(
        severity=_parse_csv_enum(severity, Severity, "severity"),
        status=_parse_csv_enum(status, AlertStatus, "status"),
        attack_type=_parse_csv_enum(attack_type, AttackType, "attack_type"),
        src_ip=src_ip,
        malicious_only=malicious_only,
        since=since,
    )

    items, total = await repo.list(
        session, filters=filters, limit=limit, offset=offset, sort=sort
    )
    # An offset past the end is an empty page, never a 404.
    return AlertListResponse(items=items, total=total, limit=limit, offset=offset)


@router.get("/{alert_id}", response_model=AlertDetail)
async def get_alert(alert_id: str, session: SessionDep, repo: AlertRepoDep) -> AlertDetail:
    detail = await repo.get(session, alert_id)
    if detail is None:
        raise NotFoundError(f"alert not found: {alert_id}")
    return detail


__all__ = ["router", "AlertListResponse"]
