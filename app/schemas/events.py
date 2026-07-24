"""SSE payload schemas (§6) — a discriminated union on the ``event`` field."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Annotated, Literal

from pydantic import Field

from app.schemas import FlareModel
from app.schemas.alert import AlertStats, AlertSummary


class ReplayState(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"


class ReplayStatus(FlareModel):
    state: ReplayState
    dataset: str | None = None
    events_per_second: float | None = None
    emitted: int = 0
    total: int | None = None
    queue_depth: dict[str, int] = {}
    started_at: datetime | None = None


class SystemNotice(FlareModel):
    level: Literal["info", "warn", "error"]
    message: str


class AlertNewEvent(FlareModel):
    event: Literal["alert.new"] = "alert.new"
    data: AlertSummary


class AlertUpdatedEvent(FlareModel):
    event: Literal["alert.updated"] = "alert.updated"
    data: AlertSummary


class StatsUpdatedEvent(FlareModel):
    event: Literal["stats.updated"] = "stats.updated"
    data: AlertStats


class ReplayStatusEvent(FlareModel):
    event: Literal["replay.status"] = "replay.status"
    data: ReplayStatus


class SystemNoticeEvent(FlareModel):
    event: Literal["system.notice"] = "system.notice"
    data: SystemNotice


FlareEvent = Annotated[
    AlertNewEvent | AlertUpdatedEvent | StatsUpdatedEvent | ReplayStatusEvent | SystemNoticeEvent,
    Field(discriminator="event"),
]
