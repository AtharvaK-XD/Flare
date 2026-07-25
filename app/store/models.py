"""SQLAlchemy ORM models — UUID-string PKs, tz-aware UTC datetimes.

Routes and workers never import these directly; they go through
``app.store.repositories``.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    desc,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.types import TypeDecorator


class UtcDateTime(TypeDecorator):
    """A DateTime that is always tz-aware UTC on the way in AND out.

    SQLite has no native timezone storage, so SQLAlchemy hands back *naive*
    datetimes even from ``DateTime(timezone=True)``. A naive datetime serializes
    without the ``Z`` the API contract mandates, and JavaScript's ``new Date()``
    then interprets it as LOCAL time — silently shifting every timestamp in the
    dashboard by the viewer's UTC offset. Normalizing here fixes it once for every
    model instead of at each call site.

    ``impl`` is unchanged, so this emits identical DDL and needs no migration.
    """

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: object) -> datetime | None:
        if value is None:
            return None
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)

    def process_result_value(self, value: datetime | None, dialect: object) -> datetime | None:
        if value is None:
            return None
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _uuid() -> str:
    return str(uuid.uuid4())


def _utcnow() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    timestamp: Mapped[datetime] = mapped_column(UtcDateTime)
    ingested_at: Mapped[datetime] = mapped_column(UtcDateTime, default=_utcnow)
    source: Mapped[str] = mapped_column(String(64))
    signature: Mapped[str] = mapped_column(String(512))
    src_ip: Mapped[str] = mapped_column(String(64), index=True)
    dst_ip: Mapped[str] = mapped_column(String(64))
    src_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dst_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(16), nullable=True)
    status: Mapped[str] = mapped_column(String(32), index=True)
    severity: Mapped[str | None] = mapped_column(String(16), nullable=True, index=True)
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    attack_type: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    ground_truth_label: Mapped[str | None] = mapped_column(String(32), nullable=True)
    raw: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    total_duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        UtcDateTime, default=_utcnow, onupdate=_utcnow
    )

    enrichment: Mapped[Enrichment | None] = relationship(
        back_populates="alert",
        cascade="all, delete-orphan",
        lazy="selectin",
        uselist=False,
    )
    remediation: Mapped[Remediation | None] = relationship(
        back_populates="alert",
        cascade="all, delete-orphan",
        lazy="selectin",
        uselist=False,
    )
    traces: Mapped[list[Trace]] = relationship(
        back_populates="alert",
        cascade="all, delete-orphan",
        lazy="selectin",
        order_by="Trace.created_at",
    )

    __table_args__ = (
        Index("ix_alerts_timestamp_desc", desc("timestamp")),
        Index("ix_alerts_severity_timestamp_desc", "severity", desc("timestamp")),
    )


class Enrichment(Base):
    __tablename__ = "enrichments"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    alert_id: Mapped[str] = mapped_column(
        ForeignKey("alerts.id", ondelete="CASCADE"), index=True
    )
    enriched_at: Mapped[datetime] = mapped_column(UtcDateTime, default=_utcnow)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    max_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    payload: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)

    alert: Mapped[Alert] = relationship(back_populates="enrichment")


class Remediation(Base):
    __tablename__ = "remediations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    alert_id: Mapped[str] = mapped_column(
        ForeignKey("alerts.id", ondelete="CASCADE"), index=True
    )
    summary: Mapped[str] = mapped_column(Text, default="")
    steps: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    techniques: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    reasoning: Mapped[str | None] = mapped_column(Text, nullable=True)
    generated_at: Mapped[datetime] = mapped_column(UtcDateTime, default=_utcnow)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)

    alert: Mapped[Alert] = relationship(back_populates="remediation")


class Trace(Base):
    __tablename__ = "traces"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    alert_id: Mapped[str] = mapped_column(
        ForeignKey("alerts.id", ondelete="CASCADE"), index=True
    )
    node: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(16))
    provider: Mapped[str | None] = mapped_column(String(64), nullable=True)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    tokens_in: Mapped[int | None] = mapped_column(Integer, nullable=True)
    tokens_out: Mapped[int | None] = mapped_column(Integer, nullable=True)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=_utcnow)

    alert: Mapped[Alert] = relationship(back_populates="traces")


class IocCache(Base):
    __tablename__ = "ioc_cache"

    indicator: Mapped[str] = mapped_column(String(256), primary_key=True)
    indicator_type: Mapped[str] = mapped_column(String(16))
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    score: Mapped[float] = mapped_column(Float, default=0.0)
    malicious: Mapped[bool] = mapped_column(Boolean, default=False)
    fetched_at: Mapped[datetime] = mapped_column(UtcDateTime, default=_utcnow)
    expires_at: Mapped[datetime] = mapped_column(UtcDateTime, index=True)


class EvalRun(Base):
    __tablename__ = "eval_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    status: Mapped[str] = mapped_column(String(16), default="running")
    sample_size: Mapped[int] = mapped_column(Integer, default=0)
    started_at: Mapped[datetime] = mapped_column(UtcDateTime, default=_utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)
    overall: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    per_class: Mapped[list[dict[str, Any]] | None] = mapped_column(JSON, nullable=True)
    confusion_matrix: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)


class BenchmarkRun(Base):
    __tablename__ = "benchmark_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    status: Mapped[str] = mapped_column(String(16), default="running")
    sample_size: Mapped[int] = mapped_column(Integer, default=0)
    started_at: Mapped[datetime] = mapped_column(UtcDateTime, default=_utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)
    results: Mapped[list[dict[str, Any]] | None] = mapped_column(JSON, nullable=True)
    agreement_rate: Mapped[float | None] = mapped_column(Float, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
