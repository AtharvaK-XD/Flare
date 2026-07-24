"""Evaluation + benchmark schemas (§5) and the ProviderTier enum (§3)."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Literal

from app.schemas import FlareModel

RunStatus = Literal["running", "completed", "failed"]


class ProviderTier(str, Enum):
    FAST = "fast"
    QUALITY = "quality"


class OverallMetrics(FlareModel):
    precision: float
    recall: float
    f1: float
    accuracy: float


class PerClassMetric(FlareModel):
    label: str
    precision: float
    recall: float
    f1: float
    support: int


class ConfusionMatrix(FlareModel):
    labels: list[str] = []
    matrix: list[list[int]] = []


class EvalRunDetail(FlareModel):
    run_id: str
    status: RunStatus
    sample_size: int
    started_at: datetime | None = None
    completed_at: datetime | None = None
    overall: OverallMetrics | None = None
    per_class: list[PerClassMetric] = []
    confusion_matrix: ConfusionMatrix | None = None
    error: str | None = None


class BenchmarkResult(FlareModel):
    tier: ProviderTier
    provider: str
    model: str
    avg_latency_ms: float
    p95_latency_ms: float
    accuracy: float
    avg_tokens: float
    failures: int


class BenchmarkRunDetail(FlareModel):
    run_id: str
    status: RunStatus
    sample_size: int
    started_at: datetime | None = None
    completed_at: datetime | None = None
    results: list[BenchmarkResult] = []
    agreement_rate: float | None = None
    error: str | None = None
