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


class TargetReport(FlareModel):
    """A full metric report for ONE classification target."""

    overall: OverallMetrics
    per_class: list[PerClassMetric] = []
    confusion_matrix: ConfusionMatrix


class EvalRunDetail(FlareModel):
    """Contract §5 eval report.

    The top-level ``overall`` / ``per_class`` / ``confusion_matrix`` are the
    **severity** target — the labels in the contract's example matrix. The system
    is scored on two independent targets, so ``attack_type`` carries the second
    report in the same shape. It is an ADDITIVE field: a client that only knows
    §5 keeps working unchanged, and a client that renders it gets the half of the
    truth that would otherwise be invisible.
    """

    run_id: str
    status: RunStatus
    sample_size: int
    started_at: datetime | None = None
    completed_at: datetime | None = None
    overall: OverallMetrics | None = None
    per_class: list[PerClassMetric] = []
    confusion_matrix: ConfusionMatrix | None = None
    attack_type: TargetReport | None = None
    error: str | None = None


class BenchmarkResult(FlareModel):
    """Contract §5 result row, plus additive detail fields.

    The first eight fields are the frozen contract shape. Everything after them is
    additive: latency spread the average alone hides, the input/output token split
    behind ``avg_tokens``, and the second accuracy target. ``estimated_cost`` is
    ``None`` when no price is configured for the model — quoting 0.00 for an
    unpriced model would read as "free" rather than "unknown".
    """

    tier: ProviderTier
    provider: str
    model: str
    avg_latency_ms: float
    p95_latency_ms: float
    accuracy: float
    avg_tokens: float
    failures: int

    p50_latency_ms: float = 0.0
    min_latency_ms: float = 0.0
    max_latency_ms: float = 0.0
    avg_tokens_in: float = 0.0
    avg_tokens_out: float = 0.0
    attack_type_accuracy: float = 0.0
    estimated_cost: float | None = None
    calls: int = 0
    warmup_calls: int = 0

    #: True when at least one call in THIS tier's run was retried because of a
    #: 429 / tokens-per-minute throttle, or surfaced a rate-limit error.
    #:
    #: A throttled tier's latency numbers include free-tier queueing, so they
    #: understate the model's real speed — Groq's fast tier has been measured at
    #: a 248ms p50 unthrottled and 8.6s avg while throttled on the SAME model.
    #: Presenting the second as a clean comparison would be a lie by omission, so
    #: the flag travels with the result and the report prints it.
    throttled: bool = False
    #: How many retries the throttle caused, for the report's footnote.
    throttle_retries: int = 0


class DisagreementExample(FlareModel):
    """One alert the two tiers triaged differently — the panel's money shot."""

    alert_id: str
    signature: str
    fast_prediction: str
    quality_prediction: str
    ground_truth: str


class BenchmarkRunDetail(FlareModel):
    run_id: str
    status: RunStatus
    sample_size: int
    started_at: datetime | None = None
    completed_at: datetime | None = None
    results: list[BenchmarkResult] = []
    agreement_rate: float | None = None
    disagreement_examples: list[DisagreementExample] = []
    error: str | None = None
