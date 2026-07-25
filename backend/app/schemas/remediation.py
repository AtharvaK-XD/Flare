"""Remediation schemas (§4: MitreTechnique, RemediationStep, Remediation)."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from app.schemas import FlareModel


class MitreTechnique(FlareModel):
    id: str
    name: str
    tactic: str
    url: str
    excerpt: str


class RemediationStep(FlareModel):
    order: int
    action: str
    detail: str
    urgency: Literal["immediate", "soon", "monitor"]


class Remediation(FlareModel):
    summary: str
    steps: list[RemediationStep] = []
    techniques: list[MitreTechnique] = []
    generated_at: datetime
    duration_ms: int
