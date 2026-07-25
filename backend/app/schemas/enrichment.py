"""IOC enrichment schemas (§4: IocVerdict, Enrichment)."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Literal

from app.schemas import FlareModel


class IntelSource(str, Enum):
    ABUSEIPDB = "abuseipdb"
    VIRUSTOTAL = "virustotal"


class IocSourceEntry(FlareModel):
    """One provider's opinion on an indicator."""

    source: IntelSource
    raw_score: float
    categories: list[str] = []
    last_seen: datetime | None = None
    link: str | None = None


class IocVerdict(FlareModel):
    indicator: str
    indicator_type: Literal["ip", "hash"]
    score: float
    malicious: bool
    sources: list[IocSourceEntry] = []
    cached: bool = False


class Enrichment(FlareModel):
    iocs: list[IocVerdict] = []
    enriched_at: datetime
    duration_ms: int
