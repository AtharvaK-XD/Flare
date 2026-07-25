"""Intel data models — a single source's verdict on one indicator."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Literal

from app.schemas import IntelSource, IocSourceEntry

IndicatorType = Literal["ip", "hash"]


@dataclass
class SourceVerdict:
    """One provider's opinion on one indicator (pre-merge).

    ``normalized_score`` is always 0–100 (higher = worse); each client documents
    exactly how it maps its native score onto that scale.
    """

    source: IntelSource
    indicator: str
    indicator_type: IndicatorType
    raw_score: float
    normalized_score: float
    malicious: bool
    categories: list[str] = field(default_factory=list)
    last_seen: datetime | None = None
    link: str | None = None
    fetched_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    cached: bool = False

    def to_source_entry(self) -> IocSourceEntry:
        return IocSourceEntry(
            source=self.source,
            raw_score=self.raw_score,
            categories=list(self.categories),
            last_seen=self.last_seen,
            link=self.link,
        )
