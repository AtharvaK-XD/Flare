"""Deduplicator tests — window suppression, counters, stats, LRU."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.ingestion.dedup import Deduplicator
from app.schemas import NormalizedAlert

BASE = datetime(2026, 1, 1, tzinfo=UTC)


def _alert(ts: datetime, sig: str = "sig", dst_port: int = 22) -> NormalizedAlert:
    return NormalizedAlert(
        id="", timestamp=ts, source="test", signature=sig,
        src_ip="8.8.8.8", dst_ip="9.9.9.9", dst_port=dst_port, raw={},
    )


def test_suppresses_inside_window() -> None:
    d = Deduplicator(window_seconds=60)
    first = d.check(_alert(BASE))
    assert first is not None
    assert d.check(_alert(BASE + timedelta(seconds=10))) is None
    assert d.check(_alert(BASE + timedelta(seconds=30))) is None
    assert first.raw["duplicate_count"] == 2


def test_passes_after_window_expires() -> None:
    d = Deduplicator(window_seconds=60)
    assert d.check(_alert(BASE)) is not None
    assert d.check(_alert(BASE + timedelta(seconds=90))) is not None


def test_different_keys_not_suppressed() -> None:
    d = Deduplicator(window_seconds=60)
    assert d.check(_alert(BASE, sig="a")) is not None
    assert d.check(_alert(BASE, sig="b")) is not None
    assert d.check(_alert(BASE, dst_port=443)) is not None


def test_stats() -> None:
    d = Deduplicator(window_seconds=60)
    d.check(_alert(BASE))
    d.check(_alert(BASE + timedelta(seconds=5)))
    d.check(_alert(BASE + timedelta(seconds=5), sig="other"))
    s = d.stats()
    assert s == {"seen": 3, "suppressed": 1, "unique": 2}


def test_lru_bounded() -> None:
    d = Deduplicator(window_seconds=60, max_keys=100)
    for i in range(250):
        d.check(_alert(BASE, sig=f"sig-{i}"))
    assert len(d._entries) <= 100
