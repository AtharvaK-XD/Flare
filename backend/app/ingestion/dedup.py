"""Sliding-window duplicate suppressor. Pure, synchronous, bounded memory."""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timedelta

from app.config import get_settings
from app.schemas import NormalizedAlert

MAX_KEYS = 10_000

DedupKey = tuple[str, str, str, int | None]


@dataclass
class _Entry:
    first: NormalizedAlert
    last_ts: datetime
    count: int


class Deduplicator:
    """Suppress repeats of (signature, src_ip, dst_ip, dst_port) within a window.

    First occurrence passes; repeats inside the window are suppressed and bump
    ``duplicate_count`` on the first alert's raw. LRU-capped at 10k keys.
    """

    def __init__(self, window_seconds: float | None = None, max_keys: int = MAX_KEYS) -> None:
        if window_seconds is None:
            window_seconds = float(getattr(get_settings(), "dedup_window_seconds", 60.0))
        self._window = timedelta(seconds=window_seconds)
        self._max_keys = max_keys
        self._entries: OrderedDict[DedupKey, _Entry] = OrderedDict()
        self._seen = 0
        self._suppressed = 0
        self._unique = 0

    @staticmethod
    def _key(alert: NormalizedAlert) -> DedupKey:
        return (alert.signature, alert.src_ip, alert.dst_ip, alert.dst_port)

    def check(self, alert: NormalizedAlert) -> NormalizedAlert | None:
        """Return the alert if it passes, or None if suppressed as a duplicate."""
        self._seen += 1
        key = self._key(alert)
        ts = alert.timestamp
        entry = self._entries.get(key)

        if entry is not None and (ts - entry.last_ts) <= self._window:
            entry.count += 1
            entry.last_ts = ts
            entry.first.raw["duplicate_count"] = entry.count
            self._entries.move_to_end(key)
            self._suppressed += 1
            return None

        alert.raw.setdefault("duplicate_count", 0)
        self._entries[key] = _Entry(first=alert, last_ts=ts, count=0)
        self._entries.move_to_end(key)
        self._unique += 1
        while len(self._entries) > self._max_keys:
            self._entries.popitem(last=False)
        return alert

    def stats(self) -> dict[str, int]:
        return {"seen": self._seen, "suppressed": self._suppressed, "unique": self._unique}
