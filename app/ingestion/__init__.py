"""Ingestion package — shared helpers used by parsers, normalizer, replay."""

from __future__ import annotations

import re
from datetime import UTC, datetime

_TZ_COMPACT = re.compile(r"([+-]\d{2})(\d{2})$")

_CICIDS_TS_FORMATS = (
    "%d/%m/%Y %H:%M:%S",
    "%d/%m/%Y %H:%M",
    "%m/%d/%Y %H:%M:%S",
    "%m/%d/%Y %H:%M",
    "%Y-%m-%d %H:%M:%S",
)


def parse_timestamp(value: object) -> datetime:
    """Parse assorted timestamp shapes into a tz-aware UTC datetime.

    Handles ISO-8601 (incl. ``Z`` and compact ``+0000`` offsets), Zeek epoch
    floats, and CICIDS ``d/m/Y H:M:S`` strings. Raises ValueError if nothing
    matches (callers treat that as a malformed record).
    """
    if isinstance(value, datetime):
        return value.astimezone(UTC) if value.tzinfo else value.replace(tzinfo=UTC)

    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=UTC)

    s = str(value).strip()
    if not s:
        raise ValueError("empty timestamp")

    try:
        return datetime.fromtimestamp(float(s), tz=UTC)
    except (ValueError, OverflowError, OSError):
        pass

    iso = s[:-1] + "+00:00" if s.endswith("Z") else s
    iso = _TZ_COMPACT.sub(r"\1:\2", iso)
    try:
        dt = datetime.fromisoformat(iso)
        return dt.astimezone(UTC) if dt.tzinfo else dt.replace(tzinfo=UTC)
    except ValueError:
        pass

    for fmt in _CICIDS_TS_FORMATS:
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=UTC)
        except ValueError:
            continue

    raise ValueError(f"unrecognized timestamp: {value!r}")
