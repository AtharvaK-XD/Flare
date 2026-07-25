"""Zeek parser — handles JSON-lines notice.log and TSV (#fields header).

Only notice records (those carrying a ``note``) produce alerts; conn logs and
other Zeek logs return None.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator

from app.ingestion import parse_timestamp
from app.schemas import NormalizedAlert

SOURCE = "zeek"


def _get(record: dict, *keys: str) -> object | None:
    """Fetch a Zeek field written either flat ('id.orig_h') or nested."""
    for key in keys:
        if key in record and record[key] not in (None, "-", ""):
            return record[key]
    for key in keys:
        if "." in key:
            head, tail = key.split(".", 1)
            sub = record.get(head)
            if isinstance(sub, dict) and sub.get(tail) not in (None, "-", ""):
                return sub[tail]
    return None


def _to_int(value: object | None) -> int | None:
    if value is None:
        return None
    try:
        return int(str(value))
    except (ValueError, TypeError):
        return None


def parse(record: dict | str) -> NormalizedAlert | None:
    if isinstance(record, str):
        stripped = record.strip()
        if not stripped or stripped.startswith("#"):
            return None
        try:
            record = json.loads(stripped)
        except json.JSONDecodeError:
            return None
    if not isinstance(record, dict):
        return None

    note = _get(record, "note")
    if note is None:
        return None

    ts = _get(record, "ts")
    return NormalizedAlert(
        id="",
        timestamp=parse_timestamp(ts) if ts is not None else parse_timestamp(0),
        source=SOURCE,
        signature=str(note),
        src_ip=str(_get(record, "id.orig_h") or ""),
        dst_ip=str(_get(record, "id.resp_h") or ""),
        src_port=_to_int(_get(record, "id.orig_p")),
        dst_port=_to_int(_get(record, "id.resp_p")),
        protocol=(str(_get(record, "proto")).upper() if _get(record, "proto") else None),
        raw=dict(record),
        extracted_iocs=[],
        ground_truth_label=None,
    )


def iter_tsv(lines: Iterable[str]) -> Iterator[dict]:
    """Yield field-mapped dicts from a Zeek TSV stream (#fields header)."""
    fields: list[str] | None = None
    for line in lines:
        line = line.rstrip("\n")
        if line.startswith("#fields"):
            fields = line.split("\t")[1:]
            continue
        if line.startswith("#") or not line.strip():
            continue
        if fields is None:
            continue
        values = line.split("\t")
        yield dict(zip(fields, values, strict=False))
