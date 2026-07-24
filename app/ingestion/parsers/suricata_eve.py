"""Suricata EVE JSON parser. Only ``event_type == "alert"`` becomes an alert."""

from __future__ import annotations

import json

from app.ingestion import parse_timestamp
from app.schemas import NormalizedAlert

SOURCE = "suricata"

_SEVERITY_HINT = {1: "high", 2: "medium", 3: "low"}


def parse(record: dict | str) -> NormalizedAlert | None:
    if isinstance(record, str):
        try:
            record = json.loads(record)
        except json.JSONDecodeError:
            return None
    if not isinstance(record, dict):
        return None
    if record.get("event_type") != "alert":
        return None

    alert = record.get("alert") or {}
    raw = dict(record)
    sev = alert.get("severity")
    if sev in _SEVERITY_HINT:
        raw["severity_hint"] = _SEVERITY_HINT[sev]

    return NormalizedAlert(
        id="",
        timestamp=parse_timestamp(record["timestamp"]),
        source=SOURCE,
        signature=alert.get("signature", "Suricata alert"),
        src_ip=str(record.get("src_ip", "")),
        dst_ip=str(record.get("dest_ip", "")),
        src_port=record.get("src_port"),
        dst_port=record.get("dest_port"),
        protocol=record.get("proto"),
        raw=raw,
        extracted_iocs=[],
        ground_truth_label=None,
    )
