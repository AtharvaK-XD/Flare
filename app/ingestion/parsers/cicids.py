"""CICIDS2017 CSV parser.

Column names in CICIDS2017 carry leading/trailing whitespace — always stripped.
The ``Label`` column maps to ``ground_truth_label`` via an explicit dict. Benign
rows are down-sampled (most return None) to avoid flooding the pipeline.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime

from app.core.logging import get_logger
from app.ingestion import parse_timestamp
from app.schemas import NormalizedAlert

log = get_logger(__name__)

SOURCE = "cicids2017"

BENIGN_SAMPLE_EVERY = 10

_LOGGED_UNKNOWN: set[str] = set()


def _map_label(label: str) -> str:
    key = label.strip()
    low = key.lower()
    if low == "benign":
        return "benign"
    if low == "portscan":
        return "port_scan"
    if low.startswith("ddos") or low.startswith("dos"):
        return "ddos"
    if key in ("FTP-Patator", "SSH-Patator") or low.endswith("-patator"):
        return "brute_force"
    if low.startswith("web attack"):
        return "web_attack"
    if low == "bot":
        return "malware_c2"
    if low == "infiltration":
        return "data_exfiltration"
    if low == "heartbleed":
        return "web_attack"
    if key not in _LOGGED_UNKNOWN:
        _LOGGED_UNKNOWN.add(key)
        log.warning("cicids.unknown_label", label=key)
    return "unknown"


def _strip_keys(record: dict) -> dict:
    return {str(k).strip(): (v.strip() if isinstance(v, str) else v) for k, v in record.items()}


def _to_int(value: object | None) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(float(str(value)))
    except (ValueError, TypeError):
        return None


def _keep_benign(flow_key: str) -> bool:
    digest = hashlib.md5(flow_key.encode()).hexdigest()
    return int(digest, 16) % BENIGN_SAMPLE_EVERY == 0


def parse(record: dict | str) -> NormalizedAlert | None:
    if not isinstance(record, dict):
        return None
    row = _strip_keys(record)

    raw_label = str(row.get("Label", "")).strip()
    if not raw_label:
        return None
    label = _map_label(raw_label)

    src_ip = str(row.get("Source IP", "") or "")
    dst_ip = str(row.get("Destination IP", "") or "")
    src_port = _to_int(row.get("Source Port"))
    dst_port = _to_int(row.get("Destination Port"))
    flow_id = str(row.get("Flow ID") or f"{src_ip}:{src_port}-{dst_ip}:{dst_port}")

    if label == "benign" and not _keep_benign(flow_id):
        return None

    proto = row.get("Protocol")
    signature = f"CICIDS {raw_label} flow {src_ip}:{src_port} -> {dst_ip}:{dst_port}"

    ts_raw = row.get("Timestamp")
    try:
        ts = parse_timestamp(ts_raw) if ts_raw else datetime.now(UTC)
    except ValueError:
        ts = datetime.now(UTC)

    return NormalizedAlert(
        id="",
        timestamp=ts,
        source=SOURCE,
        signature=signature,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=str(proto) if proto not in (None, "") else None,
        raw=row,
        extracted_iocs=[],
        ground_truth_label=label,
    )
