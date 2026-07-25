"""Normalizer — dispatch to a parser, extract IOCs, assign a deterministic id.

Never raises on a malformed record: logs a warning with the record index and
returns None.
"""

from __future__ import annotations

import ipaddress
import re
import uuid
from collections.abc import Callable, Iterable

from app.core.logging import get_logger
from app.ingestion.parsers import cicids, suricata_eve, zeek
from app.schemas import NormalizedAlert

log = get_logger(__name__)

_NAMESPACE = uuid.UUID("6f6b3b2e-1f4a-5c8d-9e0a-b1a5e0000000")

_HASH_RES = {
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
}

_CGNAT = ipaddress.ip_network("100.64.0.0/10")

_PARSERS: dict[str, Callable[[dict | str], NormalizedAlert | None]] = {
    "suricata": suricata_eve.parse,
    "suricata_eve": suricata_eve.parse,
    "zeek": zeek.parse,
    "cicids": cicids.parse,
    "cicids2017": cicids.parse,
}


def _is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    if ip.version == 4 and ip in _CGNAT:
        return False
    if ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        return False
    return ip.is_global


def _walk_strings(obj: object) -> Iterable[str]:
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _walk_strings(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from _walk_strings(v)


def extract_iocs(alert: NormalizedAlert) -> list[str]:
    """Public routable IPs + file hashes found in the alert. De-duplicated, ordered."""
    found: list[str] = []
    seen: set[str] = set()

    def _add(item: str) -> None:
        if item and item not in seen:
            seen.add(item)
            found.append(item)

    for candidate in (alert.src_ip, alert.dst_ip):
        if candidate and _is_public_ip(candidate):
            _add(candidate)

    blob = " ".join(_walk_strings(alert.raw))
    for token in blob.replace(",", " ").split():
        if _is_public_ip(token):
            _add(token)
    for rx in _HASH_RES.values():
        for h in rx.findall(blob):
            _add(h.lower())

    return found


def _deterministic_id(alert: NormalizedAlert) -> str:
    name = "|".join(
        str(x)
        for x in (
            alert.source,
            alert.timestamp.isoformat(),
            alert.signature,
            alert.src_ip,
            alert.dst_ip,
            alert.src_port,
            alert.dst_port,
        )
    )
    return str(uuid.uuid5(_NAMESPACE, name))


def normalize(
    record: dict | str, source: str, index: int = 0
) -> NormalizedAlert | None:
    parser = _PARSERS.get(source.lower())
    if parser is None:
        log.warning("normalizer.unknown_source", source=source, index=index)
        return None
    try:
        alert = parser(record)
    except Exception as exc:  # noqa: BLE001 — never raise on bad input
        log.warning("normalizer.parse_failed", source=source, index=index, error=str(exc))
        return None
    if alert is None:
        return None
    return alert.model_copy(
        update={"id": _deterministic_id(alert), "extracted_iocs": extract_iocs(alert)}
    )
