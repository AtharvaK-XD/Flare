"""Normalizer tests — IOC filtering, deterministic ids, never-raise."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from app.ingestion.normalizer import extract_iocs, normalize
from app.schemas import NormalizedAlert

FIXTURES = Path(__file__).parent.parent / "fixtures"


def _suricata_record() -> dict:
    return json.loads((FIXTURES / "suricata_eve.json").read_text())


def _bare_alert(**over: object) -> NormalizedAlert:
    base: dict = dict(
        id="", timestamp=datetime.now(UTC), source="test", signature="x",
        src_ip="1.1.1.1", dst_ip="2.2.2.2", raw={},
    )
    base.update(over)
    return NormalizedAlert(**base)  # type: ignore[arg-type]


def test_normalize_assigns_id_and_iocs() -> None:
    a = normalize(_suricata_record(), "suricata")
    assert a is not None
    assert a.id
    assert "45.13.2.99" in a.extracted_iocs
    assert "10.0.0.5" not in a.extracted_iocs


def test_deterministic_id_is_stable() -> None:
    a1 = normalize(_suricata_record(), "suricata")
    a2 = normalize(_suricata_record(), "suricata")
    assert a1 is not None and a2 is not None
    assert a1.id == a2.id


def test_private_ips_never_extracted() -> None:
    a = _bare_alert(
        src_ip="10.0.0.5",
        dst_ip="192.168.1.1",
        raw={"extra": "172.16.5.5 169.254.1.1 127.0.0.1 100.64.0.1 224.0.0.1"},
    )
    assert extract_iocs(a) == []


def test_public_ip_always_extracted() -> None:
    a = _bare_alert(src_ip="8.8.8.8", dst_ip="10.0.0.1")
    assert "8.8.8.8" in extract_iocs(a)


def test_hash_extraction() -> None:
    sha = "A" * 64
    a = _bare_alert(signature="malware", raw={"fileinfo": {"sha256": sha}})
    assert sha.lower() in extract_iocs(a)


def test_malformed_record_returns_none() -> None:
    assert normalize({"event_type": "alert", "alert": {"signature": "x"}}, "suricata") is None


def test_unknown_source_returns_none() -> None:
    assert normalize({"a": 1}, "nosuchsource") is None
