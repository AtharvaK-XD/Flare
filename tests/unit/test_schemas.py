"""Schema + error-envelope tests against the frozen contract (§3, §4, §7)."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import TypeAdapter

from app.api.errors import (
    InternalError,
    NotFoundError,
    ProviderError,
    RateLimitedError,
    ValidationError,
    register_exception_handlers,
)
from app.schemas import (
    AlertDetail,
    AlertStatus,
    AlertSummary,
    AttackType,
    FlareEvent,
    IntelSource,
    ProviderTier,
    Severity,
)

EXPECTED = {
    Severity: ["critical", "high", "medium", "low", "info"],
    AlertStatus: ["ingested", "classified", "enriched", "reasoned", "done", "failed"],
    AttackType: [
        "port_scan", "brute_force", "ddos", "web_attack", "malware_c2",
        "data_exfiltration", "privilege_escalation", "recon", "benign", "unknown",
    ],
    IntelSource: ["abuseipdb", "virustotal"],
    ProviderTier: ["fast", "quality"],
}


def test_enum_values_exact() -> None:
    for enum_cls, values in EXPECTED.items():
        assert [m.value for m in enum_cls] == values
        for v in values:
            assert enum_cls(v).value == v


def test_severity_serializes_to_string() -> None:
    s = AlertSummary(
        id="a", timestamp=datetime.now(UTC), status=AlertStatus.CLASSIFIED,
        severity=Severity.CRITICAL, signature="x", src_ip="1.1.1.1", dst_ip="2.2.2.2",
        source="suricata",
    )
    dumped = s.model_dump(mode="json")
    assert dumped["severity"] == "critical"
    assert dumped["status"] == "classified"


def test_alert_summary_all_optional_none() -> None:
    s = AlertSummary(
        id="a",
        timestamp=datetime.now(UTC),
        status=AlertStatus.INGESTED,
        signature="ET SCAN port scan",
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        source="cicids2017",
    )
    assert s.severity is None
    assert s.confidence is None
    assert s.attack_type is None
    assert s.src_port is None
    assert s.dst_port is None
    assert s.protocol is None
    assert s.max_ioc_score is None
    assert s.has_enrichment is False


def test_alert_detail_to_summary() -> None:
    d = AlertDetail(
        id="a", timestamp=datetime.now(UTC), status=AlertStatus.DONE,
        severity=Severity.LOW, signature="x", src_ip="1.1.1.1", dst_ip="2.2.2.2",
        source="zeek", has_enrichment=True,
    )
    summary = d.to_summary()
    assert isinstance(summary, AlertSummary)
    assert type(summary) is AlertSummary
    assert summary.id == "a"
    assert summary.has_enrichment is True


def test_event_discriminated_union() -> None:
    adapter: TypeAdapter = TypeAdapter(FlareEvent)
    notice = adapter.validate_python(
        {"event": "system.notice", "data": {"level": "warn", "message": "quota low"}}
    )
    assert notice.event == "system.notice"
    assert notice.data.level == "warn"

    new = adapter.validate_python(
        {
            "event": "alert.new",
            "data": {
                "id": "a", "timestamp": "2026-08-07T14:23:11Z", "status": "classified",
                "signature": "x", "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2",
                "source": "suricata",
            },
        }
    )
    assert new.event == "alert.new"
    assert isinstance(new.data, AlertSummary)


def _app_that_raises(exc: Exception) -> TestClient:
    app = FastAPI()
    register_exception_handlers(app)

    @app.get("/boom")
    async def boom() -> None:
        raise exc

    return TestClient(app, raise_server_exceptions=False)


def test_error_envelopes_per_class() -> None:
    cases = [
        (NotFoundError("missing"), 404, "not_found"),
        (ValidationError("bad", detail={"field": "x"}), 422, "validation_error"),
        (RateLimitedError("quota"), 429, "rate_limited"),
        (ProviderError("down"), 502, "provider_error"),
        (InternalError("boom"), 500, "internal_error"),
    ]
    for exc, status, code in cases:
        client = _app_that_raises(exc)
        resp = client.get("/boom")
        assert resp.status_code == status
        body = resp.json()
        assert set(body.keys()) == {"error"}
        assert set(body["error"].keys()) == {"code", "message", "detail"}
        assert body["error"]["code"] == code


def test_request_validation_envelope() -> None:
    app = FastAPI()
    register_exception_handlers(app)

    @app.get("/need")
    async def need(q: int) -> dict[str, int]:
        return {"q": q}

    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get("/need?q=notanint")
    assert resp.status_code == 422
    body = resp.json()
    assert body["error"]["code"] == "validation_error"
    assert isinstance(body["error"]["detail"], list)
