"""HTTP surface tests against the real app — contract §5/§6/§7 conformance.

The app is driven through httpx's ASGI transport WITHOUT running the lifespan, so
no workers, no real DB, and no provider calls happen. Every collaborator (db
session, bus, queues, replay engine) is injected via ``dependency_overrides``.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.bus import EventBus
from app.deps import (
    get_bus,
    get_db_session,
    get_enrich_queue,
    get_replay_engine,
    get_triage_queue,
    get_worker_manager,
)
from app.main import create_app
from app.schemas import (
    AlertNewEvent,
    AlertStatus,
    AlertUpdatedEvent,
    AttackType,
    Enrichment,
    IocSourceEntry,
    IocVerdict,
    MitreTechnique,
    NormalizedAlert,
    Remediation,
    RemediationStep,
    Severity,
    StatsUpdatedEvent,
    SystemNotice,
    SystemNoticeEvent,
    TraceNode,
)
from app.schemas.events import ReplayState, ReplayStatus, ReplayStatusEvent
from app.store.repositories import AlertRepository
from app.workers.queue import BoundedQueue

pytestmark = pytest.mark.asyncio


# --------------------------------------------------------------------------- fakes


class FakeReplayEngine:
    """Mirrors ReplayEngine's public surface without touching a dataset."""

    def __init__(self) -> None:
        self.state = ReplayState.IDLE
        self.dataset: str | None = None
        self.eps: float | None = None
        self.limit: int | None = None
        self.emitted = 0
        self.started_at: datetime | None = None

    async def start(
        self,
        dataset: str,
        events_per_second: float | None = None,
        limit: int | None = None,
    ) -> None:
        self.state = ReplayState.RUNNING
        self.dataset = dataset
        self.eps = events_per_second or 10.0
        self.limit = limit
        self.started_at = datetime(2026, 7, 25, 14, 20, tzinfo=UTC)

    def pause(self) -> None:
        self.state = ReplayState.PAUSED

    def resume(self) -> None:
        self.state = ReplayState.RUNNING

    async def stop(self) -> None:
        self.state = ReplayState.IDLE
        self.emitted = 0

    def status(self) -> ReplayStatus:
        return ReplayStatus(
            state=self.state,
            dataset=self.dataset,
            events_per_second=self.eps,
            emitted=self.emitted,
            total=self.limit,
            queue_depth={},
            started_at=self.started_at,
        )


class FakeWorkerManager:
    def stats(self) -> dict[str, Any]:
        return {"triage": {"active": 4, "restarts": 0}, "degraded": False}


# --------------------------------------------------------------------------- fixtures


@pytest_asyncio.fixture
async def seeded(db_engine: Any) -> async_sessionmaker[AsyncSession]:
    """A DB with a deterministic spread of alerts across severities/statuses."""
    maker = async_sessionmaker(db_engine, expire_on_commit=False, class_=AsyncSession)
    repo = AlertRepository()
    base = datetime.now(UTC).replace(second=0, microsecond=0)

    rows = [
        # (id, severity, attack_type, src_ip, minutes_ago, malicious_ioc)
        ("a-critical", Severity.CRITICAL, AttackType.MALWARE_C2, "193.27.228.7", 1, True),
        ("a-high", Severity.HIGH, AttackType.BRUTE_FORCE, "185.220.101.7", 2, True),
        ("a-medium", Severity.MEDIUM, AttackType.PORT_SCAN, "45.13.2.99", 3, False),
        ("a-low", Severity.LOW, AttackType.RECON, "203.0.113.9", 4, False),
        ("a-info", Severity.INFO, AttackType.BENIGN, "8.8.8.8", 5, False),
    ]

    async with maker() as session:
        for alert_id, severity, attack, src_ip, minutes, malicious in rows:
            await repo.create(
                session,
                NormalizedAlert(
                    id=alert_id,
                    timestamp=base - timedelta(minutes=minutes),
                    source="suricata",
                    signature=f"ET SIG {alert_id}",
                    src_ip=src_ip,
                    dst_ip="10.0.0.5",
                    src_port=44012,
                    dst_port=22,
                    protocol="TCP",
                    raw={"event_type": "alert", "signature": f"ET SIG {alert_id}"},
                    extracted_iocs=[src_ip],
                ),
            )
            await repo.update_classification(session, alert_id, severity, 0.9, attack)
            await repo.add_trace(
                session, alert_id, TraceNode(node="classify", status="ok", duration_ms=12)
            )
            if malicious:
                await repo.attach_enrichment(
                    session,
                    alert_id,
                    Enrichment(
                        iocs=[
                            IocVerdict(
                                indicator=src_ip,
                                indicator_type="ip",
                                score=95.0,
                                malicious=True,
                                sources=[
                                    IocSourceEntry(
                                        source="abuseipdb",
                                        raw_score=95.0,
                                        categories=["ssh_bruteforce"],
                                        last_seen=base,
                                        link="https://www.abuseipdb.com/check/" + src_ip,
                                    )
                                ],
                            )
                        ],
                        enriched_at=base,
                        duration_ms=210,
                    ),
                )
            await session.commit()

        # the critical alert also carries a full remediation for detail-shape checks
        await repo.attach_remediation(
            session,
            "a-critical",
            Remediation(
                summary="Contain the C2 beacon.",
                steps=[
                    RemediationStep(
                        order=1,
                        action="Block the IP",
                        detail="Block 193.27.228.7 at the perimeter firewall.",
                        urgency="immediate",
                    )
                ],
                techniques=[
                    MitreTechnique(
                        id="T1071",
                        name="Application Layer Protocol",
                        tactic="Command and Control",
                        url="https://attack.mitre.org/techniques/T1071/",
                        excerpt="Adversaries may communicate using application layer protocols.",
                    )
                ],
                generated_at=base,
                duration_ms=1180,
            ),
            reasoning="Beaconing consistent with T1071.",
        )
        await repo.mark_done(session, "a-critical", 1890)
        await session.commit()

    return maker


@pytest_asyncio.fixture
async def ctx(seeded: async_sessionmaker[AsyncSession]) -> AsyncIterator[dict[str, Any]]:
    """The app plus every injected collaborator, ready to drive over HTTP."""
    app = create_app()
    bus = EventBus(maxsize=50)
    triage_q = BoundedQueue("triage", 100)
    enrich_q = BoundedQueue("enrich", 50)
    engine = FakeReplayEngine()

    async def _session() -> AsyncIterator[AsyncSession]:
        async with seeded() as session:
            yield session

    app.dependency_overrides[get_db_session] = _session
    app.dependency_overrides[get_bus] = lambda: bus
    app.dependency_overrides[get_triage_queue] = lambda: triage_q
    app.dependency_overrides[get_enrich_queue] = lambda: enrich_q
    app.dependency_overrides[get_replay_engine] = lambda: engine
    app.dependency_overrides[get_worker_manager] = lambda: FakeWorkerManager()

    transport = httpx.ASGITransport(app=app)  # lifespan intentionally NOT run
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        yield {
            "client": client,
            "app": app,
            "bus": bus,
            "triage_q": triage_q,
            "enrich_q": enrich_q,
            "engine": engine,
        }


@pytest_asyncio.fixture
async def client(ctx: dict[str, Any]) -> httpx.AsyncClient:
    return ctx["client"]


# --------------------------------------------------------------------------- health


async def test_health_is_liveness_only(client: httpx.AsyncClient) -> None:
    resp = await client.get("/api/v1/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


async def test_health_deep_matches_contract_shape(
    ctx: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.api.routes import health as health_mod
    from app.providers.base import ProviderHealth

    async def fake_llm() -> dict[str, Any]:
        return {
            "groq": health_mod.ServiceHealth(status="ok", latency_ms=210),
            "gemini": health_mod.ServiceHealth(status="ok", latency_ms=640),
        }

    async def fake_intel() -> dict[str, Any]:
        return {
            "abuseipdb": health_mod._from_provider_health(
                ProviderHealth(status="ok", note="quota_remaining=940"), want_quota=True
            ),
            "virustotal": health_mod._from_provider_health(
                ProviderHealth(status="degraded", note="rate limited quota_remaining=0"),
                want_quota=True,
            ),
        }

    async def fake_chroma() -> Any:
        return health_mod.ServiceHealth(status="ok", documents=27)

    monkeypatch.setattr(health_mod, "_check_llm_providers", fake_llm)
    monkeypatch.setattr(health_mod, "_check_intel", fake_intel)
    monkeypatch.setattr(health_mod, "_check_chroma", fake_chroma)

    resp = await ctx["client"].get("/api/v1/health/deep")
    assert resp.status_code == 200
    body = resp.json()

    assert set(body) == {"status", "services", "workers"}
    assert set(body["services"]) == {
        "groq",
        "gemini",
        "abuseipdb",
        "virustotal",
        "chroma",
        "database",
    }
    assert body["services"]["groq"] == {"status": "ok", "latency_ms": 210}
    assert body["services"]["abuseipdb"] == {"status": "ok", "quota_remaining": 940}
    assert body["services"]["virustotal"]["quota_remaining"] == 0
    assert body["services"]["virustotal"]["note"] == "rate limited"
    assert body["services"]["chroma"]["documents"] == 27
    assert body["services"]["database"]["status"] == "ok"
    # top-level = worst child (virustotal is degraded)
    assert body["status"] == "degraded"
    assert body["workers"]["degraded"] is False


async def test_health_deep_survives_a_failing_check(
    ctx: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.api.routes import health as health_mod

    async def exploding() -> dict[str, Any]:
        raise RuntimeError("groq client on fire")

    async def slow() -> dict[str, Any]:
        await asyncio.sleep(5)
        return {}

    monkeypatch.setattr(health_mod, "_check_llm_providers", exploding)
    monkeypatch.setattr(health_mod, "_check_intel", slow)
    monkeypatch.setattr(health_mod, "DEEP_BUDGET_SECONDS", 0.05)

    resp = await ctx["client"].get("/api/v1/health/deep")
    assert resp.status_code == 200  # never fails the endpoint
    body = resp.json()
    assert body["services"]["groq"]["status"] == "degraded"
    assert body["services"]["virustotal"]["status"] == "degraded"  # timed out
    assert body["status"] == "degraded"


# --------------------------------------------------------------------------- alerts


async def test_alerts_list_shape_matches_contract(client: httpx.AsyncClient) -> None:
    resp = await client.get("/api/v1/alerts")
    assert resp.status_code == 200
    body = resp.json()

    assert set(body) == {"items", "total", "limit", "offset"}
    assert body["total"] == 5
    assert body["limit"] == 50
    assert body["offset"] == 0

    assert set(body["items"][0]) == {
        "id",
        "timestamp",
        "status",
        "severity",
        "confidence",
        "attack_type",
        "signature",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "protocol",
        "source",
        "has_enrichment",
        "has_remediation",
        "max_ioc_score",
    }


async def test_alert_detail_shape_matches_contract(client: httpx.AsyncClient) -> None:
    resp = await client.get("/api/v1/alerts/a-critical")
    assert resp.status_code == 200
    body = resp.json()

    assert set(body) == {
        "id",
        "timestamp",
        "status",
        "severity",
        "confidence",
        "attack_type",
        "signature",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "protocol",
        "source",
        "has_enrichment",
        "has_remediation",
        "max_ioc_score",
        "raw",
        "reasoning",
        "enrichment",
        "remediation",
        "trace",
        "total_duration_ms",
    }
    assert set(body["enrichment"]) == {"iocs", "enriched_at", "duration_ms"}
    assert set(body["enrichment"]["iocs"][0]) == {
        "indicator",
        "indicator_type",
        "score",
        "malicious",
        "sources",
        "cached",
    }
    assert set(body["enrichment"]["iocs"][0]["sources"][0]) == {
        "source",
        "raw_score",
        "categories",
        "last_seen",
        "link",
    }
    assert set(body["remediation"]) == {
        "summary",
        "steps",
        "techniques",
        "generated_at",
        "duration_ms",
    }
    assert set(body["remediation"]["steps"][0]) == {"order", "action", "detail", "urgency"}
    assert set(body["remediation"]["techniques"][0]) == {
        "id",
        "name",
        "tactic",
        "url",
        "excerpt",
    }
    assert set(body["trace"][0]) == {
        "node",
        "status",
        "provider",
        "duration_ms",
        "tokens_in",
        "tokens_out",
        "note",
    }
    assert body["total_duration_ms"] == 1890


async def test_stats_shape_matches_contract(client: httpx.AsyncClient) -> None:
    resp = await client.get("/api/v1/alerts/stats")
    assert resp.status_code == 200
    body = resp.json()

    assert set(body) == {
        "total",
        "by_severity",
        "by_attack_type",
        "by_status",
        "malicious_iocs",
        "avg_triage_ms",
        "alerts_per_min",
        "timeline",
    }
    assert body["total"] == 5
    assert body["by_severity"]["critical"] == 1
    assert body["malicious_iocs"] == 2
    # 1-minute buckets over the last 30 minutes
    assert len(body["timeline"]) == 30
    assert set(body["timeline"][0]) == {"bucket", "count", "critical"}
    assert body["timeline"][0]["bucket"].endswith("Z")


async def test_all_timestamps_are_utc_marked(client: httpx.AsyncClient) -> None:
    """Every datetime on the wire must carry UTC ("Z"), including DB round-trips.

    SQLite drops tzinfo, so a naive value would serialize bare and JS's
    ``new Date()`` would read it as local time — shifting every alert silently.
    """
    listed = (await client.get("/api/v1/alerts")).json()
    for item in listed["items"]:
        assert item["timestamp"].endswith("Z"), item["timestamp"]

    detail = (await client.get("/api/v1/alerts/a-critical")).json()
    assert detail["timestamp"].endswith("Z")
    assert detail["enrichment"]["enriched_at"].endswith("Z")
    assert detail["enrichment"]["iocs"][0]["sources"][0]["last_seen"].endswith("Z")
    assert detail["remediation"]["generated_at"].endswith("Z")

    stats = (await client.get("/api/v1/alerts/stats")).json()
    assert all(bucket["bucket"].endswith("Z") for bucket in stats["timeline"])


async def test_stats_route_is_not_parsed_as_an_id(client: httpx.AsyncClient) -> None:
    """Route-order regression: /alerts/stats must not hit /alerts/{id}."""
    resp = await client.get("/api/v1/alerts/stats")
    assert resp.status_code == 200
    assert "timeline" in resp.json()  # the stats payload, not an alert detail


async def test_unknown_id_returns_error_envelope(client: httpx.AsyncClient) -> None:
    resp = await client.get("/api/v1/alerts/does-not-exist")
    assert resp.status_code == 404
    assert resp.json() == {
        "error": {
            "code": "not_found",
            "message": "alert not found: does-not-exist",
            "detail": None,
        }
    }


@pytest.mark.parametrize(
    ("query", "expected_ids"),
    [
        ("severity=critical", ["a-critical"]),
        ("severity=critical,high", ["a-critical", "a-high"]),
        ("attack_type=port_scan", ["a-medium"]),
        ("status=done", ["a-critical"]),
        ("src_ip=45.13.2.99", ["a-medium"]),
        ("malicious_only=true", ["a-critical", "a-high"]),
    ],
)
async def test_filters(
    client: httpx.AsyncClient, query: str, expected_ids: list[str]
) -> None:
    resp = await client.get(f"/api/v1/alerts?{query}")
    assert resp.status_code == 200
    body = resp.json()
    assert sorted(item["id"] for item in body["items"]) == sorted(expected_ids)
    assert body["total"] == len(expected_ids)


async def test_since_filter(client: httpx.AsyncClient) -> None:
    items = (await client.get("/api/v1/alerts")).json()["items"]
    stamps = {
        item["id"]: datetime.fromisoformat(item["timestamp"].replace("Z", "+00:00"))
        for item in items
    }
    # a cutoff strictly between a-medium and a-high, derived from the real rows
    cutoff = (stamps["a-medium"] + timedelta(seconds=30)).isoformat()

    # params= (not an f-string) so the tz offset's "+" is percent-encoded
    resp = await client.get("/api/v1/alerts", params={"since": cutoff})
    assert resp.status_code == 200
    assert sorted(i["id"] for i in resp.json()["items"]) == ["a-critical", "a-high"]


async def test_sort_options(client: httpx.AsyncClient) -> None:
    newest = await client.get("/api/v1/alerts?sort=-timestamp")
    assert [i["id"] for i in newest.json()["items"]] == [
        "a-critical",
        "a-high",
        "a-medium",
        "a-low",
        "a-info",
    ]

    oldest = await client.get("/api/v1/alerts?sort=timestamp")
    assert [i["id"] for i in oldest.json()["items"]] == [
        "a-info",
        "a-low",
        "a-medium",
        "a-high",
        "a-critical",
    ]


async def test_sort_by_severity_uses_rank_not_alphabetical(
    client: httpx.AsyncClient,
) -> None:
    resp = await client.get("/api/v1/alerts?sort=-severity")
    severities = [item["severity"] for item in resp.json()["items"]]
    # rank order, NOT alphabetical (which would start critical, high, info, low, medium)
    assert severities == ["critical", "high", "medium", "low", "info"]


async def test_pagination_total_stable_and_offset_past_end_is_empty(
    client: httpx.AsyncClient,
) -> None:
    page1 = (await client.get("/api/v1/alerts?limit=2&offset=0")).json()
    page2 = (await client.get("/api/v1/alerts?limit=2&offset=2")).json()
    page3 = (await client.get("/api/v1/alerts?limit=2&offset=4")).json()

    assert page1["total"] == page2["total"] == page3["total"] == 5
    assert len(page1["items"]) == 2
    assert len(page2["items"]) == 2
    assert len(page3["items"]) == 1

    ids = [i["id"] for p in (page1, page2, page3) for i in p["items"]]
    assert len(set(ids)) == 5  # no overlap, nothing skipped

    beyond = await client.get("/api/v1/alerts?limit=2&offset=999")
    assert beyond.status_code == 200  # empty page, never a 404
    assert beyond.json()["items"] == []
    assert beyond.json()["total"] == 5


async def test_bad_enum_in_csv_filter_is_422_with_offending_value(
    client: httpx.AsyncClient,
) -> None:
    resp = await client.get("/api/v1/alerts?severity=critical,neon-pink")
    assert resp.status_code == 422
    body = resp.json()
    assert body["error"]["code"] == "validation_error"
    assert "neon-pink" in body["error"]["message"]
    assert body["error"]["detail"]["invalid"] == ["neon-pink"]
    assert body["error"]["detail"]["field"] == "severity"


async def test_bad_sort_is_422(client: httpx.AsyncClient) -> None:
    resp = await client.get("/api/v1/alerts?sort=-nonsense")
    assert resp.status_code == 422
    assert resp.json()["error"]["detail"]["invalid"] == ["-nonsense"]


async def test_limit_over_max_is_422(client: httpx.AsyncClient) -> None:
    resp = await client.get("/api/v1/alerts?limit=201")
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "validation_error"


# --------------------------------------------------------------------------- ingest


async def test_ingest_simplified_body_returns_202_and_enqueues(
    ctx: dict[str, Any],
) -> None:
    resp = await ctx["client"].post(
        "/api/v1/ingest",
        json={
            "signature": "SSH brute force",
            "src_ip": "45.13.2.99",
            "dst_ip": "10.0.0.5",
            "dst_port": 22,
            "protocol": "TCP",
        },
    )
    assert resp.status_code == 202
    body = resp.json()
    assert set(body) == {"id", "status"}
    assert body["status"] == "ingested"
    assert ctx["triage_q"].depth == 1

    queued = await ctx["triage_q"].get()
    assert queued.id == body["id"]
    assert queued.signature == "SSH brute force"
    assert queued.extracted_iocs == ["45.13.2.99"]  # public IP extracted


async def test_ingest_raw_eve_json(ctx: dict[str, Any]) -> None:
    resp = await ctx["client"].post(
        "/api/v1/ingest",
        json={
            "timestamp": "2026-07-25T14:23:11.482000+0000",
            "event_type": "alert",
            "src_ip": "45.13.2.99",
            "src_port": 40122,
            "dest_ip": "10.0.0.5",
            "dest_port": 22,
            "proto": "TCP",
            "alert": {"signature": "ET SCAN Potential SSH Scan", "severity": 2},
        },
    )
    assert resp.status_code == 202
    queued = await ctx["triage_q"].get()
    assert queued.signature == "ET SCAN Potential SSH Scan"
    assert queued.source == "suricata"
    assert queued.dst_port == 22


async def test_ingest_unparseable_is_422(ctx: dict[str, Any]) -> None:
    resp = await ctx["client"].post("/api/v1/ingest", json={"nothing": "useful"})
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "validation_error"
    assert ctx["triage_q"].depth == 0


async def test_ingest_when_queue_full_is_503_rate_limited(ctx: dict[str, Any]) -> None:
    triage_q: BoundedQueue = ctx["triage_q"]
    while triage_q.put("filler"):
        pass

    resp = await ctx["client"].post(
        "/api/v1/ingest",
        json={"signature": "x", "src_ip": "45.13.2.99", "dst_ip": "10.0.0.5"},
    )
    assert resp.status_code == 503
    assert resp.json()["error"]["code"] == "rate_limited"


# --------------------------------------------------------------------------- replay


async def test_replay_status_shape_matches_contract(ctx: dict[str, Any]) -> None:
    ctx["triage_q"].put("a")
    ctx["enrich_q"].put("b")
    ctx["enrich_q"].put("c")

    resp = await ctx["client"].get("/api/v1/replay/status")
    assert resp.status_code == 200
    body = resp.json()

    assert set(body) == {
        "state",
        "dataset",
        "events_per_second",
        "emitted",
        "total",
        "queue_depth",
        "started_at",
    }
    assert body["state"] == "idle"
    assert body["queue_depth"] == {"triage": 1, "enrich": 2}


async def test_replay_lifecycle_and_bus_publishes(ctx: dict[str, Any]) -> None:
    bus: EventBus = ctx["bus"]
    sub = bus.subscribe()

    started = await ctx["client"].post(
        "/api/v1/replay/start",
        json={"dataset": "cicids2017", "events_per_second": 5, "limit": 500},
    )
    assert started.status_code == 200
    assert started.json()["state"] == "running"
    assert started.json()["dataset"] == "cicids2017"

    assert (await ctx["client"].post("/api/v1/replay/pause")).json()["state"] == "paused"
    assert (await ctx["client"].post("/api/v1/replay/resume")).json()["state"] == "running"
    assert (await ctx["client"].post("/api/v1/replay/stop")).json()["state"] == "idle"

    # a replay.status event per transition
    events = [await asyncio.wait_for(sub.__anext__(), 1.0) for _ in range(4)]
    assert [e.event for e in events] == ["replay.status"] * 4
    assert [e.data.state.value for e in events] == ["running", "paused", "running", "idle"]
    sub.close()


@pytest.mark.parametrize(
    ("path", "message_fragment"),
    [
        ("/api/v1/replay/resume", "cannot resume replay while it is idle"),
        ("/api/v1/replay/pause", "cannot pause replay while it is idle"),
        ("/api/v1/replay/stop", "nothing to stop"),
    ],
)
async def test_illegal_replay_transition_from_idle_is_409(
    client: httpx.AsyncClient, path: str, message_fragment: str
) -> None:
    resp = await client.post(path)
    assert resp.status_code == 409
    body = resp.json()
    assert body["error"]["code"] == "conflict"
    assert message_fragment in body["error"]["message"]


async def test_start_while_running_is_409(client: httpx.AsyncClient) -> None:
    assert (await client.post("/api/v1/replay/start", json={})).status_code == 200
    resp = await client.post("/api/v1/replay/start", json={})
    assert resp.status_code == 409
    assert "already running" in resp.json()["error"]["message"]


# --------------------------------------------------------------------------- stream


def _parse_sse(raw: str) -> list[dict[str, str]]:
    """Parse an SSE byte stream into {event, data, retry, comment} frames."""
    frames: list[dict[str, str]] = []
    for block in raw.replace("\r\n", "\n").split("\n\n"):
        frame: dict[str, str] = {}
        for line in block.splitlines():
            if line.startswith("event:"):
                frame["event"] = line[len("event:") :].strip()
            elif line.startswith("data:"):
                frame["data"] = line[len("data:") :].strip()
            elif line.startswith("retry:"):
                frame["retry"] = line[len("retry:") :].strip()
            elif line.startswith(":"):
                frame["comment"] = line[1:].strip()
        if frame:
            frames.append(frame)
    return frames


class SSEDriver:
    """Drives the ASGI app directly to consume an endless SSE response.

    httpx's ASGITransport buffers the entire response body before returning, so it
    can never read an open-ended stream — it would hang forever. Speaking ASGI
    directly lets us read frames as they are sent and deliver a real
    ``http.disconnect``, which is exactly what the unsubscribe path must handle.
    """

    def __init__(self, app: Any, path: str) -> None:
        self._app = app
        self._path = path
        self._receive_q: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self._messages: list[dict[str, Any]] = []
        self._started = asyncio.Event()
        self._task: asyncio.Task[None] | None = None
        self.status_code: int | None = None
        self.headers: dict[str, str] = {}

    async def _receive(self) -> dict[str, Any]:
        return await self._receive_q.get()

    async def _send(self, message: dict[str, Any]) -> None:
        self._messages.append(message)
        if message["type"] == "http.response.start":
            self.status_code = message["status"]
            self.headers = {
                k.decode().lower(): v.decode() for k, v in message.get("headers", [])
            }
            self._started.set()

    async def __aenter__(self) -> SSEDriver:
        await self._receive_q.put({"type": "http.request", "body": b"", "more_body": False})
        scope: dict[str, Any] = {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1",
            "method": "GET",
            "scheme": "http",
            "path": self._path,
            "raw_path": self._path.encode(),
            "query_string": b"",
            "root_path": "",
            "headers": [(b"host", b"test"), (b"accept", b"text/event-stream")],
            "client": ("127.0.0.1", 54321),
            "server": ("test", 80),
        }
        self._task = asyncio.ensure_future(self._app(scope, self._receive, self._send))
        await asyncio.wait_for(self._started.wait(), timeout=5.0)
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.disconnect()

    def text(self) -> str:
        return b"".join(
            m.get("body", b"") for m in self._messages if m["type"] == "http.response.body"
        ).decode()

    def frames(self) -> list[dict[str, str]]:
        return _parse_sse(self.text())

    async def wait_for_events(self, count: int, timeout: float = 5.0) -> list[dict[str, str]]:
        deadline = asyncio.get_running_loop().time() + timeout
        while asyncio.get_running_loop().time() < deadline:
            named = [f for f in self.frames() if "event" in f]
            if len(named) >= count:
                return named
            await asyncio.sleep(0.02)
        raise AssertionError(f"only got {len(self.frames())} frames: {self.frames()}")

    async def disconnect(self) -> None:
        if self._task is None:
            return
        await self._receive_q.put({"type": "http.disconnect"})
        try:
            await asyncio.wait_for(self._task, timeout=5.0)
        except (TimeoutError, asyncio.CancelledError):  # pragma: no cover
            self._task.cancel()
        self._task = None


async def test_stream_delivers_named_events_then_unsubscribes(
    ctx: dict[str, Any], seeded: async_sessionmaker[AsyncSession]
) -> None:
    bus: EventBus = ctx["bus"]

    async with seeded() as session:
        detail = await AlertRepository().get(session, "a-critical")
    assert detail is not None
    summary = detail.to_summary()

    async with SSEDriver(ctx["app"], "/api/v1/stream") as driver:
        assert driver.status_code == 200
        assert driver.headers["content-type"].startswith("text/event-stream")

        # the subscription exists before anything is published
        for _ in range(50):
            if bus.subscriber_count == 1:
                break
            await asyncio.sleep(0.02)
        assert bus.subscriber_count == 1

        bus.publish(AlertNewEvent(data=summary))
        bus.publish(AlertUpdatedEvent(data=summary))
        bus.publish(SystemNoticeEvent(data=SystemNotice(level="warn", message="quota low")))

        named = await driver.wait_for_events(3)
        assert [f["event"] for f in named[:3]] == [
            "alert.new",
            "alert.updated",
            "system.notice",
        ]

        # alert.* carries an AlertSummary, never an AlertDetail
        payload = json.loads(named[0]["data"])
        assert payload["id"] == "a-critical"
        assert payload["has_enrichment"] is True
        assert "enrichment" not in payload
        assert "remediation" not in payload
        assert "trace" not in payload
        assert "raw" not in payload

        # retry directive sent on connect so EventSource reconnects predictably
        assert any(f.get("retry") == "3000" for f in driver.frames())

    # disconnect must return the bus to zero subscribers — no leak per refresh
    for _ in range(50):
        if bus.subscriber_count == 0:
            break
        await asyncio.sleep(0.02)
    assert bus.subscriber_count == 0


async def test_stream_replay_and_stats_events_carry_contract_payloads(
    ctx: dict[str, Any], seeded: async_sessionmaker[AsyncSession]
) -> None:
    bus: EventBus = ctx["bus"]

    async with seeded() as session:
        stats = await AlertRepository().stats(session)

    async with SSEDriver(ctx["app"], "/api/v1/stream") as driver:
        for _ in range(50):
            if bus.subscriber_count == 1:
                break
            await asyncio.sleep(0.02)

        bus.publish(StatsUpdatedEvent(data=stats))
        bus.publish(
            ReplayStatusEvent(
                data=ReplayStatus(
                    state=ReplayState.RUNNING,
                    dataset="cicids2017",
                    events_per_second=5,
                    emitted=312,
                    total=500,
                    queue_depth={"triage": 4, "enrich": 11},
                )
            )
        )

        named = await driver.wait_for_events(2)
        assert [f["event"] for f in named[:2]] == ["stats.updated", "replay.status"]

        stats_payload = json.loads(named[0]["data"])
        assert set(stats_payload) == {
            "total",
            "by_severity",
            "by_attack_type",
            "by_status",
            "malicious_iocs",
            "avg_triage_ms",
            "alerts_per_min",
            "timeline",
        }
        replay_payload = json.loads(named[1]["data"])
        assert replay_payload["queue_depth"] == {"triage": 4, "enrich": 11}
        assert replay_payload["state"] == "running"


async def test_stream_status_enum_values_are_contract_literals(
    client: httpx.AsyncClient,
) -> None:
    """Belt-and-braces: enum wire values never drift from contract §3."""
    assert [s.value for s in Severity] == ["critical", "high", "medium", "low", "info"]
    assert [s.value for s in AlertStatus] == [
        "ingested",
        "classified",
        "enriched",
        "reasoned",
        "done",
        "failed",
    ]
    assert [a.value for a in AttackType] == [
        "port_scan",
        "brute_force",
        "ddos",
        "web_attack",
        "malware_c2",
        "data_exfiltration",
        "privilege_escalation",
        "recon",
        "benign",
        "unknown",
    ]
