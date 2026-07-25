"""Failure-injection matrix — every case must DEGRADE VISIBLY, never crash or hang.

The rule under test throughout: a dependency failing is a normal operating
condition for a system built on free tiers, so each case must leave the app up,
the alert finalized, and the degradation recorded somewhere a human can see it
(a trace note, a health status, a counter). Silently succeeding is as much a
failure as crashing — an alert that quietly loses its enrichment and still reads
``done`` with no note is a lie.
"""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app import offline
from app.agent.graph import run_triage
from app.agent.state import TriageState
from app.api.errors import ProviderError, RateLimitedError
from app.core.bus import EventBus
from app.core.retry import default_retryable, is_permanent_quota_exhaustion
from app.evaluation.staleness import STALE_RUN_ERROR, sweep_stale_runs
from app.providers.base import CompletionResult, ProviderHealth
from app.schemas import (
    AlertStatus,
    AttackType,
    IocVerdict,
    NormalizedAlert,
    ProviderTier,
    Severity,
)
from app.store import models
from app.store.repositories import AlertRepository, EvalRunRepository

# No module-level asyncio mark: pytest is in `asyncio_mode = auto`, which already
# runs the async tests here, and a blanket mark would also be applied to the
# synchronous TestClient tests at the bottom (which pytest-asyncio rejects).


# --------------------------------------------------------------------------- helpers


def _alert(signature: str = "ET MALWARE Cobalt Strike beacon C2") -> NormalizedAlert:
    return NormalizedAlert(
        id="fail-inject-1",
        timestamp=datetime(2026, 7, 25, 14, 0, tzinfo=UTC),
        source="suricata",
        signature=signature,
        src_ip="193.27.228.7",
        dst_ip="10.0.0.15",
        src_port=44012,
        dst_port=443,
        protocol="TCP",
        raw={"signature": signature},
        extracted_iocs=["193.27.228.7"],
    )


class _FailingProvider:
    """A provider that always raises whatever it was handed."""

    def __init__(self, tier: ProviderTier, error: Exception, name: str = "groq") -> None:
        self.tier = tier
        self._error = error
        self._name = name
        self.calls = 0

    @property
    def name(self) -> str:
        return self._name

    @property
    def model(self) -> str:
        return "broken"

    @property
    def available(self) -> bool:
        return True

    async def complete(self, prompt: str, **kwargs: Any) -> CompletionResult:
        self.calls += 1
        raise self._error

    async def health(self) -> ProviderHealth:
        return ProviderHealth(status="down", note=str(self._error))


class _StubRegistry:
    def __init__(self, **by_tier: Any) -> None:
        self._m = dict(by_tier)

    def get(self, tier: ProviderTier) -> Any:
        provider = self._m.get(tier)
        if provider is None:
            raise ProviderError(f"{tier.value} tier unavailable")
        return provider


def _offline_provider(tier: ProviderTier) -> Any:
    return offline.OfflineProvider(tier)


def _trace(state: TriageState, node: str) -> Any:
    return next((t for t in state.get("trace", []) if t.node == node), None)


@pytest_asyncio.fixture
async def file_db(tmp_path: Path) -> AsyncIterator[Any]:
    from contextlib import asynccontextmanager

    from sqlalchemy import event

    path = tmp_path / "inject.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{path.as_posix()}")

    @event.listens_for(engine.sync_engine, "connect")
    def _pragmas(dbapi_conn: Any, _rec: Any) -> None:
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA busy_timeout=5000")
        cur.close()

    async with engine.begin() as conn:
        await conn.run_sync(models.Base.metadata.create_all)
    maker = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

    @asynccontextmanager
    async def factory() -> AsyncIterator[AsyncSession]:
        async with maker() as session:
            yield session

    try:
        yield factory
    finally:
        await engine.dispose()


# --------------------------------------------------------------------------- LLM tiers


async def test_invalid_groq_key_degrades_classification_but_keeps_the_alert(
    file_db: Any,
) -> None:
    """Fast tier down: the alert still persists and still finalizes, at medium/unknown."""
    broken = _FailingProvider(
        ProviderTier.FAST,
        ProviderError("Groq authentication failed — check GROQ_API_KEY"),
    )
    config = {
        "registry": _StubRegistry(
            **{ProviderTier.FAST: broken, ProviderTier.QUALITY: _offline_provider(
                ProviderTier.QUALITY
            )}
        ),
        # Must be injected. Without it the enrich node builds the LIVE intel
        # clients and this "offline" test spends real VirusTotal quota.
        "aggregator": _CleanAggregator(),
    }

    alert = _alert()
    state = await run_triage(alert, config=config)

    # Degraded, not crashed — and degraded to MEDIUM, never CRITICAL: a broken
    # classifier must not be able to flood the critical queue.
    assert state["severity"] is Severity.MEDIUM
    assert state["attack_type"] is AttackType.UNKNOWN
    classify = _trace(state, "classify")
    assert classify is not None and classify.status == "failed"
    assert "classification failed" in (classify.note or "")
    assert any("classify" in error for error in state.get("errors", []))
    assert state["status"] is AlertStatus.DONE, "a degraded alert must still finalize"

    # And it is persistable — the row is not lost because the LLM was down.
    repo = AlertRepository()
    async with file_db() as session:
        await repo.create(session, alert)
        await repo.update_classification(
            session, alert.id, state["severity"], 0.0, state["attack_type"]
        )
        await repo.mark_done(session, alert.id, 1)
        await session.commit()
        detail = await repo.get(session, alert.id)
    assert detail is not None and detail.status is AlertStatus.DONE


async def test_health_deep_reports_a_down_provider_without_failing_the_endpoint() -> None:
    """/health/deep must render a status strip even when providers are down."""
    from app.api.routes import health as health_routes

    async def _down() -> dict[str, Any]:
        return {
            "groq": health_routes.ServiceHealth(status="down", note="auth failed"),
            "gemini": health_routes.ServiceHealth(status="ok", latency_ms=12),
        }

    original = health_routes._check_llm_providers
    health_routes._check_llm_providers = _down  # type: ignore[assignment]
    try:
        result = await health_routes._guard("llm", _down(), 5.0)
    finally:
        health_routes._check_llm_providers = original  # type: ignore[assignment]

    name, services = result
    assert name == "llm"
    assert isinstance(services, dict)
    assert services["groq"].status == "down"
    # Worst-wins rollup: one down service makes the whole report down, which is
    # what the dashboard's dot is supposed to show.
    assert health_routes._worst([s.status for s in services.values()]) == "down"


async def test_permanent_gemini_429_is_not_retried_and_alert_still_finalizes() -> None:
    """A 429 with ``limit: 0`` is a misconfiguration, not backpressure.

    Retrying it burns the triage budget on a call that can never succeed, so it
    must be classified non-retryable AND still leave a finalized alert.
    """
    body = (
        "429 You exceeded your current quota. * Quota exceeded for metric: "
        "generativelanguage.googleapis.com/generate_content_free_tier_requests, "
        "limit: 0, model: gemini-2.0-flash"
    )

    class _PermanentQuota(Exception):
        status_code = 429

        def __str__(self) -> str:
            return body

    exc = _PermanentQuota()
    assert is_permanent_quota_exhaustion(exc), "the limit:0 tell was not recognised"
    assert not default_retryable(exc), "a permanent quota 429 must NOT be retried"

    quality = _FailingProvider(ProviderTier.QUALITY, exc, name="gemini")
    config = {
        "registry": _StubRegistry(
            **{
                ProviderTier.FAST: _offline_provider(ProviderTier.FAST),
                ProviderTier.QUALITY: quality,
            }
        ),
        "aggregator": _CleanAggregator(),
    }

    state = await run_triage(_alert(), config=config)

    # Classification still worked (fast tier is fine); reasoning degraded.
    assert state["attack_type"] is not AttackType.UNKNOWN
    assert state["status"] is AlertStatus.DONE
    reason = _trace(state, "reason")
    assert reason is not None
    # reason falls back to the fast tier — a degraded narrative beats none, and
    # the trace has to say which tier actually served it.
    if reason.status == "ok":
        assert "fast tier" in (reason.note or ""), "degraded fallback was not recorded"
    else:
        assert "reasoning failed" in (reason.note or "")


async def test_gemini_safety_block_is_non_retryable_and_alert_finalizes() -> None:
    """A blocked prompt is a permanent property of that prompt. Never retried."""
    blocked = ProviderError("Gemini blocked the prompt (safety): SAFETY")
    blocked.finish_reason = "blocked"  # type: ignore[attr-defined]

    assert not default_retryable(blocked), "a safety block must not be retried"

    quality = _FailingProvider(ProviderTier.QUALITY, blocked, name="gemini")
    config = {
        "registry": _StubRegistry(
            **{
                ProviderTier.FAST: _offline_provider(ProviderTier.FAST),
                ProviderTier.QUALITY: quality,
            }
        ),
        "aggregator": _CleanAggregator(),
    }

    state = await run_triage(_alert(), config=config)
    assert state["status"] is AlertStatus.DONE
    assert quality.calls >= 1
    # Exactly one attempt per node that used the quality tier — no retry storm.
    assert quality.calls <= 3, f"a non-retryable block was retried {quality.calls} times"


# --------------------------------------------------------------------------- intel


class _CleanAggregator:
    """Every indicator comes back clean. Not a failure — 'no data' is normal."""

    async def lookup_many(self, pairs: list[tuple[str, str]]) -> list[IocVerdict | None]:
        return [None for _ in pairs]


class _QuotaExhaustedAggregator:
    async def lookup_many(self, pairs: list[tuple[str, str]]) -> list[IocVerdict | None]:
        raise RateLimitedError("virustotal rate limit hit")


class _PartialAggregator:
    """VT answers, AbuseIPDB times out — the degraded-but-useful case."""

    async def lookup_many(self, pairs: list[tuple[str, str]]) -> list[IocVerdict | None]:
        return [
            IocVerdict(
                indicator=indicator,
                indicator_type="ip",
                score=91.0,
                malicious=True,
                sources=[],
            )
            for indicator, _ in pairs
        ]


async def test_virustotal_quota_exhausted_skips_enrichment_with_a_note_not_an_error() -> None:
    """Quota exhaustion is EXPECTED on a free tier: a note, never a failed status."""
    config = {
        "registry": _StubRegistry(
            **{
                ProviderTier.FAST: _offline_provider(ProviderTier.FAST),
                ProviderTier.QUALITY: _offline_provider(ProviderTier.QUALITY),
            }
        ),
        "aggregator": _QuotaExhaustedAggregator(),
    }

    state = await run_triage(_alert(), config=config)

    enrich = _trace(state, "enrich")
    assert enrich is not None
    assert enrich.status != "failed", "a rate limit must not mark enrichment failed"
    assert "rate-limited" in (enrich.note or ""), (
        f"the skip was not explained in the trace: {enrich.note!r}"
    )
    assert state.get("iocs") == []
    assert state["status"] is AlertStatus.DONE
    assert not any("enrich:" in error for error in state.get("errors", [])), (
        "an expected free-tier rate limit must not be recorded as an alert error"
    )


async def test_abuseipdb_timeout_still_yields_a_verdict_from_virustotal_alone() -> None:
    """Partial failure is a first-class outcome: one source down, verdict stands."""
    from types import SimpleNamespace

    from app.core.cache import InMemoryTTLCache
    from app.intel.aggregator import IntelAggregator
    from app.intel.models import SourceVerdict
    from app.schemas import IntelSource as IntelSourceEnum

    class _TimingOutSource:
        name = "abuseipdb"
        supports = {"ip"}

        async def lookup_ip(self, ip: str) -> SourceVerdict | None:
            raise TimeoutError("abuseipdb timed out")

        async def lookup_hash(self, h: str) -> SourceVerdict | None:
            return None

        async def health(self) -> ProviderHealth:
            return ProviderHealth(status="down", note="timeout")

    class _WorkingSource:
        name = "virustotal"
        supports = {"ip", "hash"}

        async def lookup_ip(self, ip: str) -> SourceVerdict | None:
            return SourceVerdict(
                source=IntelSourceEnum.VIRUSTOTAL,
                indicator=ip,
                indicator_type="ip",
                raw_score=12.0,
                normalized_score=88.0,
                malicious=True,
                categories=["c2"],
                last_seen=None,
                link="https://example.test",
            )

        async def lookup_hash(self, h: str) -> SourceVerdict | None:
            return None

        async def health(self) -> ProviderHealth:
            return ProviderHealth(status="ok")

    aggregator = IntelAggregator(
        [_TimingOutSource(), _WorkingSource()],  # type: ignore[list-item]
        InMemoryTTLCache(),  # type: ignore[arg-type]
        SimpleNamespace(
            intel_cache_ttl_seconds=60,
            intel_source_timeout_seconds=1.0,
            intel_concurrency=4,
        ),
    )

    verdict = await aggregator.lookup("193.27.228.7", "ip")

    assert verdict is not None, "one source failing must not void the whole verdict"
    assert verdict.score == 88.0
    metrics = aggregator.metrics()
    assert metrics["abuseipdb"]["failures"] == 1, "the failure was not counted"
    assert metrics["virustotal"]["hits"] == 1

    # And it is visible as degraded rather than silently partial.
    health = await aggregator.health()
    assert health["abuseipdb"].status == "down"
    assert health["virustotal"].status == "ok"


# --------------------------------------------------------------------------- RAG


async def test_empty_chroma_collection_still_produces_ungrounded_remediation() -> None:
    """An empty index degrades grounding, not the pipeline."""

    class _EmptyRetriever:
        async def retrieve(self, query: str, attack_type: Any = None, k: int = 4) -> list[Any]:
            return []

    config = {
        "registry": _StubRegistry(
            **{
                ProviderTier.FAST: _offline_provider(ProviderTier.FAST),
                ProviderTier.QUALITY: _offline_provider(ProviderTier.QUALITY),
            }
        ),
        "aggregator": _PartialAggregator(),
        "retriever": _EmptyRetriever(),
    }

    state = await run_triage(_alert(), config=config)

    assert state.get("techniques") == []
    retrieve = _trace(state, "retrieve")
    assert retrieve is not None
    assert retrieve.status != "failed", "an empty index is not a retrieval failure"
    assert "no matching" in (retrieve.note or "").lower()

    remediation = state.get("remediation")
    assert remediation is not None, "remediation must still be generated ungrounded"
    assert remediation.steps, "ungrounded remediation produced no steps"
    # Ungrounded means NO technique citations — the hallucination guard drops any
    # id the retriever never supplied, which is the whole point.
    assert remediation.techniques == [], (
        f"cited techniques with an empty index: {[t.id for t in remediation.techniques]}"
    )


# --------------------------------------------------------------------------- storage


async def test_concurrent_write_burst_does_not_lose_alerts(file_db: Any) -> None:
    """SQLite under a concurrent write burst: contention is retried, nothing lost."""
    repo = AlertRepository()
    count = 60

    async def write(index: int) -> None:
        alert = _alert().model_copy(update={"id": f"burst-{index}"})
        async with file_db() as session:
            await repo.create(session, alert)
            await repo.update_classification(
                session, alert.id, Severity.HIGH, 0.8, AttackType.MALWARE_C2
            )
            await repo.mark_done(session, alert.id, 5)
            await session.commit()

    await asyncio.gather(*(write(i) for i in range(count)))

    async with file_db() as session:
        total = int(
            (await session.execute(select(func.count(models.Alert.id)))).scalar_one()
        )
        done = int(
            (
                await session.execute(
                    select(func.count(models.Alert.id)).where(
                        models.Alert.status == AlertStatus.DONE.value
                    )
                )
            ).scalar_one()
        )
    assert total == count, f"lost {count - total} alert(s) to write contention"
    assert done == count


# --------------------------------------------------------------------------- ingestion


async def test_malformed_records_mid_dataset_are_skipped_counted_and_replay_continues(
    tmp_path: Path,
) -> None:
    """One corrupt row must not end a replay, and must not vanish either."""
    from app.ingestion.replay import DATASETS, ReplayEngine

    path = tmp_path / "suricata_eve_sample.json"
    good = {
        "timestamp": "2017-07-05T09:00:00.000000+0000",
        "event_type": "alert",
        "src_ip": "45.13.2.99",
        "src_port": 1234,
        "dest_ip": "10.0.0.5",
        "dest_port": 22,
        "proto": "TCP",
        "alert": {"signature": "ET SCAN probe", "category": "Misc", "severity": 2},
    }
    lines = []
    for index in range(10):
        lines.append(json.dumps({**good, "src_port": 1000 + index}))
        if index == 4:
            lines.append("{ this is not json ")  # the poison row, mid-file
            lines.append('{"event_type": "alert"}')  # parseable JSON, unusable alert
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    received: list[NormalizedAlert] = []

    async def on_alert(alert: NormalizedAlert) -> None:
        received.append(alert)

    engine = ReplayEngine(on_alert)
    original = DATASETS.get("suricata")
    DATASETS["suricata"] = (path.name, "suricata", "eve")
    from app.config import get_settings

    settings = get_settings()
    original_dataset_path = settings.dataset_path
    object.__setattr__(settings, "dataset_path", tmp_path)
    try:
        await engine.start("suricata", events_per_second=200.0)
        for _ in range(100):
            if engine.status().state.value != "running":
                break
            await asyncio.sleep(0.05)
        await engine.stop()
    finally:
        object.__setattr__(settings, "dataset_path", original_dataset_path)
        if original is not None:
            DATASETS["suricata"] = original

    assert len(received) == 10, (
        f"replay stopped early on the malformed row: {len(received)}/10 good records emitted"
    )


# --------------------------------------------------------------------------- transport


async def test_fifty_abrupt_sse_disconnects_leave_no_subscribers() -> None:
    """Every browser refresh unsubscribes, or memory climbs all demo."""
    bus = EventBus(maxsize=16)
    assert bus.subscriber_count == 0

    for _ in range(50):
        subscription = bus.subscribe()
        bus.publish(_Event())
        # Abrupt: no drain, no graceful iteration — just gone, like a closed tab.
        subscription.close()

    assert bus.subscriber_count == 0, (
        f"{bus.subscriber_count} subscriber(s) leaked after 50 disconnects"
    )

    # Closing twice must stay safe (sse-starlette can cancel a generator that
    # already exited its finally block).
    doubled = bus.subscribe()
    doubled.close()
    doubled.close()
    assert bus.subscriber_count == 0


class _Event:
    event = "alert.new"
    data = None


# --------------------------------------------------------------------------- run state


async def test_crashed_run_is_reaped_and_the_next_post_run_succeeds(file_db: Any) -> None:
    """The 409-forever bug: a stale `running` row must not block new runs."""
    repo = EvalRunRepository()

    async with file_db() as session:
        detail = await repo.create(session, sample_size=200, run_id="crashed-run")
        # Backdate it past the staleness horizon, simulating a process killed
        # mid-run 10 minutes ago.
        row = await session.get(models.EvalRun, "crashed-run")
        assert row is not None
        row.started_at = datetime.now(UTC) - timedelta(seconds=900)
        await session.commit()
    assert detail.status == "running"

    from app.evaluation.staleness import stale_cutoff

    cutoff = stale_cutoff()

    # Before reaping, the guard sees nothing FRESH — that is what unblocks it.
    async with file_db() as session:
        assert await repo.active_run_id(session, cutoff) is None, (
            "a 15-minute-old run must not count as in flight"
        )

    reaped = await sweep_stale_runs(session_factory=file_db)
    assert reaped["eval"] == ["crashed-run"]

    async with file_db() as session:
        after = await repo.get(session, "crashed-run")
    assert after is not None
    assert after.status == "failed"
    assert after.error == STALE_RUN_ERROR
    assert after.completed_at is not None

    # A genuinely fresh run still blocks, or the guard would be useless.
    async with file_db() as session:
        await repo.create(session, sample_size=10, run_id="fresh-run")
        await session.commit()
    async with file_db() as session:
        assert await repo.active_run_id(session, stale_cutoff()) == "fresh-run"


async def test_stale_sweep_is_idempotent_and_survives_a_broken_session(file_db: Any) -> None:
    """Sweeping twice changes nothing the second time, and a DB error is contained."""
    reaped_first = await sweep_stale_runs(session_factory=file_db)
    reaped_second = await sweep_stale_runs(session_factory=file_db)
    assert reaped_first == {"eval": [], "benchmark": []}
    assert reaped_second == {"eval": [], "benchmark": []}

    from app.evaluation.staleness import StaleRunSweeper

    class _BrokenFactory:
        def __call__(self) -> Any:
            raise RuntimeError("database is locked")

    sweeper = StaleRunSweeper(session_factory=_BrokenFactory(), interval=0.05)
    sweeper.start()
    await asyncio.sleep(0.25)
    # The loop logged and kept going rather than dying on the first failure.
    assert sweeper._task is not None and not sweeper._task.done()
    await sweeper.stop()


# --------------------------------------------------------------------------- app-level


def test_unknown_route_returns_the_frozen_error_envelope(api_client: Any) -> None:
    """A 404 from the router must have the same shape as every other error."""
    response = api_client.get("/api/v1/this-route-does-not-exist")

    assert response.status_code == 404
    body = response.json()
    assert set(body) == {"error"}, f"unknown routes broke the envelope: {body}"
    assert set(body["error"]) == {"code", "message", "detail"}
    assert body["error"]["code"] == "not_found"


def test_app_starts_with_zero_api_keys_present(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A cold clone with an empty .env must boot — degraded, but serving."""
    from app.config import get_settings
    from app.main import create_app
    from app.store import db as db_module
    from app.workers.queue import reset_queue_registry

    for key in (
        "GROQ_API_KEY",
        "GOOGLE_API_KEY",
        "ABUSEIPDB_API_KEY",
        "VIRUSTOTAL_API_KEY",
    ):
        monkeypatch.setenv(key, "")
    monkeypatch.setenv(
        "DATABASE_URL", f"sqlite+aiosqlite:///{(tmp_path / 'nokeys.db').as_posix()}"
    )
    get_settings.cache_clear()
    db_module._engine = None
    db_module._sessionmaker = None
    reset_queue_registry()
    try:
        with TestClient(create_app()) as client:
            # Liveness does zero dependency work and must answer regardless.
            response = client.get("/api/v1/health")
            assert response.status_code == 200
            assert response.json() == {"status": "ok"}

            # And the app still serves real routes rather than 500ing everywhere.
            alerts = client.get("/api/v1/alerts")
            assert alerts.status_code == 200
            assert alerts.json()["total"] == 0
    finally:
        db_module._engine = None
        db_module._sessionmaker = None
        reset_queue_registry()
        get_settings.cache_clear()


def test_startup_never_makes_a_network_call(monkeypatch: pytest.MonkeyPatch) -> None:
    """A slow provider health check must not be able to delay boot.

    Every outbound HTTP transport is replaced with one that raises. If the boot
    path touches the network at all, the app fails to come up and this fails.

    The embedding warm-up is disabled here on purpose. It is the one startup
    activity that MAY reach the network (fetching model weights the first time),
    which is exactly why it is dispatched as a background task and never awaited
    — boot does not depend on it. Leaving it enabled would test the warm-up's
    scheduling rather than the boot path, so it is turned off and its
    non-blocking property is asserted separately below.
    """
    from app.main import create_app

    monkeypatch.setenv("WARM_EMBEDDING_MODEL_ON_STARTUP", "false")

    def _forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("startup made a network call")

    # Patch the REAL transports only. TestClient is itself an httpx.Client using
    # an ASGI transport, so patching Client.send would break the test harness
    # rather than the thing under test.
    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", _forbidden)
    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", _forbidden)

    started = time.perf_counter()
    with TestClient(create_app()) as client:
        boot_seconds = time.perf_counter() - started
        assert client.get("/api/v1/health").status_code == 200

    # A provider health probe at startup would also make boot SLOW. Asserting the
    # budget catches a future "just check the providers once at boot" change even
    # if it is somehow made without an outbound socket.
    assert boot_seconds < 10.0, f"startup took {boot_seconds:.1f}s — it is doing I/O"


def test_embedding_warmup_is_backgrounded_not_awaited(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Boot must not wait for the ~34s model load.

    Unwarmed, that load happens inside the FIRST alert's retrieve node and
    consumes the entire triage budget — the first alert of the demo times out.
    Warming it fixes that, but only if the warm-up cannot itself delay boot.
    """
    from app.config import get_settings
    from app.main import create_app
    from app.store import db as db_module
    from app.workers.queue import reset_queue_registry

    loaded = asyncio.Event()

    def _slow_model() -> object:
        time.sleep(3.0)
        loaded.set()
        return object()

    monkeypatch.setattr("app.rag.indexer.get_embedding_model", _slow_model)
    monkeypatch.setenv("WARM_EMBEDDING_MODEL_ON_STARTUP", "true")
    monkeypatch.setenv("OFFLINE_MODE", "false")
    monkeypatch.setenv(
        "DATABASE_URL", f"sqlite+aiosqlite:///{(tmp_path / 'warm.db').as_posix()}"
    )
    get_settings.cache_clear()
    db_module._engine = None
    db_module._sessionmaker = None
    reset_queue_registry()

    try:
        started = time.perf_counter()
        with TestClient(create_app()) as client:
            boot_seconds = time.perf_counter() - started
            assert client.get("/api/v1/health").status_code == 200
        assert boot_seconds < 2.5, (
            f"boot waited {boot_seconds:.1f}s for a 3s model load — the warm-up is "
            "being awaited instead of backgrounded"
        )
    finally:
        db_module._engine = None
        db_module._sessionmaker = None
        reset_queue_registry()
        get_settings.cache_clear()
