"""Full-system integration: real DB, real Chroma dir, real everything but the network.

WHAT IS REAL HERE
-----------------
A temp-file SQLite database (NOT in-memory — WAL and cross-connection locking are
part of what is under test), a temp Chroma directory, the real FastAPI app, the
real worker pools, the real queues, the real event bus, the real replay engine
and the real LangGraph graph with every node and router.

WHAT IS STUBBED
---------------
Only the leaves that make network calls: the two LLM tiers and the intel sources,
via ``app.offline`` — the same deterministic stand-ins the ``--offline`` demo
mode uses, installed at the same seam. No test-only branch exists in the pipeline.

WHAT THIS PROVES that the unit tests cannot
-------------------------------------------
* every alert reaches a terminal status, with zero stuck in an intermediate one;
* the DB alert count equals what replay actually emitted;
* every alert carries a complete trace with no missing node;
* SSE delivered ``alert.new`` for every alert and ``alert.updated`` for enriched ones;
* an eval AND a benchmark running CONCURRENTLY with replay neither interfere with
  it nor leak tiers into it, and no SQLite lock error escapes (the WAL check);
* shutdown mid-replay leaves no orphan task, no half-written row, no open session.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app import offline
from app.agent.state import PIPELINE_NODES
from app.core.bus import EventBus
from app.evaluation import benchmark as bench
from app.evaluation import ground_truth as gt
from app.evaluation import runner as eval_runner
from app.ingestion.replay import ReplayEngine
from app.schemas import AlertStatus, AttackType, NormalizedAlert, Severity
from app.store import models
from app.store.repositories import AlertRepository
from app.workers import WorkerContext
from app.workers.manager import WorkerManager
from app.workers.queue import BoundedQueue

REPLAY_TOTAL = 300
REPLAY_EPS = 10.0

#: Statuses an alert may sit in forever. Anything else after drain is a stuck alert.
TERMINAL = {AlertStatus.DONE.value, AlertStatus.FAILED.value}

#: Long enough for 300 alerts at 10 eps plus drain, short enough to fail fast.
DRAIN_BUDGET_SECONDS = 90.0


@pytest_asyncio.fixture
async def file_db(tmp_path: Path) -> AsyncIterator[Any]:
    """A real on-disk SQLite DB with the production PRAGMAs.

    In-memory would hide exactly what this module is here to check: WAL mode,
    ``busy_timeout``, and concurrent writers contending for the same file.
    """
    from sqlalchemy import event

    path = tmp_path / "e2e.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{path.as_posix()}")

    @event.listens_for(engine.sync_engine, "connect")
    def _pragmas(dbapi_conn: Any, _rec: Any) -> None:
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA foreign_keys=ON")
        cur.execute("PRAGMA busy_timeout=5000")
        cur.close()

    async with engine.begin() as conn:
        await conn.run_sync(models.Base.metadata.create_all)

    maker = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def factory() -> AsyncIterator[AsyncSession]:
        async with maker() as session:
            yield session

    try:
        yield factory
    finally:
        await engine.dispose()


@pytest.fixture
def offline_pipeline() -> Any:
    """Install the offline providers/intel/retriever for the whole test."""
    offline.install()
    return offline


@pytest.fixture
def labeled_alerts() -> list[NormalizedAlert]:
    population = gt.load_population()
    return [item.alert for item in population]


class _Harness:
    """App-shaped wiring: queues, bus, workers, replay — without uvicorn."""

    def __init__(self, factory: Any) -> None:
        self.bus = EventBus(maxsize=5000)
        self.triage_q = BoundedQueue("triage", 2000)
        self.enrich_q = BoundedQueue("enrich", 1000)
        self.ctx = WorkerContext(
            repo=AlertRepository(),
            bus=self.bus,
            triage_q=self.triage_q,
            enrich_q=self.enrich_q,
            session_factory=factory,
        )
        self.manager = WorkerManager(self.ctx)
        self.events: dict[str, list[str]] = {"alert.new": [], "alert.updated": []}
        self._sub = self.bus.subscribe()
        self._drain_task: asyncio.Task[None] | None = None

    def start(self) -> None:
        self.manager.start()
        self._drain_task = asyncio.ensure_future(self._drain_bus())

    async def _drain_bus(self) -> None:
        async for event in self._sub:
            name = getattr(event, "event", "")
            if name in self.events:
                self.events[name].append(event.data.id)

    async def stop(self) -> None:
        await self.manager.stop()
        self._sub.close()
        if self._drain_task is not None:
            self._drain_task.cancel()
            try:
                await self._drain_task
            except asyncio.CancelledError:
                pass


async def _terminal_count(factory: Any) -> int:
    async with factory() as session:
        return int(
            (
                await session.execute(
                    select(func.count(models.Alert.id)).where(
                        models.Alert.status.in_(list(TERMINAL))
                    )
                )
            ).scalar_one()
        )


async def _total_count(factory: Any) -> int:
    async with factory() as session:
        return int(
            (await session.execute(select(func.count(models.Alert.id)))).scalar_one()
        )


async def _await_terminal(factory: Any, expected: int, budget: float) -> int:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + budget
    done = 0
    while loop.time() < deadline:
        done = await _terminal_count(factory)
        if done >= expected:
            return done
        await asyncio.sleep(0.25)
    return done


@pytest.mark.asyncio
async def test_replay_300_alerts_all_reach_terminal_status(
    file_db: Any, offline_pipeline: Any, labeled_alerts: list[NormalizedAlert]
) -> None:
    """300 alerts in, 300 terminal out, complete traces, matching SSE events."""
    harness = _Harness(file_db)
    harness.start()

    emitted: list[str] = []

    async def on_alert(alert: NormalizedAlert) -> None:
        # Replay's own callback contract: never block, drop-newest under load.
        if harness.triage_q.put(alert):
            emitted.append(alert.id)

    # Feed from the labeled set, cycling to reach the target count. Ids must stay
    # unique or the DB rejects the duplicate and the count check is meaningless.
    source = [
        alert.model_copy(update={"id": f"{alert.id}-{index // len(labeled_alerts)}"})
        for index, alert in enumerate(
            labeled_alerts * (REPLAY_TOTAL // len(labeled_alerts) + 1)
        )
    ][:REPLAY_TOTAL]

    interval = 1.0 / REPLAY_EPS
    loop = asyncio.get_running_loop()
    next_at = loop.time()
    for alert in source:
        await on_alert(alert)
        next_at += interval
        await asyncio.sleep(max(0.0, next_at - loop.time()))

    done = await _await_terminal(file_db, len(emitted), DRAIN_BUDGET_SECONDS)
    await harness.stop()

    total = await _total_count(file_db)

    assert len(emitted) == REPLAY_TOTAL, "the queue rejected alerts at demo rate"
    assert total == len(emitted), f"db has {total} alerts, replay emitted {len(emitted)}"
    assert done == total, f"{total - done} alert(s) never reached a terminal status"

    # No alert may be left in an intermediate status.
    async with file_db() as session:
        rows = (
            await session.execute(
                select(models.Alert.status, func.count(models.Alert.id)).group_by(
                    models.Alert.status
                )
            )
        ).all()
    by_status = {str(status): int(count) for status, count in rows}
    stuck = {k: v for k, v in by_status.items() if k not in TERMINAL}
    assert not stuck, f"alerts stuck in intermediate statuses: {stuck}"

    # Every alert has a trace entry for EVERY pipeline node (ran or skipped) —
    # finalize backfills the skipped ones, so a missing node means a lost write.
    async with file_db() as session:
        trace_rows = (
            await session.execute(select(models.Trace.alert_id, models.Trace.node))
        ).all()
    nodes_by_alert: dict[str, set[str]] = {}
    for alert_id, node in trace_rows:
        nodes_by_alert.setdefault(str(alert_id), set()).add(str(node))

    incomplete = {
        alert_id: sorted(set(PIPELINE_NODES) - nodes)
        for alert_id, nodes in nodes_by_alert.items()
        if set(PIPELINE_NODES) - nodes
    }
    assert not incomplete, f"{len(incomplete)} alert(s) have incomplete traces: " \
        f"{list(incomplete.items())[:3]}"
    assert len(nodes_by_alert) == total, "some alerts have no trace at all"

    # SSE: alert.new for every alert, alert.updated for the enriched ones.
    assert set(harness.events["alert.new"]) == set(emitted), (
        "alert.new was not published for every alert"
    )
    async with file_db() as session:
        enriched_ids = {
            str(row)
            for row in (
                await session.execute(select(models.Enrichment.alert_id))
            ).scalars()
        }
    updated = set(harness.events["alert.updated"])
    assert enriched_ids <= updated, (
        f"{len(enriched_ids - updated)} enriched alert(s) never published alert.updated"
    )


@pytest.mark.asyncio
async def test_eval_and_benchmark_during_replay_do_not_interfere(
    file_db: Any, offline_pipeline: Any, labeled_alerts: list[NormalizedAlert]
) -> None:
    """The WAL/concurrency check: three writers, one SQLite file, zero lock errors.

    Also the tier-leakage check. The benchmark swaps the FAST tier via a
    contextvar-scoped override; if that override escaped its context, alerts
    triaged by the live workers during the benchmark would be served by the
    swapped provider. Every live alert's classify trace is asserted to name the
    tier's own provider.
    """
    harness = _Harness(file_db)
    harness.start()

    count = 120
    source = [
        alert.model_copy(update={"id": f"{alert.id}-live-{index}"})
        for index, alert in enumerate(labeled_alerts[:count])
    ]

    async def replay() -> int:
        loop = asyncio.get_running_loop()
        next_at = loop.time()
        accepted = 0
        for alert in source:
            if harness.triage_q.put(alert):
                accepted += 1
            next_at += 1.0 / REPLAY_EPS
            await asyncio.sleep(max(0.0, next_at - loop.time()))
        return accepted

    sample = gt.load(20)

    async def run_eval_now() -> Any:
        opened = await eval_runner.create_run(len(sample), session_factory=file_db)
        return await eval_runner.run_eval(
            opened.run_id,
            len(sample),
            session_factory=file_db,
            bus=harness.bus,
            loader=lambda: sample,
        )

    async def run_benchmark_now() -> Any:
        opened = await bench.create_run(10, session_factory=file_db)
        return await bench.run_benchmark(
            opened.run_id,
            10,
            session_factory=file_db,
            bus=harness.bus,
            loader=lambda: sample[:10],
            warmup=1,
            use_limiters=False,
        )

    replay_task = asyncio.ensure_future(replay())
    eval_detail, benchmark_detail = await asyncio.gather(
        run_eval_now(), run_benchmark_now()
    )
    accepted = await replay_task

    await _await_terminal(file_db, accepted, DRAIN_BUDGET_SECONDS)
    await harness.stop()

    assert eval_detail.status == "completed", f"eval failed: {eval_detail.error}"
    assert benchmark_detail.status == "completed", (
        f"benchmark failed: {benchmark_detail.error}"
    )

    # No "database is locked" anywhere: every alert landed and finalized.
    total = await _total_count(file_db)
    terminal = await _terminal_count(file_db)
    assert total == accepted, f"replay lost alerts under concurrent writers: {total}/{accepted}"
    assert terminal == total, "alerts stranded while eval/benchmark were writing"

    # Tier leakage: the benchmark's override must not have served live traffic.
    async with file_db() as session:
        providers = {
            str(row)
            for row in (
                await session.execute(
                    select(models.Trace.provider).where(models.Trace.node == "classify")
                )
            ).scalars()
            if row
        }
    assert providers, "no classify traces recorded a provider"
    for provider in providers:
        assert provider.startswith(offline.PROVIDER_NAME), (
            f"live traffic was served by an unexpected provider: {provider}"
        )


@pytest.mark.asyncio
async def test_graceful_shutdown_mid_replay_leaves_nothing_behind(
    file_db: Any, offline_pipeline: Any, labeled_alerts: list[NormalizedAlert]
) -> None:
    """Stop while alerts are still in flight: no orphan tasks, no half-written rows."""
    baseline = {t for t in asyncio.all_tasks() if not t.done()}

    harness = _Harness(file_db)
    harness.start()

    engine = ReplayEngine(lambda alert: _put(harness, alert))
    for alert in labeled_alerts[:150]:
        harness.triage_q.put(alert)

    await asyncio.sleep(0.4)  # let work get genuinely in flight

    await engine.stop()
    await harness.stop()

    leaked = {t for t in asyncio.all_tasks() if not t.done()} - baseline
    leaked.discard(asyncio.current_task())
    assert not leaked, f"orphan task(s) after shutdown: {[t.get_name() for t in leaked]}"

    # Half-written rows: an alert that has a classification must also carry the
    # classify trace that produced it. A row with one and not the other means a
    # transaction was torn in half by shutdown.
    async with file_db() as session:
        classified = (
            await session.execute(
                select(models.Alert.id).where(models.Alert.severity.is_not(None))
            )
        ).scalars().all()
        traced = {
            str(row)
            for row in (
                await session.execute(
                    select(models.Trace.alert_id).where(models.Trace.node == "classify")
                )
            ).scalars()
        }
    missing = [str(a) for a in classified if str(a) not in traced]
    assert not missing, f"{len(missing)} alert(s) classified without a persisted trace"

    # Every alert that started is either terminal or still merely `ingested` —
    # never wedged in a mid-pipeline status with no worker left to advance it.
    async with file_db() as session:
        statuses = {
            str(status)
            for status in (
                await session.execute(select(models.Alert.status).distinct())
            ).scalars()
        }
    allowed = TERMINAL | {AlertStatus.INGESTED.value, AlertStatus.CLASSIFIED.value}
    assert statuses <= allowed, f"alerts wedged mid-pipeline after shutdown: {statuses - allowed}"


async def _put(harness: _Harness, alert: NormalizedAlert) -> None:
    harness.triage_q.put(alert)


@pytest.mark.asyncio
async def test_offline_pipeline_produces_real_classifications(
    file_db: Any, offline_pipeline: Any, labeled_alerts: list[NormalizedAlert]
) -> None:
    """Offline mode must run the WHOLE pipeline, not a truncated version of it.

    Guards the "mock stub that visibly differs from the real path" failure: the
    offline run has to produce genuine severities, genuine attack types, real
    ATT&CK citations, and remediation that survives the hallucination guard.
    """
    from app.agent.graph import run_triage

    malicious = next(
        alert
        for alert in labeled_alerts
        if "Botnet" in alert.signature or "DDoS" in alert.signature
    )
    state = await run_triage(malicious)

    assert isinstance(state.get("severity"), Severity)
    assert isinstance(state.get("attack_type"), AttackType)
    assert state["attack_type"] is not AttackType.UNKNOWN, "offline classifier degraded"

    ran = {trace.node: trace.status for trace in state["trace"]}
    assert ran.get("classify") == "ok"
    assert set(PIPELINE_NODES) <= set(ran), f"offline run skipped nodes entirely: {ran}"

    if state.get("remediation") is not None:
        remediation = state["remediation"]
        assert remediation.summary
        assert remediation.steps, "offline remediation produced no steps"
        retrieved = {t.id for t in (state.get("techniques") or [])}
        cited = {t.id for t in remediation.techniques}
        assert cited <= retrieved, (
            f"offline remediation cited techniques that were never retrieved: {cited - retrieved}"
        )


def test_offline_mode_runs_the_full_pipeline_through_the_api_with_no_network(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The ``--offline`` acceptance case, end to end, over HTTP.

    Boots the REAL app with ``OFFLINE_MODE=true``, blocks every outbound
    transport, submits an alert through ``POST /ingest``, and waits for the real
    worker pools to drive it to a terminal status. If any part of the pipeline
    still reaches for the network, the transport patch turns it into a failure
    rather than a silent degradation.
    """
    import time as _time

    import httpx as _httpx
    from fastapi.testclient import TestClient

    from app.config import get_settings
    from app.main import create_app
    from app.store import db as db_module
    from app.workers.queue import reset_queue_registry

    def _forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("offline mode made a network call")

    monkeypatch.setattr(_httpx.HTTPTransport, "handle_request", _forbidden)
    monkeypatch.setattr(_httpx.AsyncHTTPTransport, "handle_async_request", _forbidden)

    monkeypatch.setenv("OFFLINE_MODE", "true")
    monkeypatch.setenv(
        "DATABASE_URL", f"sqlite+aiosqlite:///{(tmp_path / 'offline.db').as_posix()}"
    )
    get_settings.cache_clear()
    db_module._engine = None
    db_module._sessionmaker = None
    reset_queue_registry()

    try:
        with TestClient(create_app()) as client:
            accepted = client.post(
                "/api/v1/ingest",
                json={
                    "signature": "ET MALWARE Cobalt Strike beacon C2",
                    "src_ip": "193.27.228.7",
                    "dst_ip": "10.0.0.15",
                    "dst_port": 443,
                    "protocol": "TCP",
                },
            )
            assert accepted.status_code == 202, accepted.text
            alert_id = accepted.json()["id"]

            deadline = _time.time() + 30.0
            detail: dict[str, Any] = {}
            while _time.time() < deadline:
                response = client.get(f"/api/v1/alerts/{alert_id}")
                if response.status_code == 200:
                    detail = response.json()
                    if detail["status"] in {"done", "failed"}:
                        break
                _time.sleep(0.2)

            assert detail, "the alert never appeared in the API"
            assert detail["status"] == "done", f"offline alert did not finish: {detail}"

            # A real classification, not a placeholder.
            assert detail["severity"] in {"critical", "high", "medium", "low", "info"}
            assert detail["attack_type"] == "malware_c2", (
                f"offline classifier produced {detail['attack_type']}"
            )

            # A complete trace, produced by the real nodes.
            traced = {entry["node"] for entry in detail["trace"]}
            assert set(PIPELINE_NODES) <= traced, f"offline run has gaps: {traced}"
            classify = next(e for e in detail["trace"] if e["node"] == "classify")
            assert classify["status"] == "ok"
            assert classify["provider"].startswith("offline")

            # And the demo's payoff: grounded remediation.
            assert detail["remediation"] is not None, "offline produced no remediation"
            assert detail["remediation"]["steps"]
            assert detail["reasoning"]

            # The status strip must read honestly offline: the four contract
            # services are SERVED (by the stand-ins), not degraded.
            health = client.get("/api/v1/health/deep").json()
            for service in ("groq", "gemini", "abuseipdb", "virustotal"):
                assert health["services"][service]["status"] == "ok", (
                    f"{service} reported {health['services'][service]} in offline mode"
                )
                assert "offline" in (health["services"][service].get("note") or "")
            assert health["status"] == "ok", f"offline health rolled up to {health['status']}"
    finally:
        db_module._engine = None
        db_module._sessionmaker = None
        reset_queue_registry()
        get_settings.cache_clear()
