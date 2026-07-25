"""Eval harness integration tests — sampling, the denominator, and run status.

The pipeline itself is injected (``triage_fn``) so these run without an LLM, but
the things that decide whether the published numbers are honest — stratification,
failures staying in the denominator, and a run never being stranded in
``running`` — are exercised against the real DB and the real runner.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Sequence
from pathlib import Path
from typing import Any

import httpx
import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.agent import graph as graph_mod
from app.core.bus import EventBus
from app.deps import get_bus, get_db_session
from app.evaluation import ground_truth as gt
from app.evaluation import runner as runner_mod
from app.evaluation.runner import run_eval
from app.main import create_app
from app.schemas import AttackType, EvalRunDetail, Severity, TraceNode
from app.store.repositories import EvalRunRepository

pytestmark = pytest.mark.asyncio

CSV_HEADER = (
    "Flow ID,Source IP,Source Port,Destination IP,Destination Port,"
    "Protocol,Timestamp,Flow Duration,Label\n"
)

# label -> rows. Deliberately skewed like the real dataset: benign dominates and
# two attack classes are down in the noise.
POPULATION = {
    "BENIGN": 80,
    "PortScan": 10,
    "DDoS": 6,
    "Web Attack - Brute Force": 4,
    "SSH-Patator": 3,
    "Bot": 2,
}

EXPECTED_LABELS = {"benign", "port_scan", "ddos", "web_attack", "brute_force", "malware_c2"}


def _write_dataset(tmp_path: Path, extra: dict[str, int] | None = None) -> Path:
    """A CICIDS2017-shaped CSV with a controlled label distribution."""
    path = tmp_path / "labeled.csv"
    lines = [CSV_HEADER]
    counter = 0
    for label, count in {**POPULATION, **(extra or {})}.items():
        for _ in range(count):
            counter += 1
            octet_a, octet_b = divmod(counter, 250)
            src = f"45.{octet_a}.{octet_b}.9"
            flow = f"{src}-10.0.0.5-{40000 + counter}-443-6"
            lines.append(
                f"{flow},{src},{40000 + counter},10.0.0.5,443,6,"
                f"05/07/2017 09:00:00,120,{label}\n"
            )
    path.write_text("".join(lines), encoding="utf-8")
    return path


def _loader(dataset: Path, sample_size: int, seed: int = 7) -> Any:
    def _load() -> Sequence[gt.LabeledAlert]:
        return gt.load(sample_size, path=dataset, seed=seed)

    return _load


class RecordingTriage:
    """Stands in for ``run_triage`` and records exactly how it was called."""

    def __init__(
        self,
        *,
        fail_every: int | None = None,
        degrade_every: int | None = None,
        on_call: Any = None,
    ) -> None:
        self.calls: list[dict[str, Any]] = []
        self.fail_every = fail_every
        self.degrade_every = degrade_every
        self.on_call = on_call

    async def __call__(
        self, alert: Any, config: dict[str, Any] | None = None, stop_after: str | None = None
    ) -> dict[str, Any]:
        index = len(self.calls)
        self.calls.append({"alert": alert, "config": config, "stop_after": stop_after})
        if self.on_call is not None:
            await self.on_call(index)

        if self.fail_every and index % self.fail_every == 0:
            raise RuntimeError("provider exploded")
        if self.degrade_every and index % self.degrade_every == 0:
            # What the classify node itself returns when the provider fails.
            return {
                "severity": Severity.MEDIUM,
                "attack_type": AttackType.UNKNOWN,
                "trace": [
                    TraceNode(
                        node="classify",
                        status="failed",
                        duration_ms=3,
                        note="classification failed, defaulted to medium/unknown",
                    )
                ],
                "errors": ["classify: boom"],
            }

        # Otherwise: predict the truth, so the honest cases score perfectly.
        label = alert.ground_truth_label or "benign"
        return {
            "severity": gt.LABEL_TO_SEVERITY.get(label, Severity.MEDIUM),
            "attack_type": gt.LABEL_TO_ATTACK_TYPE.get(label, AttackType.UNKNOWN),
            "trace": [TraceNode(node="classify", status="ok", duration_ms=5)],
        }


@pytest_asyncio.fixture
async def maker(db_engine: Any) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(db_engine, expire_on_commit=False, class_=AsyncSession)


@pytest.fixture
def dataset(tmp_path: Path) -> Path:
    return _write_dataset(tmp_path)


async def _open_run(maker: async_sessionmaker[AsyncSession], sample_size: int) -> str:
    async with maker() as session:
        detail = await EvalRunRepository().create(session, sample_size=sample_size)
        await session.commit()
    return detail.run_id


async def _fetch(maker: async_sessionmaker[AsyncSession], run_id: str) -> EvalRunDetail:
    async with maker() as session:
        detail = await EvalRunRepository().get(session, run_id)
    assert detail is not None
    return detail


# --------------------------------------------------------------------- ground truth


async def test_stratified_sample_contains_every_label(dataset: Path) -> None:
    sample = gt.load(20, path=dataset, seed=7)

    assert len(sample) == 20
    assert set(gt.support(sample)) == EXPECTED_LABELS
    assert all(count >= 1 for count in gt.support(sample).values())
    # A uniform draw of 20 from a 79%-benign population would very likely miss
    # Bot (2/105) entirely; stratification must not.
    assert gt.support(sample)["malware_c2"] >= 1


async def test_benign_rows_are_not_lost_to_the_replay_downsampler(dataset: Path) -> None:
    """The ingestion parser keeps 1-in-10 benign flows; ground truth keeps all."""
    from app.ingestion.parsers import cicids

    population = gt.load_population(dataset)
    assert gt.support(population)["benign"] == POPULATION["BENIGN"]
    # and the parser's live-demo behaviour is restored afterwards
    assert cicids.BENIGN_SAMPLE_EVERY == 10


async def test_sampling_is_deterministic_for_a_fixed_seed(dataset: Path) -> None:
    first = [item.alert.id for item in gt.load(20, path=dataset, seed=7)]
    second = [item.alert.id for item in gt.load(20, path=dataset, seed=7)]
    other = [item.alert.id for item in gt.load(20, path=dataset, seed=99)]

    assert first == second
    assert first != other  # a different seed really does draw differently


async def test_low_support_classes_are_flagged(dataset: Path) -> None:
    sample = gt.load(12, path=dataset, seed=7)
    flagged = gt.low_support_labels(sample)

    assert "malware_c2" in flagged  # 2 rows in the population, cannot be dense here
    assert all(gt.support(sample)[label] < gt.LOW_SUPPORT_THRESHOLD for label in flagged)


async def test_unmappable_labels_are_excluded_not_guessed(tmp_path: Path) -> None:
    dataset = _write_dataset(tmp_path, extra={"Some Future Attack": 5})
    population = gt.load_population(dataset)

    assert "unknown" not in gt.support(population)
    assert len(population) == sum(POPULATION.values())


async def test_sample_smaller_than_the_class_count_is_refused(dataset: Path) -> None:
    with pytest.raises(gt.GroundTruthError, match="support >= 1"):
        gt.load(3, path=dataset, seed=7)


async def test_missing_ground_truth_raises(tmp_path: Path) -> None:
    with pytest.raises(gt.GroundTruthError):
        gt.load_population(tmp_path / "nothing-here.csv")


# -------------------------------------------------------------------------- runner


async def test_runner_uses_the_production_graph_by_default() -> None:
    """The eval must not have its own classifier hiding behind the same name."""
    assert runner_mod.run_triage is graph_mod.run_triage


async def test_skip_enrich_uses_the_live_fast_path_mechanism(
    maker: async_sessionmaker[AsyncSession], dataset: Path
) -> None:
    triage = RecordingTriage()
    run_id = await _open_run(maker, 10)

    await run_eval(
        run_id,
        10,
        session_factory=maker,
        bus=EventBus(maxsize=200),
        loader=_loader(dataset, 10),
        triage_fn=triage,
        skip_enrich=True,
    )
    # identical to what the triage worker does on the fast path
    assert {call["stop_after"] for call in triage.calls} == {"classify"}

    triage_full = RecordingTriage()
    run_id = await _open_run(maker, 10)
    await run_eval(
        run_id,
        10,
        session_factory=maker,
        bus=EventBus(maxsize=200),
        loader=_loader(dataset, 10),
        triage_fn=triage_full,
        skip_enrich=False,
    )
    assert {call["stop_after"] for call in triage_full.calls} == {None}


async def test_run_transitions_running_to_completed_and_scores_both_targets(
    maker: async_sessionmaker[AsyncSession], dataset: Path
) -> None:
    observed: list[str] = []

    async def _peek(index: int) -> None:
        if index == 0:
            observed.append((await _fetch(maker, run_id)).status)

    run_id = await _open_run(maker, 20)
    assert (await _fetch(maker, run_id)).status == "running"

    detail = await run_eval(
        run_id,
        20,
        session_factory=maker,
        bus=EventBus(maxsize=200),
        loader=_loader(dataset, 20),
        triage_fn=RecordingTriage(on_call=_peek),
    )

    assert observed == ["running"]  # still running while alerts are in flight
    assert detail.status == "completed"
    assert detail.completed_at is not None
    assert detail.sample_size == 20

    # severity target in the contract fields
    assert detail.overall is not None
    assert detail.overall.accuracy == 1.0  # the fake predicts the truth
    assert detail.confusion_matrix is not None
    assert detail.confusion_matrix.labels == [s.value for s in Severity]
    assert sum(sum(row) for row in detail.confusion_matrix.matrix) == 20

    # attack-type target reported separately, never folded into the first
    assert detail.attack_type is not None
    assert detail.attack_type.overall.accuracy == 1.0
    assert sum(sum(row) for row in detail.attack_type.confusion_matrix.matrix) == 20
    assert set(detail.attack_type.confusion_matrix.labels) <= {a.value for a in AttackType}

    # the DB agrees with the returned object
    assert (await _fetch(maker, run_id)).status == "completed"


@pytest.mark.parametrize("mode", ["raises", "degrades"])
async def test_failed_classifications_are_scored_unknown_not_dropped(
    maker: async_sessionmaker[AsyncSession], dataset: Path, mode: str
) -> None:
    """The denominator is sacred: every sampled alert produces a prediction."""
    sample_size = 20
    triage = RecordingTriage(
        fail_every=3 if mode == "raises" else None,
        degrade_every=3 if mode == "degrades" else None,
    )
    run_id = await _open_run(maker, sample_size)

    detail = await run_eval(
        run_id,
        sample_size,
        session_factory=maker,
        bus=EventBus(maxsize=200),
        loader=_loader(dataset, sample_size),
        triage_fn=triage,
    )

    assert detail.status == "completed"
    assert detail.sample_size == sample_size
    assert len(triage.calls) == sample_size

    # nothing vanished: both matrices still total the full sample
    assert detail.confusion_matrix is not None
    assert sum(sum(row) for row in detail.confusion_matrix.matrix) == sample_size
    assert sum(c.support for c in detail.per_class) == sample_size

    assert detail.attack_type is not None
    attack = detail.attack_type
    assert sum(sum(row) for row in attack.confusion_matrix.matrix) == sample_size
    assert sum(c.support for c in attack.per_class) == sample_size

    # the failures landed on unknown / medium rather than disappearing
    failures = len([i for i in range(sample_size) if i % 3 == 0])
    labels = attack.confusion_matrix.labels
    unknown_column = labels.index(AttackType.UNKNOWN.value)
    predicted_unknown = sum(row[unknown_column] for row in attack.confusion_matrix.matrix)
    assert predicted_unknown == failures

    medium_column = detail.confusion_matrix.labels.index(Severity.MEDIUM.value)
    predicted_medium = sum(row[medium_column] for row in detail.confusion_matrix.matrix)
    assert predicted_medium >= failures

    # and they cost the score — a dropped failure would have left accuracy at 1.0
    assert detail.overall is not None
    assert detail.overall.accuracy < 1.0


async def test_run_transitions_running_to_failed_on_an_injected_exception(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    def _explode() -> Sequence[gt.LabeledAlert]:
        raise RuntimeError("ground truth is on fire")

    run_id = await _open_run(maker, 10)
    bus = EventBus(maxsize=200)
    sub = bus.subscribe()

    detail = await run_eval(
        run_id, 10, session_factory=maker, bus=bus, loader=_explode, triage_fn=RecordingTriage()
    )

    assert detail.status == "failed"
    assert "ground truth is on fire" in (detail.error or "")
    assert detail.completed_at is not None
    stored = await _fetch(maker, run_id)
    assert stored.status == "failed"  # never stranded in `running`
    assert "ground truth is on fire" in (stored.error or "")

    events = []
    while True:
        try:
            events.append(await asyncio.wait_for(sub.__anext__(), 0.05))
        except TimeoutError:
            break
    sub.close()
    assert any(e.data.level == "error" for e in events)


async def test_progress_notices_are_published(
    maker: async_sessionmaker[AsyncSession], dataset: Path
) -> None:
    bus = EventBus(maxsize=200)
    sub = bus.subscribe()
    run_id = await _open_run(maker, 20)

    await run_eval(
        run_id,
        20,
        session_factory=maker,
        bus=bus,
        loader=_loader(dataset, 20),
        triage_fn=RecordingTriage(),
    )

    messages = []
    while True:
        try:
            event = await asyncio.wait_for(sub.__anext__(), 0.05)
        except TimeoutError:
            break
        messages.append(event.data.message)
    sub.close()

    progress = [m for m in messages if "alerts scored" in m]
    assert len(progress) >= 10  # every 10%
    assert any("100%" in m for m in progress)
    assert any("complete" in m and "macro-F1" in m for m in messages)
    # the determinism caveat is published, not implied
    assert any("LLM decoding may still vary" in m for m in messages)


async def test_partial_metrics_are_persisted_while_running(
    maker: async_sessionmaker[AsyncSession], dataset: Path
) -> None:
    """A long run must not be a blank panel — each decile is persisted."""
    gate = asyncio.Event()

    async def _hold_back_the_tail(index: int) -> None:
        if index >= 12:
            await gate.wait()

    run_id = await _open_run(maker, 20)
    task = asyncio.create_task(
        run_eval(
            run_id,
            20,
            session_factory=maker,
            bus=EventBus(maxsize=200),
            loader=_loader(dataset, 20),
            triage_fn=RecordingTriage(on_call=_hold_back_the_tail),
            concurrency=1,
        )
    )

    mid = None
    for _ in range(200):
        await asyncio.sleep(0.02)
        candidate = await _fetch(maker, run_id)
        if candidate.overall is not None:
            mid = candidate
            break

    assert mid is not None, "no partial report was persisted mid-run"
    assert mid.status == "running"  # partial data must not read as final
    assert 0 < sum(c.support for c in mid.per_class) < 20

    gate.set()
    final = await task
    assert final.status == "completed"
    assert sum(c.support for c in final.per_class) == 20


# ----------------------------------------------------------------------- HTTP layer


@pytest_asyncio.fixture
async def client(
    maker: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> AsyncIterator[httpx.AsyncClient]:
    """The real app with the DB and bus injected; the runner stubbed out."""
    from app.api.routes import evaluation as eval_routes

    async def _never_finishes(run_id: str, sample_size: int, **_: Any) -> EvalRunDetail:
        # Leaves the row in `running`, which is exactly the in-flight state.
        return EvalRunDetail(run_id=run_id, status="running", sample_size=sample_size)

    monkeypatch.setattr(eval_routes, "run_eval", _never_finishes)

    app = create_app()

    async def _session() -> AsyncIterator[AsyncSession]:
        async with maker() as session:
            yield session

    app.dependency_overrides[get_db_session] = _session
    app.dependency_overrides[get_bus] = lambda: EventBus(maxsize=50)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
        yield http


async def test_post_run_returns_202_and_a_run_id(client: httpx.AsyncClient) -> None:
    resp = await client.post("/api/v1/evaluation/run", json={"sample_size": 25})

    assert resp.status_code == 202
    body = resp.json()
    assert set(body) == {"run_id", "status"}
    assert body["status"] == "running"

    detail = await client.get(f"/api/v1/evaluation/runs/{body['run_id']}")
    assert detail.status_code == 200
    assert detail.json()["sample_size"] == 25


async def test_second_run_while_one_is_in_flight_is_409(client: httpx.AsyncClient) -> None:
    first = await client.post("/api/v1/evaluation/run", json={"sample_size": 10})
    assert first.status_code == 202

    second = await client.post("/api/v1/evaluation/run", json={"sample_size": 10})
    assert second.status_code == 409
    body = second.json()
    assert body["error"]["code"] == "conflict"
    assert first.json()["run_id"] in body["error"]["message"]


async def test_concurrent_posts_only_start_one_run(client: httpx.AsyncClient) -> None:
    """Two POSTs in the same tick must not both slip past the in-flight check."""
    responses = await asyncio.gather(
        client.post("/api/v1/evaluation/run", json={"sample_size": 10}),
        client.post("/api/v1/evaluation/run", json={"sample_size": 10}),
    )
    codes = sorted(r.status_code for r in responses)
    assert codes == [202, 409]

    listed = (await client.get("/api/v1/evaluation/runs")).json()
    assert len(listed) == 1


async def test_get_run_returns_the_contract_shape(
    client: httpx.AsyncClient, maker: async_sessionmaker[AsyncSession], dataset: Path
) -> None:
    run_id = await _open_run(maker, 20)
    await run_eval(
        run_id,
        20,
        session_factory=maker,
        bus=EventBus(maxsize=200),
        loader=_loader(dataset, 20),
        triage_fn=RecordingTriage(degrade_every=4),
    )

    resp = await client.get(f"/api/v1/evaluation/runs/{run_id}")
    assert resp.status_code == 200
    body = resp.json()

    assert set(body) == {
        "run_id",
        "status",
        "sample_size",
        "started_at",
        "completed_at",
        "overall",
        "per_class",
        "confusion_matrix",
        "attack_type",
        "error",
    }
    assert set(body["overall"]) == {"precision", "recall", "f1", "accuracy"}
    assert set(body["per_class"][0]) == {"label", "precision", "recall", "f1", "support"}
    assert set(body["confusion_matrix"]) == {"labels", "matrix"}
    assert body["confusion_matrix"]["labels"] == ["critical", "high", "medium", "low", "info"]
    assert len(body["confusion_matrix"]["matrix"]) == 5
    assert body["started_at"].endswith("Z")
    # per-class support is present so a thin class is visibly thin
    assert all(isinstance(row["support"], int) for row in body["per_class"])


async def test_runs_list_is_summary_only_newest_first(
    client: httpx.AsyncClient, maker: async_sessionmaker[AsyncSession]
) -> None:
    older = await _open_run(maker, 10)
    async with maker() as session:
        await EvalRunRepository().mark_failed(session, older, "boom")
        await session.commit()
    newer = await _open_run(maker, 30)

    resp = await client.get("/api/v1/evaluation/runs")
    assert resp.status_code == 200
    rows = resp.json()

    assert [r["run_id"] for r in rows] == [newer, older]
    assert set(rows[0]) == {
        "run_id",
        "status",
        "sample_size",
        "started_at",
        "completed_at",
        "overall",
        "error",
    }
    assert "confusion_matrix" not in rows[0]
    assert rows[1]["error"] == "boom"


async def test_unknown_run_is_404(client: httpx.AsyncClient) -> None:
    resp = await client.get("/api/v1/evaluation/runs/nope")
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "not_found"
