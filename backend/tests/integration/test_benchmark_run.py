"""Benchmark persistence + HTTP surface — contract §5 conformance.

The fairness properties live in tests/unit/test_benchmark.py. This file covers
what gets stored, what the API returns, and the run lifecycle: 202 + detached
task, one run at a time, failed runs never stranded in `running`.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Sequence
from typing import Any

import httpx
import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.bus import EventBus
from app.deps import get_bus, get_db_session
from app.evaluation import benchmark as bench
from app.evaluation.ground_truth import LabeledAlert
from app.main import create_app
from app.schemas import BenchmarkRunDetail, ProviderTier, Severity
from app.store.repositories import BenchmarkRunRepository
from tests.unit.test_benchmark import (
    LABEL_SEVERITY,
    SAMPLE_LABELS,
    ScriptedProvider,
    _marker,
    _registry,
    _sample,
)


@pytest_asyncio.fixture
async def maker(db_engine: Any) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(db_engine, expire_on_commit=False, class_=AsyncSession)


@pytest.fixture
def sample() -> list[LabeledAlert]:
    return _sample(SAMPLE_LABELS)


def _loader(sample: Sequence[LabeledAlert]) -> Any:
    return lambda: list(sample)


async def _open_run(maker: async_sessionmaker[AsyncSession], sample_size: int) -> str:
    async with maker() as session:
        detail = await BenchmarkRunRepository().create(session, sample_size=sample_size)
        await session.commit()
    return detail.run_id


async def _fetch(maker: async_sessionmaker[AsyncSession], run_id: str) -> BenchmarkRunDetail:
    async with maker() as session:
        detail = await BenchmarkRunRepository().get(session, run_id)
    assert detail is not None
    return detail


def _tiers(
    *, quality_disagrees: bool = True, quality_slow: bool = True
) -> tuple[ScriptedProvider, ScriptedProvider]:
    fast = ScriptedProvider(
        "groq",
        "llama-fast",
        ProviderTier.FAST,
        latency_ms=180.0,
        severity_for=LABEL_SEVERITY,
        tokens=(180, 40),
    )
    quality_map = dict(LABEL_SEVERITY)
    if quality_disagrees:
        quality_map["ddos"] = Severity.CRITICAL
    quality = ScriptedProvider(
        "gemini",
        "gemini-flash",
        ProviderTier.QUALITY,
        latency_ms=1150.0 if quality_slow else 180.0,
        severity_for=quality_map,
        tokens=(520, 90),
    )
    return fast, quality


async def _run(
    maker: async_sessionmaker[AsyncSession],
    sample: Sequence[LabeledAlert],
    *,
    bus: EventBus | None = None,
    run_id: str | None = None,
    **kwargs: Any,
) -> BenchmarkRunDetail:
    fast, quality = kwargs.pop("tiers", None) or _tiers()
    rid = run_id or await _open_run(maker, len(sample))
    return await bench.run_benchmark(
        rid,
        len(sample),
        session_factory=maker,
        bus=bus if bus is not None else EventBus(maxsize=200),
        loader=_loader(sample),
        registry=_registry(fast, quality),
        warmup=1,
        use_limiters=False,
        **kwargs,
    )


async def test_completed_run_persists_the_contract_results_array(
    maker: async_sessionmaker[AsyncSession], sample: list[LabeledAlert]
) -> None:
    detail = await _run(maker, sample)

    assert detail.status == "completed"
    assert detail.sample_size == len(sample)
    assert [r.tier for r in detail.results] == [ProviderTier.FAST, ProviderTier.QUALITY]

    fast, quality = detail.results
    assert (fast.provider, fast.model) == ("groq", "llama-fast")
    assert (quality.provider, quality.model) == ("gemini", "gemini-flash")
    assert fast.avg_latency_ms == 180.0
    assert quality.avg_latency_ms == 1150.0
    assert fast.avg_tokens == 220.0  # 180 in + 40 out
    assert quality.avg_tokens == 610.0
    assert fast.failures == 0

    # survived the round trip
    stored = await _fetch(maker, detail.run_id)
    assert stored.results[0].avg_latency_ms == 180.0
    assert stored.agreement_rate == detail.agreement_rate


async def test_agreement_and_disagreement_examples_are_persisted(
    maker: async_sessionmaker[AsyncSession], sample: list[LabeledAlert]
) -> None:
    detail = await _run(maker, sample)

    # the tiers differ on the single ddos alert out of six
    assert detail.agreement_rate == pytest.approx(5 / 6, abs=1e-4)
    assert len(detail.disagreement_examples) == 1

    example = detail.disagreement_examples[0]
    assert example.fast_prediction == "high"
    assert example.quality_prediction == "critical"
    assert example.ground_truth == "high"
    assert _marker("ddos") in example.signature

    stored = await _fetch(maker, detail.run_id)
    assert stored.disagreement_examples == detail.disagreement_examples


async def test_warmup_calls_are_not_in_the_persisted_stats(
    maker: async_sessionmaker[AsyncSession], sample: list[LabeledAlert]
) -> None:
    fast, quality = _tiers()
    fast.first_call_latency_ms = 9000.0

    detail = await _run(maker, sample, tiers=(fast, quality))
    fast_result = detail.results[0]

    assert fast_result.warmup_calls == 1
    assert fast_result.calls == len(sample)
    assert fast_result.avg_latency_ms == 180.0  # the 9s cold call is gone
    assert fast_result.max_latency_ms == 180.0


async def test_failed_run_is_marked_failed_with_the_error(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    def _explode() -> Sequence[LabeledAlert]:
        raise RuntimeError("ground truth is on fire")

    run_id = await _open_run(maker, 6)
    bus = EventBus(maxsize=200)
    detail = await bench.run_benchmark(
        run_id,
        6,
        session_factory=maker,
        bus=bus,
        loader=_explode,
        registry=_registry(*_tiers()),
        warmup=0,
        use_limiters=False,
    )

    assert detail.status == "failed"
    assert "ground truth is on fire" in (detail.error or "")
    stored = await _fetch(maker, run_id)
    assert stored.status == "failed"  # never stranded in `running`
    assert stored.completed_at is not None


async def test_missing_tier_key_fails_the_run(
    maker: async_sessionmaker[AsyncSession], sample: list[LabeledAlert]
) -> None:
    fast, quality = _tiers()
    quality.available = False

    detail = await _run(maker, sample, tiers=(fast, quality))

    assert detail.status == "failed"
    assert "not a comparison" in (detail.error or "")


async def test_start_and_completion_notices_are_published(
    maker: async_sessionmaker[AsyncSession], sample: list[LabeledAlert]
) -> None:
    bus = EventBus(maxsize=200)
    sub = bus.subscribe()

    await _run(maker, sample, bus=bus)

    messages = []
    while True:
        try:
            event = await asyncio.wait_for(sub.__anext__(), 0.05)
        except TimeoutError:
            break
        messages.append(event.data.message)
    sub.close()

    assert any("starting" in m for m in messages)
    completion = next(m for m in messages if "complete" in m)
    assert "groq" in completion and "gemini" in completion
    assert "agreement" in completion


async def test_run_uses_the_same_sampler_as_the_eval_harness() -> None:
    """One loader, one seed — the two panels must score the same alerts."""
    import inspect

    source = inspect.getsource(bench.run_benchmark)
    assert "gt.load(" in source  # ground_truth.load, not a private second sampler
    assert not hasattr(bench, "_sample")  # no rival sampler defined here


@pytest_asyncio.fixture
async def client(
    maker: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> AsyncIterator[httpx.AsyncClient]:
    from app.api.routes import benchmark as benchmark_routes

    async def _never_finishes(run_id: str, sample_size: int, **_: Any) -> BenchmarkRunDetail:
        return BenchmarkRunDetail(run_id=run_id, status="running", sample_size=sample_size)

    monkeypatch.setattr(benchmark_routes, "run_benchmark", _never_finishes)

    app = create_app()

    async def _session() -> AsyncIterator[AsyncSession]:
        async with maker() as session:
            yield session

    app.dependency_overrides[get_db_session] = _session
    app.dependency_overrides[get_bus] = lambda: EventBus(maxsize=50)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
        yield http


async def test_post_run_returns_202_with_a_run_id(client: httpx.AsyncClient) -> None:
    resp = await client.post("/api/v1/benchmark/run", json={"sample_size": 25})

    assert resp.status_code == 202
    body = resp.json()
    assert set(body) == {"run_id", "status"}
    assert body["status"] == "running"


async def test_sample_size_over_the_cap_is_400_with_a_clear_message(
    client: httpx.AsyncClient,
) -> None:
    from app.config import get_settings

    cap = get_settings().benchmark_max_sample
    resp = await client.post("/api/v1/benchmark/run", json={"sample_size": cap + 1})

    assert resp.status_code == 400
    body = resp.json()
    assert body["error"]["code"] == "validation_error"
    message = body["error"]["message"]
    assert str(cap) in message
    assert "BOTH tiers" in message

    # rejected before a row was opened, so the next run is not blocked
    assert (await client.get("/api/v1/benchmark/runs")).json() == []
    assert (
        await client.post("/api/v1/benchmark/run", json={"sample_size": cap})
    ).status_code == 202


async def test_second_run_while_one_is_in_flight_is_409(client: httpx.AsyncClient) -> None:
    first = await client.post("/api/v1/benchmark/run", json={"sample_size": 5})
    assert first.status_code == 202

    second = await client.post("/api/v1/benchmark/run", json={"sample_size": 5})
    assert second.status_code == 409
    assert second.json()["error"]["code"] == "conflict"
    assert first.json()["run_id"] in second.json()["error"]["message"]


async def test_concurrent_posts_only_start_one_run(client: httpx.AsyncClient) -> None:
    responses = await asyncio.gather(
        client.post("/api/v1/benchmark/run", json={"sample_size": 5}),
        client.post("/api/v1/benchmark/run", json={"sample_size": 5}),
    )
    assert sorted(r.status_code for r in responses) == [202, 409]
    assert len((await client.get("/api/v1/benchmark/runs")).json()) == 1


async def test_get_run_matches_the_contract_shape(
    client: httpx.AsyncClient,
    maker: async_sessionmaker[AsyncSession],
    sample: list[LabeledAlert],
) -> None:
    detail = await _run(maker, sample)

    resp = await client.get(f"/api/v1/benchmark/runs/{detail.run_id}")
    assert resp.status_code == 200
    body = resp.json()

    assert set(body) == {
        "run_id",
        "status",
        "sample_size",
        "started_at",
        "completed_at",
        "results",
        "agreement_rate",
        "disagreement_examples",
        "error",
    }
    contract_fields = {
        "tier",
        "provider",
        "model",
        "avg_latency_ms",
        "p95_latency_ms",
        "accuracy",
        "avg_tokens",
        "failures",
    }
    assert contract_fields <= set(body["results"][0])
    assert [r["tier"] for r in body["results"]] == ["fast", "quality"]
    assert set(body["disagreement_examples"][0]) == {
        "alert_id",
        "signature",
        "fast_prediction",
        "quality_prediction",
        "ground_truth",
    }
    assert body["started_at"].endswith("Z")
    assert 0.0 <= body["agreement_rate"] <= 1.0


async def test_runs_list_is_summary_only_newest_first(
    client: httpx.AsyncClient, maker: async_sessionmaker[AsyncSession]
) -> None:
    older = await _open_run(maker, 5)
    async with maker() as session:
        await BenchmarkRunRepository().mark_failed(session, older, "boom")
        await session.commit()
    newer = await _open_run(maker, 25)

    rows = (await client.get("/api/v1/benchmark/runs")).json()

    assert [r["run_id"] for r in rows] == [newer, older]
    assert set(rows[0]) == {
        "run_id",
        "status",
        "sample_size",
        "started_at",
        "completed_at",
        "agreement_rate",
        "error",
    }
    assert "results" not in rows[0]
    assert rows[1]["error"] == "boom"


async def test_unknown_run_is_404(client: httpx.AsyncClient) -> None:
    resp = await client.get("/api/v1/benchmark/runs/nope")
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "not_found"
