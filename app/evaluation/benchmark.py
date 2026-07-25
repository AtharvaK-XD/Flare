"""Provider benchmark — the "two tiers, distinct roles" claim, made measurable.

An unfair comparison is worse than no comparison, so the fairness rules are
structural rather than conventions to remember:

* **Identical input.** Both tiers score the SAME stratified sample from
  ``ground_truth.load`` (same loader, same seed as the eval harness — there is no
  second sampler), in the same randomized order.
* **Identical prompt and decoding params.** Neither tier gets its own call site.
  Both run through the production ``classify`` node, which builds one prompt and
  passes one ``max_tokens``/``temperature``. The quality provider is swapped in by
  overriding the tier the node asks for, so the node cannot tell the difference —
  and the recorded prompts are asserted byte-identical in the tests.
* **Tier selection via ``ProviderRegistry.override``** (contextvar-scoped, Phase
  4). Never by mutating settings or a module global: a benchmark must not change
  what concurrent live traffic is served by.
* **Sequential tiers.** Running both at once means they contend for CPU, event
  loop and uplink, and both latency numbers become meaningless. One tier finishes
  entirely before the next starts, and the recorded call windows prove it.
* **Warm-up calls discarded** (``settings.benchmark_warmup``). TLS handshake and
  client construction would otherwise be charged entirely to whichever tier ran
  first.
* **Failures are not free.** A failed call is counted as a failure, EXCLUDED from
  latency stats (a call that errored in 40ms is not "fast") and INCLUDED in the
  accuracy denominator (a provider that fails half its calls must not read as
  fast and accurate).

Latency is the provider's own measurement around its API call
(``CompletionResult.latency_ms``), which both providers take the same way.
Rate-limiter waiting happens before the clock starts: queueing for a token is a
property of the free-tier quota, not of the model's speed.

THROTTLING IS REPORTED, NOT HIDDEN
----------------------------------
Our own limiter is bypassed by the clock, but the PROVIDER's server-side
tokens-per-minute ceiling is not: a 429 mid-run costs a retry with a
``Retry-After`` delay of 10s or more, and that delay lands INSIDE the measured
window. Sequential 1.1k-token prompts on Groq's free tier reliably trigger this
(observed: 8.6s tier average against a 248ms unthrottled p50 for the same model).
That is a real free-tier constraint, not a bug to engineer away — but a throttled
run is not a clean latency comparison, so every tier carries a ``throttled`` flag
(plus the retry count) and the report prints it next to the numbers instead of
quietly publishing free-tier queueing as the model's speed.
"""

from __future__ import annotations

import asyncio
import random
import time
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.agent.graph import run_triage
from app.api.errors import BadRequestError, ProviderError
from app.config import get_settings
from app.core.bus import EventBus, get_event_bus
from app.core.logging import get_logger
from app.core.metrics import COST_PER_1K_TOKENS, metrics, percentile
from app.core.retry import is_rate_limit
from app.evaluation import ground_truth as gt
from app.evaluation.metrics import accuracy
from app.evaluation.runner import Prediction, predict_one
from app.providers.base import CompletionResult, LLMProvider
from app.providers.registry import ProviderRegistry, get_registry
from app.schemas import (
    BenchmarkResult,
    BenchmarkRunDetail,
    DisagreementExample,
    ProviderTier,
    SystemNotice,
    SystemNoticeEvent,
)
from app.store.db import get_sessionmaker
from app.store.repositories import BenchmarkRunRepository

log = get_logger(__name__)

#: The node every benchmarked call goes through. Both tiers, one code path.
BENCHMARK_NODE = "classify"

#: Cap on captured disagreements — this is demo evidence, not an export.
MAX_DISAGREEMENT_EXAMPLES = 5

TriageFn = Callable[..., Awaitable[Any]]
Loader = Callable[[], Sequence[gt.LabeledAlert]]


@dataclass
class CallRecord:
    """One provider call, as observed at the provider boundary."""

    alert_id: str
    prompt: str
    max_tokens: int
    temperature: float
    started_at: float
    ended_at: float
    latency_ms: float
    tokens_in: int
    tokens_out: int
    ok: bool
    warmup: bool
    error: str | None = None


@dataclass
class TierRun:
    """Everything one tier produced: raw calls plus per-alert predictions."""

    tier: ProviderTier
    provider: str
    model: str
    records: list[CallRecord] = field(default_factory=list)
    predictions: dict[str, Prediction] = field(default_factory=dict)
    #: Retries this tier's run incurred because of a 429 / TPM throttle. Non-zero
    #: means the latency numbers below include free-tier queueing.
    throttle_retries: int = 0

    @property
    def throttled(self) -> bool:
        return self.throttle_retries > 0

    @property
    def measured(self) -> list[CallRecord]:
        return [r for r in self.records if not r.warmup]

    @property
    def latencies(self) -> list[float]:
        """Successful, non-warm-up calls only — see the module docstring."""
        return [r.latency_ms for r in self.measured if r.ok]


class RecordingProvider:
    """Wraps a tier's provider: rate-limits, times, and records every call.

    Deliberately transparent — it forwards ``complete`` verbatim so the node's
    prompt and decoding params reach the real provider unmodified. It is the only
    place the benchmark touches the call path, which is what keeps the two tiers
    comparable.
    """

    def __init__(self, inner: LLMProvider, limiter: Any = None) -> None:
        self._inner = inner
        self._limiter = limiter
        self.records: list[CallRecord] = []
        self.warmup = False
        self.alert_id = ""
        #: Rate-limit errors that reached this wrapper (retries were exhausted).
        #: Retries that succeeded are counted separately, via the metrics
        #: registry, because they never surface as an exception here.
        self.rate_limit_errors = 0

    @property
    def name(self) -> str:
        return self._inner.name

    @property
    def model(self) -> str:
        return self._inner.model

    @property
    def tier(self) -> ProviderTier:
        return self._inner.tier

    @property
    def available(self) -> bool:
        return bool(getattr(self._inner, "available", True))

    async def health(self) -> Any:
        return await self._inner.health()

    async def complete(self, prompt: str, **kwargs: Any) -> CompletionResult:
        # Token acquisition happens BEFORE the clock starts: waiting for free-tier
        # quota is not the model being slow.
        if self._limiter is not None:
            await self._limiter.acquire(1)

        max_tokens = int(kwargs.get("max_tokens", 512))
        temperature = float(kwargs.get("temperature", 0.0))
        started = time.perf_counter()
        try:
            result = await self._inner.complete(prompt, **kwargs)
        except Exception as exc:
            ended = time.perf_counter()
            if is_rate_limit(exc):
                self.rate_limit_errors += 1
            self.records.append(
                CallRecord(
                    alert_id=self.alert_id,
                    prompt=prompt,
                    max_tokens=max_tokens,
                    temperature=temperature,
                    started_at=started,
                    ended_at=ended,
                    latency_ms=(ended - started) * 1000.0,
                    tokens_in=0,
                    tokens_out=0,
                    ok=False,
                    warmup=self.warmup,
                    error=str(exc),
                )
            )
            raise

        ended = time.perf_counter()
        latency = result.latency_ms or (ended - started) * 1000.0
        self.records.append(
            CallRecord(
                alert_id=self.alert_id,
                prompt=prompt,
                max_tokens=max_tokens,
                temperature=temperature,
                started_at=started,
                ended_at=ended,
                latency_ms=latency,
                tokens_in=result.tokens_in,
                tokens_out=result.tokens_out,
                ok=True,
                warmup=self.warmup,
            )
        )
        return result


def _limiter_for(provider_name: str) -> Any:
    """The existing limiter for this provider, or None if it has none."""
    from app.core.ratelimit import get_limiter_registry

    try:
        return get_limiter_registry().get(provider_name)
    except KeyError:
        log.info("benchmark.no_limiter", provider=provider_name)
        return None


async def run_tier(
    tier: ProviderTier,
    provider: LLMProvider,
    sample: Sequence[gt.LabeledAlert],
    *,
    registry: ProviderRegistry,
    warmup: int,
    triage_fn: TriageFn,
    limiter: Any = None,
) -> TierRun:
    """Score the whole sample on ONE tier, sequentially, warm-up first.

    The override targets the tier the ``classify`` node asks for
    (``ProviderTier.FAST``) rather than ``tier`` itself — that is what routes the
    quality provider through the identical node, prompt and parameters instead of
    a parallel code path built just for benchmarking.
    """
    proxy = RecordingProvider(provider, limiter)
    run = TierRun(tier=tier, provider=provider.name, model=provider.model)

    # Throttling is measured as a DELTA across this tier's window only: a 429
    # retry that happened during the other tier's run, or during live traffic,
    # must not mark this tier throttled.
    retries_before = metrics.rate_limit_retries(provider.name, provider.model)

    with registry.override(ProviderTier.FAST, proxy):
        # Warm-up: same call, same path, results thrown away. predict_one already
        # degrades instead of raising, so a cold-start failure lands in the
        # records tagged `warmup` and is excluded with the rest.
        proxy.warmup = True
        for index in range(warmup):
            item = sample[index % len(sample)]
            proxy.alert_id = item.alert.id
            await predict_one(item, triage_fn, {}, stop_after=BENCHMARK_NODE)
        proxy.warmup = False

        for item in sample:
            proxy.alert_id = item.alert.id
            run.predictions[item.alert.id] = await predict_one(
                item, triage_fn, {}, stop_after=BENCHMARK_NODE
            )

    run.records = proxy.records
    retried = metrics.rate_limit_retries(provider.name, provider.model) - retries_before
    run.throttle_retries = max(0, retried) + proxy.rate_limit_errors
    if run.throttled:
        log.warning(
            "benchmark.tier_throttled",
            tier=tier.value,
            provider=provider.name,
            model=provider.model,
            retries=run.throttle_retries,
            note="latency for this tier includes free-tier queueing and understates the model",
        )
    return run


def _estimated_cost(model: str, tokens_in: int, tokens_out: int) -> float | None:
    """None when the model has no configured price — not 0.0, which reads free."""
    rate = COST_PER_1K_TOKENS.get(model)
    if rate is None:
        return None
    return round(rate * (tokens_in + tokens_out) / 1000.0, 6)


def summarize_tier(run: TierRun, sample: Sequence[gt.LabeledAlert]) -> BenchmarkResult:
    """Latency/accuracy/token stats for one tier, in the contract's shape."""
    measured = run.measured
    latencies = run.latencies
    successes = [r for r in measured if r.ok]

    tokens_in = sum(r.tokens_in for r in successes)
    tokens_out = sum(r.tokens_out for r in successes)
    n_ok = len(successes) or 1  # only ever divides sums that are 0 when there are none

    # Accuracy uses every sampled alert, including the ones whose call failed —
    # those carry the classify node's own unknown/medium fallback.
    predictions = [run.predictions.get(item.alert.id) for item in sample]
    severity_true = [item.expected_severity.value for item in sample]
    severity_pred = [
        (p.severity.value if p is not None else "medium") for p in predictions
    ]
    attack_true = [item.expected_attack_type.value for item in sample]
    attack_pred = [
        (p.attack_type.value if p is not None else "unknown") for p in predictions
    ]

    return BenchmarkResult(
        tier=run.tier,
        provider=run.provider,
        model=run.model,
        avg_latency_ms=round(sum(latencies) / len(latencies), 2) if latencies else 0.0,
        p95_latency_ms=round(percentile(latencies, 95), 2),
        accuracy=round(accuracy(severity_true, severity_pred), 4),
        avg_tokens=round((tokens_in + tokens_out) / n_ok, 2) if successes else 0.0,
        failures=sum(1 for r in measured if not r.ok),
        p50_latency_ms=round(percentile(latencies, 50), 2),
        min_latency_ms=round(min(latencies), 2) if latencies else 0.0,
        max_latency_ms=round(max(latencies), 2) if latencies else 0.0,
        avg_tokens_in=round(tokens_in / n_ok, 2) if successes else 0.0,
        avg_tokens_out=round(tokens_out / n_ok, 2) if successes else 0.0,
        attack_type_accuracy=round(accuracy(attack_true, attack_pred), 4),
        estimated_cost=_estimated_cost(run.model, tokens_in, tokens_out),
        calls=len(measured),
        warmup_calls=len(run.records) - len(measured),
        throttled=run.throttled,
        throttle_retries=run.throttle_retries,
    )


def compare_tiers(
    fast: TierRun, quality: TierRun, sample: Sequence[gt.LabeledAlert]
) -> tuple[float | None, list[DisagreementExample]]:
    """Cross-tier severity agreement plus the alerts behind the number.

    Only alerts where BOTH tiers actually produced a classification are compared:
    two providers that both failed and fell back to ``medium`` have not agreed
    about anything, and counting that as agreement inflates the rate. ``None`` is
    returned when nothing was comparable rather than a fabricated 0.0.
    """
    compared = 0
    matches = 0
    examples: list[DisagreementExample] = []

    for item in sample:
        fast_prediction = fast.predictions.get(item.alert.id)
        quality_prediction = quality.predictions.get(item.alert.id)
        if fast_prediction is None or quality_prediction is None:
            continue
        if fast_prediction.failed or quality_prediction.failed:
            continue

        compared += 1
        if fast_prediction.severity == quality_prediction.severity:
            matches += 1
        elif len(examples) < MAX_DISAGREEMENT_EXAMPLES:
            examples.append(
                DisagreementExample(
                    alert_id=item.alert.id,
                    signature=item.alert.signature,
                    fast_prediction=fast_prediction.severity.value,
                    quality_prediction=quality_prediction.severity.value,
                    ground_truth=item.expected_severity.value,
                )
            )

    rate = round(matches / compared, 4) if compared else None
    return rate, examples


def _notice(bus: EventBus | None, level: str, message: str) -> None:
    if bus is None:
        return
    bus.publish(SystemNoticeEvent(data=SystemNotice(level=level, message=message)))  # type: ignore[arg-type]


def check_sample_size(sample_size: int) -> int:
    """Validate against the cap. Refuses loudly; never truncates silently."""
    cap = get_settings().benchmark_max_sample
    if sample_size < 1:
        raise BadRequestError(f"sample_size must be at least 1, got {sample_size}")
    if sample_size > cap:
        raise BadRequestError(
            f"sample_size {sample_size} exceeds the benchmark cap of {cap}: a benchmark "
            f"runs every alert through BOTH tiers sequentially, so {sample_size} alerts "
            f"would be {sample_size * 2} live LLM calls. Re-run with sample_size <= {cap}."
        )
    return sample_size


async def create_run(
    sample_size: int, *, session_factory: Any = None, run_id: str | None = None
) -> BenchmarkRunDetail:
    """Open a ``running`` row and return it (the API answers 202 from this)."""
    maker = session_factory or get_sessionmaker()
    async with maker() as session:
        detail = await BenchmarkRunRepository().create(
            session, sample_size=sample_size, run_id=run_id
        )
        await session.commit()
    return detail


def _tier_providers(
    registry: ProviderRegistry,
) -> list[tuple[ProviderTier, LLMProvider]]:
    """Both tiers' own providers, ignoring any ambient override."""
    return [
        (ProviderTier.FAST, registry.base_provider(ProviderTier.FAST)),
        (ProviderTier.QUALITY, registry.base_provider(ProviderTier.QUALITY)),
    ]


async def benchmark_tiers(
    sample: Sequence[gt.LabeledAlert],
    *,
    registry: ProviderRegistry | None = None,
    warmup: int | None = None,
    triage_fn: TriageFn | None = None,
    use_limiters: bool = True,
) -> list[TierRun]:
    """Run every tier over the sample, SEQUENTIALLY, and return the raw runs.

    No DB, no bus — this is the measurement itself, kept separable from the
    persistence around it so the fairness properties can be asserted directly.
    """
    reg = registry or get_registry()
    triage = triage_fn or run_triage
    warm = get_settings().benchmark_warmup if warmup is None else warmup
    order = list(sample)

    runs: list[TierRun] = []
    for tier, provider in _tier_providers(reg):
        if not getattr(provider, "available", True):
            raise ProviderError(
                f"{tier.value} tier ({provider.name}) is not configured — a benchmark "
                "with one tier missing is not a comparison"
            )
        # One tier at a time: concurrent tiers would contend and both latency
        # numbers would be noise.
        runs.append(
            await run_tier(
                tier,
                provider,
                order,
                registry=reg,
                warmup=warm,
                triage_fn=triage,
                limiter=_limiter_for(provider.name) if use_limiters else None,
            )
        )
    return runs


async def run_benchmark(
    run_id: str,
    sample_size: int | None = None,
    *,
    session_factory: Any = None,
    bus: EventBus | None = None,
    loader: Loader | None = None,
    registry: ProviderRegistry | None = None,
    triage_fn: TriageFn | None = None,
    warmup: int | None = None,
    seed: int | None = None,
    ground_truth_path: Path | None = None,
    use_limiters: bool = True,
) -> BenchmarkRunDetail:
    """Benchmark both tiers on the labeled sample and persist the report.

    Returns the final detail — ``completed``, or ``failed`` with the error stored.
    Never raises out to the caller (this runs detached as a background task).
    """
    settings = get_settings()
    maker = session_factory or get_sessionmaker()
    event_bus = bus if bus is not None else get_event_bus()
    repo = BenchmarkRunRepository()

    requested = sample_size if sample_size is not None else settings.benchmark_sample_size
    run_seed = seed if seed is not None else settings.eval_seed

    try:
        check_sample_size(requested)

        async with maker() as session:
            if await repo.get(session, run_id) is None:
                await repo.create(session, sample_size=requested, run_id=run_id)
                await session.commit()

        _notice(
            event_bus,
            "info",
            f"benchmark {run_id}: starting on {requested} alerts, both tiers "
            "sequentially (fast first)",
        )

        # The SAME sample the eval harness scores: same loader, same seed.
        # CSV parsing is blocking — off the loop, exactly as the eval runner does
        # it, or the API stalls for the duration of the read.
        def _load() -> Sequence[gt.LabeledAlert]:
            if loader is not None:
                return loader()
            return gt.load(requested, path=ground_truth_path, seed=run_seed)

        sample = list(await asyncio.to_thread(_load))
        if not sample:
            raise gt.GroundTruthError("ground truth produced an empty sample")

        if loader is None:
            health = await asyncio.to_thread(gt.check_label_health, ground_truth_path)
            if not health.ok:
                log.error("benchmark.label_set_unhealthy", detail=health.message())
                _notice(event_bus, "warn", f"benchmark {run_id}: {health.message()}")

        # Same order for both tiers, shuffled so neither tier is handed the
        # easy classes first.
        random.Random(run_seed).shuffle(sample)

        runs = await benchmark_tiers(
            sample,
            registry=registry,
            warmup=warmup,
            triage_fn=triage_fn,
            use_limiters=use_limiters,
        )
        results = [summarize_tier(run, sample) for run in runs]

        by_tier = {run.tier: run for run in runs}
        agreement, examples = compare_tiers(
            by_tier[ProviderTier.FAST], by_tier[ProviderTier.QUALITY], sample
        )

        async with maker() as session:
            detail = await repo.mark_completed(
                session,
                run_id,
                results=results,
                agreement_rate=agreement,
                disagreement_examples=examples,
                sample_size=len(sample),
            )
            await session.commit()

        log.info(
            "benchmark.completed",
            run_id=run_id,
            sample_size=len(sample),
            agreement_rate=agreement,
            tiers={r.tier.value: r.avg_latency_ms for r in results},
            throttled={r.tier.value: r.throttled for r in results},
        )
        throttled_tiers = [r.tier.value for r in results if r.throttled]
        _notice(
            event_bus,
            "warn" if throttled_tiers else "info",
            f"benchmark {run_id} complete: "
            + "; ".join(
                f"{r.tier.value} {r.provider} {r.avg_latency_ms:.0f}ms avg"
                + (f" (THROTTLED, {r.throttle_retries} rate-limit retries)" if r.throttled else "")
                + f", accuracy {r.accuracy:.2f}, {r.failures} failure(s)"
                for r in results
            )
            + (
                f"; WARNING: {', '.join(throttled_tiers)} tier(s) hit the provider's free-tier "
                "rate limit mid-run — their latency includes queueing and understates the model"
                if throttled_tiers
                else ""
            )
            + (
                f"; agreement {agreement:.0%} with {len(examples)} example disagreement(s)"
                if agreement is not None
                else "; agreement unavailable (no alert was classified by both tiers)"
            ),
        )

        if detail is not None:
            return detail
        return await _fail(repo, maker, event_bus, run_id, "run row vanished mid-benchmark")

    except Exception as exc:  # noqa: BLE001 — a run must never stay stuck in `running`
        log.error("benchmark.failed", run_id=run_id, error=str(exc))
        return await _fail(repo, maker, event_bus, run_id, str(exc))


async def _fail(
    repo: BenchmarkRunRepository,
    maker: Any,
    bus: EventBus | None,
    run_id: str,
    error: str,
) -> BenchmarkRunDetail:
    """Mark the run failed and publish it. Best-effort: never raises."""
    try:
        async with maker() as session:
            detail = await repo.mark_failed(session, run_id, error)
            await session.commit()
    except Exception as exc:  # noqa: BLE001 — already on the error path
        log.error("benchmark.mark_failed_failed", run_id=run_id, error=str(exc))
        detail = None

    _notice(bus, "error", f"benchmark {run_id} failed: {error}")
    if detail is not None:
        return detail
    return BenchmarkRunDetail(run_id=run_id, status="failed", sample_size=0, error=error)


__all__ = [
    "BENCHMARK_NODE",
    "MAX_DISAGREEMENT_EXAMPLES",
    "CallRecord",
    "RecordingProvider",
    "TierRun",
    "benchmark_tiers",
    "check_sample_size",
    "compare_tiers",
    "create_run",
    "run_benchmark",
    "run_tier",
    "summarize_tier",
]
