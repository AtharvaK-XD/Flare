"""Benchmark fairness tests — scripted providers, zero network.

Every property that makes the comparison legitimate is asserted here: identical
prompts, warm-up exclusion, sequential tiers, failure accounting, agreement
arithmetic, and override isolation. If one of these regresses the panel is still
green and still lying, so these are the tests that matter most in this phase.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

import pytest

from app.agent.graph import run_triage
from app.api.errors import BadRequestError, ProviderError
from app.core.metrics import percentile
from app.evaluation import benchmark as bench
from app.evaluation.ground_truth import LabeledAlert
from app.providers.base import CompletionResult, ProviderHealth
from app.providers.registry import ProviderRegistry
from app.schemas import AttackType, NormalizedAlert, ProviderTier, Severity

# asyncio_mode=auto handles the coroutine tests; no module-level asyncio mark, or
# the sync guard tests below get flagged for carrying it.


def _marker(label: str) -> str:
    """A token that appears ONLY in this alert's prompt.

    The classify prompt template enumerates every attack type by name, so a
    scripted provider that matched on a bare label like "ddos" would match every
    prompt via the template and silently score a constant.
    """
    return f"[[{label}]]"


class ScriptedProvider:
    """An LLM provider with scripted latency and scripted classifications.

    ``severity_for`` maps a ground-truth label to what this provider "thinks",
    which is how the tests build exact agreement/accuracy cases by hand.
    """

    def __init__(
        self,
        name: str,
        model: str,
        tier: ProviderTier,
        *,
        latency_ms: float = 100.0,
        first_call_latency_ms: float | None = None,
        severity_for: dict[str, Severity] | None = None,
        fail_on: set[str] | None = None,
        tokens: tuple[int, int] = (100, 20),
        sleep_ms: float = 0.0,
    ) -> None:
        self._name = name
        self._model = model
        self.tier = tier
        self.latency_ms = latency_ms
        self.first_call_latency_ms = first_call_latency_ms
        self.severity_for = severity_for or {}
        self.fail_on = fail_on or set()
        self.tokens = tokens
        self.sleep_ms = sleep_ms
        self.prompts: list[str] = []
        self.kwargs: list[dict[str, Any]] = []
        self.calls = 0
        self.available = True

    @property
    def name(self) -> str:
        return self._name

    @property
    def model(self) -> str:
        return self._model

    async def health(self) -> ProviderHealth:
        return ProviderHealth(status="ok")

    def _severity(self, prompt: str) -> Severity:
        for label, severity in self.severity_for.items():
            if _marker(label) in prompt:
                return severity
        return Severity.MEDIUM

    async def complete(self, prompt: str, **kwargs: Any) -> CompletionResult:
        self.calls += 1
        self.prompts.append(prompt)
        self.kwargs.append(kwargs)
        if self.sleep_ms:
            await asyncio.sleep(self.sleep_ms / 1000.0)

        for marker in self.fail_on:
            if marker in prompt:
                raise ProviderError(f"{self._name} scripted failure")

        latency = self.latency_ms
        if self.calls == 1 and self.first_call_latency_ms is not None:
            latency = self.first_call_latency_ms

        severity = self._severity(prompt)
        model_cls = kwargs.get("response_model")
        parsed = None
        if model_cls is not None:
            parsed = model_cls(
                severity=severity,
                confidence=0.9,
                attack_type=AttackType.PORT_SCAN,
                rationale="scripted",
            )
        return CompletionResult(
            text="{}",
            parsed=parsed,
            tokens_in=self.tokens[0],
            tokens_out=self.tokens[1],
            latency_ms=latency,
            provider=self._name,
            model=self._model,
            finish_reason="stop",
        )


def _alert(index: int, label: str) -> NormalizedAlert:
    return NormalizedAlert(
        id=f"alert-{index}",
        timestamp=datetime(2026, 7, 25, 9, index % 60, tzinfo=UTC),
        source="cicids2017",
        signature=f"CICIDS {_marker(label)} {label} flow {index}",
        src_ip=f"45.13.2.{index % 250}",
        dst_ip="10.0.0.5",
        src_port=40000 + index,
        dst_port=443,
        protocol="6",
        raw={"Label": label},
        extracted_iocs=[],
    )


LABEL_SEVERITY = {
    "benign": Severity.INFO,
    "port_scan": Severity.LOW,
    "ddos": Severity.HIGH,
    "malware_c2": Severity.CRITICAL,
}
LABEL_ATTACK = {
    "benign": AttackType.BENIGN,
    "port_scan": AttackType.PORT_SCAN,
    "ddos": AttackType.DDOS,
    "malware_c2": AttackType.MALWARE_C2,
}


def _sample(labels: list[str]) -> list[LabeledAlert]:
    return [
        LabeledAlert(
            alert=_alert(i, label),
            label=label,
            expected_attack_type=LABEL_ATTACK[label],
            expected_severity=LABEL_SEVERITY[label],
        )
        for i, label in enumerate(labels)
    ]


def _registry(fast: Any, quality: Any) -> ProviderRegistry:
    registry = ProviderRegistry()
    registry._providers = {ProviderTier.FAST: fast, ProviderTier.QUALITY: quality}
    return registry


SAMPLE_LABELS = ["benign", "port_scan", "ddos", "malware_c2", "benign", "port_scan"]


async def test_both_tiers_receive_byte_identical_prompts() -> None:
    """Different prompts would make the whole comparison meaningless."""
    fast = ScriptedProvider("groq", "llama-fast", ProviderTier.FAST)
    quality = ScriptedProvider("gemini", "gemini-flash", ProviderTier.QUALITY)
    sample = _sample(SAMPLE_LABELS)

    runs = await bench.benchmark_tiers(
        sample, registry=_registry(fast, quality), warmup=0, use_limiters=False
    )

    fast_prompts = [r.prompt for r in runs[0].records]
    quality_prompts = [r.prompt for r in runs[1].records]
    assert fast_prompts == quality_prompts
    assert len(fast_prompts) == len(sample)
    # not merely equal-length: the same bytes, in the same order
    assert all(a == b for a, b in zip(fast_prompts, quality_prompts, strict=True))


async def test_both_tiers_receive_identical_decoding_parameters() -> None:
    fast = ScriptedProvider("groq", "llama-fast", ProviderTier.FAST)
    quality = ScriptedProvider("gemini", "gemini-flash", ProviderTier.QUALITY)

    runs = await bench.benchmark_tiers(
        _sample(SAMPLE_LABELS), registry=_registry(fast, quality), warmup=0, use_limiters=False
    )

    fast_params = {(r.max_tokens, r.temperature) for r in runs[0].records}
    quality_params = {(r.max_tokens, r.temperature) for r in runs[1].records}
    assert fast_params == quality_params
    assert len(fast_params) == 1  # one setting, not a spread


async def test_warmup_calls_are_excluded_from_latency_stats() -> None:
    """A slow cold call must not move the average it is excluded from."""
    fast = ScriptedProvider(
        "groq", "llama-fast", ProviderTier.FAST, latency_ms=100.0, first_call_latency_ms=5000.0
    )
    quality = ScriptedProvider("gemini", "gemini-flash", ProviderTier.QUALITY, latency_ms=800.0)
    sample = _sample(SAMPLE_LABELS)

    runs = await bench.benchmark_tiers(
        sample, registry=_registry(fast, quality), warmup=2, use_limiters=False
    )
    fast_run = runs[0]

    assert len(fast_run.records) == len(sample) + 2
    assert len(fast_run.measured) == len(sample)
    assert 5000.0 in [r.latency_ms for r in fast_run.records if r.warmup]
    assert 5000.0 not in fast_run.latencies

    result = bench.summarize_tier(fast_run, sample)
    assert result.avg_latency_ms == 100.0  # untouched by the 5s cold call
    assert result.max_latency_ms == 100.0
    assert result.warmup_calls == 2
    assert result.calls == len(sample)


async def test_tiers_run_sequentially_with_no_overlapping_call_windows() -> None:
    """Concurrent tiers contend for CPU and network; both latencies go to noise."""
    fast = ScriptedProvider("groq", "llama-fast", ProviderTier.FAST, sleep_ms=2.0)
    quality = ScriptedProvider("gemini", "gemini-flash", ProviderTier.QUALITY, sleep_ms=2.0)
    sample = _sample(SAMPLE_LABELS)

    runs = await bench.benchmark_tiers(
        sample, registry=_registry(fast, quality), warmup=1, use_limiters=False
    )
    fast_run, quality_run = runs

    assert max(r.ended_at for r in fast_run.records) <= min(
        r.started_at for r in quality_run.records
    )
    # and within a tier, calls do not overlap each other either
    for run in runs:
        windows = sorted((r.started_at, r.ended_at) for r in run.records)
        assert all(
            windows[i][1] <= windows[i + 1][0] for i in range(len(windows) - 1)
        ), f"{run.tier} overlapped itself"


async def test_failures_leave_latency_stats_but_stay_in_the_accuracy_denominator() -> None:
    """A provider that fails half its calls must not read as fast and accurate."""
    sample = _sample(SAMPLE_LABELS)
    # fails on every ddos/malware_c2 alert (2 of 6), and is otherwise perfect
    fast = ScriptedProvider(
        "groq",
        "llama-fast",
        ProviderTier.FAST,
        latency_ms=50.0,
        severity_for=LABEL_SEVERITY,
        fail_on={_marker("ddos"), _marker("malware_c2")},
    )
    quality = ScriptedProvider(
        "gemini",
        "gemini-flash",
        ProviderTier.QUALITY,
        latency_ms=900.0,
        severity_for=LABEL_SEVERITY,
    )

    runs = await bench.benchmark_tiers(
        sample, registry=_registry(fast, quality), warmup=0, use_limiters=False
    )
    fast_result = bench.summarize_tier(runs[0], sample)
    quality_result = bench.summarize_tier(runs[1], sample)

    assert fast_result.failures == 2
    # failed calls contributed no latency sample
    assert len(runs[0].latencies) == 4
    assert fast_result.avg_latency_ms == 50.0

    # ...but all 6 alerts are in the accuracy denominator: the 2 failures fell
    # back to medium, which is wrong for both, so 4/6.
    assert fast_result.accuracy == pytest.approx(4 / 6, abs=1e-4)
    assert quality_result.accuracy == 1.0
    assert quality_result.failures == 0


async def test_failures_are_not_silently_dropped_from_the_call_count() -> None:
    sample = _sample(SAMPLE_LABELS)
    fast = ScriptedProvider(
        "groq", "llama-fast", ProviderTier.FAST, fail_on={_marker("ddos"), _marker("malware_c2")}
    )
    quality = ScriptedProvider("gemini", "gemini-flash", ProviderTier.QUALITY)

    runs = await bench.benchmark_tiers(
        sample, registry=_registry(fast, quality), warmup=0, use_limiters=False
    )
    result = bench.summarize_tier(runs[0], sample)

    assert result.calls == len(sample)  # 6 attempted
    assert result.calls == len(runs[0].latencies) + result.failures


async def test_percentiles_come_from_the_shared_helper() -> None:
    """One definition of p95 — two panels must not quote different numbers."""
    fast = ScriptedProvider("groq", "llama-fast", ProviderTier.FAST)
    quality = ScriptedProvider("gemini", "gemini-flash", ProviderTier.QUALITY)
    sample = _sample(SAMPLE_LABELS)

    runs = await bench.benchmark_tiers(
        sample, registry=_registry(fast, quality), warmup=0, use_limiters=False
    )
    # scripted latencies vary per call so the percentile is not degenerate
    runs[0].records[0].latency_ms = 10.0
    runs[0].records[-1].latency_ms = 999.0

    result = bench.summarize_tier(runs[0], sample)
    assert result.p95_latency_ms == round(percentile(runs[0].latencies, 95), 2)
    assert result.p50_latency_ms == round(percentile(runs[0].latencies, 50), 2)


async def test_agreement_rate_and_disagreement_examples_on_a_hand_built_case() -> None:
    """6 alerts, tiers differ on exactly 2 => agreement 4/6."""
    sample = _sample(SAMPLE_LABELS)
    fast = ScriptedProvider(
        "groq", "llama-fast", ProviderTier.FAST, severity_for=LABEL_SEVERITY
    )
    quality = ScriptedProvider(
        "gemini",
        "gemini-flash",
        ProviderTier.QUALITY,
        # disagrees on ddos (high -> critical) and malware_c2 (critical -> high)
        severity_for={**LABEL_SEVERITY, "ddos": Severity.CRITICAL, "malware_c2": Severity.HIGH},
    )

    runs = await bench.benchmark_tiers(
        sample, registry=_registry(fast, quality), warmup=0, use_limiters=False
    )
    rate, examples = bench.compare_tiers(runs[0], runs[1], sample)

    assert rate == pytest.approx(4 / 6, abs=1e-4)
    assert len(examples) == 2
    by_id = {e.alert_id: e for e in examples}

    ddos = by_id["alert-2"]
    assert ddos.fast_prediction == "high"
    assert ddos.quality_prediction == "critical"
    assert ddos.ground_truth == "high"
    assert "ddos" in ddos.signature

    c2 = by_id["alert-3"]
    assert (c2.fast_prediction, c2.quality_prediction, c2.ground_truth) == (
        "critical",
        "high",
        "critical",
    )


async def test_disagreement_examples_are_capped_at_five() -> None:
    labels = ["port_scan"] * 12
    sample = _sample(labels)
    fast = ScriptedProvider(
        "groq", "llama-fast", ProviderTier.FAST, severity_for={"port_scan": Severity.LOW}
    )
    quality = ScriptedProvider(
        "gemini",
        "gemini-flash",
        ProviderTier.QUALITY,
        severity_for={"port_scan": Severity.HIGH},
    )

    runs = await bench.benchmark_tiers(
        sample, registry=_registry(fast, quality), warmup=0, use_limiters=False
    )
    rate, examples = bench.compare_tiers(runs[0], runs[1], sample)

    assert rate == 0.0  # they never agreed
    assert len(examples) == bench.MAX_DISAGREEMENT_EXAMPLES == 5


async def test_double_failure_is_not_counted_as_agreement() -> None:
    """Two providers both falling back to `medium` have not agreed on anything."""
    sample = _sample(SAMPLE_LABELS)
    fast = ScriptedProvider(
        "groq",
        "llama-fast",
        ProviderTier.FAST,
        severity_for=LABEL_SEVERITY,
        fail_on={_marker("ddos")},
    )
    quality = ScriptedProvider(
        "gemini",
        "gemini-flash",
        ProviderTier.QUALITY,
        severity_for=LABEL_SEVERITY,
        fail_on={_marker("ddos")},
    )

    runs = await bench.benchmark_tiers(
        sample, registry=_registry(fast, quality), warmup=0, use_limiters=False
    )
    rate, _ = bench.compare_tiers(runs[0], runs[1], sample)

    # 5 comparable alerts, all matching — the ddos pair is excluded, not scored 1
    assert rate == 1.0
    assert runs[0].predictions["alert-2"].failed
    assert runs[1].predictions["alert-2"].failed


async def test_agreement_is_none_when_nothing_was_comparable() -> None:
    sample = _sample(["benign", "port_scan"])
    fast = ScriptedProvider("groq", "llama-fast", ProviderTier.FAST, fail_on={"CICIDS"})
    quality = ScriptedProvider("gemini", "gemini-flash", ProviderTier.QUALITY)

    runs = await bench.benchmark_tiers(
        sample, registry=_registry(fast, quality), warmup=0, use_limiters=False
    )
    rate, examples = bench.compare_tiers(runs[0], runs[1], sample)

    assert rate is None  # not a fabricated 0.0
    assert examples == []


async def test_override_does_not_leak_into_a_concurrent_triage() -> None:
    """A benchmark must not change what concurrent live traffic is served by."""
    fast = ScriptedProvider("groq", "llama-fast", ProviderTier.FAST, sleep_ms=5.0)
    quality = ScriptedProvider("gemini", "gemini-flash", ProviderTier.QUALITY, sleep_ms=5.0)
    registry = _registry(fast, quality)
    sample = _sample(SAMPLE_LABELS)

    live_alert = _alert(99, "port_scan")

    async def _live_triage() -> Any:
        # staggered so it runs while the benchmark holds an override
        await asyncio.sleep(0.01)
        return await run_triage(
            live_alert, config={"registry": registry}, stop_after="classify"
        )

    benchmark_task = asyncio.create_task(
        bench.benchmark_tiers(
            sample, registry=registry, warmup=1, use_limiters=False
        )
    )
    live_task = asyncio.create_task(_live_triage())
    runs, live_state = await asyncio.gather(benchmark_task, live_task)

    # the live alert was classified by the registry's OWN fast provider
    classify_trace = next(t for t in live_state["trace"] if t.node == "classify")
    assert classify_trace.provider == "groq:llama-fast"
    assert live_state["severity"] is not None

    # and the benchmark's quality run still went through gemini for its own calls
    assert runs[1].provider == "gemini"
    assert any("flow 99" in p for p in fast.prompts)  # live call hit the fast provider
    assert not any("flow 99" in p for p in quality.prompts)


async def test_override_is_restored_after_a_tier_finishes() -> None:
    fast = ScriptedProvider("groq", "llama-fast", ProviderTier.FAST)
    quality = ScriptedProvider("gemini", "gemini-flash", ProviderTier.QUALITY)
    registry = _registry(fast, quality)

    await bench.benchmark_tiers(
        _sample(SAMPLE_LABELS), registry=registry, warmup=0, use_limiters=False
    )

    assert registry.get(ProviderTier.FAST) is fast
    assert registry.get(ProviderTier.QUALITY) is quality


def test_sample_size_over_the_cap_is_refused_with_an_explanation() -> None:
    from app.config import get_settings

    cap = get_settings().benchmark_max_sample
    with pytest.raises(BadRequestError) as excinfo:
        bench.check_sample_size(cap + 1)

    assert excinfo.value.http_status == 400
    assert excinfo.value.code == "validation_error"
    message = excinfo.value.message
    assert str(cap) in message
    assert str((cap + 1) * 2) in message  # explains the doubling
    assert bench.check_sample_size(cap) == cap


def test_sample_size_below_one_is_refused() -> None:
    with pytest.raises(BadRequestError, match="at least 1"):
        bench.check_sample_size(0)


async def test_missing_tier_key_fails_the_run_instead_of_half_comparing() -> None:
    fast = ScriptedProvider("groq", "llama-fast", ProviderTier.FAST)
    quality = ScriptedProvider("gemini", "gemini-flash", ProviderTier.QUALITY)
    quality.available = False

    with pytest.raises(ProviderError, match="not a comparison"):
        await bench.benchmark_tiers(
            _sample(SAMPLE_LABELS), registry=_registry(fast, quality), warmup=0,
            use_limiters=False,
        )


async def test_estimated_cost_is_none_when_the_model_has_no_price() -> None:
    """Unpriced must render as unknown, never as 0.00 (which reads as free)."""
    fast = ScriptedProvider("groq", "llama-fast", ProviderTier.FAST)
    quality = ScriptedProvider("gemini", "gemini-flash", ProviderTier.QUALITY)
    sample = _sample(SAMPLE_LABELS)

    runs = await bench.benchmark_tiers(
        sample, registry=_registry(fast, quality), warmup=0, use_limiters=False
    )
    assert bench.summarize_tier(runs[0], sample).estimated_cost is None

    from app.core.metrics import COST_PER_1K_TOKENS

    COST_PER_1K_TOKENS["llama-fast"] = 0.05
    try:
        result = bench.summarize_tier(runs[0], sample)
        # 6 calls * (100 in + 20 out) = 720 tokens => 0.05 * 720/1000
        assert result.estimated_cost == pytest.approx(0.036)
    finally:
        COST_PER_1K_TOKENS.pop("llama-fast", None)


async def test_result_row_matches_the_contract_shape() -> None:
    fast = ScriptedProvider("groq", "llama-fast", ProviderTier.FAST)
    quality = ScriptedProvider("gemini", "gemini-flash", ProviderTier.QUALITY)
    sample = _sample(SAMPLE_LABELS)

    runs = await bench.benchmark_tiers(
        sample, registry=_registry(fast, quality), warmup=0, use_limiters=False
    )
    payload = bench.summarize_tier(runs[0], sample).model_dump(mode="json")

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
    assert contract_fields <= set(payload)
    assert payload["tier"] == "fast"
    assert payload["provider"] == "groq"
    assert payload["model"] == "llama-fast"
    assert payload["avg_tokens"] == 120.0  # 100 in + 20 out
    assert payload["avg_tokens_in"] == 100.0
    assert payload["avg_tokens_out"] == 20.0


async def test_throttled_flag_is_false_on_a_clean_run() -> None:
    """No rate-limit retries means the latency numbers stand unqualified."""
    from app.core.metrics import metrics

    metrics.reset()
    fast = ScriptedProvider("groq", "clean-fast", ProviderTier.FAST)
    quality = ScriptedProvider("gemini", "clean-quality", ProviderTier.QUALITY)
    sample = _sample(SAMPLE_LABELS)

    runs = await bench.benchmark_tiers(
        sample, registry=_registry(fast, quality), warmup=0, use_limiters=False
    )
    for run in runs:
        assert run.throttled is False
        assert bench.summarize_tier(run, sample).throttled is False


async def test_throttled_flag_is_set_when_a_tier_hits_a_rate_limit() -> None:
    """A tier that queued behind a 429 must be FLAGGED, not quietly published.

    Groq's free tier throttles sequential 1.1k-token prompts and answers with a
    10s+ Retry-After. That delay lands inside the measured window, so the tier's
    latency reflects free-tier queueing rather than the model — the exact reading
    that made an earlier benchmark report an 8.6s average against a 248ms
    unthrottled p50 for the SAME model.
    """
    from app.core.metrics import metrics

    metrics.reset()
    fast = ScriptedProvider("groq", "throttled-fast", ProviderTier.FAST)
    quality = ScriptedProvider("gemini", "calm-quality", ProviderTier.QUALITY)
    sample = _sample(SAMPLE_LABELS)

    # Exactly what the provider's own retry hook records on a 429.
    metrics.record_retry("groq", "throttled-fast", "classify", rate_limited=True)
    metrics.record_retry("groq", "throttled-fast", "classify", rate_limited=True)

    before = metrics.rate_limit_retries("groq", "throttled-fast")
    assert before == 2

    runs = await bench.benchmark_tiers(
        sample, registry=_registry(fast, quality), warmup=0, use_limiters=False
    )

    # Retries recorded BEFORE this tier's window must not be attributed to it:
    # the flag is a delta across the tier's own run, not a lifetime counter.
    by_tier = {run.tier: run for run in runs}
    assert by_tier[ProviderTier.FAST].throttled is False, (
        "throttling from before the run leaked into this tier's flag"
    )

    # Now a retry DURING the tier's window.
    async def _throttle_midrun(*args: Any, **kwargs: Any) -> Any:
        metrics.record_retry("groq", "throttled-fast", "classify", rate_limited=True)
        return await ScriptedProvider.complete(fast, *args, **kwargs)

    fast.complete = _throttle_midrun  # type: ignore[method-assign]
    runs = await bench.benchmark_tiers(
        sample, registry=_registry(fast, quality), warmup=0, use_limiters=False
    )
    by_tier = {run.tier: run for run in runs}
    fast_run = by_tier[ProviderTier.FAST]

    assert fast_run.throttled is True
    assert fast_run.throttle_retries == len(sample)
    assert by_tier[ProviderTier.QUALITY].throttled is False, (
        "one tier's throttling must not mark the other"
    )

    result = bench.summarize_tier(fast_run, sample)
    assert result.throttled is True
    assert result.throttle_retries == len(sample)


async def test_rate_limit_error_reaching_the_recorder_counts_as_throttling() -> None:
    """Retries that EXHAUST and surface as an error are throttling too."""
    from app.api.errors import RateLimitedError
    from app.core.metrics import metrics

    metrics.reset()

    class _AlwaysRateLimited(ScriptedProvider):
        async def complete(self, prompt: str, **kwargs: Any) -> CompletionResult:
            raise RateLimitedError("Groq rate limit hit")

    fast = _AlwaysRateLimited("groq", "hard-limited", ProviderTier.FAST)
    quality = ScriptedProvider("gemini", "calm", ProviderTier.QUALITY)
    sample = _sample(SAMPLE_LABELS)

    runs = await bench.benchmark_tiers(
        sample, registry=_registry(fast, quality), warmup=0, use_limiters=False
    )
    fast_run = {run.tier: run for run in runs}[ProviderTier.FAST]

    assert fast_run.throttled is True
    assert fast_run.throttle_retries >= len(sample)

    # And the failures are still counted as failures, not hidden by the flag.
    result = bench.summarize_tier(fast_run, sample)
    assert result.failures == len(sample)
    assert result.throttled is True
