"""Per-node behavior with fakes injected via ``state["config"]``.

Zero network. Each node must return a valid state on provider failure, append an
error where the spec demands one (and NOT where it doesn't), and honour the
escalation / hallucination-guard rules.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from app.agent.nodes.classify import ClassificationResult, classify
from app.agent.nodes.enrich import enrich
from app.agent.nodes.reason import reason
from app.agent.nodes.recommend import recommend
from app.agent.nodes.retrieve import retrieve
from app.api.errors import ProviderError, RateLimitedError
from app.providers.base import CompletionResult
from app.schemas import (
    AlertStatus,
    AttackType,
    IocVerdict,
    MitreTechnique,
    NormalizedAlert,
    ProviderTier,
    Remediation,
    RemediationStep,
    Severity,
)

pytestmark = pytest.mark.asyncio


class FakeProvider:
    def __init__(
        self,
        *,
        name: str = "groq",
        model: str = "fake-model",
        tier: ProviderTier = ProviderTier.FAST,
        parsed: Any = None,
        text: str = "",
        raises: BaseException | None = None,
    ) -> None:
        self._name = name
        self._model = model
        self.tier = tier
        self._parsed = parsed
        self._text = text
        self._raises = raises
        self.calls = 0

    @property
    def name(self) -> str:
        return self._name

    @property
    def model(self) -> str:
        return self._model

    async def complete(
        self,
        prompt: str,
        *,
        system: str | None = None,
        max_tokens: int = 512,
        temperature: float = 0.0,
        response_model: Any = None,
        timeout: float | None = None,
        model: str | None = None,
        node: str = "-",
    ) -> CompletionResult:
        self.calls += 1
        if self._raises is not None:
            raise self._raises
        return CompletionResult(
            text=self._text,
            parsed=self._parsed,
            tokens_in=11,
            tokens_out=22,
            latency_ms=5.0,
            provider=self._name,
            model=self._model,
            finish_reason="stop",
        )


class FakeRegistry:
    def __init__(self, mapping: dict[ProviderTier, FakeProvider]) -> None:
        self._m = mapping

    def get(self, tier: ProviderTier) -> FakeProvider:
        provider = self._m.get(tier)
        if provider is None:
            raise ProviderError(f"no provider for {tier.value}")
        return provider


class FakeAggregator:
    def __init__(
        self, verdicts: list[IocVerdict | None] | None = None, raises: BaseException | None = None
    ) -> None:
        self._verdicts = verdicts or []
        self._raises = raises

    async def lookup_many(self, pairs: list[tuple[str, str]]) -> list[IocVerdict | None]:
        if self._raises is not None:
            raise self._raises
        return self._verdicts


class FakeRetriever:
    def __init__(
        self, techniques: list[MitreTechnique] | None = None, raises: BaseException | None = None
    ) -> None:
        self._t = techniques or []
        self._raises = raises

    async def retrieve(
        self, query: str, attack_type: Any = None, k: int = 4
    ) -> list[MitreTechnique]:
        if self._raises is not None:
            raise self._raises
        return self._t


def _alert(iocs: list[str] | None = None) -> NormalizedAlert:
    return NormalizedAlert(
        id="alert-1",
        timestamp=datetime(2026, 7, 25, tzinfo=UTC),
        source="suricata",
        signature="ET SCAN Multiple failed SSH logins",
        src_ip="45.13.2.99",
        dst_ip="10.0.0.5",
        src_port=40122,
        dst_port=22,
        protocol="TCP",
        extracted_iocs=iocs if iocs is not None else [],
    )


def _verdict(score: float, malicious: bool = True) -> IocVerdict:
    return IocVerdict(
        indicator="45.13.2.99",
        indicator_type="ip",
        score=score,
        malicious=malicious,
        sources=[],
        cached=False,
    )


def _tech(tid: str) -> MitreTechnique:
    return MitreTechnique(
        id=tid,
        name=f"Technique {tid}",
        tactic="Discovery",
        url=f"https://attack.mitre.org/techniques/{tid}/",
        excerpt="excerpt",
    )


def _state(**kw: Any) -> dict[str, Any]:
    base: dict[str, Any] = {"alert": _alert(), "config": {}, "trace": [], "errors": []}
    base.update(kw)
    return base


async def test_classify_success() -> None:
    parsed = ClassificationResult(
        severity=Severity.CRITICAL,
        confidence=0.9,
        attack_type=AttackType.BRUTE_FORCE,
        rationale="active brute force",
    )
    provider = FakeProvider(parsed=parsed)
    state = _state(config={"registry": FakeRegistry({ProviderTier.FAST: provider})})

    result = await classify(state)

    assert result["severity"] == Severity.CRITICAL
    assert result["attack_type"] == AttackType.BRUTE_FORCE
    assert result["status"] == AlertStatus.CLASSIFIED
    assert result["trace"][0].status == "ok"
    assert result["trace"][0].node == "classify"


async def test_classify_failure_defaults_medium_never_critical() -> None:
    provider = FakeProvider(raises=ProviderError("groq down"))
    state = _state(config={"registry": FakeRegistry({ProviderTier.FAST: provider})})

    result = await classify(state)

    assert result["severity"] == Severity.MEDIUM
    assert result["severity"] != Severity.CRITICAL
    assert result["attack_type"] == AttackType.UNKNOWN
    assert result["confidence"] == 0.0
    assert result["status"] == AlertStatus.CLASSIFIED
    assert any("classify" in e for e in result["errors"])
    assert result["trace"][0].status == "failed"


async def test_enrich_escalates_medium_to_high_and_traces_it() -> None:
    agg = FakeAggregator([_verdict(90.0)])
    state = _state(
        alert=_alert(["45.13.2.99"]),
        severity=Severity.MEDIUM,
        config={"aggregator": agg},
    )

    result = await enrich(state)

    assert result["severity"] == Severity.HIGH
    assert result["max_ioc_score"] == 90
    assert result["status"] == AlertStatus.ENRICHED
    note = result["trace"][0].note or ""
    assert "upgraded" in note and "high" in note


async def test_enrich_below_threshold_keeps_severity() -> None:
    agg = FakeAggregator([_verdict(50.0)])
    state = _state(
        alert=_alert(["45.13.2.99"]),
        severity=Severity.MEDIUM,
        config={"aggregator": agg},
    )

    result = await enrich(state)

    assert "severity" not in result  # no upgrade -> classifier's value stands
    assert result["max_ioc_score"] == 50


async def test_enrich_rate_limited_is_not_an_error_state() -> None:
    agg = FakeAggregator(raises=RateLimitedError("VT quota exhausted"))
    state = _state(
        alert=_alert(["45.13.2.99"]),
        severity=Severity.HIGH,
        config={"aggregator": agg},
    )

    result = await enrich(state)

    assert result["iocs"] == []
    assert result["max_ioc_score"] is None
    assert "errors" not in result  # quota exhaustion is expected, not a bug
    assert result["trace"][0].status == "ok"
    assert "rate-limited" in (result["trace"][0].note or "")


async def test_enrich_no_public_iocs_short_circuits() -> None:
    state = _state(alert=_alert([]), severity=Severity.HIGH, config={})

    result = await enrich(state)

    assert result["iocs"] == []
    assert result["max_ioc_score"] is None
    assert "no public IOCs" in (result["trace"][0].note or "")


async def test_enrich_aggregator_failure_degrades_with_error() -> None:
    agg = FakeAggregator(raises=RuntimeError("boom"))
    state = _state(
        alert=_alert(["45.13.2.99"]), severity=Severity.HIGH, config={"aggregator": agg}
    )

    result = await enrich(state)

    assert result["iocs"] == []
    assert any("enrich" in e for e in result["errors"])
    assert result["trace"][0].status == "failed"


async def test_retrieve_returns_techniques() -> None:
    retriever = FakeRetriever([_tech("T1110"), _tech("T1078")])
    state = _state(attack_type=AttackType.BRUTE_FORCE, config={"retriever": retriever})

    result = await retrieve(state)

    assert [t.id for t in result["techniques"]] == ["T1110", "T1078"]
    assert result["trace"][0].status == "ok"


async def test_retrieve_empty_is_fine() -> None:
    retriever = FakeRetriever([])
    state = _state(attack_type=AttackType.BENIGN, config={"retriever": retriever})

    result = await retrieve(state)

    assert result["techniques"] == []
    assert result["trace"][0].status == "ok"
    assert "no matching" in (result["trace"][0].note or "")


async def test_retrieve_failure_degrades() -> None:
    retriever = FakeRetriever(raises=RuntimeError("chroma exploded"))
    state = _state(attack_type=AttackType.PORT_SCAN, config={"retriever": retriever})

    result = await retrieve(state)

    assert result["techniques"] == []
    assert any("retrieve" in e for e in result["errors"])
    assert result["trace"][0].status == "failed"


async def test_reason_quality_success() -> None:
    provider = FakeProvider(name="gemini", tier=ProviderTier.QUALITY, text="Analysis (T1110).")
    state = _state(
        severity=Severity.HIGH,
        attack_type=AttackType.BRUTE_FORCE,
        techniques=[_tech("T1110")],
        config={"registry": FakeRegistry({ProviderTier.QUALITY: provider})},
    )

    result = await reason(state)

    assert result["reasoning"] == "Analysis (T1110)."
    assert result["trace"][0].provider == "gemini:fake-model"


async def test_reason_falls_back_to_fast_tier() -> None:
    quality = FakeProvider(name="gemini", tier=ProviderTier.QUALITY, raises=ProviderError("down"))
    fast = FakeProvider(name="groq", tier=ProviderTier.FAST, text="Fast-tier analysis.")
    state = _state(
        severity=Severity.HIGH,
        config={
            "registry": FakeRegistry(
                {ProviderTier.QUALITY: quality, ProviderTier.FAST: fast}
            )
        },
    )

    result = await reason(state)

    assert result["reasoning"] == "Fast-tier analysis."
    assert fast.calls == 1
    assert "fast tier" in (result["trace"][0].note or "")


async def test_reason_both_tiers_fail() -> None:
    quality = FakeProvider(name="gemini", tier=ProviderTier.QUALITY, raises=ProviderError("q down"))
    fast = FakeProvider(name="groq", tier=ProviderTier.FAST, raises=ProviderError("f down"))
    state = _state(
        severity=Severity.HIGH,
        config={
            "registry": FakeRegistry(
                {ProviderTier.QUALITY: quality, ProviderTier.FAST: fast}
            )
        },
    )

    result = await reason(state)

    assert result["reasoning"] is None
    assert any("reason" in e for e in result["errors"])
    assert result["trace"][0].status == "failed"


async def test_recommend_drops_hallucinated_techniques_and_renumbers() -> None:
    parsed = Remediation(
        summary="Contain the brute-force source.",
        steps=[
            RemediationStep(order=5, action="Block", detail="Block the IP.", urgency="immediate"),
            RemediationStep(order=2, action="Rotate", detail="Rotate keys.", urgency="soon"),
            RemediationStep(order=9, action="Monitor", detail="Watch retries.", urgency="monitor"),
        ],
        techniques=[_tech("T1110"), _tech("T9999")],  # T9999 is fabricated
        generated_at=datetime(2026, 7, 25, tzinfo=UTC),
        duration_ms=0,
    )
    provider = FakeProvider(name="gemini", tier=ProviderTier.QUALITY, parsed=parsed)
    state = _state(
        severity=Severity.HIGH,
        reasoning="Brute force (T1110).",
        techniques=[_tech("T1110")],  # only T1110 was actually retrieved
        config={"registry": FakeRegistry({ProviderTier.QUALITY: provider})},
    )

    result = await recommend(state)

    remediation = result["remediation"]
    kept_ids = [t.id for t in remediation.techniques]
    assert kept_ids == ["T1110"]  # fabricated T9999 dropped
    assert [s.order for s in remediation.steps] == [1, 2, 3]  # renumbered sequentially
    assert result["status"] == AlertStatus.REASONED
    assert "dropped 1" in (result["trace"][0].note or "")


async def test_recommend_failure_degrades() -> None:
    provider = FakeProvider(name="gemini", tier=ProviderTier.QUALITY, raises=ProviderError("down"))
    state = _state(
        severity=Severity.HIGH,
        reasoning="something",
        techniques=[_tech("T1110")],
        config={"registry": FakeRegistry({ProviderTier.QUALITY: provider})},
    )

    result = await recommend(state)

    assert result["remediation"] is None
    assert any("recommend" in e for e in result["errors"])
    assert result["trace"][0].status == "failed"
