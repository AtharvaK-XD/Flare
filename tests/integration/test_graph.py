"""End-to-end graph integration — stubbed externals, ZERO network.

Verifies the whole control-flow surface: a critical alert traverses all five
nodes, a benign alert short-circuits with four skipped trace entries, every path
yields a complete five-node trace, a hung alert times out into a partial state,
and routing is deterministic at temperature 0.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest

from app.agent.graph import run_triage
from app.agent.nodes.classify import ClassificationResult
from app.agent.state import PIPELINE_NODES
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


# --------------------------------------------------------------------------- fakes


class FakeProvider:
    def __init__(
        self,
        *,
        name: str,
        parsed: Any = None,
        text: str = "",
        delay: float = 0.0,
    ) -> None:
        self._name = name
        self._parsed = parsed
        self._text = text
        self._delay = delay

    @property
    def name(self) -> str:
        return self._name

    @property
    def model(self) -> str:
        return "fake-model"

    async def complete(self, prompt: str, **kwargs: Any) -> CompletionResult:
        if self._delay:
            await asyncio.sleep(self._delay)
        return CompletionResult(
            text=self._text,
            parsed=self._parsed,
            tokens_in=10,
            tokens_out=20,
            latency_ms=1.0,
            provider=self._name,
            model="fake-model",
            finish_reason="stop",
        )


class FakeRegistry:
    def __init__(self, mapping: dict[ProviderTier, FakeProvider]) -> None:
        self._m = mapping

    def get(self, tier: ProviderTier) -> FakeProvider:
        return self._m[tier]


class FakeAggregator:
    def __init__(self, verdicts: list[IocVerdict | None]) -> None:
        self._verdicts = verdicts

    async def lookup_many(self, pairs: list[tuple[str, str]]) -> list[IocVerdict | None]:
        return self._verdicts


class FakeRetriever:
    def __init__(self, techniques: list[MitreTechnique]) -> None:
        self._t = techniques

    async def retrieve(
        self, query: str, attack_type: Any = None, k: int = 4
    ) -> list[MitreTechnique]:
        return self._t


# --------------------------------------------------------------------------- builders


def _alert(iocs: list[str] | None = None) -> NormalizedAlert:
    return NormalizedAlert(
        id="alert-graph",
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


def _tech(tid: str) -> MitreTechnique:
    return MitreTechnique(
        id=tid, name=f"Technique {tid}", tactic="Credential Access",
        url=f"https://attack.mitre.org/techniques/{tid}/", excerpt="excerpt",
    )


def _remediation() -> Remediation:
    return Remediation(
        summary="Contain the brute-force source.",
        steps=[
            RemediationStep(order=1, action="Block", detail="Block the IP.", urgency="immediate"),
            RemediationStep(order=2, action="Rotate", detail="Rotate keys.", urgency="soon"),
        ],
        techniques=[_tech("T1110")],
        generated_at=datetime(2026, 7, 25, tzinfo=UTC),
        duration_ms=0,
    )


def _critical_config() -> dict[str, Any]:
    classify_provider = FakeProvider(
        name="groq",
        parsed=ClassificationResult(
            severity=Severity.CRITICAL,
            confidence=0.9,
            attack_type=AttackType.BRUTE_FORCE,
            rationale="active brute force",
        ),
    )
    quality_provider = FakeProvider(
        name="gemini", text="Active SSH brute force (T1110).", parsed=_remediation()
    )
    return {
        "registry": FakeRegistry(
            {ProviderTier.FAST: classify_provider, ProviderTier.QUALITY: quality_provider}
        ),
        "aggregator": FakeAggregator(
            [IocVerdict(indicator="45.13.2.99", indicator_type="ip", score=95.0, malicious=True)]
        ),
        "retriever": FakeRetriever([_tech("T1110")]),
    }


def _benign_config() -> dict[str, Any]:
    classify_provider = FakeProvider(
        name="groq",
        parsed=ClassificationResult(
            severity=Severity.INFO,
            confidence=0.95,
            attack_type=AttackType.BENIGN,
            rationale="normal DNS",
        ),
    )
    return {
        "registry": FakeRegistry({ProviderTier.FAST: classify_provider}),
        "aggregator": FakeAggregator([]),
        "retriever": FakeRetriever([]),
    }


def _ran_nodes(state: dict[str, Any]) -> dict[str, str]:
    return {t.node: t.status for t in state["trace"]}


# --------------------------------------------------------------------------- tests


async def test_critical_alert_traverses_all_five_nodes() -> None:
    state = await run_triage(_alert(["45.13.2.99"]), config=_critical_config())

    ran = _ran_nodes(state)
    assert set(ran) == set(PIPELINE_NODES)
    assert all(status == "ok" for status in ran.values())  # none skipped, none failed
    assert state["status"] == AlertStatus.DONE
    assert state["severity"] == Severity.CRITICAL
    assert state["remediation"] is not None
    assert [t.id for t in state["remediation"].techniques] == ["T1110"]
    assert state["total_duration_ms"] is not None


async def test_benign_alert_short_circuits_with_four_skipped() -> None:
    state = await run_triage(_alert([]), config=_benign_config())

    ran = _ran_nodes(state)
    assert ran["classify"] == "ok"
    skipped = [t for t in state["trace"] if t.status == "skipped"]
    assert {t.node for t in skipped} == {"enrich", "retrieve", "reason", "recommend"}
    assert len(skipped) == 4
    assert state["status"] == AlertStatus.DONE
    assert state.get("remediation") is None
    # every skipped node carries a human-readable reason
    assert all(t.note for t in skipped)


async def test_every_path_produces_complete_trace() -> None:
    for config, alert in (
        (_critical_config(), _alert(["45.13.2.99"])),
        (_benign_config(), _alert([])),
    ):
        state = await run_triage(alert, config=config)
        nodes = {t.node for t in state["trace"]}
        assert nodes == set(PIPELINE_NODES)  # no missing node, ever


async def test_timeout_returns_partial_state(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "app.agent.graph.get_settings",
        lambda: SimpleNamespace(triage_timeout_seconds=0.05),
    )
    slow_classify = FakeProvider(
        name="groq",
        parsed=ClassificationResult(
            severity=Severity.CRITICAL, confidence=0.9,
            attack_type=AttackType.BRUTE_FORCE, rationale="x",
        ),
        delay=0.3,
    )
    config = {"registry": FakeRegistry({ProviderTier.FAST: slow_classify})}

    state = await run_triage(_alert(["45.13.2.99"]), config=config)

    assert state["status"] == AlertStatus.DONE  # never hangs
    assert any("budget" in e for e in state["errors"])
    assert state["total_duration_ms"] is not None


async def test_routing_is_deterministic_across_runs() -> None:
    a = await run_triage(_alert(["45.13.2.99"]), config=_critical_config())
    b = await run_triage(_alert(["45.13.2.99"]), config=_critical_config())

    assert [t.node for t in a["trace"]] == [t.node for t in b["trace"]]
    assert a["status"] == b["status"]
    assert a["severity"] == b["severity"]
