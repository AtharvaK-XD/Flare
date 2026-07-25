"""Offline mode — the whole pipeline, deterministically, with no network.

WHAT THIS IS FOR
----------------
Venue wifi dies. Free-tier quota runs out mid-demo. A provider has an outage
twenty minutes before the judging slot. ``OFFLINE_MODE=true`` keeps the demo
running through all three.

WHAT IS REAL AND WHAT IS SUBSTITUTED — the important part
--------------------------------------------------------
Substituted: ONLY the four leaves that touch the network.

    LLM fast tier      -> OfflineProvider (deterministic)
    LLM quality tier   -> OfflineProvider (deterministic)
    threat intel       -> OfflineIntelSource (deterministic reputation)
    ATT&CK retrieval   -> OfflineRetriever (the committed corpus, no embeddings)

Real, unchanged: the LangGraph graph, every node, both routers, the trace
decorator, the IOC escalation rule, the hallucination guard, the worker pools,
both queues, the event bus, SQLite, the repositories, SSE, and every API route.

This is deliberately NOT a mock that short-circuits the pipeline. The offline
provider returns a genuine :class:`CompletionResult` whose ``text`` is JSON, and
that JSON is parsed by the SAME ``extract_json_meta`` / ``coerce_to_model`` path
a Groq or Gemini response goes through — so a schema change that would break the
live pipeline breaks offline mode too, instead of passing and hiding the break.
The graph literally cannot tell the difference: it resolves providers through
``ProviderRegistry`` exactly as it always does.

HONESTY
-------
Offline responses are heuristics, not a model. Anything derived from them is
labelled as such rather than passed off as a measurement:

* the provider reports ``name="offline"`` and ``model="offline-deterministic"``,
  so a benchmark run in offline mode prints that in its results table;
* :func:`describe` gives the banner the startup logs and ``/health/deep`` show;
* the eval runner emits a warning notice when it scores offline predictions.

Latency is simulated (a few ms, jittered from a seeded RNG) so the dashboard's
duration column is not a row of zeroes — but it is derived from a fixed seed, so
two offline runs produce identical numbers.
"""

from __future__ import annotations

import json
import random
import time
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel

from app.core.logging import get_logger
from app.intel.models import IndicatorType, SourceVerdict
from app.providers.base import CompletionResult, ProviderHealth
from app.providers.parsing import coerce_to_model, extract_json_meta
from app.schemas import (
    AttackType,
    IntelSource,
    MitreTechnique,
    ProviderTier,
    Severity,
)

log = get_logger(__name__)

PROVIDER_NAME = "offline"
MODEL_NAME = "offline-deterministic"

#: Fixed so two offline runs produce byte-identical numbers.
_SEED = 20260725

#: Signature keywords -> (severity, attack_type). Ordered: the first match wins,
#: so the most specific patterns come first. This is the whole "model".
_RULES: list[tuple[tuple[str, ...], Severity, AttackType]] = [
    (("exfil", "data theft", "large upload", "infiltration"), Severity.CRITICAL,
     AttackType.DATA_EXFILTRATION),
    (("c2", "beacon", "cobalt", "trojan", "malware", "botnet", "bot", "tunnel"),
     Severity.CRITICAL, AttackType.MALWARE_C2),
    (("ddos", "dos ", "flood", "slowloris", "goldeneye", "hulk", "slowhttptest"),
     Severity.HIGH, AttackType.DDOS),
    (("sql injection", "xss", "web attack", "heartbleed", "webattack"), Severity.MEDIUM,
     AttackType.WEB_ATTACK),
    (("patator", "brute", "failed login", "failed password", "credential"), Severity.MEDIUM,
     AttackType.BRUTE_FORCE),
    (("portscan", "port scan", "sweep", "nmap", "probe", "scan"), Severity.LOW,
     AttackType.PORT_SCAN),
    (("recon", "enumeration", "discovery"), Severity.LOW, AttackType.RECON),
]

#: Indicators the offline intel treats as known-bad, with their scores. Chosen to
#: include addresses that appear in the shipped datasets so the demo actually
#: shows an IOC-driven escalation rather than a wall of clean verdicts.
_BAD_INDICATORS: dict[str, float] = {
    "45.13.2.99": 95.0,
    "185.220.101.7": 92.0,
    "91.219.236.4": 88.0,
    "193.27.228.7": 97.0,
    "205.174.165.73": 91.0,  # CICIDS2017 attacker host
    "172.16.0.1": 84.0,      # CICIDS2017 attack source
}


def describe() -> str:
    """One line for the startup banner and health output."""
    return (
        "OFFLINE MODE: LLM tiers, threat intel and ATT&CK retrieval are served by "
        "deterministic in-process stand-ins. Graph, workers, queues, DB, SSE and API "
        "are the real ones. Numbers produced in this mode are NOT measurements."
    )


def _classify_signature(text: str) -> tuple[Severity, AttackType]:
    lowered = text.lower()
    for keywords, severity, attack_type in _RULES:
        if any(keyword in lowered for keyword in keywords):
            return severity, attack_type
    return Severity.INFO, AttackType.BENIGN


def _alert_context(prompt: str) -> str:
    """The alert block the node appended, never the static instructions.

    Matching against the whole prompt would let the prompt's own examples decide
    the classification — the same trap the Phase 8 demo stubs documented.
    """
    for marker in ("Alert to classify:", "Alert under analysis:", "\n\nAlert:"):
        if marker in prompt:
            return prompt.split(marker)[-1]
    return prompt


def _technique_ids(prompt: str) -> list[str]:
    """Technique ids the node put in the prompt — the only ones we may cite."""
    import re

    context = prompt.split("ATT&CK", 1)[-1]
    seen: list[str] = []
    for match in re.findall(r"T\d{4}(?:\.\d{3})?", context):
        if match not in seen:
            seen.append(match)
    return seen


def _classification_json(prompt: str) -> str:
    severity, attack_type = _classify_signature(_alert_context(prompt))
    return json.dumps(
        {
            "severity": severity.value,
            "confidence": 0.82,
            "attack_type": attack_type.value,
            "rationale": (
                f"offline heuristic: signature keywords indicate {attack_type.value}"
            ),
        }
    )


def _remediation_json(prompt: str) -> str:
    context = _alert_context(prompt)
    severity, attack_type = _classify_signature(context)
    cited = _technique_ids(prompt)
    label = attack_type.value.replace("_", " ")
    return json.dumps(
        {
            "summary": (
                f"Offline playbook for suspected {label}. Contain the source, preserve "
                "evidence, then close the exposure that allowed it."
            ),
            "steps": [
                {
                    "order": 1,
                    "action": "Contain the source",
                    "detail": "Block the source address at the perimeter and drop active flows.",
                    "urgency": "immediate",
                },
                {
                    "order": 2,
                    "action": "Preserve evidence",
                    "detail": "Capture full packet data and host telemetry for the affected pair.",
                    "urgency": "soon",
                },
                {
                    "order": 3,
                    "action": "Close the exposure",
                    "detail": (
                        "Rotate any credentials reachable from the destination host and patch "
                        "the exposed service."
                    ),
                    "urgency": "monitor",
                },
            ],
            # Only ids the retriever actually supplied: emitting a plausible
            # T-number here would let the recommend node's hallucination guard
            # pass on evidence it should have rejected.
            "techniques": [{"id": tid, "name": "", "tactic": "", "url": "", "excerpt": ""}
                           for tid in cited],
            # Required by the Remediation schema. The recommend node overwrites
            # both in _sanitize, but they must be present and valid HERE or the
            # response fails validation exactly as a real model's would.
            "generated_at": datetime.now(UTC).isoformat(),
            "duration_ms": 0,
        }
    )


def _narrative(prompt: str) -> str:
    context = _alert_context(prompt)
    severity, attack_type = _classify_signature(context)
    cited = _technique_ids(prompt)
    techniques = ", ".join(cited) if cited else "no ATT&CK techniques were retrieved"
    return (
        f"The flow is consistent with {attack_type.value.replace('_', ' ')} activity and is "
        f"triaged at {severity.value} severity. Reputation context comes only from the IOC "
        f"verdicts supplied with this alert. Mapped ATT&CK coverage: {techniques}. "
        "Generated offline by a deterministic analyzer, not a language model."
    )


class OfflineProvider:
    """A provider that never leaves the process but behaves like one that does.

    Implements the same duck type as :class:`~app.providers.groq.GroqProvider`,
    including the JSON-parsing step, so the calling node's code path is
    byte-for-byte the one it runs in production.
    """

    def __init__(self, tier: ProviderTier) -> None:
        self.tier = tier
        self._rng = random.Random(f"{_SEED}:{tier.value}")
        self.throttled = False

    @property
    def name(self) -> str:
        return PROVIDER_NAME

    @property
    def model(self) -> str:
        return MODEL_NAME

    @property
    def available(self) -> bool:
        return True

    def _body(self, prompt: str, response_model: type[BaseModel] | None) -> str:
        if response_model is None:
            return _narrative(prompt)
        # Dispatch on the schema the NODE asked for, not on prompt sniffing: the
        # node's contract is "give me this shape", and that is what decides it.
        if "severity" in response_model.model_fields and "steps" not in response_model.model_fields:
            return _classification_json(prompt)
        return _remediation_json(prompt)

    async def complete(
        self,
        prompt: str,
        *,
        system: str | None = None,
        max_tokens: int = 512,
        temperature: float = 0.0,
        response_model: type[BaseModel] | None = None,
        timeout: float | None = None,
        model: str | None = None,
        node: str = "-",
    ) -> CompletionResult:
        started = time.perf_counter()
        text = self._body(prompt, response_model)

        parsed: BaseModel | None = None
        repaired = False
        if response_model is not None:
            # The REAL parsing path. If a schema change breaks live parsing, it
            # breaks here too — which is the point of not shortcutting it.
            meta = extract_json_meta(text)
            parsed = coerce_to_model(meta.data, response_model)
            repaired = meta.repaired

        # A plausible, seeded duration so the trace panel is not a column of
        # zeroes. Deterministic: the same run twice gives the same numbers.
        latency_ms = round(self._rng.uniform(4.0, 18.0), 2)
        elapsed_ms = (time.perf_counter() - started) * 1000.0

        return CompletionResult(
            text=text,
            parsed=parsed,
            tokens_in=max(1, len(prompt) // 4),
            tokens_out=max(1, len(text) // 4),
            latency_ms=max(latency_ms, elapsed_ms),
            provider=PROVIDER_NAME,
            model=MODEL_NAME,
            finish_reason="stop",
            attempts=1,
            repaired=repaired,
        )

    async def health(self) -> ProviderHealth:
        return ProviderHealth(status="ok", latency_ms=1.0, note=describe())


class OfflineIntelSource:
    """Deterministic reputation. Same duck type as the real intel clients."""

    supports: set[str] = {"ip", "hash"}

    def __init__(self, name: str = "offline-intel") -> None:
        self._name = name

    @property
    def name(self) -> str:
        return self._name

    async def lookup_ip(self, ip: str) -> SourceVerdict | None:
        return self._verdict(ip, "ip")

    async def lookup_hash(self, h: str) -> SourceVerdict | None:
        return self._verdict(h, "hash")

    def _verdict(self, indicator: str, itype: IndicatorType) -> SourceVerdict | None:
        score = _BAD_INDICATORS.get(indicator)
        if score is None:
            # None means "no data on this indicator", NOT a failure — the same
            # distinction the real clients draw. A clean IP must not look like an
            # outage in offline mode either.
            return None
        return SourceVerdict(
            source=IntelSource.ABUSEIPDB,
            indicator=indicator,
            indicator_type=itype,
            raw_score=score,
            normalized_score=score,
            malicious=score >= 50.0,
            categories=["offline_known_bad"],
            last_seen=datetime.now(UTC),
            link=f"https://www.abuseipdb.com/check/{indicator}",
        )

    async def health(self) -> ProviderHealth:
        return ProviderHealth(status="ok", latency_ms=1.0, note="offline intel")

    async def aclose(self) -> None:
        """No pool to release — present so the aggregator can close uniformly."""
        return None


class OfflineRetriever:
    """ATT&CK grounding from the COMMITTED corpus — real techniques, no embeddings.

    The live retriever needs Chroma plus a sentence-transformers download; a cold
    clone with no network has neither. The corpus JSON is in the repo, and the
    ``AttackType -> technique ids`` map is the same one the live retriever filters
    by, so the techniques cited offline are the real ones for that attack type.
    """

    def __init__(self) -> None:
        from app.rag.mitre_loader import load_corpus

        self._by_id = {doc.id: doc for doc in load_corpus()}

    async def retrieve(
        self, query: str, attack_type: AttackType | None = None, k: int = 4
    ) -> list[MitreTechnique]:
        from app.rag.mitre_loader import techniques_for

        out: list[MitreTechnique] = []
        for tid in techniques_for(attack_type)[:k]:
            doc = self._by_id.get(tid)
            if doc is None:
                continue
            out.append(
                MitreTechnique(
                    id=doc.id,
                    name=doc.name,
                    tactic=doc.tactics[0] if doc.tactics else "",
                    url=doc.url,
                    excerpt=doc.description[:300],
                )
            )
        return out


def build_offline_aggregator() -> Any:
    """An IntelAggregator wired to the offline source and an in-memory cache."""
    from types import SimpleNamespace

    from app.core.cache import InMemoryTTLCache
    from app.intel.aggregator import IntelAggregator

    settings = SimpleNamespace(
        intel_cache_ttl_seconds=3600,
        intel_source_timeout_seconds=5.0,
        intel_concurrency=10,
    )
    # The real TieredCache writes through to SQLite; offline keeps it in memory
    # so a demo run leaves no cache rows behind to confuse the next one.
    cache: Any = InMemoryTTLCache()
    return IntelAggregator([OfflineIntelSource()], cache, settings)


def install() -> None:
    """Point the registry, aggregator and retriever at the offline stand-ins.

    Installed at the seams the real implementations use, so nothing downstream
    branches on "am I offline" — there is no ``if offline:`` anywhere in the
    graph, the nodes, or the workers.
    """
    from app.agent.state import set_default_aggregator, set_default_retriever
    from app.providers.registry import get_registry

    registry = get_registry()
    registry.set_provider(ProviderTier.FAST, OfflineProvider(ProviderTier.FAST))
    registry.set_provider(ProviderTier.QUALITY, OfflineProvider(ProviderTier.QUALITY))

    set_default_aggregator(build_offline_aggregator())
    set_default_retriever(OfflineRetriever())

    log.warning("offline.installed", detail=describe())


__all__ = [
    "MODEL_NAME",
    "PROVIDER_NAME",
    "OfflineIntelSource",
    "OfflineProvider",
    "OfflineRetriever",
    "build_offline_aggregator",
    "describe",
    "install",
]
