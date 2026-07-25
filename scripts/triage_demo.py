"""Scratch acceptance demo — 20 mixed alerts through the real triage graph.

Runs fully offline and deterministically: the LLM tiers are replaced by heuristic
stubs and the MITRE retriever by a corpus-backed stub (real technique IDs/names,
no embeddings, no network). The graph, routers, trace decorator, escalation, and
hallucination guard are the REAL Phase-8 code — only the leaf I/O is stubbed.

It demonstrates the two headline behaviors:
  * benign / low alerts short-circuit to `done` with skipped enrich/reason/etc.
  * malicious alerts get enriched, escalated, and receive CITED remediation.

Usage: python scripts/triage_demo.py
"""

from __future__ import annotations

import asyncio
import re
from datetime import UTC, datetime
from typing import Any

from app.agent.graph import run_triage
from app.agent.nodes.classify import ClassificationResult
from app.providers.base import CompletionResult
from app.rag.mitre_loader import load_corpus, techniques_for
from app.schemas import (
    AttackType,
    IocVerdict,
    MitreTechnique,
    NormalizedAlert,
    ProviderTier,
    Remediation,
    RemediationStep,
    Severity,
)

_IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_TID_RE = re.compile(r"T\d{4}(?:\.\d{3})?")

# IPs the stub intel treats as known-bad (score 95). Everything else is clean.
_BAD_IPS = {"45.13.2.99", "185.220.101.7", "91.219.236.4", "193.27.228.7"}


# --------------------------------------------------------------------------- stubs


def _classify(prompt: str) -> ClassificationResult:
    # Only inspect the appended alert block, never the static instructions.
    p = prompt.split("Alert to classify:")[-1].lower()
    if "exfil" in p:
        return ClassificationResult(
            severity=Severity.HIGH, confidence=0.86,
            attack_type=AttackType.DATA_EXFILTRATION, rationale="large outbound transfer",
        )
    if any(k in p for k in ("c2", "beacon", "trojan", "malware", "cobalt", "tunnel")):
        return ClassificationResult(
            severity=Severity.CRITICAL, confidence=0.9,
            attack_type=AttackType.MALWARE_C2, rationale="C2/malware indicators",
        )
    if any(k in p for k in ("ddos", "flood")):
        return ClassificationResult(
            severity=Severity.HIGH, confidence=0.82,
            attack_type=AttackType.DDOS, rationale="volumetric flood",
        )
    if any(k in p for k in ("brute", "failed login", "failed password", "10+")):
        return ClassificationResult(
            severity=Severity.HIGH, confidence=0.85,
            attack_type=AttackType.BRUTE_FORCE, rationale="repeated auth failures",
        )
    if any(k in p for k in ("scan", "sweep", "probe")):
        return ClassificationResult(
            severity=Severity.MEDIUM, confidence=0.8,
            attack_type=AttackType.PORT_SCAN, rationale="sequential port access",
        )
    return ClassificationResult(
        severity=Severity.INFO, confidence=0.9,
        attack_type=AttackType.BENIGN, rationale="ordinary traffic",
    )


def _remediation(prompt: str) -> Remediation:
    # Restrict to the appended context block (skip the example IP in the md).
    ctx = prompt.split("\n\nAlert:", 1)[-1]
    ips = _IP_RE.findall(ctx)
    ip = ips[0] if ips else "the source host"
    cited = _TID_RE.findall(ctx)
    # cite the real retrieved IDs PLUS a fabricated one the guard must drop
    techniques = [
        MitreTechnique(id=tid, name="", tactic="", url="", excerpt="") for tid in cited
    ] + [MitreTechnique(id="T9999", name="Fake", tactic="", url="", excerpt="")]
    steps = [
        RemediationStep(order=1, action="Contain source",
                        detail=f"Block {ip} at the perimeter firewall.", urgency="immediate"),
        RemediationStep(order=2, action="Preserve evidence",
                        detail=f"Capture flows to/from {ip} for forensics.", urgency="soon"),
        RemediationStep(order=3, action="Harden",
                        detail="Rotate exposed credentials and patch the target service.",
                        urgency="monitor"),
    ]
    return Remediation(
        summary=f"Suspicious activity from {ip}; contain and investigate.",
        steps=steps, techniques=techniques,
        generated_at=datetime.now(UTC), duration_ms=0,
    )


class StubProvider:
    def __init__(self, name: str, tier: ProviderTier) -> None:
        self._name = name
        self.tier = tier

    @property
    def name(self) -> str:
        return self._name

    @property
    def model(self) -> str:
        return "stub"

    async def complete(
        self, prompt: str, *, response_model: Any = None, **kw: Any
    ) -> CompletionResult:
        parsed: Any = None
        text = ""
        if response_model is ClassificationResult:
            parsed = _classify(prompt)
        elif response_model is Remediation:
            parsed = _remediation(prompt)
        else:  # reason narrative — cite only IDs from the ATT&CK context section
            ctx = prompt.split("ATT&CK context", 1)[-1]
            ids = ", ".join(_TID_RE.findall(ctx)) or "no techniques"
            text = f"Activity aligns with ATT&CK ({ids}). Reputation from provided IOCs only."
        return CompletionResult(
            text=text, parsed=parsed, tokens_in=50, tokens_out=80,
            latency_ms=1.0, provider=self._name, model="stub", finish_reason="stop",
        )


class StubRegistry:
    def __init__(self) -> None:
        self._m = {
            ProviderTier.FAST: StubProvider("groq", ProviderTier.FAST),
            ProviderTier.QUALITY: StubProvider("gemini", ProviderTier.QUALITY),
        }

    def get(self, tier: ProviderTier) -> StubProvider:
        return self._m[tier]


class StubAggregator:
    async def lookup_many(
        self, pairs: list[tuple[str, str]]
    ) -> list[IocVerdict | None]:
        out: list[IocVerdict | None] = []
        for indicator, itype in pairs:
            if indicator in _BAD_IPS:
                out.append(
                    IocVerdict(
                        indicator=indicator, indicator_type=itype, score=95.0, malicious=True
                    )
                )
            else:
                out.append(None)
        return out


class CorpusRetriever:
    """Offline retriever: attack_type -> real technique docs from the committed corpus."""

    def __init__(self) -> None:
        self._by_id = {d.id: d for d in load_corpus()}

    async def retrieve(
        self, query: str, attack_type: Any = None, k: int = 4
    ) -> list[MitreTechnique]:
        ids = techniques_for(attack_type)[:k]
        out: list[MitreTechnique] = []
        for tid in ids:
            doc = self._by_id.get(tid)
            if doc is None:
                continue
            out.append(
                MitreTechnique(
                    id=doc.id, name=doc.name,
                    tactic=doc.tactics[0] if doc.tactics else "",
                    url=doc.url, excerpt=doc.description[:200],
                )
            )
        return out


# --------------------------------------------------------------------------- alerts


# (signature, src_ip, dst_ip, dst_port, protocol)
_ROWS: list[tuple[str, str, str, int | None, str]] = [
    ("Outbound DNS to public resolver", "10.0.4.12", "8.8.8.8", 53, "UDP"),
    ("HTTPS to CDN edge", "10.0.4.20", "104.18.2.10", 443, "TCP"),
    ("NTP sync", "10.0.4.5", "129.6.15.28", 123, "UDP"),
    ("Internal file share access", "10.0.4.30", "10.0.4.9", 445, "TCP"),
    ("ET SCAN Sequential port sweep", "45.13.2.99", "10.0.0.5", 22, "TCP"),
    ("ET SCAN NULL probe", "203.0.113.9", "10.0.0.7", 3389, "TCP"),
    ("ET SCAN Nmap service probe", "198.51.100.4", "10.0.0.5", 8080, "TCP"),
    ("ET SCAN Multiple failed SSH logins 10+/60s", "185.220.101.7", "10.0.0.5", 22, "TCP"),
    ("RDP brute force failed login burst", "91.219.236.4", "10.0.0.8", 3389, "TCP"),
    ("SMTP AUTH failed password repeated", "203.0.113.44", "10.0.0.25", 25, "TCP"),
    ("ET MALWARE Cobalt Strike beacon C2", "193.27.228.7", "10.0.0.15", 443, "TCP"),
    ("ET MALWARE Trojan check-in C2", "198.51.100.77", "10.0.0.16", 8443, "TCP"),
    ("Suspected data exfil large upload", "10.0.0.16", "45.13.2.99", 443, "TCP"),
    ("ET DDOS SYN flood inbound", "203.0.113.200", "10.0.0.1", 80, "TCP"),
    ("HTTP GET static asset", "10.0.4.40", "151.101.1.69", 80, "TCP"),
    ("DHCP request", "10.0.4.41", "10.0.4.1", 67, "UDP"),
    ("ICMP echo request", "10.0.4.42", "10.0.4.1", None, "ICMP"),
    ("ET SCAN low-and-slow probe", "198.51.100.9", "10.0.0.5", 22, "TCP"),
    ("Kerberos AS-REQ", "10.0.4.50", "10.0.4.2", 88, "TCP"),
    ("ET MALWARE DNS tunneling exfil", "193.27.228.7", "10.0.0.20", 53, "UDP"),
]


def _alert(
    sig: str, src: str, dst: str, dport: int | None, proto: str
) -> NormalizedAlert:
    # Public IPs on either end become IOCs, mirroring the real normalizer.
    iocs = [ip for ip in (src, dst) if ip in _BAD_IPS]
    return NormalizedAlert(
        id=f"demo-{abs(hash((sig, src, dport))) % 10_000_000}",
        timestamp=datetime(2026, 7, 25, 14, 0, tzinfo=UTC),
        source="suricata", signature=sig, src_ip=src, dst_ip=dst,
        src_port=44012, dst_port=dport, protocol=proto,
        raw={"signature": sig, "src_ip": src, "dst_ip": dst},
        extracted_iocs=iocs,
    )


def _alerts() -> list[NormalizedAlert]:
    return [_alert(*row) for row in _ROWS]


# --------------------------------------------------------------------------- run


def _fmt_trace(state: dict[str, Any]) -> str:
    marks = {"ok": "R", "skipped": ".", "failed": "X"}
    order = {"classify": 0, "enrich": 1, "retrieve": 2, "reason": 3, "recommend": 4}
    by_node = {t.node: t.status for t in state["trace"]}
    return "".join(marks.get(by_node.get(n, "skipped"), "?") for n in sorted(order, key=order.get))


async def main() -> None:
    config = {
        "registry": StubRegistry(),
        "aggregator": StubAggregator(),
        "retriever": CorpusRetriever(),
    }

    header = (
        f"{'#':>2}  {'severity':<9} {'attack_type':<14} {'trace':<6} "
        f"{'score':>5} {'remediation (cited techniques)':<40}"
    )
    print("\nTrace legend: classify enrich retrieve reason recommend  (R ran . skipped X failed)\n")
    print(header)
    print("-" * len(header))

    short_circuited = 0
    remediated = 0

    for i, alert in enumerate(_alerts(), 1):
        state = await run_triage(alert, config=config)
        sev = state["severity"].value
        at = (state.get("attack_type") or AttackType.UNKNOWN).value
        trace = _fmt_trace(state)
        score = state.get("max_ioc_score")
        score_s = str(score) if score is not None else "-"

        rem = state.get("remediation")
        if rem is None:
            rem_s = "- (short-circuited)"
            short_circuited += 1
        else:
            tids = ", ".join(t.id for t in rem.techniques) or "none"
            rem_s = f"{len(rem.steps)} steps [{tids}]"
            remediated += 1

        print(f"{i:>2}  {sev:<9} {at:<14} {trace:<6} {score_s:>5} {rem_s:<40}")

    print("-" * len(header))
    print(
        f"\n{remediated} alert(s) received cited remediation; "
        f"{short_circuited} short-circuited to done (cost saved).\n"
    )

    # Spotlight one malicious alert's full cited playbook.
    malicious = _alert(
        "ET MALWARE Cobalt Strike beacon C2", "193.27.228.7", "10.0.0.15", 443, "TCP"
    )
    state = await run_triage(malicious, config=config)
    rem = state.get("remediation")
    print("Spotlight - malicious C2 alert remediation:")
    print(f"  severity: {state['severity'].value}  (IOC score {state.get('max_ioc_score')})")
    if rem is not None:
        print(f"  summary: {rem.summary}")
        for s in rem.steps:
            print(f"    {s.order}. [{s.urgency}] {s.action} - {s.detail}")
        print(f"  cited ATT&CK: {', '.join(f'{t.id} {t.name}' for t in rem.techniques) or 'none'}")


if __name__ == "__main__":
    asyncio.run(main())
