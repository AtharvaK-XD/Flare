"""Alert schemas + enums (§3 enums, §4 AlertSummary/AlertDetail/TraceNode).

Also the internal-only RawAlert / NormalizedAlert shapes ingestion produces,
and the /alerts/stats payload (AlertStats + TimelineBucket).
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import ConfigDict

from app.schemas import FlareModel
from app.schemas.enrichment import Enrichment
from app.schemas.remediation import Remediation


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertStatus(str, Enum):
    INGESTED = "ingested"
    CLASSIFIED = "classified"
    ENRICHED = "enriched"
    REASONED = "reasoned"
    DONE = "done"
    FAILED = "failed"


class AttackType(str, Enum):
    PORT_SCAN = "port_scan"
    BRUTE_FORCE = "brute_force"
    DDOS = "ddos"
    WEB_ATTACK = "web_attack"
    MALWARE_C2 = "malware_c2"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    RECON = "recon"
    BENIGN = "benign"
    UNKNOWN = "unknown"


class TraceNode(FlareModel):
    node: Literal["classify", "enrich", "retrieve", "reason", "recommend"]
    status: Literal["ok", "skipped", "failed"]
    provider: str | None = None
    duration_ms: int
    tokens_in: int | None = None
    tokens_out: int | None = None
    note: str | None = None


class AlertSummary(FlareModel):
    id: str
    timestamp: datetime
    status: AlertStatus
    severity: Severity | None = None
    confidence: float | None = None
    attack_type: AttackType | None = None
    signature: str
    src_ip: str
    dst_ip: str
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str | None = None
    source: str
    has_enrichment: bool = False
    has_remediation: bool = False
    max_ioc_score: float | None = None


class AlertDetail(AlertSummary):
    raw: dict[str, Any] = {}
    reasoning: str | None = None
    enrichment: Enrichment | None = None
    remediation: Remediation | None = None
    trace: list[TraceNode] = []
    total_duration_ms: int | None = None

    def to_summary(self) -> AlertSummary:
        """Project the detail down to the list-view summary shape."""
        return AlertSummary(
            id=self.id,
            timestamp=self.timestamp,
            status=self.status,
            severity=self.severity,
            confidence=self.confidence,
            attack_type=self.attack_type,
            signature=self.signature,
            src_ip=self.src_ip,
            dst_ip=self.dst_ip,
            src_port=self.src_port,
            dst_port=self.dst_port,
            protocol=self.protocol,
            source=self.source,
            has_enrichment=self.has_enrichment,
            has_remediation=self.has_remediation,
            max_ioc_score=self.max_ioc_score,
        )


class RawAlert(FlareModel):
    """Permissive inbound alert — raw Suricata EVE JSON or a minimal object."""

    model_config = ConfigDict(
        populate_by_name=True,
        use_enum_values=False,
        ser_json_timedelta="float",
        extra="allow",
    )

    signature: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str | None = None


class NormalizedAlert(FlareModel):
    """Canonical internal shape produced by ingestion parsers."""

    id: str
    timestamp: datetime
    source: str
    signature: str
    src_ip: str
    dst_ip: str
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str | None = None
    raw: dict[str, Any] = {}
    extracted_iocs: list[str] = []
    ground_truth_label: str | None = None


class TimelineBucket(FlareModel):
    bucket: datetime
    count: int
    critical: int


class AlertStats(FlareModel):
    total: int
    by_severity: dict[str, int] = {}
    by_attack_type: dict[str, int] = {}
    by_status: dict[str, int] = {}
    malicious_iocs: int
    avg_triage_ms: float | None = None
    alerts_per_min: float
    timeline: list[TimelineBucket] = []
