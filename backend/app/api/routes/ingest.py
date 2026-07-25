"""Manual ingest (§5 ``POST /ingest``) — the "try your own alert" demo button.

Accepts either raw Suricata EVE JSON or the contract's simplified body. Parses,
normalizes, enqueues, and returns ``202`` in milliseconds. The graph is NEVER run
inline: the triaged result arrives over SSE, exactly as the contract promises.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, status

from app.api.errors import QueueFullError, ValidationError
from app.core.logging import get_logger
from app.deps import TriageQueueDep
from app.ingestion.normalizer import extract_iocs, normalize
from app.schemas import FlareModel, NormalizedAlert

log = get_logger(__name__)

router = APIRouter(tags=["ingest"])

MANUAL_SOURCE = "manual"


class IngestAccepted(FlareModel):
    id: str
    status: str = "ingested"


def _from_simplified(body: dict[str, Any]) -> NormalizedAlert | None:
    """Build an alert from the contract's minimal body.

    Requires a signature and both addresses; everything else is optional. The
    parsers can't be reused here — they expect vendor-shaped records.
    """
    signature = body.get("signature")
    src_ip = body.get("src_ip")
    dst_ip = body.get("dst_ip")
    if not (signature and src_ip and dst_ip):
        return None

    def _port(value: Any) -> int | None:
        try:
            return int(value) if value is not None else None
        except (TypeError, ValueError):
            return None

    alert = NormalizedAlert(
        id="",
        timestamp=datetime.now(UTC),
        source=MANUAL_SOURCE,
        signature=str(signature),
        src_ip=str(src_ip),
        dst_ip=str(dst_ip),
        src_port=_port(body.get("src_port")),
        dst_port=_port(body.get("dst_port")),
        protocol=str(body["protocol"]) if body.get("protocol") else None,
        raw=dict(body),
    )
    return alert.model_copy(update={"extracted_iocs": extract_iocs(alert)})


def _parse(body: dict[str, Any]) -> NormalizedAlert | None:
    """EVE JSON if it looks like EVE, otherwise the simplified body."""
    if "event_type" in body:
        return normalize(body, "suricata")
    return _from_simplified(body)


@router.post("/ingest", status_code=status.HTTP_202_ACCEPTED, response_model=IngestAccepted)
async def ingest(body: dict[str, Any], triage_q: TriageQueueDep) -> IngestAccepted:
    alert = _parse(body)
    if alert is None:
        raise ValidationError(
            "could not parse alert — expected Suricata EVE JSON (event_type=alert) "
            "or an object with signature, src_ip and dst_ip",
            detail={"received_keys": sorted(body.keys())},
        )

    # A fresh id per submission: the demo button is expected to work twice in a
    # row with identical input, which a content-derived id would reject as a
    # duplicate primary key.
    alert = alert.model_copy(update={"id": str(uuid.uuid4())})

    if not triage_q.put(alert):
        raise QueueFullError(
            "triage queue is saturated — alert not accepted, retry shortly",
            detail={"queue": "triage", "depth": triage_q.depth},
        )

    log.info("ingest.accepted", alert_id=alert.id, source=alert.source)
    return IngestAccepted(id=alert.id)


__all__ = ["router", "IngestAccepted"]
