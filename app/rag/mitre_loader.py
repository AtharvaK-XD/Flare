"""Load the checked-in MITRE ATT&CK corpus + the AttackType→technique mapping.

The corpus under ``app/rag/corpus/`` is committed to the repo so the demo never
depends on network access to attack.mitre.org at runtime.
"""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, ValidationError

from app.core.logging import get_logger
from app.schemas import AttackType

log = get_logger(__name__)

CORPUS_DIR = Path(__file__).parent / "corpus"


class TechniqueDoc(BaseModel):
    id: str
    name: str
    tactics: list[str]
    description: str
    detection: str = ""
    mitigations: list[str] = []
    platforms: list[str] = []
    data_sources: list[str] = []
    url: str


ATTACK_TYPE_TO_TECHNIQUES: dict[AttackType, list[str]] = {
    AttackType.PORT_SCAN: ["T1046", "T1595", "T1018"],
    AttackType.BRUTE_FORCE: ["T1110", "T1110.001", "T1110.003", "T1110.004", "T1078"],
    AttackType.DDOS: ["T1498", "T1499"],
    AttackType.WEB_ATTACK: ["T1190", "T1059.007", "T1505.003"],
    AttackType.MALWARE_C2: ["T1071", "T1071.001", "T1573", "T1105", "T1568"],
    AttackType.DATA_EXFILTRATION: ["T1041", "T1048", "T1567", "T1030"],
    AttackType.PRIVILEGE_ESCALATION: ["T1068", "T1548", "T1055"],
    AttackType.RECON: ["T1595", "T1590", "T1592"],
    AttackType.BENIGN: [],
    AttackType.UNKNOWN: [],
}


def load_corpus() -> list[TechniqueDoc]:
    """Read and validate every technique JSON. Fail loudly with the filename."""
    files = sorted(CORPUS_DIR.glob("*.json"))
    if not files:
        raise FileNotFoundError(f"no corpus documents found in {CORPUS_DIR}")

    docs: list[TechniqueDoc] = []
    for path in files:
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            docs.append(TechniqueDoc.model_validate(raw))
        except (json.JSONDecodeError, ValidationError) as exc:
            raise ValueError(f"malformed corpus document {path.name}: {exc}") from exc
    return docs


def techniques_for(attack_type: AttackType | None) -> list[str]:
    if attack_type is None:
        return []
    return ATTACK_TYPE_TO_TECHNIQUES.get(attack_type, [])


def fetch_from_mitre(technique_ids: list[str]) -> list[dict]:  # pragma: no cover
    """OFFLINE corpus-regeneration helper — NEVER called at runtime.

    Pulls technique detail from the MITRE ATT&CK STIX bundle so the checked-in
    corpus can be refreshed by a maintainer. Requires network access and is
    intentionally excluded from the runtime path; the demo reads only the
    committed JSON under ``corpus/``.
    """
    raise NotImplementedError(
        "fetch_from_mitre is an offline maintenance helper; regenerate the corpus "
        "manually and commit the JSON. Not available at runtime."
    )
