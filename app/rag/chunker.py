"""Split technique docs into section-coherent chunks with identity-prefixed text.

Sections (description / detection / mitigations) are chunked separately — never
split across a section boundary. Each chunk's embedded text is prefixed with the
technique identity ("T1046 Network Service Discovery — Detection: ...") because
bare chunk text loses that identity and retrieval quality drops. Chunk ids are
deterministic so re-indexing upserts in place instead of duplicating the corpus.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.rag.mitre_loader import TechniqueDoc

TARGET_TOKENS = 400
MAX_TOKENS = 512
OVERLAP_TOKENS = 50

_SECTION_TITLES = {
    "description": "Description",
    "detection": "Detection",
    "mitigations": "Mitigations",
}


@dataclass
class Chunk:
    id: str
    embed_text: str
    metadata: dict[str, Any] = field(default_factory=dict)


def _word_count(text: str) -> int:
    return len(text.split())


def _split_section(text: str) -> list[str]:
    """Split only a long section, with word overlap; short sections stay whole."""
    words = text.split()
    if len(words) <= MAX_TOKENS:
        return [text.strip()]
    pieces: list[str] = []
    step = TARGET_TOKENS - OVERLAP_TOKENS
    start = 0
    while start < len(words):
        pieces.append(" ".join(words[start : start + TARGET_TOKENS]))
        if start + TARGET_TOKENS >= len(words):
            break
        start += step
    return pieces


def _section_text(doc: TechniqueDoc, section: str) -> str:
    if section == "mitigations":
        return " ".join(doc.mitigations).strip()
    return str(getattr(doc, section, "")).strip()


def chunk_doc(doc: TechniqueDoc) -> list[Chunk]:
    tactic = doc.tactics[0] if doc.tactics else ""
    chunks: list[Chunk] = []
    for section in ("description", "detection", "mitigations"):
        raw = _section_text(doc, section)
        if not raw:
            continue
        for index, piece in enumerate(_split_section(raw)):
            title = _SECTION_TITLES[section]
            embed_text = f"{doc.id} {doc.name} — {title}: {piece}"
            chunks.append(
                Chunk(
                    id=f"{doc.id}:{section}:{index}",
                    embed_text=embed_text,
                    metadata={
                        "technique_id": doc.id,
                        "technique_name": doc.name,
                        "tactic": tactic,
                        "section": section,
                        "url": doc.url,
                        "chunk_index": index,
                    },
                )
            )
    return chunks


def chunk_corpus(docs: list[TechniqueDoc]) -> list[Chunk]:
    chunks: list[Chunk] = []
    for doc in docs:
        chunks.extend(chunk_doc(doc))
    return chunks
