"""Chunker tests — section boundaries, complete metadata, deterministic ids."""

from __future__ import annotations

from app.rag.chunker import MAX_TOKENS, chunk_doc
from app.rag.mitre_loader import TechniqueDoc

DOC = TechniqueDoc(
    id="T1046",
    name="Network Service Discovery",
    tactics=["Discovery"],
    description="Adversaries scan for listening services on remote hosts.",
    detection="Monitor for many connection attempts from one source to many ports.",
    mitigations=["M1042: Disable or Remove Feature", "M1031: Network Intrusion Prevention"],
    platforms=["Linux"],
    data_sources=["Network Traffic: Network Connection Creation"],
    url="https://attack.mitre.org/techniques/T1046/",
)


def test_sections_are_separate_chunks() -> None:
    chunks = chunk_doc(DOC)
    sections = {c.metadata["section"] for c in chunks}
    assert sections == {"description", "detection", "mitigations"}


def test_metadata_complete() -> None:
    for c in chunk_doc(DOC):
        m = c.metadata
        assert m["technique_id"] == "T1046"
        assert m["technique_name"] == "Network Service Discovery"
        assert m["tactic"] == "Discovery"
        assert m["section"] in {"description", "detection", "mitigations"}
        assert m["url"].endswith("/T1046/")
        assert isinstance(m["chunk_index"], int)


def test_embed_text_has_identity_prefix() -> None:
    detection = next(c for c in chunk_doc(DOC) if c.metadata["section"] == "detection")
    assert detection.embed_text.startswith("T1046 Network Service Discovery — Detection: ")


def test_ids_deterministic_and_formatted() -> None:
    first = [c.id for c in chunk_doc(DOC)]
    second = [c.id for c in chunk_doc(DOC)]
    assert first == second
    assert "T1046:description:0" in first
    assert "T1046:detection:0" in first
    assert "T1046:mitigations:0" in first


def test_long_section_splits_with_overlap() -> None:
    long_desc = " ".join(f"word{i}" for i in range(MAX_TOKENS + 300))
    doc = DOC.model_copy(update={"description": long_desc, "detection": "", "mitigations": []})
    chunks = chunk_doc(doc)
    desc_chunks = [c for c in chunks if c.metadata["section"] == "description"]
    assert len(desc_chunks) >= 2
    assert [c.metadata["chunk_index"] for c in desc_chunks] == list(range(len(desc_chunks)))
    body0 = desc_chunks[0].embed_text.split(": ", 1)[1].split()
    body1 = desc_chunks[1].embed_text.split(": ", 1)[1].split()
    assert body0[-1] in body1[:60]
