"""RAG integration tests — real temp Chroma + real embedding model (slow)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from app.rag.indexer import build_index
from app.rag.retriever import MitreRetriever
from app.schemas import AttackType

pytestmark = [pytest.mark.slow, pytest.mark.asyncio]


def _collection(tmp_path: Path, name: str = "mitre_test") -> Any:
    import chromadb

    client = chromadb.PersistentClient(path=str(tmp_path / "chroma"))
    return client.get_or_create_collection(name=name, metadata={"hnsw:space": "cosine"})


async def test_build_index_is_idempotent(tmp_path: Path) -> None:
    col = _collection(tmp_path)
    stats1 = await build_index(collection=col)
    count1 = col.count()
    assert count1 > 0

    stats2 = await build_index(collection=col)
    assert col.count() == count1
    assert stats2["corpus_hash"] == stats1["corpus_hash"]

    stats3 = await build_index(force=True, collection=col)
    assert col.count() == count1
    assert stats3["corpus_hash"] == stats1["corpus_hash"]


async def test_retrieve_brute_force_returns_t1110_top(tmp_path: Path) -> None:
    col = _collection(tmp_path)
    await build_index(collection=col)
    r = MitreRetriever(collection=col)

    results = await r.retrieve(
        "ssh login failures repeated many times", attack_type=AttackType.BRUTE_FORCE, k=4
    )
    assert results
    assert results[0].id.startswith("T1110")
    ids = [t.id for t in results]
    assert len(ids) == len(set(ids))


async def test_empty_collection_returns_empty(tmp_path: Path) -> None:
    col = _collection(tmp_path, name="empty")
    r = MitreRetriever(collection=col)
    assert await r.retrieve("anything", attack_type=AttackType.PORT_SCAN) == []
