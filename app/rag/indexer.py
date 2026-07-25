"""Build the MITRE ATT&CK vector index in Chroma — idempotent via upsert.

Running ``build_index`` twice leaves the collection identical: deterministic
chunk ids + upsert, plus a stored corpus hash that lets a matching index skip
work entirely (unless ``force=True``).
"""

from __future__ import annotations

import asyncio
import hashlib
import time
from datetime import UTC, datetime
from functools import partial
from typing import Any

from app.config import get_settings
from app.core.logging import get_logger
from app.rag.chunker import Chunk, chunk_corpus
from app.rag.mitre_loader import load_corpus

log = get_logger(__name__)

_model: Any = None
_PROGRESS_EVERY = 25


def get_embedding_model() -> Any:
    """Cached sentence-transformers model (settings.EMBEDDING_MODEL)."""
    global _model
    if _model is None:
        from sentence_transformers import SentenceTransformer

        _model = SentenceTransformer(get_settings().embedding_model)
    return _model


def corpus_hash(chunks: list[Chunk]) -> str:
    h = hashlib.sha256()
    for c in sorted(chunks, key=lambda x: x.id):
        h.update(c.id.encode())
        h.update(b"\x1f")
        h.update(c.embed_text.encode())
        h.update(b"\x1e")
    return h.hexdigest()


async def _get_default_collection() -> Any:
    from app.store.chroma import get_collection

    return await get_collection()


def _embed_all(texts: list[str]) -> list[list[float]]:
    model = get_embedding_model()
    embeddings: list[list[float]] = []
    for start in range(0, len(texts), _PROGRESS_EVERY):
        batch = texts[start : start + _PROGRESS_EVERY]
        vecs = model.encode(batch, show_progress_bar=False)
        embeddings.extend(v.tolist() for v in vecs)
        log.info("rag.embed_progress", done=len(embeddings), total=len(texts))
    return embeddings


async def build_index(force: bool = False, collection: Any = None) -> dict[str, Any]:
    """Build/refresh the index. Every chromadb and file call goes to a thread.

    chromadb's client and the corpus reader are both synchronous; run bare in a
    coroutine they block the loop for the whole index build (tens of seconds on
    a cold embedding model), which stalls the API if this is ever triggered from
    a running app rather than the CLI.
    """
    t0 = time.perf_counter()
    docs = await asyncio.to_thread(load_corpus)
    chunks = chunk_corpus(docs)
    chash = corpus_hash(chunks)
    expected = len(chunks)

    col = collection or await _get_default_collection()

    meta = dict(col.metadata or {})
    if not force and await asyncio.to_thread(col.count) == expected:
        if meta.get("corpus_hash") == chash:
            log.info("rag.index_skip", reason="up-to-date", documents=expected)
            return await asyncio.to_thread(index_stats, col)

    ids = [c.id for c in chunks]
    texts = [c.embed_text for c in chunks]
    metadatas = [c.metadata for c in chunks]

    embeddings = await asyncio.to_thread(_embed_all, texts)

    built_at = datetime.now(UTC).isoformat()
    await asyncio.to_thread(
        partial(col.upsert, ids=ids, embeddings=embeddings, documents=texts, metadatas=metadatas)
    )
    await asyncio.to_thread(
        partial(
            col.modify,
            metadata={
                "corpus_hash": chash,
                "built_at": built_at,
                "model": get_settings().embedding_model,
                "techniques": len(docs),
            },
        )
    )

    elapsed = time.perf_counter() - t0
    log.info(
        "rag.index_built",
        documents=expected,
        techniques=len(docs),
        elapsed_s=round(elapsed, 1),
    )
    return {
        "documents": await asyncio.to_thread(col.count),
        "techniques": len(docs),
        "model": get_settings().embedding_model,
        "built_at": built_at,
        "corpus_hash": chash,
    }


def index_stats(collection: Any) -> dict[str, Any]:
    meta = dict(collection.metadata or {})
    return {
        "documents": collection.count(),
        "techniques": meta.get("techniques"),
        "model": meta.get("model"),
        "built_at": meta.get("built_at"),
        "corpus_hash": meta.get("corpus_hash"),
    }
