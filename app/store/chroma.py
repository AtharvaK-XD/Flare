"""Chroma vector store lifecycle only — no embedding/indexing (that's Phase 7).

Module-level lazy singleton client; blocking calls are wrapped in
``asyncio.to_thread`` so they are safe to await from async code.
"""

from __future__ import annotations

import asyncio
from typing import Any

import chromadb
from chromadb.api import ClientAPI
from chromadb.api.models.Collection import Collection

from app.config import get_settings

_client: ClientAPI | None = None


def _build_client() -> ClientAPI:
    settings = get_settings()
    return chromadb.PersistentClient(path=str(settings.chroma_persist_dir))


def get_client() -> ClientAPI:
    """Lazily create the module-level PersistentClient."""
    global _client
    if _client is None:
        _client = _build_client()
    return _client


def _get_collection_sync() -> Collection:
    settings = get_settings()
    return get_client().get_or_create_collection(
        name=settings.chroma_collection,
        metadata={"hnsw:space": "cosine"},
    )


async def get_collection() -> Collection:
    """Get-or-create the configured collection (cosine space)."""
    return await asyncio.to_thread(_get_collection_sync)


def _collection_stats_sync() -> dict[str, Any]:
    col = _get_collection_sync()
    return {"documents": col.count()}


async def collection_stats() -> dict[str, Any]:
    """Return ``{"documents": n}`` for /health/deep."""
    return await asyncio.to_thread(_collection_stats_sync)


def reset_client() -> None:
    """Drop the cached client (mainly for tests)."""
    global _client
    _client = None
