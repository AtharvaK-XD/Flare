"""Shared test fixtures — in-memory DB + throwaway Chroma collection."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from typing import Any

import pytest
import pytest_asyncio
from sqlalchemy import event
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import StaticPool

from app.store.models import Base


@pytest_asyncio.fixture
async def db_engine() -> AsyncIterator[Any]:
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @event.listens_for(engine.sync_engine, "connect")
    def _fk_on(dbapi_conn: Any, _rec: Any) -> None:
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture
async def db_session(db_engine: Any) -> AsyncIterator[AsyncSession]:
    maker = async_sessionmaker(db_engine, expire_on_commit=False, class_=AsyncSession)
    async with maker() as session:
        yield session


@pytest.fixture
def chroma_collection(tmp_path: Any) -> Any:
    import chromadb

    client = chromadb.PersistentClient(path=str(tmp_path / "chroma"))
    name = f"test_{uuid.uuid4().hex[:8]}"
    col = client.get_or_create_collection(name=name, metadata={"hnsw:space": "cosine"})
    yield col
    client.delete_collection(name)
