"""Shared test fixtures — in-memory DB + throwaway Chroma collection.

The suite is pinned away from the developer's ``.env`` (see
:func:`_pin_settings_env`): a run whose behaviour depends on whichever model id
or API key happens to be in a local file is not a test, and a stale value there
was surfacing as a warning in an otherwise clean run.
"""

from __future__ import annotations

import asyncio
import gc
import os
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

#: Environment-variable overrides beat ``.env`` in pydantic-settings precedence,
#: so setting these makes the suite independent of the local file without
#: touching it. Values are the shipped defaults, never live credentials.
_PINNED_ENV = {
    "GEMINI_MODEL": "gemini-flash-latest",
    "GROQ_FAST_MODEL": "openai/gpt-oss-120b",
    "GROQ_QUALITY_MODEL": "llama-3.3-70b-versatile",
    "OFFLINE_MODE": "false",
}


def pytest_configure(config: Any) -> None:  # noqa: ARG001
    """Pin config BEFORE any test imports app.config and caches its settings."""
    for key, value in _PINNED_ENV.items():
        os.environ.setdefault(key, value)

    from app.config import get_settings

    get_settings.cache_clear()


@pytest_asyncio.fixture(autouse=True)
async def _no_leaked_intel_clients() -> AsyncIterator[None]:
    """Close the live intel aggregator after every test.

    ``app.agent.state`` builds it lazily the first time a graph run reaches the
    enrich node WITHOUT an injected aggregator — which also means that run just
    called VirusTotal and AbuseIPDB for real, on the developer's quota. Closing
    it here stops the httpx pools from leaking sockets between tests (they
    surface later as ResourceWarnings attributed to an unrelated test, which is
    a miserable thing to debug).
    """
    yield
    from app.agent.state import close_default_aggregator
    from app.store.db import dispose_db

    await close_default_aggregator()
    # The module-level engine is shared across tests. Each app lifespan builds
    # and disposes it, but a test that touches the DB WITHOUT a lifespan leaves
    # pooled aiosqlite connections for the GC — which then reports
    # "Exception ignored in Connection.__del__" against whichever unrelated test
    # was running when the collection happened.
    await dispose_db()
    # Run finalizers HERE, while this test's event loop is still alive. Left to
    # chance, a sqlite3 connection's __del__ fires during some later test after
    # its loop is gone, and the resulting unraisable is attributed to whichever
    # test was unlucky — a genuinely miserable failure to chase.
    gc.collect()
    await asyncio.sleep(0)


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
def api_client(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> Any:
    """A TestClient bound to a THROWAWAY database.

    Without this, an API test runs the real lifespan against the real
    ``DATABASE_URL`` — it reads and writes the developer's ``data/flare.db``, so
    results depend on whatever is sitting in it and a test can corrupt a demo
    dataset. It also shares the module-level engine across tests, which leaves
    aiosqlite connections to be finalized on a loop that has already closed
    ("Connection was deleted before being closed").

    Everything is torn down in the reverse order it was set up so no global
    survives into the next test.
    """
    from fastapi.testclient import TestClient

    from app.config import get_settings
    from app.store import db as db_module
    from app.workers.queue import reset_queue_registry

    monkeypatch.setenv(
        "DATABASE_URL", f"sqlite+aiosqlite:///{(tmp_path / 'api.db').as_posix()}"
    )
    get_settings.cache_clear()
    db_module._engine = None
    db_module._sessionmaker = None
    reset_queue_registry()

    from app.main import create_app

    try:
        with TestClient(create_app()) as client:
            yield client
    finally:
        db_module._engine = None
        db_module._sessionmaker = None
        reset_queue_registry()
        get_settings.cache_clear()
        gc.collect()


@pytest.fixture
def chroma_collection(tmp_path: Any) -> Any:
    import chromadb

    client = chromadb.PersistentClient(path=str(tmp_path / "chroma"))
    name = f"test_{uuid.uuid4().hex[:8]}"
    col = client.get_or_create_collection(name=name, metadata={"hnsw:space": "cosine"})
    yield col
    client.delete_collection(name)
