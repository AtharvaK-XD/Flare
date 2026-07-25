"""FastAPI dependency providers — DI wiring for sessions, repos, and runtime.

Routes depend on these rather than reaching into module singletons or
``app.state`` directly, so tests can override any collaborator (db, bus, queues,
replay engine, worker pools) without starting the real lifespan.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.bus import EventBus, get_event_bus
from app.ingestion.replay import ReplayEngine
from app.store.chroma import get_collection
from app.store.db import get_session
from app.store.repositories import (
    AlertRepository,
    BenchmarkRunRepository,
    EvalRunRepository,
    IocCacheRepository,
)
from app.workers.manager import WorkerManager
from app.workers.queue import BoundedQueue, get_queue_registry


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    async for session in get_session():
        yield session


SessionDep = Annotated[AsyncSession, Depends(get_db_session)]


def get_alert_repo() -> AlertRepository:
    return AlertRepository()


def get_ioc_cache_repo() -> IocCacheRepository:
    return IocCacheRepository()


def get_eval_repo() -> EvalRunRepository:
    return EvalRunRepository()


def get_benchmark_repo() -> BenchmarkRunRepository:
    return BenchmarkRunRepository()


async def get_chroma():  # noqa: ANN201 — chroma Collection type is dynamic
    """Yield the shared Chroma collection."""
    return await get_collection()


def get_bus() -> EventBus:
    """The process-wide event bus (workers publish, /stream subscribes)."""
    return get_event_bus()


def get_triage_queue() -> BoundedQueue:
    return get_queue_registry().get("triage")


def get_enrich_queue() -> BoundedQueue:
    return get_queue_registry().get("enrich")


def get_replay_engine(request: Request) -> ReplayEngine:
    """The replay engine built by the lifespan. 503 if the app isn't running one."""
    engine = getattr(request.app.state, "replay_engine", None)
    if engine is None:
        from app.api.errors import QueueFullError

        raise QueueFullError("replay engine is not running")
    return engine


def get_worker_manager(request: Request) -> WorkerManager | None:
    """The worker pools, or None when the app runs without them (e.g. tests)."""
    return getattr(request.app.state, "worker_manager", None)


AlertRepoDep = Annotated[AlertRepository, Depends(get_alert_repo)]
IocCacheRepoDep = Annotated[IocCacheRepository, Depends(get_ioc_cache_repo)]
EvalRepoDep = Annotated[EvalRunRepository, Depends(get_eval_repo)]
BenchmarkRepoDep = Annotated[BenchmarkRunRepository, Depends(get_benchmark_repo)]
BusDep = Annotated[EventBus, Depends(get_bus)]
TriageQueueDep = Annotated[BoundedQueue, Depends(get_triage_queue)]
EnrichQueueDep = Annotated[BoundedQueue, Depends(get_enrich_queue)]
ReplayDep = Annotated[ReplayEngine, Depends(get_replay_engine)]
WorkerManagerDep = Annotated[WorkerManager | None, Depends(get_worker_manager)]
