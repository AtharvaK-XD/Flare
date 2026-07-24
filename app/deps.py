"""FastAPI dependency providers — DI wiring for sessions, repos, and chroma."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from typing import Annotated

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.store.chroma import get_collection
from app.store.db import get_session
from app.store.repositories import (
    AlertRepository,
    BenchmarkRunRepository,
    EvalRunRepository,
    IocCacheRepository,
)


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


AlertRepoDep = Annotated[AlertRepository, Depends(get_alert_repo)]
IocCacheRepoDep = Annotated[IocCacheRepository, Depends(get_ioc_cache_repo)]
EvalRepoDep = Annotated[EvalRunRepository, Depends(get_eval_repo)]
BenchmarkRepoDep = Annotated[BenchmarkRunRepository, Depends(get_benchmark_repo)]
