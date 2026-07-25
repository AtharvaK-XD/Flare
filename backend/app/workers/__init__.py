"""Worker pool package — dual-queue triage/enrich processing over the graph.

``WorkerContext`` bundles the collaborators a worker needs (repo, bus, queues,
session factory, and the graph entry points). Everything is injectable so tests
can drive the workers with a stub graph and an in-memory DB, and so the graph
functions stay the single source of node logic.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.agent.graph import run_triage, stream_resume
from app.agent.state import TriageState
from app.config import Settings, get_settings
from app.core.bus import EventBus
from app.store.db import session_scope
from app.store.repositories import AlertRepository
from app.workers.queue import BoundedQueue

SessionFactory = Callable[[], AbstractAsyncContextManager[AsyncSession]]
ClassifyFn = Callable[..., Any]  # async (alert, config=, stop_after=) -> TriageState
ResumeFn = Callable[..., AsyncIterator[TriageState]]  # async iterator over states


@dataclass
class EnrichJob:
    """A classified alert handed to the enrich queue, with a requeue budget."""

    state: TriageState
    attempts: int = 0


@dataclass
class WorkerContext:
    repo: AlertRepository
    bus: EventBus
    triage_q: BoundedQueue
    enrich_q: BoundedQueue
    settings: Settings = field(default_factory=get_settings)
    session_factory: SessionFactory = session_scope
    graph_config: dict[str, Any] = field(default_factory=dict)
    classify_fn: ClassifyFn = run_triage
    resume_fn: ResumeFn = stream_resume


__all__ = [
    "WorkerContext",
    "EnrichJob",
    "SessionFactory",
    "ClassifyFn",
    "ResumeFn",
]
