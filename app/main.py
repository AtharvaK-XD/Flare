"""Flare FastAPI application factory."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from app.api.errors import register_exception_handlers
from app.api.router import api_router
from app.config import get_settings
from app.core.bus import get_event_bus
from app.core.logging import (
    bind_request_context,
    clear_request_context,
    configure_logging,
    get_logger,
)
from app.ingestion.replay import ReplayEngine
from app.schemas import NormalizedAlert
from app.store.db import dispose_db, init_db
from app.workers.manager import WorkerManager
from app.workers.queue import get_queue_registry

log = get_logger(__name__)


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    configure_logging()
    log.info("flare.startup.begin")

    await init_db()

    # Workers + queues + bus. ReplayEngine feeds the triage queue; the graph and
    # workers never learn an HTTP connection exists.
    bus = get_event_bus()
    triage_q = get_queue_registry().get("triage")
    manager = WorkerManager()
    manager.start()

    async def _on_alert(alert: NormalizedAlert) -> None:
        triage_q.put(alert)  # non-blocking; drops newest under backpressure

    replay = ReplayEngine(_on_alert)

    _app.state.event_bus = bus
    _app.state.worker_manager = manager
    _app.state.replay_engine = replay

    log.info("flare.startup.ready")
    try:
        yield
    finally:
        log.info("flare.shutdown.begin")
        await replay.stop()
        await manager.stop()
        await dispose_db()
        log.info("flare.shutdown.done")


class RequestIdMiddleware(BaseHTTPMiddleware):
    """Generate a uuid4 request id, bind it to logs, echo as X-Request-ID."""

    async def dispatch(self, request: Request, call_next) -> Response:  # noqa: ANN001
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id
        bind_request_context(request_id=request_id)
        try:
            response = await call_next(request)
        finally:
            clear_request_context()
        response.headers["X-Request-ID"] = request_id
        return response


def _build_cors_origins(settings) -> list[str]:  # noqa: ANN001
    origins = list(settings.cors_origins)
    if settings.is_dev:
        origins.append("*")
    return origins


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging()

    app = FastAPI(title="Flare", version="0.1.0", lifespan=lifespan)

    register_exception_handlers(app)

    app.add_middleware(RequestIdMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_build_cors_origins(settings),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["X-Request-ID"],
    )

    app.include_router(api_router)
    return app


app = create_app()
