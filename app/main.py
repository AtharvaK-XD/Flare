"""Flare FastAPI application factory."""

from __future__ import annotations

import asyncio
import time
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from app import offline
from app.agent.state import close_default_aggregator
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
from app.evaluation.ground_truth import check_label_health
from app.evaluation.staleness import StaleRunSweeper, sweep_stale_runs
from app.ingestion.replay import ReplayEngine
from app.schemas import NormalizedAlert
from app.store.chroma import close_client as close_chroma_client
from app.store.db import dispose_db, init_db
from app.workers.manager import WorkerManager
from app.workers.queue import get_queue_registry, reset_queue_registry

log = get_logger(__name__)


def _startup_checks(settings) -> None:  # noqa: ANN001
    """Announce misconfiguration at boot. NEVER touches the network.

    Everything here is local: reading config, globbing a directory, parsing a
    CSV. A provider health probe belongs in ``/health/deep``, not in startup —
    a slow or hanging provider must not be able to delay the app coming up, and
    the app must start with ZERO API keys configured.
    """
    missing = [name for name, ok in settings.available_providers.items() if not ok]
    if missing and not settings.offline_mode:
        log.warning(
            "flare.startup.providers_missing",
            missing=missing,
            note="those features degrade; the app runs. Set the keys or OFFLINE_MODE=true.",
        )

    try:
        health = check_label_health()
        log.info("flare.startup.ground_truth", ok=health.ok, rows=health.rows,
                 detail=health.message())
        if not health.ok:
            log.error("flare.startup.ground_truth_unusable", detail=health.message())
    except Exception as exc:  # noqa: BLE001 — a bad label set must not block boot
        log.error("flare.startup.ground_truth_check_failed", error=str(exc))


def _start_embedding_warmup(settings) -> asyncio.Task[None] | None:  # noqa: ANN001
    """Load the embedding model in the background. Boot does not wait for it.

    Cold-loading sentence-transformers takes ~34s on demo hardware. Left to the
    first alert it happens INSIDE the retrieve node and eats the whole triage
    budget — the first alert of the demo times out. Done here it overlaps with
    everything else and the first alert finds it ready.

    Backgrounded rather than awaited on purpose: the very first load may also
    fetch weights from the network, and startup must never block on that.
    """
    if not settings.warm_embedding_model_on_startup or settings.offline_mode:
        return None

    async def _warm() -> None:
        from app.rag.indexer import get_embedding_model

        started = time.perf_counter()
        try:
            await asyncio.to_thread(get_embedding_model)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 — retrieval degrades, boot does not fail
            log.warning("flare.embedding_warmup_failed", error=str(exc))
            return
        log.info("flare.embedding_warmed", seconds=round(time.perf_counter() - started, 1))

    task = asyncio.ensure_future(_warm())
    task.set_name("embedding-warmup")
    return task


async def _cancel(task: asyncio.Task[None] | None) -> None:
    """Cancel and await a background task. Safe with None; never raises."""
    if task is None or task.done():
        return
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    except Exception as exc:  # noqa: BLE001 — already shutting down
        log.warning("flare.shutdown_task_failed", error=str(exc))


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    configure_logging()
    settings = get_settings()
    log.info("flare.startup.begin", offline=settings.offline_mode)

    if settings.offline_mode:
        offline.install()

    _startup_checks(settings)

    await init_db()

    # A process killed mid-run leaves an eval/benchmark row in `running`, and the
    # in-flight guard then 409s every future POST /run. Reap before serving, so a
    # crashed session never carries over into the demo.
    try:
        await sweep_stale_runs()
    except Exception as exc:  # noqa: BLE001 — never block boot on housekeeping
        log.warning("flare.startup.stale_sweep_failed", error=str(exc))

    # Workers + queues + bus. ReplayEngine feeds the triage queue; the graph and
    # workers never learn an HTTP connection exists.
    #
    # The registry is rebuilt here, not merely fetched: BoundedQueue wraps an
    # asyncio.Queue, which binds to whatever loop is running when it is first
    # created. A registry built on an earlier loop (a reload, a second app
    # instance, a test) hands this lifespan queues bound elsewhere, and EVERY
    # worker dies on first use with "bound to a different event loop" — visible
    # only as a log line while the app appears healthy. One lifespan owns one
    # loop owns one set of queues.
    reset_queue_registry()
    bus = get_event_bus()
    triage_q = get_queue_registry().get("triage")
    manager = WorkerManager()
    manager.start()

    sweeper = StaleRunSweeper()
    sweeper.start()

    warmup = _start_embedding_warmup(settings)

    async def _on_alert(alert: NormalizedAlert) -> None:
        triage_q.put(alert)  # non-blocking; drops newest under backpressure

    replay = ReplayEngine(_on_alert)

    _app.state.event_bus = bus
    _app.state.worker_manager = manager
    _app.state.replay_engine = replay
    _app.state.stale_run_sweeper = sweeper
    _app.state.offline_mode = settings.offline_mode
    _app.state.embedding_warmup = warmup

    log.info("flare.startup.ready", offline=settings.offline_mode)
    try:
        yield
    finally:
        # Order matters: stop producing, then stop consuming, then release
        # connections. Reversing it drops in-flight work or closes a pool a
        # worker is still using.
        log.info("flare.shutdown.begin")
        await replay.stop()
        await sweeper.stop()
        await _cancel(warmup)
        await manager.stop()
        # Intel clients own httpx pools; unclosed they emit "Unclosed client
        # session" on the way out and leak sockets across reloads.
        await close_default_aggregator()
        # Chroma holds a sqlite3 connection of its own, separate from the app's.
        await close_chroma_client()
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
