"""The single ``/api/v1`` router — every route the frontend touches, in one place.

Mounted by ``app.main.create_app``. Aggregation order matters only within a
router (see alerts.py's stats-before-{id} note), not between them.
"""

from __future__ import annotations

from fastapi import APIRouter

from app.api.routes import alerts, benchmark, evaluation, health, ingest, replay, stream

api_router = APIRouter(prefix="/api/v1")

api_router.include_router(health.router)
api_router.include_router(alerts.router)
api_router.include_router(ingest.router)
api_router.include_router(replay.router)
api_router.include_router(stream.router)
api_router.include_router(evaluation.router)
api_router.include_router(benchmark.router)

__all__ = ["api_router"]
