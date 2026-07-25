"""Error hierarchy + handlers producing the frozen error envelope.

Every non-2xx response is exactly::

    { "error": { "code": str, "message": str, "detail": any|null } }
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException


class FlareError(Exception):
    """Base Flare error. Subclasses fix ``code`` and ``http_status``."""

    code: str = "internal_error"
    http_status: int = 500

    def __init__(self, message: str, detail: Any | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.detail = detail

    def to_envelope(self) -> dict[str, Any]:
        return {"error": {"code": self.code, "message": self.message, "detail": self.detail}}


class NotFoundError(FlareError):
    code = "not_found"
    http_status = 404


class ValidationError(FlareError):
    code = "validation_error"
    http_status = 422


class RateLimitedError(FlareError):
    code = "rate_limited"
    http_status = 429


class QueueFullError(FlareError):
    """Backpressure: work was refused because a queue is saturated.

    Reported as ``rate_limited`` (the contract's code for "upstream is saturated,
    keep the UI running") but at 503 — the request was not throttled, the system
    is momentarily unable to accept more work. Being honest here beats silently
    dropping the alert.
    """

    code = "rate_limited"
    http_status = 503


class ConflictError(FlareError):
    """An illegal state transition (e.g. resume while idle). Never a 500."""

    code = "conflict"
    http_status = 409


class ProviderError(FlareError):
    code = "provider_error"
    http_status = 502


class InternalError(FlareError):
    code = "internal_error"
    http_status = 500


def _envelope(code: str, message: str, detail: Any | None = None) -> dict[str, Any]:
    return {"error": {"code": code, "message": message, "detail": detail}}


async def _flare_error_handler(_request: Request, exc: FlareError) -> JSONResponse:
    return JSONResponse(status_code=exc.http_status, content=exc.to_envelope())


async def _request_validation_handler(
    _request: Request, exc: RequestValidationError
) -> JSONResponse:
    return JSONResponse(
        status_code=422,
        content=_envelope("validation_error", "Request validation failed", exc.errors()),
    )


async def _http_exception_handler(
    _request: Request, exc: StarletteHTTPException
) -> JSONResponse:
    code = "not_found" if exc.status_code == 404 else "internal_error"
    if exc.status_code == 429:
        code = "rate_limited"
    return JSONResponse(
        status_code=exc.status_code,
        content=_envelope(code, str(exc.detail), None),
    )


async def _unhandled_handler(_request: Request, exc: Exception) -> JSONResponse:
    return JSONResponse(
        status_code=500,
        content=_envelope("internal_error", "Internal server error", None),
    )


def register_exception_handlers(app: FastAPI) -> None:
    """Install all Flare error handlers on the app."""
    app.add_exception_handler(FlareError, _flare_error_handler)  # type: ignore[arg-type]
    app.add_exception_handler(RequestValidationError, _request_validation_handler)  # type: ignore[arg-type]
    app.add_exception_handler(StarletteHTTPException, _http_exception_handler)  # type: ignore[arg-type]
    app.add_exception_handler(Exception, _unhandled_handler)
