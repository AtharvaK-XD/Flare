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

from app.core.logging import get_logger

log = get_logger(__name__)


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


class BadRequestError(FlareError):
    """A rejected request VALUE (e.g. a sample size over the cap).

    Carries the contract's ``validation_error`` code — the frontend switches on
    ``code``, not status — at 400 rather than 422, because the value parsed fine
    and was refused on policy grounds. Refusing loudly beats silently truncating
    the caller's request into something smaller than they asked for.
    """

    code = "validation_error"
    http_status = 400


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


#: HTTP status -> contract error code. Anything absent falls back by class, so a
#: status nobody anticipated still produces the frozen envelope rather than
#: Starlette's ``{"detail": ...}`` — the frontend switches on ``code``, and a
#: response missing it is unhandleable.
_STATUS_CODES: dict[int, str] = {
    400: "validation_error",
    401: "unauthorized",
    403: "forbidden",
    404: "not_found",
    405: "method_not_allowed",
    409: "conflict",
    422: "validation_error",
    429: "rate_limited",
    502: "provider_error",
    503: "rate_limited",
}


def _code_for_status(status: int) -> str:
    known = _STATUS_CODES.get(status)
    if known is not None:
        return known
    return "validation_error" if 400 <= status < 500 else "internal_error"


async def _http_exception_handler(
    _request: Request, exc: StarletteHTTPException
) -> JSONResponse:
    """Every Starlette HTTPException, INCLUDING the router's own 404 and 405.

    Unknown routes never reach a Flare handler, so without this an unrecognized
    path would answer ``{"detail": "Not Found"}`` — a different shape from every
    other error the API produces.
    """
    return JSONResponse(
        status_code=exc.status_code,
        content=_envelope(_code_for_status(exc.status_code), str(exc.detail), None),
        headers=getattr(exc, "headers", None),
    )


async def _unhandled_handler(request: Request, exc: Exception) -> JSONResponse:
    """Last resort. Logs the cause with context; the CLIENT is told nothing.

    An unhandled exception is a bug in this service, and its text can carry
    internals (paths, SQL, occasionally a token). It is logged with the traceback
    and the request id, and the response body stays generic — the request id is
    the join key between the two.
    """
    request_id = getattr(request.state, "request_id", None)
    log.error(
        "api.unhandled_exception",
        path=request.url.path,
        method=request.method,
        request_id=request_id,
        error_type=type(exc).__name__,
        error=str(exc),
        exc_info=exc,
    )
    return JSONResponse(
        status_code=500,
        content=_envelope(
            "internal_error",
            "Internal server error",
            {"request_id": request_id} if request_id else None,
        ),
    )


def register_exception_handlers(app: FastAPI) -> None:
    """Install all Flare error handlers on the app."""
    app.add_exception_handler(FlareError, _flare_error_handler)  # type: ignore[arg-type]
    app.add_exception_handler(RequestValidationError, _request_validation_handler)  # type: ignore[arg-type]
    app.add_exception_handler(StarletteHTTPException, _http_exception_handler)  # type: ignore[arg-type]
    app.add_exception_handler(Exception, _unhandled_handler)
