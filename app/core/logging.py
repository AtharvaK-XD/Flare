"""Structured logging via structlog.

Console renderer in dev, JSON in prod. Request-scoped ``request_id`` /
``alert_id`` / ``trace_id`` bind through contextvars and appear on every line.
Any key matching /key|token|secret|password/i is redacted before rendering.
"""

from __future__ import annotations

import logging
import re
import sys
from typing import Any

import structlog
from structlog.contextvars import (
    bind_contextvars,
    clear_contextvars,
    merge_contextvars,
)

from app.config import get_settings

_SECRET_KEY_RE = re.compile(r"key|token|secret|password", re.IGNORECASE)
_REDACTED = "***REDACTED***"

EventDict = dict[str, Any]


def _redact_processor(_logger: Any, _name: str, event_dict: EventDict) -> EventDict:
    """Redact any value whose key looks like a credential."""
    for key in list(event_dict.keys()):
        if _SECRET_KEY_RE.search(key):
            event_dict[key] = _REDACTED
    return event_dict


def configure_logging() -> None:
    """Configure structlog once. Idempotent — safe to call from lifespan."""
    settings = get_settings()
    level = getattr(logging, settings.log_level.upper(), logging.INFO)

    logging.basicConfig(format="%(message)s", stream=sys.stdout, level=level)

    shared: list[Any] = [
        merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        _redact_processor,
    ]

    renderer: Any = (
        structlog.dev.ConsoleRenderer()
        if settings.is_dev
        else structlog.processors.JSONRenderer()
    )

    structlog.configure(
        processors=[*shared, structlog.processors.format_exc_info, renderer],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """Return a bound logger, optionally named."""
    return structlog.get_logger(name)


def bind_request_context(
    *,
    request_id: str | None = None,
    alert_id: str | None = None,
    trace_id: str | None = None,
) -> None:
    """Bind request-scoped identifiers to the contextvars log context."""
    ctx: dict[str, str] = {}
    if request_id is not None:
        ctx["request_id"] = request_id
    if alert_id is not None:
        ctx["alert_id"] = alert_id
    if trace_id is not None:
        ctx["trace_id"] = trace_id
    if ctx:
        bind_contextvars(**ctx)


def clear_request_context() -> None:
    """Clear all contextvars-bound log fields."""
    clear_contextvars()
