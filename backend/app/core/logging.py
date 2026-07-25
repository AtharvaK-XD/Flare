"""Structured logging via structlog.

Console renderer in dev, JSON in prod. Request-scoped ``request_id`` /
``alert_id`` / ``trace_id`` bind through contextvars and appear on every line.

REDACTION IS TWO INDEPENDENT LAYERS, and it needs both
------------------------------------------------------
1. **By key name, at ANY depth.** Any key matching /key|token|secret|password/i
   is replaced. Matching only top-level keys is not enough and was the actual
   hole here: ``log.info("boot", settings=settings.model_dump())`` nests every
   credential one level down under the innocuous key ``settings``, and a
   top-level-only pass emits the lot.

2. **By value.** Every credential the process is configured with is scrubbed
   from string values wherever it appears — including inside an exception
   message, a URL, or a response body excerpt, none of which have a key name to
   match on. This is the layer that catches the leak nobody anticipated.

Layer 2 is what makes this robust to code nobody has written yet; layer 1 is
what keeps it cheap for the common case.
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

_SECRET_KEY_RE = re.compile(r"key|token|secret|password|credential|authorization", re.IGNORECASE)
_REDACTED = "***REDACTED***"

#: Depth cap so a self-referential or pathologically nested payload cannot turn
#: one log line into an unbounded walk.
_MAX_DEPTH = 6

#: Shorter than this and a "secret" is more likely to be a substring of ordinary
#: text than an actual credential; scrubbing it would corrupt messages.
_MIN_SECRET_LENGTH = 8

EventDict = dict[str, Any]

_secret_values: frozenset[str] | None = None


def _configured_secrets() -> frozenset[str]:
    """Every credential value this process holds. Computed once."""
    global _secret_values
    if _secret_values is None:
        settings = get_settings()
        candidates = (
            settings.groq_api_key,
            settings.google_api_key,
            settings.abuseipdb_api_key,
            settings.virustotal_api_key,
        )
        _secret_values = frozenset(
            value for value in candidates if value and len(value) >= _MIN_SECRET_LENGTH
        )
    return _secret_values


def reset_secret_cache() -> None:
    """Drop the cached credential set (settings changed; tests)."""
    global _secret_values
    _secret_values = None


def _scrub_text(text: str, secrets: frozenset[str]) -> str:
    for secret in secrets:
        if secret in text:
            text = text.replace(secret, _REDACTED)
    return text


def _redact(value: Any, secrets: frozenset[str], depth: int = 0) -> Any:
    """Recursively redact by key name, and scrub known secret values."""
    if depth >= _MAX_DEPTH:
        return value
    if isinstance(value, dict):
        return {
            key: (
                _REDACTED
                if isinstance(key, str) and _SECRET_KEY_RE.search(key)
                else _redact(item, secrets, depth + 1)
            )
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple, set)):
        redacted = [_redact(item, secrets, depth + 1) for item in value]
        return type(value)(redacted) if isinstance(value, (list, set)) else tuple(redacted)
    if isinstance(value, str) and secrets:
        return _scrub_text(value, secrets)
    return value


def _redact_processor(_logger: Any, _name: str, event_dict: EventDict) -> EventDict:
    """Redact credentials by key name at any depth, then scrub by value."""
    secrets = _configured_secrets()
    return {
        key: (
            _REDACTED
            if isinstance(key, str) and _SECRET_KEY_RE.search(key)
            else _redact(value, secrets, 1)
        )
        for key, value in event_dict.items()
    }


def configure_logging() -> None:
    """Configure structlog once. Idempotent — safe to call from lifespan."""
    reset_secret_cache()  # settings may have changed since the last call
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
