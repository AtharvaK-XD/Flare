"""Cross-cutting hardening invariants — the §4 rules, asserted rather than assumed.

These are the properties that quietly rot: a new log line that prints a key, a
new error path that answers a different JSON shape, a new synchronous call
dropped into a coroutine. Each one is cheap to check and expensive to discover
during a demo.
"""

from __future__ import annotations

import asyncio
import io
import json
import logging
import time
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.config import get_settings
from app.core.logging import bind_request_context, clear_request_context, get_logger
from app.main import create_app

# Distinctive enough that a substring hit cannot be a coincidence.
FAKE_SECRETS = {
    "GROQ_API_KEY": "gsk_LEAKCANARY_groq_9f3b2c1d",
    "GOOGLE_API_KEY": "AIza_LEAKCANARY_google_7e4a11",
    "ABUSEIPDB_API_KEY": "LEAKCANARY_abuse_0c9d2f",
    "VIRUSTOTAL_API_KEY": "LEAKCANARY_vt_55ab77",
}


@pytest.fixture
def captured_logs() -> Any:
    """Capture everything written at DEBUG through the stdlib root handler."""
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setLevel(logging.DEBUG)
    root = logging.getLogger()
    previous = root.level
    root.addHandler(handler)
    root.setLevel(logging.DEBUG)
    try:
        yield stream
    finally:
        root.removeHandler(handler)
        root.setLevel(previous)


def test_no_secret_values_appear_in_debug_logs(
    monkeypatch: pytest.MonkeyPatch, captured_logs: Any, capsys: Any
) -> None:
    """At the most verbose level, no configured credential may reach any log line.

    DEBUG specifically: an INFO-only check passes trivially, and DEBUG is what a
    developer flips on at the worst possible moment (mid-demo, mid-incident)
    before pasting the output into a chat window.
    """
    for name, value in FAKE_SECRETS.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("LOG_LEVEL", "DEBUG")
    get_settings.cache_clear()

    try:
        from app.core.logging import configure_logging

        configure_logging()
        settings = get_settings()
        log = get_logger("leak-test")

        bind_request_context(request_id="req-leak-1", alert_id="alert-leak-1")

        # Every plausible way a key ends up in a log line.
        log.debug("test.direct_key", groq_api_key=settings.groq_api_key)
        log.debug("test.token_field", api_token=settings.google_api_key)
        log.debug("test.secret_field", client_secret=settings.abuseipdb_api_key)
        log.debug("test.password_field", db_password=settings.virustotal_api_key)
        log.info("test.settings_dump", settings=settings.model_dump())
        log.warning("test.provider_config", providers=settings.providers.model_dump())
        log.debug("test.available", available=settings.available_providers)
        clear_request_context()

        captured = captured_logs.getvalue() + capsys.readouterr().out

        leaked = [name for name, value in FAKE_SECRETS.items() if value in captured]
        assert not leaked, (
            f"credential value(s) reached the log output: {leaked}. "
            "app/core/logging.py redacts by KEY NAME — a value logged under a key that "
            "does not match /key|token|secret|password/i slips through."
        )
        # The redaction must actually have fired, or this test proves nothing.
        assert "***REDACTED***" in captured, "the redaction processor did not run at all"
    finally:
        get_settings.cache_clear()
        from app.core.logging import configure_logging

        configure_logging()


def test_settings_dump_never_carries_raw_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A whole-settings dump is the widest blast radius; check it on its own."""
    for name, value in FAKE_SECRETS.items():
        monkeypatch.setenv(name, value)
    get_settings.cache_clear()
    try:
        settings = get_settings()
        # Serialized the way a structured logger would.
        dumped = json.dumps(settings.model_dump(), default=str)
        present = [name for name, value in FAKE_SECRETS.items() if value in dumped]
        # This SHOULD contain them — model_dump has no redaction — which is
        # exactly why the logging processor must never be bypassed. Asserting it
        # documents the hazard instead of leaving it as folklore.
        assert present, (
            "Settings.model_dump() no longer exposes raw keys; the logging redaction "
            "processor may now be the only thing standing between config and logs — "
            "re-read app/core/logging.py before relaxing anything here."
        )
    finally:
        get_settings.cache_clear()


ERROR_PATHS = [
    ("get", "/api/v1/no-such-route", 404, "not_found"),
    ("get", "/api/v1/alerts/does-not-exist", 404, "not_found"),
    ("get", "/api/v1/evaluation/runs/nope", 404, "not_found"),
    ("get", "/api/v1/benchmark/runs/nope", 404, "not_found"),
    ("get", "/api/v1/alerts?sort=bogus", 422, "validation_error"),
    ("get", "/api/v1/alerts?severity=purple", 422, "validation_error"),
    ("get", "/api/v1/alerts?limit=99999", 422, "validation_error"),
    ("post", "/api/v1/replay/pause", 409, "conflict"),
    ("post", "/api/v1/replay/resume", 409, "conflict"),
]


@pytest.mark.parametrize(("method", "path", "status", "code"), ERROR_PATHS)
def test_every_error_path_uses_the_frozen_envelope(
    api_client: Any, method: str, path: str, status: int, code: str
) -> None:
    """One error shape, everywhere. The frontend switches on ``code``."""
    response = getattr(api_client, method)(path)

    assert response.status_code == status, f"{path} answered {response.status_code}"
    body = response.json()
    assert set(body) == {"error"}, f"{path} returned a non-envelope body: {body}"
    assert set(body["error"]) == {"code", "message", "detail"}, (
        f"{path} envelope has the wrong keys: {body['error']}"
    )
    assert body["error"]["code"] == code
    assert isinstance(body["error"]["message"], str) and body["error"]["message"]


def test_unhandled_exception_returns_the_envelope_and_leaks_nothing() -> None:
    """A bug in a handler must not put internals on the wire."""
    app = create_app()

    @app.get("/api/v1/_boom")
    async def _boom() -> dict[str, str]:
        raise RuntimeError("internal detail: /secret/path and token abc123")

    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get("/api/v1/_boom")

    assert response.status_code == 500
    body = response.json()
    assert set(body) == {"error"}
    assert body["error"]["code"] == "internal_error"
    assert body["error"]["message"] == "Internal server error"
    serialized = json.dumps(body)
    assert "secret/path" not in serialized, "the exception text reached the client"
    assert "abc123" not in serialized


def test_health_endpoint_never_touches_a_dependency(api_client: Any) -> None:
    """Liveness must answer while every dependency is down."""
    started = time.perf_counter()
    response = api_client.get("/api/v1/health")
    elapsed = time.perf_counter() - started

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert elapsed < 1.0, f"/health took {elapsed:.2f}s — it is doing dependency work"


@pytest.mark.asyncio
async def test_no_coroutine_blocks_the_event_loop_for_more_than_100ms() -> None:
    """Run the pipeline under asyncio debug mode and watch for slow callbacks.

    asyncio's own slow-callback detector is the instrument: with debug mode on it
    logs any callback that occupies the loop longer than
    ``loop.slow_callback_duration``. A synchronous Chroma query, a bare file read
    or a sentence-transformers encode dropped into a coroutine trips it — which
    is precisely the regression this guards.
    """
    from app import offline
    from app.agent.graph import run_triage
    from app.evaluation import ground_truth as gt

    offline.install()

    loop = asyncio.get_running_loop()
    previous_debug = loop.get_debug()
    previous_duration = loop.slow_callback_duration
    loop.set_debug(True)
    loop.slow_callback_duration = 0.1

    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setLevel(logging.WARNING)
    asyncio_log = logging.getLogger("asyncio")
    asyncio_log.addHandler(handler)
    previous_level = asyncio_log.level
    asyncio_log.setLevel(logging.WARNING)

    try:
        alerts = [item.alert for item in gt.load_population()][:25]
        for alert in alerts:
            await run_triage(alert)
    finally:
        loop.set_debug(previous_debug)
        loop.slow_callback_duration = previous_duration
        asyncio_log.removeHandler(handler)
        asyncio_log.setLevel(previous_level)

    slow = [line for line in stream.getvalue().splitlines() if "Executing" in line]
    assert not slow, (
        "coroutine(s) blocked the event loop for >100ms — wrap the synchronous call in "
        "asyncio.to_thread:\n" + "\n".join(slow[:5])
    )


@pytest.mark.asyncio
async def test_intel_clients_release_their_pools_on_close() -> None:
    """Nothing may be left holding a connection pool after shutdown."""
    import httpx

    from app.core.ratelimit import TokenBucket
    from app.intel.abuseipdb import AbuseIPDBClient

    limiter = TokenBucket(rate=10, period_seconds=60.0, name="test")
    owned = AbuseIPDBClient(limiter=limiter)
    assert owned._owns_client is True
    await owned.aclose()
    assert owned._client.is_closed, "a client the class built was not closed"
    # Idempotent: shutdown may run twice (lifespan + explicit stop).
    await owned.aclose()

    # A caller-supplied client belongs to the caller and must survive.
    borrowed_transport = httpx.AsyncClient()
    borrowed = AbuseIPDBClient(client=borrowed_transport, limiter=limiter)
    assert borrowed._owns_client is False
    await borrowed.aclose()
    assert not borrowed_transport.is_closed, "closed a client it does not own"
    await borrowed_transport.aclose()


@pytest.mark.asyncio
async def test_aggregator_close_survives_a_broken_source() -> None:
    """One wedged source must not stop the others being released."""
    from types import SimpleNamespace

    from app.core.cache import InMemoryTTLCache
    from app.intel.aggregator import IntelAggregator

    closed: list[str] = []

    class _Broken:
        name = "broken"
        supports = {"ip"}

        async def aclose(self) -> None:
            raise RuntimeError("transport wedged")

    class _Fine:
        name = "fine"
        supports = {"ip"}

        async def aclose(self) -> None:
            closed.append(self.name)

    aggregator = IntelAggregator(
        [_Broken(), _Fine()],  # type: ignore[list-item]
        InMemoryTTLCache(),  # type: ignore[arg-type]
        SimpleNamespace(intel_cache_ttl_seconds=60),
    )
    await aggregator.aclose()  # must not raise
    assert closed == ["fine"], "a failing close prevented the other source from closing"
