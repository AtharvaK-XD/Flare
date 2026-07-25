"""Provider tests — fully monkeypatched clients, ZERO real network calls."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest
from pydantic import BaseModel, Field

from app.api.errors import ProviderError, RateLimitedError
from app.core.metrics import MetricsRegistry
from app.providers.gemini import GeminiProvider
from app.providers.groq import GroqProvider
from app.schemas import Severity


class _Out(BaseModel):
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)


@pytest.fixture(autouse=True)
def _no_backoff(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("app.core.retry.random.uniform", lambda a, b: 0.0)


class _FakeStatusError(Exception):
    def __init__(self, status_code: int) -> None:
        super().__init__(f"http {status_code}")
        self.status_code = status_code


def _groq_resp(content: str) -> SimpleNamespace:
    return SimpleNamespace(
        choices=[
            SimpleNamespace(
                message=SimpleNamespace(content=content), finish_reason="stop"
            )
        ],
        usage=SimpleNamespace(prompt_tokens=11, completion_tokens=7),
    )


class _FakeGroqClient:
    def __init__(self, handler) -> None:  # noqa: ANN001
        self.calls = 0
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))
        self._handler = handler

    async def _create(self, **kwargs):  # noqa: ANN003
        self.calls += 1
        return self._handler(self.calls, kwargs)


async def test_groq_parses_response_model() -> None:
    client = _FakeGroqClient(lambda n, kw: _groq_resp('{"severity": "high", "confidence": 0.9}'))
    p = GroqProvider(client=client)
    res = await p.complete("classify", response_model=_Out, max_tokens=50)
    assert res.parsed is not None
    assert res.parsed.severity is Severity.HIGH
    assert res.tokens_in == 11 and res.tokens_out == 7
    assert client.calls == 1


async def test_groq_coerces_dirty_json() -> None:
    client = _FakeGroqClient(
        lambda n, kw: _groq_resp('```json\n{"severity": "HIGH", "confidence": 90}\n```')
    )
    p = GroqProvider(client=client)
    res = await p.complete("classify", response_model=_Out)
    assert res.parsed.severity is Severity.HIGH
    assert res.parsed.confidence == pytest.approx(0.9)
    assert res.repaired is True


async def test_groq_retries_on_500_then_succeeds() -> None:
    def handler(n: int, kw: dict):
        if n < 3:
            raise _FakeStatusError(500)
        return _groq_resp('{"severity": "low", "confidence": 0.2}')

    client = _FakeGroqClient(handler)
    p = GroqProvider(client=client)
    res = await p.complete("x", response_model=_Out)
    assert res.parsed.severity is Severity.LOW
    assert client.calls == 3


async def test_groq_429_maps_to_rate_limited() -> None:
    client = _FakeGroqClient(lambda n, kw: (_ for _ in ()).throw(_FakeStatusError(429)))
    p = GroqProvider(client=client)
    with pytest.raises(RateLimitedError):
        await p.complete("x")
    assert client.calls == 3


async def test_groq_auth_error_not_retried() -> None:
    client = _FakeGroqClient(lambda n, kw: (_ for _ in ()).throw(_FakeStatusError(401)))
    p = GroqProvider(client=client)
    with pytest.raises(ProviderError) as ei:
        await p.complete("x")
    assert "GROQ_API_KEY" in ei.value.message
    assert client.calls == 1


def _gemini_resp(text: str, finish: str = "STOP", block: str | None = None, empty: bool = False):
    feedback = SimpleNamespace(block_reason=block)
    if empty:
        candidates = []
    else:
        candidates = [
            SimpleNamespace(
                finish_reason=SimpleNamespace(name=finish),
                content=SimpleNamespace(parts=[SimpleNamespace(text=text)]),
            )
        ]
    return SimpleNamespace(
        prompt_feedback=feedback,
        candidates=candidates,
        usage_metadata=SimpleNamespace(prompt_token_count=20, candidates_token_count=9),
    )


async def test_gemini_parses_response_model() -> None:
    def gen(prompt, cfg, system):  # noqa: ANN001
        assert cfg["response_mime_type"] == "application/json"
        return _gemini_resp('{"severity": "medium", "confidence": 0.6}')

    p = GeminiProvider(generate=gen)
    res = await p.complete("classify", response_model=_Out)
    assert res.parsed.severity is Severity.MEDIUM
    assert res.tokens_in == 20 and res.tokens_out == 9


async def test_gemini_blocked_prompt_not_retried() -> None:
    calls = {"n": 0}

    def gen(prompt, cfg, system):  # noqa: ANN001
        calls["n"] += 1
        return _gemini_resp("", block="SAFETY")

    p = GeminiProvider(generate=gen)
    with pytest.raises(ProviderError) as ei:
        await p.complete("malware analysis")
    assert getattr(ei.value, "finish_reason", None) == "blocked"
    assert calls["n"] == 1


async def test_gemini_empty_candidates_raises() -> None:
    p = GeminiProvider(generate=lambda prompt, cfg, system: _gemini_resp("", empty=True))
    with pytest.raises(ProviderError):
        await p.complete("x")


async def test_gemini_max_tokens_truncation_repaired() -> None:
    def gen(prompt, cfg, system):  # noqa: ANN001
        return _gemini_resp('{"severity": "high", "confidence": 0.7', finish="MAX_TOKENS")

    p = GeminiProvider(generate=gen)
    res = await p.complete("x", response_model=_Out)
    assert res.finish_reason == "MAX_TOKENS"
    assert res.parsed.severity is Severity.HIGH
    assert res.repaired is True


def test_metrics_concurrent_increments() -> None:
    reg = MetricsRegistry()

    def bump() -> None:
        reg.record_call("groq", "m", "classify", 10.0, 1, 1, ok=True)

    with ThreadPoolExecutor(max_workers=16) as ex:
        list(ex.map(lambda _: bump(), range(1000)))

    snap = reg.snapshot()
    assert snap["totals"]["calls"] == 1000
    assert snap["totals"]["tokens_in"] == 1000
