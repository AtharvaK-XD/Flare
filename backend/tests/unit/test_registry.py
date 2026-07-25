"""Registry tests — no-key construction, get() failures, override isolation.

These force the providers' credentials to None so the outcome never depends on
whatever keys happen to be in the ambient .env.
"""

from __future__ import annotations

import asyncio

import pytest

from app.api.errors import ProviderError
from app.providers.base import ProviderHealth
from app.providers.registry import ProviderRegistry
from app.schemas import ProviderTier


class _FakeProvider:
    name = "fake"
    model = "fake-1"
    tier = ProviderTier.FAST
    available = True

    async def complete(self, *a, **k):  # noqa: ANN002, ANN003
        raise NotImplementedError

    async def health(self) -> ProviderHealth:
        return ProviderHealth(status="ok", latency_ms=1.0)


def _make_registry_no_keys() -> ProviderRegistry:
    reg = ProviderRegistry()
    for tier in (ProviderTier.FAST, ProviderTier.QUALITY):
        p = reg.base_provider(tier)
        for attr in ("_api_key", "_client", "_generate"):
            if hasattr(p, attr):
                setattr(p, attr, None)
    return reg


@pytest.fixture
def reg() -> ProviderRegistry:
    return _make_registry_no_keys()


def test_construction_never_fails_without_keys() -> None:
    assert ProviderRegistry() is not None


def test_get_missing_key_raises_actionable(reg: ProviderRegistry) -> None:
    with pytest.raises(ProviderError) as ei:
        reg.get(ProviderTier.FAST)
    assert "GROQ_API_KEY" in ei.value.message
    with pytest.raises(ProviderError) as ei2:
        reg.get(ProviderTier.QUALITY)
    assert "GOOGLE_API_KEY" in ei2.value.message


async def test_override_isolated_between_tasks(reg: ProviderRegistry) -> None:
    fake = _FakeProvider()
    results: dict[str, str] = {}

    async def with_override() -> None:
        with reg.override(ProviderTier.FAST, fake):
            await asyncio.sleep(0.02)
            results["a"] = reg.get(ProviderTier.FAST).name

    async def without_override() -> None:
        await asyncio.sleep(0.01)
        try:
            reg.get(ProviderTier.FAST)
            results["b"] = "got"
        except ProviderError:
            results["b"] = "raised"

    await asyncio.gather(with_override(), without_override())
    assert results["a"] == "fake"
    assert results["b"] == "raised"


async def test_override_resets_after_context(reg: ProviderRegistry) -> None:
    with reg.override(ProviderTier.FAST, _FakeProvider()):
        assert reg.get(ProviderTier.FAST).name == "fake"
    with pytest.raises(ProviderError):
        reg.get(ProviderTier.FAST)


async def test_health_all_concurrent(reg: ProviderRegistry) -> None:
    health = await reg.health_all()
    assert set(health.keys()) == {"groq", "gemini"}
    assert health["groq"].status == "down"
    assert health["gemini"].status == "down"
