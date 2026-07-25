"""Settings tests — loads from a tmp .env, missing keys never raise."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError as PydValidationError

from app.config import Settings

MINIMAL_ENV = """\
APP_ENV=development
API_PORT=8000
GROQ_API_KEY=gsk_test_1234
DATABASE_URL=sqlite+aiosqlite:///./data/flare.db
"""


def _write_env(tmp_path: Path, body: str) -> Path:
    p = tmp_path / ".env"
    p.write_text(body)
    return p


def test_loads_from_tmp_env(tmp_path: Path) -> None:
    env = _write_env(tmp_path, MINIMAL_ENV)
    s = Settings(_env_file=str(env))  # type: ignore[call-arg]
    assert s.app_env == "development"
    assert s.groq_api_key == "gsk_test_1234"
    assert s.available_providers["groq"] is True
    assert s.available_providers["virustotal"] is False


def test_missing_keys_do_not_raise(tmp_path: Path) -> None:
    env = _write_env(tmp_path, "APP_ENV=development\n")
    s = Settings(_env_file=str(env))  # type: ignore[call-arg]
    assert s.groq_api_key is None
    assert s.google_api_key is None
    assert all(v is False for v in s.available_providers.values())


def test_nested_views(tmp_path: Path) -> None:
    env = _write_env(tmp_path, MINIMAL_ENV)
    s = Settings(_env_file=str(env))  # type: ignore[call-arg]
    assert s.providers.groq_api_key == "gsk_test_1234"
    assert s.intel.vt_rate_limit_per_min >= 1
    assert s.store.database_url.startswith("sqlite+aiosqlite")


def test_port_out_of_range_raises(tmp_path: Path) -> None:
    env = _write_env(tmp_path, "API_PORT=70000\n")
    with pytest.raises(PydValidationError):
        Settings(_env_file=str(env))  # type: ignore[call-arg]


def test_bad_database_url_raises(tmp_path: Path) -> None:
    env = _write_env(tmp_path, "DATABASE_URL=postgresql://x\n")
    with pytest.raises(PydValidationError):
        Settings(_env_file=str(env))  # type: ignore[call-arg]


def test_vt_rate_limit_must_be_positive(tmp_path: Path) -> None:
    env = _write_env(tmp_path, "VT_RATE_LIMIT_PER_MIN=0\n")
    with pytest.raises(PydValidationError):
        Settings(_env_file=str(env))  # type: ignore[call-arg]


def test_chroma_dir_is_absolute_and_created(tmp_path: Path) -> None:
    target = tmp_path / "vec"
    env = _write_env(tmp_path, f"CHROMA_PERSIST_DIR={target}\n")
    s = Settings(_env_file=str(env))  # type: ignore[call-arg]
    assert s.chroma_persist_dir.is_absolute()
    assert s.chroma_persist_dir.exists()
