"""Replay engine tests — rate, pause/resume cursor, stop reset, missing file."""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.api.errors import NotFoundError
from app.ingestion.replay import ReplayEngine
from app.schemas.events import ReplayState

HEADER = (
    "Flow ID,Source IP,Source Port,Destination IP,Destination Port,"
    "Protocol,Timestamp,Flow Duration,Label\n"
)


def _write_dataset(dir_: Path, n: int = 60) -> None:
    rows = [HEADER]
    for i in range(n):
        rows.append(
            f"flow-{i},45.13.2.{i % 254 + 1},{50000 + i},8.8.8.8,80,6,"
            f"05/07/2017 09:00:00,120,PortScan\n"
        )
    (dir_ / "cicids2017_sample.csv").write_text("".join(rows))


@pytest.fixture
def patched(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    _write_dataset(tmp_path)
    fake = SimpleNamespace(dataset_path=str(tmp_path), replay_events_per_second=10)
    monkeypatch.setattr("app.ingestion.replay.get_settings", lambda: fake)
    return tmp_path


async def _collector() -> tuple[list, object]:
    got: list = []

    async def on_alert(alert) -> None:  # noqa: ANN001
        got.append(alert)

    return got, on_alert


async def test_rate_roughly_matches_eps(patched: Path) -> None:
    got, on_alert = await _collector()
    eng = ReplayEngine(on_alert)
    await eng.start("cicids2017", events_per_second=10)
    await asyncio.sleep(1.0)
    n = len(got)
    await eng.stop()
    assert 8 <= n <= 13, f"expected ~10 emits in 1s, got {n}"


async def test_pause_stops_and_resume_continues(patched: Path) -> None:
    got, on_alert = await _collector()
    eng = ReplayEngine(on_alert)
    await eng.start("cicids2017", events_per_second=10)
    await asyncio.sleep(0.45)

    eng.pause()
    assert eng.status().state == ReplayState.PAUSED
    at_pause = len(got)
    await asyncio.sleep(0.5)
    assert len(got) - at_pause <= 1

    eng.resume()
    await asyncio.sleep(0.5)
    assert len(got) > at_pause
    await eng.stop()


async def test_stop_resets(patched: Path) -> None:
    got, on_alert = await _collector()
    eng = ReplayEngine(on_alert)
    await eng.start("cicids2017", events_per_second=10)
    await asyncio.sleep(0.3)
    await eng.stop()
    st = eng.status()
    assert st.state == ReplayState.IDLE
    assert st.emitted == 0


async def test_unknown_dataset_raises(patched: Path) -> None:
    eng = ReplayEngine((await _collector())[1])
    with pytest.raises(NotFoundError):
        await eng.start("does_not_exist")


async def test_missing_file_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = SimpleNamespace(dataset_path=str(tmp_path), replay_events_per_second=10)
    monkeypatch.setattr("app.ingestion.replay.get_settings", lambda: fake)
    eng = ReplayEngine((await _collector())[1])
    with pytest.raises(NotFoundError):
        await eng.start("cicids2017")
