"""Async replay engine — streams a dataset and emits NormalizedAlerts.

Dependency-inverted: the engine never imports workers, the db, or a bus. It
calls an injected ``on_alert`` coroutine. Rate control uses a monotonic,
non-drifting scheduler (accumulated target time, never ``sleep(1/rate)``).
"""

from __future__ import annotations

import asyncio
import csv
import json
from collections.abc import Awaitable, Callable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from time import monotonic

from app.api.errors import NotFoundError
from app.config import get_settings
from app.core.logging import get_logger
from app.ingestion.normalizer import normalize
from app.schemas import NormalizedAlert
from app.schemas.events import ReplayState, ReplayStatus

log = get_logger(__name__)

OnAlert = Callable[[NormalizedAlert], Awaitable[None]]

_STOP_TIMEOUT = 5.0

#: Records pulled per worker-thread hop. Large enough that the hop is amortized,
#: small enough that pause/stop still respond within one batch at demo rates.
_READ_BATCH = 32

DATASETS: dict[str, tuple[str, str, str]] = {
    "cicids2017": ("cicids2017_sample.csv", "cicids2017", "csv"),
    "cicids": ("cicids2017_sample.csv", "cicids2017", "csv"),
    "suricata": ("suricata_eve_sample.json", "suricata", "eve"),
}


class ReplayEngine:
    """Single-instance-per-process async dataset replayer."""

    def __init__(self, on_alert: OnAlert) -> None:
        self._on_alert = on_alert
        self._state = ReplayState.IDLE
        self._task: asyncio.Task[None] | None = None
        self._resume = asyncio.Event()
        self._resume.set()
        self._stopped = False

        self._dataset: str | None = None
        self._source: str | None = None
        self._path: Path | None = None
        self._fmt: str | None = None
        self._eps: float = 0.0
        self._limit: int | None = None
        self._emitted = 0
        self._cursor = 0
        #: Records the parsers refused (malformed rows, unmapped sources, and
        #: down-sampled benign flows). Surfaced on ``status()`` so "300 in, 180
        #: out" is explainable rather than looking like lost alerts.
        self._skipped = 0
        self._started_at: datetime | None = None


    async def start(
        self,
        dataset: str,
        events_per_second: float | None = None,
        limit: int | None = None,
    ) -> None:
        if self._state == ReplayState.RUNNING:
            return
        if dataset not in DATASETS:
            raise NotFoundError(f"unknown dataset: {dataset}")
        filename, source, fmt = DATASETS[dataset]
        path = Path(get_settings().dataset_path) / filename
        if not path.exists():
            raise NotFoundError(f"dataset file not found: {path}")

        self._dataset, self._source, self._path, self._fmt = dataset, source, path, fmt
        self._eps = float(events_per_second or get_settings().replay_events_per_second)
        self._limit = limit
        self._emitted = 0
        self._cursor = 0
        self._skipped = 0
        self._stopped = False
        self._resume.set()
        self._started_at = datetime.now(UTC)
        self._state = ReplayState.RUNNING
        self._task = asyncio.create_task(self._run())

    def pause(self) -> None:
        if self._state == ReplayState.RUNNING:
            self._state = ReplayState.PAUSED
            self._resume.clear()

    def resume(self) -> None:
        if self._state == ReplayState.PAUSED:
            self._state = ReplayState.RUNNING
            self._resume.set()

    async def stop(self) -> None:
        self._stopped = True
        self._resume.set()
        if self._task is not None:
            try:
                await asyncio.wait_for(asyncio.shield(self._task), timeout=_STOP_TIMEOUT)
            except TimeoutError:
                self._task.cancel()
                try:
                    await self._task
                except asyncio.CancelledError:
                    pass
            self._task = None
        self._cursor = 0
        self._emitted = 0
        self._skipped = 0
        self._state = ReplayState.IDLE

    def status(self) -> ReplayStatus:
        return ReplayStatus(
            state=self._state,
            dataset=self._dataset,
            events_per_second=self._eps or None,
            emitted=self._emitted,
            total=self._limit,
            queue_depth={},
            started_at=self._started_at,
            skipped=self._skipped,
        )


    def _iter_records(self) -> Iterator[tuple[int, dict]]:
        assert self._path is not None and self._fmt is not None
        if self._fmt == "csv":
            with self._path.open("r", encoding="utf-8", newline="") as fh:
                reader = csv.DictReader(fh)
                yield from enumerate(reader)
        elif self._fmt == "eve":
            yield from self._iter_eve()

    def _iter_eve(self) -> Iterator[tuple[int, dict]]:
        assert self._path is not None
        with self._path.open("r", encoding="utf-8") as fh:
            head = fh.read(1)
            fh.seek(0)
            if head == "[":
                for i, rec in enumerate(json.load(fh)):
                    if isinstance(rec, dict):
                        yield i, rec
            else:
                malformed = 0
                for i, line in enumerate(fh):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError as exc:
                        # One corrupt line must not end the replay, but it must
                        # not vanish either: count it and name the first one.
                        malformed += 1
                        if malformed == 1:
                            log.warning("replay.malformed_json", line_number=i + 1, error=str(exc))
                        self._skipped += 1
                        continue
                    if isinstance(rec, dict):
                        yield i, rec
                if malformed:
                    log.warning(
                        "replay.malformed_json_total",
                        lines=malformed,
                        path=str(self._path),
                    )

    @staticmethod
    def _take(source: Iterator[tuple[int, dict]], size: int) -> list[tuple[int, dict]]:
        """Pull up to ``size`` records. Runs in a worker thread — see ``_run``."""
        batch: list[tuple[int, dict]] = []
        for record in source:
            batch.append(record)
            if len(batch) >= size:
                break
        return batch

    async def _run(self) -> None:
        """Emit records at the configured rate, never blocking the event loop.

        The record iterators are synchronous file readers: advancing one from a
        coroutine does disk I/O on the loop thread, which stalls every other
        alert, the SSE heartbeat and the API for the duration of the read. They
        are advanced in a worker thread instead, a batch at a time — one thread
        hop per record would cost more than the read it avoids.
        """
        assert self._source is not None
        interval = 1.0 / self._eps if self._eps > 0 else 0.0
        next_target = monotonic()
        records = self._iter_records()
        try:
            while not self._stopped:
                batch = await asyncio.to_thread(self._take, records, _READ_BATCH)
                if not batch:
                    break

                for index, raw in batch:
                    if self._stopped:
                        break
                    await self._resume.wait()
                    if self._stopped:
                        break

                    alert = normalize(raw, self._source, index)
                    self._cursor = index + 1
                    if alert is None:
                        # A record the parsers refused: malformed, unmapped, or
                        # a down-sampled benign flow. Counted and skipped so a
                        # bad row in the middle of a dataset cannot end a replay.
                        self._skipped += 1
                        continue

                    await self._on_alert(alert)
                    self._emitted += 1
                    if self._limit is not None and self._emitted >= self._limit:
                        return

                    if interval > 0:
                        next_target += interval
                        delay = next_target - monotonic()
                        if delay > 0:
                            await asyncio.sleep(delay)
                        else:
                            next_target = monotonic()
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 — a replay fault must not kill the app
            log.warning(
                "replay.run_failed", error=str(exc), emitted=self._emitted, cursor=self._cursor
            )
        finally:
            if self._skipped:
                log.info("replay.records_skipped", skipped=self._skipped, emitted=self._emitted)
            if not self._stopped:
                self._state = ReplayState.COMPLETED
