"""Manually reap eval/benchmark runs stuck in ``running``.

The app already does this at startup and every
``RUN_STALE_SWEEP_INTERVAL_SECONDS`` while it is up (see
``app/evaluation/staleness.py``). This is the escape hatch for when the app is
NOT running and you want the rows cleared before starting it — or when you want
to see exactly what is stuck.

Usage:
    python -m scripts.reap_runs              # honour RUN_STALE_TIMEOUT_SECONDS
    python -m scripts.reap_runs --all        # reap every running row, now
    python -m scripts.reap_runs --dry-run
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from app.config import get_settings
from app.evaluation.staleness import stale_cutoff, sweep_stale_runs
from app.store.db import dispose_db, get_sessionmaker, init_db
from app.store.repositories import BenchmarkRunRepository, EvalRunRepository


async def _list_running() -> tuple[list[str], list[str]]:
    async with get_sessionmaker()() as session:
        evals = [r.run_id for r in await EvalRunRepository().list(session) if r.status == "running"]
        benchmarks = [
            r.run_id
            for r in await BenchmarkRunRepository().list(session)
            if r.status == "running"
        ]
    return evals, benchmarks


async def main() -> int:
    parser = argparse.ArgumentParser(description="Reap stale eval/benchmark runs")
    parser.add_argument(
        "--all",
        action="store_true",
        help="reap EVERY running row regardless of age (use when nothing is actually running)",
    )
    parser.add_argument("--dry-run", action="store_true", help="report, change nothing")
    args = parser.parse_args()

    timeout = 0.0 if args.all else float(get_settings().run_stale_timeout_seconds)

    await init_db()
    try:
        evals, benchmarks = await _list_running()
        print(f"[reap_runs] running eval runs      : {len(evals)} {evals or ''}")
        print(f"[reap_runs] running benchmark runs : {len(benchmarks)} {benchmarks or ''}")
        print(f"[reap_runs] cutoff                 : {stale_cutoff(timeout).isoformat()}")

        if args.dry_run:
            print("[reap_runs] dry run — nothing changed")
            return 0

        reaped = await sweep_stale_runs(timeout_seconds=timeout)
        total = len(reaped["eval"]) + len(reaped["benchmark"])
        if total:
            print(
                f"[reap_runs] reaped {total}: eval={reaped['eval']} "
                f"benchmark={reaped['benchmark']}"
            )
        else:
            print("[reap_runs] nothing stale to reap")
        return 0
    finally:
        await dispose_db()


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
