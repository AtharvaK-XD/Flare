"""Seed ~200 fully-triaged alerts so the dashboard is never empty on first load.

WHY
---
A judge opening the dashboard on a cold clone sees an empty table, an empty
timeline and zeroed counters until a replay has run for a minute. That is the
worst possible first frame. This writes a realistic, already-triaged history so
the first frame is a populated dashboard, and pressing "start replay" then shows
NEW alerts arriving on top of it.

HOW — the same pipeline, not hand-written rows
----------------------------------------------
Alerts come from the committed labeled subset and go through the REAL graph with
the offline providers installed (``app.offline``): real classify/enrich/retrieve/
reason/recommend nodes, real routers, real IOC escalation, real hallucination
guard, real repositories. Nothing is fabricated at the DB layer, so the seeded
rows have genuine traces, genuine remediation steps citing genuine ATT&CK ids,
and a status distribution the routers actually produce.

It runs entirely offline and takes seconds — no API keys, no quota, no network.

Timestamps are backdated across the last few hours so the 30-minute timeline
chart has shape instead of one spike.

Usage:
    python -m scripts.seed_demo                 # ~200 alerts
    python -m scripts.seed_demo --count 50
    python -m scripts.seed_demo --reset         # delete existing alerts first
"""

from __future__ import annotations

import argparse
import asyncio
import random
import sys
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, func, select

from app import offline
from app.agent.graph import run_triage
from app.config import get_settings
from app.core.logging import configure_logging, get_logger
from app.evaluation import ground_truth as gt
from app.schemas import Enrichment, NormalizedAlert
from app.store import models
from app.store.db import dispose_db, get_sessionmaker, init_db
from app.store.repositories import AlertRepository

log = get_logger(__name__)

DEFAULT_COUNT = 200

#: Spread the seeded history over this window. Wider than the dashboard's
#: 30-minute timeline on purpose: the chart should open with recent activity AND
#: the list should have older entries to scroll.
HISTORY_HOURS = 6

SEED = 20260725


def _backdated(alerts: list[NormalizedAlert], count: int) -> list[NormalizedAlert]:
    """Re-stamp alerts across the recent past, newest last.

    Deterministic (seeded): re-running the seeder produces the same history, so
    a rehearsal and the real demo look identical.
    """
    rng = random.Random(SEED)
    chosen = list(alerts)
    rng.shuffle(chosen)
    chosen = chosen[:count]

    now = datetime.now(UTC)
    window = timedelta(hours=HISTORY_HOURS)
    out: list[NormalizedAlert] = []
    for index, alert in enumerate(chosen):
        # Weighted toward the recent end so the 30-minute chart is populated.
        fraction = (index / max(1, len(chosen) - 1)) ** 0.6
        stamp = now - window + window * fraction
        out.append(alert.model_copy(update={"timestamp": stamp}))
    return out


async def _existing_count() -> int:
    async with get_sessionmaker()() as session:
        return int(
            (await session.execute(select(func.count(models.Alert.id)))).scalar_one()
        )


async def _reset() -> int:
    """Delete every alert (cascades to traces/enrichment/remediation)."""
    async with get_sessionmaker()() as session:
        result = await session.execute(delete(models.Alert))
        await session.commit()
        return int(getattr(result, "rowcount", 0) or 0)


async def _persist(repo: AlertRepository, alert: NormalizedAlert, state: dict) -> str:
    """Write one triaged alert exactly as the workers would.

    Mirrors app/workers/triage_worker.py and enrich_worker.py: create, classify,
    traces, enrichment, remediation, mark_done. Same repository methods, so the
    seeded rows are indistinguishable from live ones.
    """
    async with get_sessionmaker()() as session:
        await repo.create(session, alert)
        severity = state.get("severity")
        attack_type = state.get("attack_type")
        if severity is not None and attack_type is not None:
            await repo.update_classification(
                session, alert.id, severity, state.get("confidence") or 0.0, attack_type
            )

        for trace in state.get("trace", []):
            await repo.add_trace(session, alert.id, trace)

        iocs = state.get("iocs") or []
        if iocs:
            await repo.attach_enrichment(
                session,
                alert.id,
                Enrichment(iocs=iocs, enriched_at=alert.timestamp, duration_ms=12),
            )

        remediation = state.get("remediation")
        if remediation is not None:
            await repo.attach_remediation(
                session, alert.id, remediation, reasoning=state.get("reasoning")
            )

        await repo.mark_done(session, alert.id, state.get("total_duration_ms"))
        await session.commit()
    return alert.id


async def seed(count: int, reset: bool) -> int:
    configure_logging()
    settings = get_settings()

    # Offline providers regardless of OFFLINE_MODE: seeding must never spend live
    # quota, and must work on a machine with no keys at all.
    offline.install()

    await init_db()
    try:
        if reset:
            removed = await _reset()
            print(f"[seed_demo] deleted {removed} existing alert(s)")

        existing = await _existing_count()
        if existing >= count and not reset:
            print(
                f"[seed_demo] {existing} alert(s) already present (>= {count}); nothing to do. "
                "Pass --reset to rebuild."
            )
            return 0

        try:
            population = gt.load_population()
        except gt.GroundTruthError as exc:
            print(f"[seed_demo] FAILED: no labeled data to seed from: {exc}")
            print("[seed_demo] fix with: python -m scripts.build_label_set")
            return 1

        alerts = _backdated([item.alert for item in population], count)
        print(
            f"[seed_demo] seeding {len(alerts)} alert(s) through the real graph "
            f"(offline providers), backdated over {HISTORY_HOURS}h"
        )

        repo = AlertRepository()
        enriched = 0
        remediated = 0
        for index, alert in enumerate(alerts, 1):
            state = await run_triage(alert)
            await _persist(repo, alert, dict(state))
            if state.get("iocs"):
                enriched += 1
            if state.get("remediation") is not None:
                remediated += 1
            if index % 25 == 0 or index == len(alerts):
                print(f"[seed_demo]   {index}/{len(alerts)}")

        total = await _existing_count()
        print(
            f"[seed_demo] done: {total} alert(s) in {settings.database_url}; "
            f"{enriched} enriched, {remediated} with remediation"
        )
        return 0
    finally:
        await dispose_db()


def main() -> int:
    parser = argparse.ArgumentParser(description="Seed the demo dashboard with triaged alerts")
    parser.add_argument("--count", type=int, default=DEFAULT_COUNT, help="alerts to seed")
    parser.add_argument(
        "--reset", action="store_true", help="delete existing alerts before seeding"
    )
    args = parser.parse_args()
    if args.count < 1:
        print("[seed_demo] --count must be >= 1")
        return 2
    return asyncio.run(seed(args.count, args.reset))


if __name__ == "__main__":
    sys.exit(main())
