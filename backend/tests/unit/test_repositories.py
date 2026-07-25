"""Repository tests — sort ranking, pagination, filters, cascade, cache, stats."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select

from app.schemas import (
    AttackType,
    Enrichment,
    IocVerdict,
    NormalizedAlert,
    Remediation,
    RemediationStep,
    Severity,
    TraceNode,
)
from app.store import models
from app.store.repositories import (
    AlertFilters,
    AlertRepository,
    IocCacheRepository,
)

pytestmark = pytest.mark.asyncio


def _now() -> datetime:
    return datetime.now(UTC)


async def _make_alert(session, repo: AlertRepository, ts: datetime, src_ip: str = "1.1.1.1"):
    na = NormalizedAlert(
        id=str(uuid.uuid4()),
        timestamp=ts,
        source="suricata",
        signature="ET SCAN test",
        src_ip=src_ip,
        dst_ip="2.2.2.2",
        src_port=1234,
        dst_port=22,
        protocol="TCP",
        raw={"k": "v"},
    )
    return await repo.create(session, na)


async def test_severity_rank_sort_order(db_session) -> None:
    repo = AlertRepository()
    base = _now()
    order = [Severity.INFO, Severity.CRITICAL, Severity.MEDIUM, Severity.LOW, Severity.HIGH]
    for i, sev in enumerate(order):
        a = await _make_alert(db_session, repo, base + timedelta(seconds=i))
        await repo.update_classification(db_session, a.id, sev, 0.9, AttackType.PORT_SCAN)

    items, total = await repo.list(db_session, sort="-severity", limit=50)
    got = [i.severity for i in items]
    assert got == [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
    assert total == 5


async def test_pagination_total_independent_of_limit(db_session) -> None:
    repo = AlertRepository()
    base = _now()
    for i in range(7):
        await _make_alert(db_session, repo, base + timedelta(seconds=i))

    items, total = await repo.list(db_session, limit=3, offset=0)
    assert len(items) == 3
    assert total == 7

    items2, total2 = await repo.list(db_session, limit=3, offset=6)
    assert len(items2) == 1
    assert total2 == 7


async def test_malicious_only_filter(db_session) -> None:
    repo = AlertRepository()
    base = _now()
    clean = await _make_alert(db_session, repo, base)
    dirty = await _make_alert(db_session, repo, base + timedelta(seconds=1))
    await repo.attach_enrichment(
        db_session,
        dirty.id,
        Enrichment(
            iocs=[
                IocVerdict(
                    indicator="9.9.9.9", indicator_type="ip", score=90.0, malicious=True
                )
            ],
            enriched_at=_now(),
            duration_ms=12,
        ),
    )

    items, total = await repo.list(db_session, filters=AlertFilters(malicious_only=True))
    ids = {i.id for i in items}
    assert dirty.id in ids
    assert clean.id not in ids
    assert total == 1


async def test_cascade_delete_removes_children(db_session) -> None:
    repo = AlertRepository()
    a = await _make_alert(db_session, repo, _now())
    await repo.attach_enrichment(
        db_session, a.id, Enrichment(iocs=[], enriched_at=_now(), duration_ms=1)
    )
    await repo.attach_remediation(
        db_session,
        a.id,
        Remediation(
            summary="do x",
            steps=[
                RemediationStep(order=1, action="block", detail="block ip", urgency="immediate")
            ],
            techniques=[],
            generated_at=_now(),
            duration_ms=1,
        ),
        reasoning="because",
    )
    await repo.add_trace(
        db_session,
        a.id,
        TraceNode(node="classify", status="ok", provider="groq", duration_ms=5),
    )
    await db_session.flush()

    orm_alert = await db_session.get(models.Alert, a.id)
    await db_session.delete(orm_alert)
    await db_session.flush()

    for model in (models.Enrichment, models.Remediation, models.Trace):
        n = (
            await db_session.execute(select(func.count()).select_from(model))
        ).scalar_one()
        assert n == 0


async def test_ioc_cache_respects_expiry(db_session) -> None:
    repo = IocCacheRepository()
    fresh = IocVerdict(indicator="8.8.8.8", indicator_type="ip", score=10.0, malicious=False)
    await repo.put(db_session, fresh, ttl=100)
    got = await repo.get(db_session, "8.8.8.8")
    assert got is not None
    assert got.cached is True

    stale = IocVerdict(indicator="6.6.6.6", indicator_type="ip", score=80.0, malicious=True)
    await repo.put(db_session, stale, ttl=-10)
    assert await repo.get(db_session, "6.6.6.6") is None

    purged = await repo.purge_expired(db_session)
    assert purged >= 1


async def test_stats_timeline_contiguous(db_session) -> None:
    repo = AlertRepository()
    now = _now()
    await _make_alert(db_session, repo, now)
    await _make_alert(db_session, repo, now - timedelta(minutes=2))
    await db_session.flush()

    stats = await repo.stats(db_session, window_minutes=5)
    assert len(stats.timeline) == 5
    for earlier, later in zip(stats.timeline, stats.timeline[1:], strict=False):
        assert later.bucket - earlier.bucket == timedelta(minutes=1)
    assert stats.total == 2
