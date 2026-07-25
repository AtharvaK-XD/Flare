"""Repositories — the ONLY gateway between the app and the ORM.

Every method is async, takes an :class:`AsyncSession`, and does not commit
implicitly (callers own transaction boundaries). ``flush`` is used where a
generated PK is needed before returning.
"""

from __future__ import annotations

import builtins
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TypeVar

from sqlalchemy import Select, case, delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.elements import Case

from app.schemas import (
    AlertDetail,
    AlertStats,
    AlertStatus,
    AlertSummary,
    AttackType,
    BenchmarkResult,
    BenchmarkRunDetail,
    ConfusionMatrix,
    DisagreementExample,
    Enrichment,
    EvalRunDetail,
    IocVerdict,
    MitreTechnique,
    NormalizedAlert,
    OverallMetrics,
    PerClassMetric,
    Remediation,
    RemediationStep,
    Severity,
    TargetReport,
    TimelineBucket,
    TraceNode,
)
from app.store import models

MALICIOUS_SCORE_THRESHOLD = 50.0

#: Stamped on any run row the staleness sweep reaps. Kept as a module constant so
#: the sweeper, the API and the tests all assert on ONE string.
STALE_RUN_ERROR = "stale: exceeded timeout, likely crashed process"


def _now() -> datetime:
    return datetime.now(UTC)


def _severity_rank_case() -> Case:
    """SQL ordering that matches the app's Python severity ordering exactly.

    Built from ``app.agent.state.SEVERITY_RANK`` rather than a second hand-kept
    table: two rankings that drift make the `-severity` sort disagree with every
    in-process comparison, and nothing would fail loudly when they do.
    """
    from app.agent.state import SEVERITY_RANK

    return case(
        *[
            (models.Alert.severity == severity.value, rank)
            for severity, rank in SEVERITY_RANK.items()
        ],
        else_=0,
    )


#: Both run tables share ``models.RunRowMixin``'s lifecycle columns, so the
#: staleness helpers below are written once against that shape.
RunModel = TypeVar("RunModel", models.EvalRun, models.BenchmarkRun)


async def _reap_stale(
    session: AsyncSession, model: type[RunModel], cutoff: datetime
) -> builtins.list[str]:
    """Mark every ``running`` row older than ``cutoff`` as failed. Returns their ids.

    A crashed process leaves its row in ``running`` forever, and the "already in
    flight" guard then rejects every future run with a 409 that no amount of
    waiting clears. Reaping is therefore not housekeeping — it is what keeps the
    endpoint usable after a crash.
    """
    rows = (
        (
            await session.execute(
                select(model).where(model.status == "running", model.started_at < cutoff)
            )
        )
        .scalars()
        .all()
    )
    for row in rows:
        row.status = "failed"
        row.completed_at = _now()
        row.error = STALE_RUN_ERROR
    if rows:
        await session.flush()
    return [row.id for row in rows]


async def _active_run_id(
    session: AsyncSession, model: type[RunModel], cutoff: datetime
) -> str | None:
    """The id of a GENUINELY fresh in-flight run, or None.

    ``cutoff`` excludes rows old enough to be presumed crashed, so a dead run can
    never block a new one — the exact bug that made POST /run 409 permanently.
    """
    return (
        await session.execute(
            select(model.id)
            .where(model.status == "running", model.started_at >= cutoff)
            .order_by(model.started_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()


def _enrichment_schema(row: models.Enrichment | None) -> Enrichment | None:
    if row is None:
        return None
    return Enrichment(
        iocs=[IocVerdict.model_validate(d) for d in (row.payload or [])],
        enriched_at=row.enriched_at,
        duration_ms=row.duration_ms,
    )


def _remediation_schema(row: models.Remediation | None) -> Remediation | None:
    if row is None:
        return None
    return Remediation(
        summary=row.summary,
        steps=[RemediationStep.model_validate(d) for d in (row.steps or [])],
        techniques=[MitreTechnique.model_validate(d) for d in (row.techniques or [])],
        generated_at=row.generated_at,
        duration_ms=row.duration_ms,
    )


def _summary_from_alert(a: models.Alert) -> AlertSummary:
    return AlertSummary(
        id=a.id,
        timestamp=a.timestamp,
        status=AlertStatus(a.status),
        severity=Severity(a.severity) if a.severity else None,
        confidence=a.confidence,
        attack_type=AttackType(a.attack_type) if a.attack_type else None,
        signature=a.signature,
        src_ip=a.src_ip,
        dst_ip=a.dst_ip,
        src_port=a.src_port,
        dst_port=a.dst_port,
        protocol=a.protocol,
        source=a.source,
        has_enrichment=a.enrichment is not None,
        has_remediation=a.remediation is not None,
        max_ioc_score=a.enrichment.max_score if a.enrichment else None,
    )


def _detail_from_alert(a: models.Alert) -> AlertDetail:
    return AlertDetail(
        **_summary_from_alert(a).model_dump(),
        raw=a.raw or {},
        reasoning=a.remediation.reasoning if a.remediation else None,
        enrichment=_enrichment_schema(a.enrichment),
        remediation=_remediation_schema(a.remediation),
        trace=[
            TraceNode(
                node=t.node,  # type: ignore[arg-type]
                status=t.status,  # type: ignore[arg-type]
                provider=t.provider,
                duration_ms=t.duration_ms,
                tokens_in=t.tokens_in,
                tokens_out=t.tokens_out,
                note=t.note,
            )
            for t in a.traces
        ],
        total_duration_ms=a.total_duration_ms,
    )


@dataclass
class AlertFilters:
    severity: list[str] = field(default_factory=list)
    status: list[str] = field(default_factory=list)
    attack_type: list[str] = field(default_factory=list)
    src_ip: str | None = None
    malicious_only: bool = False
    since: datetime | None = None


class AlertRepository:
    async def create(self, session: AsyncSession, alert: NormalizedAlert) -> models.Alert:
        row = models.Alert(
            id=alert.id,
            timestamp=alert.timestamp,
            source=alert.source,
            signature=alert.signature,
            src_ip=alert.src_ip,
            dst_ip=alert.dst_ip,
            src_port=alert.src_port,
            dst_port=alert.dst_port,
            protocol=alert.protocol,
            status=AlertStatus.INGESTED.value,
            ground_truth_label=alert.ground_truth_label,
            raw=alert.raw,
        )
        session.add(row)
        await session.flush()
        return row

    async def get(self, session: AsyncSession, alert_id: str) -> AlertDetail | None:
        row = await session.get(models.Alert, alert_id)
        if row is None:
            return None
        return _detail_from_alert(row)

    def _apply_filters(self, stmt: Select, f: AlertFilters) -> Select:
        if f.severity:
            stmt = stmt.where(models.Alert.severity.in_(f.severity))
        if f.status:
            stmt = stmt.where(models.Alert.status.in_(f.status))
        if f.attack_type:
            stmt = stmt.where(models.Alert.attack_type.in_(f.attack_type))
        if f.src_ip:
            stmt = stmt.where(models.Alert.src_ip == f.src_ip)
        if f.since:
            stmt = stmt.where(models.Alert.timestamp >= f.since)
        if f.malicious_only:
            stmt = stmt.join(models.Enrichment).where(
                models.Enrichment.max_score >= MALICIOUS_SCORE_THRESHOLD
            )
        return stmt

    async def list(
        self,
        session: AsyncSession,
        filters: AlertFilters | None = None,
        limit: int = 50,
        offset: int = 0,
        sort: str = "-timestamp",
    ) -> tuple[list[AlertSummary], int]:
        f = filters or AlertFilters()

        count_stmt = self._apply_filters(select(func.count(models.Alert.id)), f)
        total = (await session.execute(count_stmt)).scalar_one()

        stmt = self._apply_filters(select(models.Alert), f)
        if sort == "timestamp":
            stmt = stmt.order_by(models.Alert.timestamp.asc())
        elif sort == "-severity":
            stmt = stmt.order_by(_severity_rank_case().desc(), models.Alert.timestamp.desc())
        else:
            stmt = stmt.order_by(models.Alert.timestamp.desc())
        stmt = stmt.limit(limit).offset(offset)

        rows = (await session.execute(stmt)).scalars().unique().all()
        return [_summary_from_alert(r) for r in rows], total

    async def update_classification(
        self,
        session: AsyncSession,
        alert_id: str,
        severity: Severity,
        confidence: float,
        attack_type: AttackType,
    ) -> models.Alert | None:
        row = await session.get(models.Alert, alert_id)
        if row is None:
            return None
        row.severity = severity.value
        row.confidence = confidence
        row.attack_type = attack_type.value
        row.status = AlertStatus.CLASSIFIED.value
        await session.flush()
        return row

    async def attach_enrichment(
        self, session: AsyncSession, alert_id: str, enrichment: Enrichment
    ) -> models.Alert | None:
        row = await session.get(models.Alert, alert_id)
        if row is None:
            return None
        max_score = max((i.score for i in enrichment.iocs), default=None)
        row.enrichment = models.Enrichment(
            enriched_at=enrichment.enriched_at,
            duration_ms=enrichment.duration_ms,
            max_score=max_score,
            payload=[i.model_dump(mode="json") for i in enrichment.iocs],
        )
        row.status = AlertStatus.ENRICHED.value
        await session.flush()
        return row

    async def attach_remediation(
        self,
        session: AsyncSession,
        alert_id: str,
        remediation: Remediation,
        reasoning: str | None = None,
    ) -> models.Alert | None:
        row = await session.get(models.Alert, alert_id)
        if row is None:
            return None
        row.remediation = models.Remediation(
            summary=remediation.summary,
            steps=[s.model_dump(mode="json") for s in remediation.steps],
            techniques=[t.model_dump(mode="json") for t in remediation.techniques],
            reasoning=reasoning,
            generated_at=remediation.generated_at,
            duration_ms=remediation.duration_ms,
        )
        row.status = AlertStatus.REASONED.value
        await session.flush()
        return row

    async def set_status(
        self, session: AsyncSession, alert_id: str, status: AlertStatus
    ) -> models.Alert | None:
        row = await session.get(models.Alert, alert_id)
        if row is None:
            return None
        row.status = status.value
        await session.flush()
        return row

    async def mark_done(
        self, session: AsyncSession, alert_id: str, total_duration_ms: int | None = None
    ) -> models.Alert | None:
        """Terminal transition: status=done, stamp end-to-end duration if known."""
        row = await session.get(models.Alert, alert_id)
        if row is None:
            return None
        row.status = AlertStatus.DONE.value
        if total_duration_ms is not None:
            row.total_duration_ms = total_duration_ms
        await session.flush()
        return row

    async def add_trace(
        self, session: AsyncSession, alert_id: str, trace: TraceNode
    ) -> models.Trace:
        row = models.Trace(
            alert_id=alert_id,
            node=trace.node,
            status=trace.status,
            provider=trace.provider,
            duration_ms=trace.duration_ms,
            tokens_in=trace.tokens_in,
            tokens_out=trace.tokens_out,
            note=trace.note,
        )
        session.add(row)
        await session.flush()
        return row

    async def stats(self, session: AsyncSession, window_minutes: int = 30) -> AlertStats:
        total = (await session.execute(select(func.count(models.Alert.id)))).scalar_one()

        async def _group(col) -> dict[str, int]:
            res = await session.execute(
                select(col, func.count()).where(col.is_not(None)).group_by(col)
            )
            return {str(k): int(v) for k, v in res.all()}

        by_severity = await _group(models.Alert.severity)
        by_attack_type = await _group(models.Alert.attack_type)
        by_status = await _group(models.Alert.status)

        malicious_iocs = (
            await session.execute(
                select(func.count(models.Enrichment.id)).where(
                    models.Enrichment.max_score >= MALICIOUS_SCORE_THRESHOLD
                )
            )
        ).scalar_one()

        avg_triage = (
            await session.execute(
                select(func.avg(models.Alert.total_duration_ms)).where(
                    models.Alert.total_duration_ms.is_not(None)
                )
            )
        ).scalar_one()

        now = _now()
        window_start = now - timedelta(minutes=window_minutes)
        in_window = (
            await session.execute(
                select(func.count(models.Alert.id)).where(
                    models.Alert.timestamp >= window_start
                )
            )
        ).scalar_one()

        minute = func.strftime("%Y-%m-%dT%H:%M", models.Alert.timestamp)
        crit = func.sum(case((models.Alert.severity == "critical", 1), else_=0))
        agg = await session.execute(
            select(minute.label("m"), func.count().label("c"), crit.label("k"))
            .where(models.Alert.timestamp >= window_start)
            .group_by("m")
        )
        buckets: dict[str, tuple[int, int]] = {
            m: (int(c), int(k or 0)) for m, c, k in agg.all()
        }

        timeline: list[TimelineBucket] = []
        base = now.replace(second=0, microsecond=0)
        for i in range(window_minutes - 1, -1, -1):
            slot = base - timedelta(minutes=i)
            key = slot.strftime("%Y-%m-%dT%H:%M")
            c, k = buckets.get(key, (0, 0))
            timeline.append(TimelineBucket(bucket=slot, count=c, critical=k))

        return AlertStats(
            total=int(total),
            by_severity=by_severity,
            by_attack_type=by_attack_type,
            by_status=by_status,
            malicious_iocs=int(malicious_iocs),
            avg_triage_ms=float(avg_triage) if avg_triage is not None else None,
            alerts_per_min=round(int(in_window) / max(window_minutes, 1), 2),
            timeline=timeline,
        )


class IocCacheRepository:
    async def get(self, session: AsyncSession, indicator: str) -> IocVerdict | None:
        row = await session.get(models.IocCache, indicator)
        if row is None:
            return None
        expires = row.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=UTC)
        if expires <= _now():
            return None
        verdict = IocVerdict.model_validate(row.payload)
        verdict.cached = True
        return verdict

    async def put(
        self, session: AsyncSession, verdict: IocVerdict, ttl: int
    ) -> models.IocCache:
        now = _now()
        row = await session.get(models.IocCache, verdict.indicator)
        payload = verdict.model_dump(mode="json")
        if row is None:
            row = models.IocCache(indicator=verdict.indicator)
            session.add(row)
        row.indicator_type = verdict.indicator_type
        row.payload = payload
        row.score = verdict.score
        row.malicious = verdict.malicious
        row.fetched_at = now
        row.expires_at = now + timedelta(seconds=ttl)
        await session.flush()
        return row

    async def purge_expired(self, session: AsyncSession) -> int:
        res = await session.execute(
            delete(models.IocCache).where(models.IocCache.expires_at <= _now())
        )
        return res.rowcount or 0  # type: ignore[attr-defined]


def _eval_detail(row: models.EvalRun) -> EvalRunDetail:
    return EvalRunDetail(
        run_id=row.id,
        status=row.status,  # type: ignore[arg-type]
        sample_size=row.sample_size,
        started_at=row.started_at,
        completed_at=row.completed_at,
        overall=OverallMetrics.model_validate(row.overall) if row.overall else None,
        per_class=[PerClassMetric.model_validate(d) for d in (row.per_class or [])],
        confusion_matrix=(
            ConfusionMatrix.model_validate(row.confusion_matrix)
            if row.confusion_matrix
            else None
        ),
        attack_type=(
            TargetReport.model_validate(row.attack_type_metrics)
            if row.attack_type_metrics
            else None
        ),
        error=row.error,
    )


class EvalRunRepository:
    async def create(
        self, session: AsyncSession, sample_size: int, run_id: str | None = None
    ) -> EvalRunDetail:
        """Open a run in ``running``. ``run_id`` lets a caller fix the id up front
        (the API returns it in the 202 before the work starts)."""
        row = models.EvalRun(status="running", sample_size=sample_size)
        if run_id is not None:
            row.id = run_id
        session.add(row)
        await session.flush()
        return _eval_detail(row)

    async def save_progress(
        self,
        session: AsyncSession,
        run_id: str,
        overall: OverallMetrics | None = None,
        per_class: builtins.list[PerClassMetric] | None = None,
        confusion_matrix: ConfusionMatrix | None = None,
        attack_type: TargetReport | None = None,
        sample_size: int | None = None,
    ) -> EvalRunDetail | None:
        """Write partial metrics WITHOUT leaving ``running``.

        A long eval is otherwise a blank panel for minutes; persisting each decile
        lets the polling frontend fill in as the run proceeds. Status is untouched
        so nothing reads a partial report as final.
        """
        row = await session.get(models.EvalRun, run_id)
        if row is None:
            return None
        if sample_size is not None:
            row.sample_size = sample_size
        if overall is not None:
            row.overall = overall.model_dump(mode="json")
        if per_class is not None:
            row.per_class = [p.model_dump(mode="json") for p in per_class]
        if confusion_matrix is not None:
            row.confusion_matrix = confusion_matrix.model_dump(mode="json")
        if attack_type is not None:
            row.attack_type_metrics = attack_type.model_dump(mode="json")
        await session.flush()
        return _eval_detail(row)

    async def get(self, session: AsyncSession, run_id: str) -> EvalRunDetail | None:
        row = await session.get(models.EvalRun, run_id)
        return _eval_detail(row) if row else None

    async def reap_stale(
        self, session: AsyncSession, cutoff: datetime
    ) -> builtins.list[str]:
        """Fail every ``running`` row started before ``cutoff``. Returns their ids."""
        return await _reap_stale(session, models.EvalRun, cutoff)

    async def active_run_id(self, session: AsyncSession, cutoff: datetime) -> str | None:
        """Id of a genuinely fresh in-flight run (started at or after ``cutoff``)."""
        return await _active_run_id(session, models.EvalRun, cutoff)

    async def list(self, session: AsyncSession) -> builtins.list[EvalRunDetail]:
        res = await session.execute(
            select(models.EvalRun).order_by(models.EvalRun.started_at.desc())
        )
        return [_eval_detail(r) for r in res.scalars().all()]

    async def mark_completed(
        self,
        session: AsyncSession,
        run_id: str,
        overall: OverallMetrics,
        per_class: builtins.list[PerClassMetric],
        confusion_matrix: ConfusionMatrix,
        attack_type: TargetReport | None = None,
        sample_size: int | None = None,
    ) -> EvalRunDetail | None:
        row = await session.get(models.EvalRun, run_id)
        if row is None:
            return None
        row.status = "completed"
        row.completed_at = _now()
        if sample_size is not None:
            row.sample_size = sample_size
        row.overall = overall.model_dump(mode="json")
        row.per_class = [p.model_dump(mode="json") for p in per_class]
        row.confusion_matrix = confusion_matrix.model_dump(mode="json")
        if attack_type is not None:
            row.attack_type_metrics = attack_type.model_dump(mode="json")
        await session.flush()
        return _eval_detail(row)

    async def mark_failed(
        self, session: AsyncSession, run_id: str, error: str
    ) -> EvalRunDetail | None:
        row = await session.get(models.EvalRun, run_id)
        if row is None:
            return None
        row.status = "failed"
        row.completed_at = _now()
        row.error = error
        await session.flush()
        return _eval_detail(row)


def _benchmark_detail(row: models.BenchmarkRun) -> BenchmarkRunDetail:
    return BenchmarkRunDetail(
        run_id=row.id,
        status=row.status,  # type: ignore[arg-type]
        sample_size=row.sample_size,
        started_at=row.started_at,
        completed_at=row.completed_at,
        results=[BenchmarkResult.model_validate(d) for d in (row.results or [])],
        agreement_rate=row.agreement_rate,
        disagreement_examples=[
            DisagreementExample.model_validate(d) for d in (row.disagreement_examples or [])
        ],
        error=row.error,
    )


class BenchmarkRunRepository:
    async def create(
        self, session: AsyncSession, sample_size: int, run_id: str | None = None
    ) -> BenchmarkRunDetail:
        row = models.BenchmarkRun(status="running", sample_size=sample_size)
        if run_id is not None:
            row.id = run_id
        session.add(row)
        await session.flush()
        return _benchmark_detail(row)

    async def get(self, session: AsyncSession, run_id: str) -> BenchmarkRunDetail | None:
        row = await session.get(models.BenchmarkRun, run_id)
        return _benchmark_detail(row) if row else None

    async def reap_stale(
        self, session: AsyncSession, cutoff: datetime
    ) -> builtins.list[str]:
        """Fail every ``running`` row started before ``cutoff``. Returns their ids."""
        return await _reap_stale(session, models.BenchmarkRun, cutoff)

    async def active_run_id(self, session: AsyncSession, cutoff: datetime) -> str | None:
        """Id of a genuinely fresh in-flight run (started at or after ``cutoff``)."""
        return await _active_run_id(session, models.BenchmarkRun, cutoff)

    async def list(self, session: AsyncSession) -> builtins.list[BenchmarkRunDetail]:
        res = await session.execute(
            select(models.BenchmarkRun).order_by(models.BenchmarkRun.started_at.desc())
        )
        return [_benchmark_detail(r) for r in res.scalars().all()]

    async def mark_completed(
        self,
        session: AsyncSession,
        run_id: str,
        results: builtins.list[BenchmarkResult],
        agreement_rate: float | None,
        disagreement_examples: builtins.list[DisagreementExample] | None = None,
        sample_size: int | None = None,
    ) -> BenchmarkRunDetail | None:
        row = await session.get(models.BenchmarkRun, run_id)
        if row is None:
            return None
        row.status = "completed"
        row.completed_at = _now()
        if sample_size is not None:
            row.sample_size = sample_size
        row.results = [r.model_dump(mode="json") for r in results]
        row.agreement_rate = agreement_rate
        row.disagreement_examples = [
            d.model_dump(mode="json") for d in (disagreement_examples or [])
        ]
        await session.flush()
        return _benchmark_detail(row)

    async def mark_failed(
        self, session: AsyncSession, run_id: str, error: str
    ) -> BenchmarkRunDetail | None:
        row = await session.get(models.BenchmarkRun, run_id)
        if row is None:
            return None
        row.status = "failed"
        row.completed_at = _now()
        row.error = error
        await session.flush()
        return _benchmark_detail(row)
