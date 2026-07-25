"""Eval runner — pushes labeled alerts through the PRODUCTION triage graph.

Three rules make the difference between a measurement and a demo prop:

1. **The same code path.** Every alert goes through ``app.agent.graph.run_triage``
   — the identical function the live triage worker calls. No reimplemented
   classifier, no eval-only branch inside a node, no "if eval: ..." anywhere. If
   the eval path could diverge from the live path, the numbers would be fiction.

2. **Failures are predictions, not deletions.** An alert that fails to classify
   is scored as ``unknown`` / ``medium`` — the exact fallback the classify node
   already applies in production — and stays in the denominator. Dropping the
   hard cases is the second classic way eval code lies about itself.

3. **A run never ends silently.** Any exception marks the run ``failed`` with the
   error text stored; a run is never left stuck in ``running``.

ENRICHMENT IS OFF BY DEFAULT (``skip_enrich``, ``settings.eval_skip_enrich``).
The eval measures classification quality, and 200 alerts through VirusTotal at
4 requests/minute is ~50 minutes of wall clock. Skipping maps onto exactly the
mechanism the live fast path already uses — ``run_triage(..., stop_after="classify")``,
the same call the triage worker makes — so it is the production path truncated,
not a different one. Pass ``skip_enrich=False`` to score the full pipeline
(including the enrich node's IOC-driven severity upgrade), which is the live
end-state severity but costs live API quota.

DETERMINISM: the sample is fixed by ``settings.eval_seed``, so two runs score the
identical alerts. The classifier runs at low temperature but LLM decoding is not
bit-exact, so two runs on the same sample can still differ slightly. That caveat
is published in the run's completion notice rather than being quietly implied.
"""

from __future__ import annotations

import asyncio
import math
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.agent.graph import run_triage
from app.config import get_settings
from app.core.bus import EventBus, get_event_bus
from app.core.logging import get_logger
from app.evaluation import ground_truth as gt
from app.evaluation.metrics import (
    MetricReport,
    observed_labels,
    precision_recall_f1,
    to_contract,
)
from app.schemas import (
    AttackType,
    EvalRunDetail,
    Severity,
    SystemNotice,
    SystemNoticeEvent,
    TargetReport,
)
from app.store.db import get_sessionmaker
from app.store.repositories import EvalRunRepository

log = get_logger(__name__)

#: Severity axes are fixed at all five values so the heatmap axis is stable
#: across runs (contract §5's example matrix). A class with no true instances
#: shows support 0 and is excluded from the macro average, per the metrics policy.
SEVERITY_LABELS: list[str] = [s.value for s in Severity]

#: Attack-type axes are the observed union in canonical order — pinning all ten
#: would render a mostly-empty 10x10 grid.
ATTACK_TYPE_LABELS: list[str] = [a.value for a in AttackType]

#: What a failed classification is scored as — identical to the classify node's
#: own production fallback. Never dropped, never scored as correct.
FAILURE_SEVERITY = Severity.MEDIUM
FAILURE_ATTACK_TYPE = AttackType.UNKNOWN

PROGRESS_STEPS = 10  # publish + persist every 10%

TriageFn = Callable[..., Awaitable[Any]]
Loader = Callable[[], Sequence[gt.LabeledAlert]]


@dataclass(frozen=True)
class Prediction:
    """One scored alert: expected vs predicted, for both targets."""

    alert_id: str
    label: str
    expected_severity: Severity
    expected_attack_type: AttackType
    severity: Severity
    attack_type: AttackType
    failed: bool = False
    error: str | None = None


def _notice(bus: EventBus | None, level: str, message: str) -> None:
    if bus is None:
        return
    bus.publish(SystemNoticeEvent(data=SystemNotice(level=level, message=message)))  # type: ignore[arg-type]


def _classification_failed(state: Any) -> bool:
    """True when the classify node itself degraded (its trace is marked failed)."""
    for trace in state.get("trace") or []:
        if getattr(trace, "node", None) != "classify":
            continue
        if getattr(trace, "status", None) == "failed":
            return True
    return False


async def predict_one(
    item: gt.LabeledAlert,
    triage_fn: TriageFn,
    config: dict[str, Any],
    stop_after: str | None,
) -> Prediction:
    """Run one alert through the production graph and read off both predictions.

    Public because the provider benchmark scores the same way — one definition of
    "what did the pipeline predict, and did it fail" for both panels.
    """
    error: str | None = None
    state: Any = {}
    try:
        state = await triage_fn(item.alert, config=config, stop_after=stop_after)
    except Exception as exc:  # noqa: BLE001 — a broken alert is a prediction, not a gap
        log.warning("eval.alert_failed", alert_id=item.alert.id, error=str(exc))
        error = str(exc)
        state = {}

    severity = state.get("severity") if isinstance(state, dict) else None
    attack_type = state.get("attack_type") if isinstance(state, dict) else None
    missing = not isinstance(severity, Severity) or not isinstance(attack_type, AttackType)
    failed = bool(error) or missing or _classification_failed(state)

    if not isinstance(severity, Severity):
        severity = FAILURE_SEVERITY
    if not isinstance(attack_type, AttackType):
        attack_type = FAILURE_ATTACK_TYPE

    if failed and error is None:
        errors = state.get("errors") or [] if isinstance(state, dict) else []
        error = "; ".join(str(e) for e in errors) or "classification degraded"

    return Prediction(
        alert_id=item.alert.id,
        label=item.label,
        expected_severity=item.expected_severity,
        expected_attack_type=item.expected_attack_type,
        severity=severity,
        attack_type=attack_type,
        failed=failed,
        error=error,
    )


def build_reports(predictions: Sequence[Prediction]) -> tuple[MetricReport, MetricReport]:
    """Score BOTH targets independently. Neither is derived from the other."""
    severity_true = [p.expected_severity.value for p in predictions]
    severity_pred = [p.severity.value for p in predictions]
    severity_report = precision_recall_f1(severity_true, severity_pred, SEVERITY_LABELS)

    attack_true = [p.expected_attack_type.value for p in predictions]
    attack_pred = [p.attack_type.value for p in predictions]
    attack_labels = observed_labels(attack_true, attack_pred, ATTACK_TYPE_LABELS)
    attack_report = precision_recall_f1(attack_true, attack_pred, attack_labels)

    return severity_report, attack_report


def _target_report(report: MetricReport) -> TargetReport:
    overall, per_class, matrix = to_contract(report)
    return TargetReport(overall=overall, per_class=per_class, confusion_matrix=matrix)


async def create_run(
    sample_size: int, *, session_factory: Any = None, run_id: str | None = None
) -> EvalRunDetail:
    """Open a ``running`` row and return it (the API answers 202 from this)."""
    maker = session_factory or get_sessionmaker()
    repo = EvalRunRepository()
    async with maker() as session:
        detail = await repo.create(session, sample_size=sample_size, run_id=run_id)
        await session.commit()
    return detail


async def run_eval(
    run_id: str,
    sample_size: int | None = None,
    *,
    session_factory: Any = None,
    bus: EventBus | None = None,
    loader: Loader | None = None,
    triage_fn: TriageFn | None = None,
    skip_enrich: bool | None = None,
    concurrency: int | None = None,
    seed: int | None = None,
    ground_truth_path: Path | None = None,
) -> EvalRunDetail:
    """Score a stratified sample end to end and persist the report.

    Returns the final :class:`EvalRunDetail` — ``completed`` with both target
    reports, or ``failed`` with the error stored. Exceptions are never propagated
    to the caller (this runs detached as a background task); they are recorded on
    the run instead.
    """
    settings = get_settings()
    maker = session_factory or get_sessionmaker()
    event_bus = bus if bus is not None else get_event_bus()
    triage = triage_fn or run_triage
    repo = EvalRunRepository()

    requested = sample_size if sample_size is not None else settings.eval_sample_size
    skip = settings.eval_skip_enrich if skip_enrich is None else skip_enrich
    limit = concurrency if concurrency is not None else settings.eval_concurrency
    run_seed = seed if seed is not None else settings.eval_seed

    # Skipping enrichment == the live fast path (`stop_after="classify"`), not a
    # separate code path. Nothing else about the graph changes.
    stop_after = "classify" if skip else None
    config: dict[str, Any] = {}

    try:
        async with maker() as session:
            existing = await repo.get(session, run_id)
            if existing is None:
                await repo.create(session, sample_size=requested, run_id=run_id)
                await session.commit()

        _notice(
            event_bus,
            "info",
            f"evaluation {run_id}: starting on {requested} alerts "
            f"(enrichment {'off' if skip else 'on'}, seed {run_seed})",
        )

        # CSV parsing is blocking — keep it off the event loop.
        def _load() -> Sequence[gt.LabeledAlert]:
            if loader is not None:
                return loader()
            return gt.load(requested, path=ground_truth_path, seed=run_seed)

        sample = list(await asyncio.to_thread(_load))
        total = len(sample)
        if total == 0:
            raise gt.GroundTruthError("ground truth produced an empty sample")

        # A tiny or fallback label set still runs, but the dashboard is told, so
        # nobody reads a macro-F1 computed on a handful of rows as a result.
        if loader is None:
            health = await asyncio.to_thread(gt.check_label_health, ground_truth_path)
            if not health.ok:
                log.error("eval.label_set_unhealthy", **{"detail": health.message()})
                _notice(event_bus, "warn", f"evaluation {run_id}: {health.message()}")

        thin = gt.low_support_labels(list(sample))
        if thin:
            _notice(
                event_bus,
                "warn",
                f"evaluation {run_id}: classes {', '.join(thin)} have fewer than "
                f"{gt.LOW_SUPPORT_THRESHOLD} examples — their per-class scores are noise",
            )

        async with maker() as session:
            await repo.save_progress(session, run_id, sample_size=total)
            await session.commit()

        predictions: list[Prediction] = []
        lock = asyncio.Lock()
        semaphore = asyncio.Semaphore(limit)
        step = max(1, math.ceil(total / PROGRESS_STEPS))
        next_mark = step

        async def _score(item: gt.LabeledAlert) -> None:
            nonlocal next_mark
            async with semaphore:
                prediction = await predict_one(item, triage, config, stop_after)
            async with lock:
                predictions.append(prediction)
                done = len(predictions)
                if done < next_mark and done != total:
                    return
                next_mark = done + step
                # Persist the partial report so a long run is visible while it
                # runs; status stays `running` so nothing reads it as final.
                partial_severity, partial_attack = build_reports(predictions)
                overall, per_class, matrix = to_contract(partial_severity)
                async with maker() as session:
                    await repo.save_progress(
                        session,
                        run_id,
                        overall=overall,
                        per_class=per_class,
                        confusion_matrix=matrix,
                        attack_type=_target_report(partial_attack),
                    )
                    await session.commit()
                _notice(
                    event_bus,
                    "info",
                    f"evaluation {run_id}: {done}/{total} alerts scored "
                    f"({round(100 * done / total)}%)",
                )

        await asyncio.gather(*(_score(item) for item in sample))

        assert len(predictions) == total, (
            f"predictions ({len(predictions)}) != sample ({total}) — "
            "an alert was dropped from the denominator"
        )

        severity_report, attack_report = build_reports(predictions)
        overall, per_class, matrix = to_contract(severity_report)
        failures = sum(1 for p in predictions if p.failed)

        async with maker() as session:
            detail = await repo.mark_completed(
                session,
                run_id,
                overall=overall,
                per_class=per_class,
                confusion_matrix=matrix,
                attack_type=_target_report(attack_report),
                sample_size=total,
            )
            await session.commit()

        log.info(
            "eval.completed",
            run_id=run_id,
            sample_size=total,
            severity_macro_f1=round(severity_report.macro.f1, 4),
            attack_type_macro_f1=round(attack_report.macro.f1, 4),
            accuracy=round(severity_report.accuracy, 4),
            failures=failures,
        )
        _notice(
            event_bus,
            "warn" if failures else "info",
            f"evaluation {run_id} complete: {total} alerts, "
            f"severity macro-F1 {severity_report.macro.f1:.2f}, "
            f"attack-type macro-F1 {attack_report.macro.f1:.2f}, "
            f"{failures} classification failure(s) scored as unknown/medium"
            + (f"; low-support classes: {', '.join(thin)}" if thin else "")
            + f"; sample fixed by seed {run_seed}, LLM decoding may still vary between runs",
        )

        if detail is not None:
            return detail
        return await _fail(repo, maker, event_bus, run_id, "run row vanished mid-eval")

    except asyncio.CancelledError:
        await _fail(repo, maker, event_bus, run_id, "evaluation cancelled")
        raise
    except Exception as exc:  # noqa: BLE001 — a run must never stay stuck in `running`
        log.error("eval.failed", run_id=run_id, error=str(exc))
        return await _fail(repo, maker, event_bus, run_id, str(exc))


async def _fail(
    repo: EvalRunRepository,
    maker: Any,
    bus: EventBus | None,
    run_id: str,
    error: str,
) -> EvalRunDetail:
    """Mark the run failed and publish it. Best-effort: never raises."""
    try:
        async with maker() as session:
            detail = await repo.mark_failed(session, run_id, error)
            await session.commit()
    except Exception as exc:  # noqa: BLE001 — already on the error path
        log.error("eval.mark_failed_failed", run_id=run_id, error=str(exc))
        detail = None

    _notice(bus, "error", f"evaluation {run_id} failed: {error}")
    if detail is not None:
        return detail
    return EvalRunDetail(run_id=run_id, status="failed", sample_size=0, error=error)


__all__ = [
    "ATTACK_TYPE_LABELS",
    "FAILURE_ATTACK_TYPE",
    "FAILURE_SEVERITY",
    "SEVERITY_LABELS",
    "Prediction",
    "build_reports",
    "create_run",
    "predict_one",
    "run_eval",
]
