"""Run the evaluation harness from the command line.

Usage:
    python -m scripts.run_eval --sample-size 200
    python -m scripts.run_eval --sample-size 50 --enrich   # also hits the intel APIs

Prints the per-class table, macro metrics and an ASCII confusion matrix for BOTH
scored targets — severity and attack type. Classes whose support is below the
noise threshold are marked; a per-class F1 computed on two examples is not a
measurement and is not presented as one.
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from app.config import get_settings
from app.evaluation.ground_truth import LOW_SUPPORT_THRESHOLD, check_label_health
from app.evaluation.runner import create_run, run_eval
from app.schemas import ConfusionMatrix, EvalRunDetail, PerClassMetric, TargetReport
from app.store.db import dispose_db, init_db

BAR = "-" * 72


def _rule(title: str) -> None:
    print(f"\n{title}\n{BAR}")


def _per_class_table(rows: list[PerClassMetric]) -> None:
    print(f"{'label':<20}{'precision':>11}{'recall':>9}{'f1':>9}{'support':>9}")
    for row in rows:
        flag = " !" if 0 < row.support < LOW_SUPPORT_THRESHOLD else ""
        # ASCII only: this prints to a live terminal on stage, and a Windows
        # console in cp1252 turns a stray em dash into a replacement glyph.
        zero = " (no true instances: excluded from macro)" if row.support == 0 else ""
        print(
            f"{row.label:<20}{row.precision:>11.3f}{row.recall:>9.3f}"
            f"{row.f1:>9.3f}{row.support:>9}{flag}{zero}"
        )
    thin = [r.label for r in rows if 0 < r.support < LOW_SUPPORT_THRESHOLD]
    if thin:
        print(
            f"\n  ! support < {LOW_SUPPORT_THRESHOLD}: these per-class numbers are "
            "NOISE, not measurements."
        )


def _confusion(matrix: ConfusionMatrix) -> None:
    labels = matrix.labels
    if not labels:
        print("  (no matrix)")
        return
    width = max(8, max(len(label) for label in labels) + 1)
    header = " " * (width + 2) + "".join(f"{label[:width - 1]:>{width}}" for label in labels)
    print("  rows = TRUE label, columns = PREDICTED label")
    print(header)
    for label, row in zip(labels, matrix.matrix, strict=True):
        cells = "".join(f"{value:>{width}}" for value in row)
        print(f"  {label:<{width}}{cells}")


def _print_target(name: str, report: TargetReport) -> None:
    _rule(f"{name} | macro precision {report.overall.precision:.3f}  "
          f"recall {report.overall.recall:.3f}  f1 {report.overall.f1:.3f}  "
          f"accuracy {report.overall.accuracy:.3f}")
    _per_class_table(report.per_class)
    print()
    _confusion(report.confusion_matrix)


def _print_report(detail: EvalRunDetail, *, skip_enrich: bool) -> None:
    settings = get_settings()
    _rule("FLARE EVALUATION")
    print(f"run_id      : {detail.run_id}")
    print(f"status      : {detail.status}")
    print(f"sample_size : {detail.sample_size}")
    print(f"enrichment  : {'skipped' if skip_enrich else 'enabled'}")
    print(f"seed        : {settings.eval_seed}  (sample is reproducible; LLM decoding is not)")

    if detail.status != "completed" or detail.overall is None:
        print(f"\nERROR: {detail.error or 'run did not complete'}")
        return

    _print_target(
        "SEVERITY (overall / per_class / confusion_matrix in the API response)",
        TargetReport(
            overall=detail.overall,
            per_class=detail.per_class,
            confusion_matrix=detail.confusion_matrix or ConfusionMatrix(),
        ),
    )
    if detail.attack_type is not None:
        _print_target("ATTACK TYPE (`attack_type` in the API response)", detail.attack_type)
    print()
    print("Averages are MACRO: every class gets an equal vote, so a rare attack class")
    print("cannot be hidden behind the benign majority.")
    print(BAR)


async def main() -> int:
    parser = argparse.ArgumentParser(description="Run the Flare evaluation harness")
    parser.add_argument(
        "--sample-size",
        type=int,
        default=get_settings().eval_sample_size,
        help="stratified sample size (default: EVAL_SAMPLE_SIZE)",
    )
    parser.add_argument(
        "--enrich",
        action="store_true",
        help="run the full pipeline including IOC enrichment (slow: live API quota)",
    )
    parser.add_argument(
        "--seed", type=int, default=None, help="override EVAL_SEED for the sample draw"
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="run even when the label set is missing, tiny, or the replay fallback",
    )
    args = parser.parse_args()

    # Announce the label set BEFORE spending minutes of LLM quota on it. An eval
    # scored against a 6-row fallback is not worth running, and finding that out
    # afterwards is how Phase 11/12 shipped meaningless numbers.
    health = check_label_health()
    _rule("GROUND TRUTH")
    print(health.message())
    if not health.ok and not args.force:
        print(
            "\nRefusing to run. Fix with:  python -m scripts.build_label_set"
            "\n(or pass --force to score against it anyway)"
        )
        return 2

    await init_db()
    try:
        opened = await create_run(args.sample_size)
        detail = await run_eval(
            opened.run_id,
            args.sample_size,
            skip_enrich=not args.enrich,
            seed=args.seed,
        )
    finally:
        await dispose_db()

    _print_report(detail, skip_enrich=not args.enrich)
    return 0 if detail.status == "completed" else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
