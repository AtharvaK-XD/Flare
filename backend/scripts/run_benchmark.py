"""Run the provider benchmark from the command line.

Prints the per-tier table, the cross-tier agreement rate and the alerts behind
it. A tier that hit the provider's free-tier rate limit mid-run is marked
THROTTLED: its latency includes queueing and understates the model, and printing
it as a clean comparison would be a lie by omission.

Usage:
    python -m scripts.run_benchmark
    python -m scripts.run_benchmark --sample-size 10
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from app.config import get_settings
from app.evaluation.benchmark import create_run, run_benchmark
from app.evaluation.ground_truth import check_label_health
from app.schemas import BenchmarkRunDetail
from app.store.db import dispose_db, init_db

BAR = "-" * 78


def _rule(title: str) -> None:
    print(f"\n{title}\n{BAR}")


def _print_report(detail: BenchmarkRunDetail) -> None:
    _rule("FLARE PROVIDER BENCHMARK")
    print(f"run_id      : {detail.run_id}")
    print(f"status      : {detail.status}")
    print(f"sample_size : {detail.sample_size}")

    if detail.status != "completed":
        print(f"\nERROR: {detail.error or 'run did not complete'}")
        return

    header = (
        f"{'tier':<9}{'provider':<10}{'model':<26}{'p50 ms':>9}{'p95 ms':>9}"
        f"{'sev acc':>9}{'at acc':>8}{'fails':>7}"
    )
    print(header)
    print("-" * len(header))
    for result in detail.results:
        flag = "  THROTTLED" if result.throttled else ""
        print(
            f"{result.tier.value:<9}{result.provider:<10}{result.model[:25]:<26}"
            f"{result.p50_latency_ms:>9.0f}{result.p95_latency_ms:>9.0f}"
            f"{result.accuracy:>9.2f}{result.attack_type_accuracy:>8.2f}"
            f"{result.failures:>7}{flag}"
        )

    throttled = [r for r in detail.results if r.throttled]
    if throttled:
        print()
        for result in throttled:
            print(
                f"  ! {result.tier.value} tier was THROTTLED: {result.throttle_retries} "
                "rate-limit retry/retries landed inside the measured window. Its latency "
                "reflects free-tier queueing, NOT the model's speed. Re-run when the "
                "per-minute budget has reset for a clean number."
            )

    print()
    if detail.agreement_rate is None:
        print("agreement: unavailable (no alert was classified by both tiers)")
    else:
        print(f"agreement: {detail.agreement_rate:.0%} on severity, across both tiers")

    if detail.disagreement_examples:
        print("\ndisagreements (fast vs quality vs ground truth):")
        for example in detail.disagreement_examples:
            print(
                f"  {example.signature[:52]:<54} "
                f"fast={example.fast_prediction:<9} quality={example.quality_prediction:<9} "
                f"truth={example.ground_truth}"
            )
    print(BAR)


async def main() -> int:
    parser = argparse.ArgumentParser(description="Run the Flare provider benchmark")
    parser.add_argument(
        "--sample-size",
        type=int,
        default=get_settings().benchmark_sample_size,
        help="alerts per tier (every alert is run through BOTH tiers)",
    )
    parser.add_argument(
        "--force", action="store_true", help="run even if the label set is unhealthy"
    )
    args = parser.parse_args()

    health = check_label_health()
    _rule("GROUND TRUTH")
    print(health.message())
    if not health.ok and not args.force:
        print("\nRefusing to run. Fix with:  python -m scripts.build_label_set")
        return 2

    await init_db()
    try:
        opened = await create_run(args.sample_size)
        detail = await run_benchmark(opened.run_id, args.sample_size)
    finally:
        await dispose_db()

    _print_report(detail)
    return 0 if detail.status == "completed" else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
