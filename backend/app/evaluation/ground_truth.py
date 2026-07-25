"""Labeled ground-truth loader — the numbers are only as good as this file.

Reads CICIDS2017 rows (which carry a ``Label`` column) and turns each into a
``NormalizedAlert`` plus the TWO expected outputs the pipeline is scored on.

WHY STRATIFIED SAMPLING
-----------------------
CICIDS2017 is ~80% BENIGN. A uniform random draw of 200 rows yields ~160 benign
flows, a handful of port scans, and quite possibly ZERO of some attack class —
per-class recall for that class is then either undefined or computed on one or
two examples, which is noise dressed up as a metric. :func:`load` therefore
allocates the sample per label: one guaranteed slot per class, then the rest
proportional to class frequency. The draw is seeded (``settings.eval_seed``), so
two runs score the identical sample set.

TWO SEPARATE MAPPINGS
---------------------
:data:`LABEL_TO_ATTACK_TYPE` and :data:`LABEL_TO_SEVERITY` are independent on
purpose. Attack type is *what happened*; severity is *how much it matters*. They
are different targets, scored separately, and conflating them would hide the
case where the system names the attack correctly but triages it at the wrong
urgency (or vice versa).

Rows whose label has no entry in BOTH mappings are excluded from the population
with a loud warning: there is no defensible expected value to score them against.

THE SILENT-FALLBACK BUG THIS MODULE NOW REFUSES TO REPEAT
---------------------------------------------------------
``data/labels/`` was empty for the whole of Phase 11/12. :func:`_candidate_files`
quietly fell back to the 6-row replay placeholder, and every eval since produced
a plausible-looking macro-F1 computed on SIX rows. Nothing failed; the number was
simply meaningless. Two guards close that hole:

* :func:`check_label_health` — called at startup and by ``scripts/run_eval.py``
  before a run — reports the population size, whether the fallback was taken, and
  whether the count clears ``settings.eval_min_label_rows``.
* :func:`load_population` logs at ERROR (not debug, not info) when the loaded
  count is below that threshold, and the eval runner turns it into a ``warn``
  system notice that reaches the dashboard.

A tiny label set is still allowed to run — refusing outright would break a
deliberately small test fixture — but it can no longer happen quietly.
"""

from __future__ import annotations

import csv
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from random import Random

from app.config import get_settings
from app.core.logging import get_logger
from app.ingestion.normalizer import normalize
from app.ingestion.parsers import cicids
from app.schemas import AttackType, NormalizedAlert, Severity

log = get_logger(__name__)

SOURCE = "cicids2017"

#: Per-class support below this is statistically meaningless — a per-class F1 on
#: 2 examples is noise. Flagged loudly at load time and surfaced in the report.
LOW_SUPPORT_THRESHOLD = 5

#: Hard cap so a full 2.8M-row CICIDS export cannot exhaust memory.
MAX_POPULATION_ROWS = 200_000

# --------------------------------------------------------------------------- mappings
# Keys are the canonical dataset labels produced by app.ingestion.parsers.cicids
# (e.g. raw "Web Attack - Brute Force" -> "web_attack", "SSH-Patator" ->
# "brute_force"). Normalizing raw CICIDS label spellings stays in the parser so
# ingestion and evaluation can never disagree about what a row is.

#: label -> AttackType. The classification target.
LABEL_TO_ATTACK_TYPE: dict[str, AttackType] = {
    "benign": AttackType.BENIGN,
    "port_scan": AttackType.PORT_SCAN,
    "recon": AttackType.RECON,
    "brute_force": AttackType.BRUTE_FORCE,
    "web_attack": AttackType.WEB_ATTACK,
    "ddos": AttackType.DDOS,
    "malware_c2": AttackType.MALWARE_C2,
    "data_exfiltration": AttackType.DATA_EXFILTRATION,
    "infiltration": AttackType.DATA_EXFILTRATION,
}

#: label -> Severity. The triage-urgency target. Separate from the mapping above.
LABEL_TO_SEVERITY: dict[str, Severity] = {
    "benign": Severity.INFO,
    "port_scan": Severity.LOW,
    "recon": Severity.LOW,
    "brute_force": Severity.MEDIUM,
    "web_attack": Severity.MEDIUM,
    "ddos": Severity.HIGH,
    "malware_c2": Severity.CRITICAL,
    "data_exfiltration": Severity.CRITICAL,
    "infiltration": Severity.CRITICAL,
}


@dataclass(frozen=True)
class LabeledAlert:
    """One ground-truth item: the alert plus BOTH expected fields."""

    alert: NormalizedAlert
    label: str
    expected_attack_type: AttackType
    expected_severity: Severity


class GroundTruthError(RuntimeError):
    """No usable labeled data — an eval run must fail loudly, not score nothing."""


@contextmanager
def _full_label_coverage() -> Iterator[None]:
    """Disable the ingestion parser's BENIGN down-sampler for the duration.

    ``cicids.parse`` keeps only 1-in-N benign flows so a live replay demo is not
    flooded by them. That is right for the demo and wrong here: it silently
    deletes 90% of one class before stratification can balance it. Ground truth
    loads the FULL labeled population; balancing is this module's job.
    """
    original = cicids.BENIGN_SAMPLE_EVERY
    cicids.BENIGN_SAMPLE_EVERY = 1
    try:
        yield
    finally:
        cicids.BENIGN_SAMPLE_EVERY = original


#: Set by :func:`_candidate_files` when the replay placeholder was substituted
#: for a real label set. Read by :func:`check_label_health` so the fallback is
#: reported, not merely logged and forgotten.
_used_fallback = False


def _candidate_files(path: Path, allow_fallback: bool) -> list[Path]:
    """Labeled CSVs under ``path``, else the replay dataset as a fallback.

    The fallback only applies to the CONFIGURED ``GROUND_TRUTH_PATH`` — a path
    passed in explicitly that turns up nothing is an error, not an invitation to
    quietly score a different file.

    Taking the fallback is logged at ERROR: it is the failure mode that produced
    an entire phase of meaningless eval numbers, and it must be impossible to
    miss in a console scrollback.
    """
    global _used_fallback
    _used_fallback = False

    if path.is_file():
        return [path]
    files = sorted(path.glob("*.csv")) if path.is_dir() else []
    if files or not allow_fallback:
        return files

    fallback = Path(get_settings().dataset_path) / "cicids2017_sample.csv"
    if fallback.exists():
        _used_fallback = True
        log.error(
            "eval.ground_truth_fallback",
            configured=str(path),
            using=str(fallback),
            note=(
                "NO LABELED CSV UNDER GROUND_TRUTH_PATH — falling back to the replay "
                "sample. Any metric produced from this is NOT a measurement. Run "
                "`python -m scripts.build_label_set` to fetch the real labeled subset."
            ),
        )
        return [fallback]
    return []


def _read_rows(files: list[Path]) -> Iterator[dict[str, str]]:
    seen = 0
    for file in files:
        with file.open("r", encoding="utf-8", newline="") as handle:
            for row in csv.DictReader(handle):
                yield row
                seen += 1
                if seen >= MAX_POPULATION_ROWS:
                    log.warning("eval.population_capped", cap=MAX_POPULATION_ROWS)
                    return


def load_population(path: Path | None = None) -> list[LabeledAlert]:
    """Every labeled row we can score, in file order. No sampling."""
    root = Path(path) if path is not None else Path(get_settings().ground_truth_path)
    files = _candidate_files(root, allow_fallback=path is None)
    if not files:
        raise GroundTruthError(
            f"no labeled ground-truth CSV found under {root} "
            "(expected CICIDS2017 rows with a 'Label' column)"
        )

    population: list[LabeledAlert] = []
    unmapped: dict[str, int] = {}

    with _full_label_coverage():
        for index, row in enumerate(_read_rows(files)):
            alert = normalize(row, SOURCE, index)
            if alert is None:
                continue
            label = alert.ground_truth_label or "unknown"
            attack_type = LABEL_TO_ATTACK_TYPE.get(label)
            severity = LABEL_TO_SEVERITY.get(label)
            if attack_type is None or severity is None:
                unmapped[label] = unmapped.get(label, 0) + 1
                continue
            population.append(
                LabeledAlert(
                    alert=alert,
                    label=label,
                    expected_attack_type=attack_type,
                    expected_severity=severity,
                )
            )

    for label, count in sorted(unmapped.items()):
        log.warning("eval.unmapped_label_excluded", label=label, rows=count)

    if not population:
        raise GroundTruthError(
            f"found {len(files)} file(s) under {root} but no row carried a mappable label"
        )

    minimum = get_settings().eval_min_label_rows
    if len(population) < minimum:
        # ERROR, not warning: a run on this many rows yields a real-looking
        # macro-F1 that is pure noise, and nothing downstream would ever fail.
        log.error(
            "eval.label_set_too_small",
            rows=len(population),
            minimum=minimum,
            path=str(root),
            fallback=_used_fallback,
            note=(
                "labeled set is below EVAL_MIN_LABEL_ROWS — per-class metrics from it "
                "are noise. Run `python -m scripts.build_label_set`."
            ),
        )
    return population


def support(items: list[LabeledAlert]) -> dict[str, int]:
    """Rows per label, label-sorted."""
    counts: dict[str, int] = {}
    for item in items:
        counts[item.label] = counts.get(item.label, 0) + 1
    return dict(sorted(counts.items()))


def low_support_labels(
    items: list[LabeledAlert], threshold: int = LOW_SUPPORT_THRESHOLD
) -> list[str]:
    """Labels whose per-class metrics will be noise. Must be shown, not hidden."""
    return [label for label, count in support(items).items() if count < threshold]


def _allocate(counts: dict[str, int], sample_size: int) -> dict[str, int]:
    """Split ``sample_size`` across classes: 1 guaranteed each, rest proportional.

    Deterministic (labels iterated in sorted order) and never over-draws a class
    beyond the rows it actually has.
    """
    labels = sorted(counts)
    total = sum(counts.values())
    if sample_size >= total:
        return dict(counts)
    if sample_size < len(labels):
        raise GroundTruthError(
            f"sample_size {sample_size} is smaller than the {len(labels)} labeled "
            "classes; every class must keep support >= 1 for per-class metrics to mean "
            f"anything (need at least {len(labels)})"
        )

    alloc = dict.fromkeys(labels, 1)
    remaining = sample_size - len(labels)

    while remaining > 0:
        eligible = [label for label in labels if alloc[label] < counts[label]]
        if not eligible:
            break
        pool = sum(counts[label] - alloc[label] for label in eligible)
        shares = {
            label: (counts[label] - alloc[label]) * remaining / pool for label in eligible
        }

        given = 0
        for label in eligible:
            take = min(int(shares[label]), counts[label] - alloc[label], remaining - given)
            alloc[label] += take
            given += take

        if given == 0:
            # Every proportional share was < 1: hand out the remainder one at a
            # time, largest fractional share first (deterministic tie-break).
            order = sorted(eligible, key=lambda x: (-(shares[x] % 1.0), -counts[x], x))
            for label in order:
                if given >= remaining:
                    break
                alloc[label] += 1
                given += 1

        remaining -= given
        if given == 0:  # pragma: no cover - defensive, cannot happen
            break

    return alloc


def load(
    sample_size: int | None = None,
    *,
    path: Path | None = None,
    seed: int | None = None,
) -> list[LabeledAlert]:
    """A stratified, seeded sample of the labeled set.

    Guarantees every label present in the population has support >= 1 in the
    sample (asserted), and logs a loud warning for any class below
    :data:`LOW_SUPPORT_THRESHOLD` — those per-class numbers must be presented as
    noise, not as measurements.
    """
    settings = get_settings()
    size = sample_size if sample_size is not None else settings.eval_sample_size
    if size < 1:
        raise GroundTruthError(f"sample_size must be >= 1, got {size}")

    rng = Random(seed if seed is not None else settings.eval_seed)
    population = load_population(path)

    grouped: dict[str, list[LabeledAlert]] = {}
    for item in population:
        grouped.setdefault(item.label, []).append(item)

    counts = {label: len(members) for label, members in grouped.items()}
    alloc = _allocate(counts, size)

    sample: list[LabeledAlert] = []
    for label in sorted(grouped):
        members = grouped[label]
        take = alloc[label]
        sample.extend(members if take >= len(members) else rng.sample(members, take))

    # Interleave classes so bounded concurrency does not run one class at a time.
    rng.shuffle(sample)

    drawn = support(sample)
    missing = sorted(set(counts) - set(drawn))
    assert not missing, f"stratified sample dropped labels entirely: {missing}"

    thin = low_support_labels(sample)
    if thin:
        log.warning(
            "eval.low_support_classes",
            labels=thin,
            threshold=LOW_SUPPORT_THRESHOLD,
            note="per-class metrics for these labels are noise and must be labeled as such",
        )

    log.info(
        "eval.sample_loaded",
        requested=size,
        drawn=len(sample),
        population=len(population),
        support=drawn,
    )
    return sample


@dataclass(frozen=True)
class LabelSetHealth:
    """What the configured label set actually is — reported, never assumed."""

    ok: bool
    rows: int
    classes: int
    minimum: int
    path: str
    used_fallback: bool
    thin_classes: list[str]
    error: str | None = None

    def message(self) -> str:
        if self.error is not None:
            return f"ground truth UNUSABLE at {self.path}: {self.error}"
        if self.used_fallback:
            return (
                f"ground truth FELL BACK to the replay sample ({self.rows} rows): no labeled "
                f"CSV under {self.path}. Eval numbers from this are NOT measurements — run "
                "`python -m scripts.build_label_set`."
            )
        if not self.ok:
            return (
                f"ground truth has only {self.rows} labeled row(s) at {self.path}, below the "
                f"{self.minimum}-row minimum. Per-class metrics from this are noise — run "
                "`python -m scripts.build_label_set`."
            )
        detail = f"ground truth OK: {self.rows} labeled rows, {self.classes} classes"
        if self.thin_classes:
            detail += f" (low support: {', '.join(self.thin_classes)})"
        return detail


def check_label_health(path: Path | None = None) -> LabelSetHealth:
    """Load the label set and report its usability. NEVER raises.

    Called at startup and before every CLI eval run so a missing or tiny label
    set is announced up front rather than discovered in the numbers afterwards.
    """
    settings = get_settings()
    root = Path(path) if path is not None else Path(settings.ground_truth_path)
    minimum = settings.eval_min_label_rows

    try:
        population = load_population(path)
    except (GroundTruthError, OSError) as exc:
        return LabelSetHealth(
            ok=False,
            rows=0,
            classes=0,
            minimum=minimum,
            path=str(root),
            used_fallback=_used_fallback,
            thin_classes=[],
            error=str(exc),
        )

    counts = support(population)
    return LabelSetHealth(
        ok=len(population) >= minimum and not _used_fallback,
        rows=len(population),
        classes=len(counts),
        minimum=minimum,
        path=str(root),
        used_fallback=_used_fallback,
        thin_classes=low_support_labels(population),
    )


__all__ = [
    "LOW_SUPPORT_THRESHOLD",
    "LABEL_TO_ATTACK_TYPE",
    "LABEL_TO_SEVERITY",
    "GroundTruthError",
    "LabelSetHealth",
    "LabeledAlert",
    "check_label_health",
    "load",
    "load_population",
    "low_support_labels",
    "support",
]
