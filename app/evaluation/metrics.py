"""Classification metrics — pure functions, no I/O, no pipeline imports.

This module is deliberately independently verifiable by hand: everything here is
arithmetic over two equal-length label sequences. The only import beyond the
stdlib is ``app.schemas`` (frozen pydantic response shapes), used solely by
:func:`to_contract` to project a report onto contract §5.

ZERO-DIVISION POLICY (the classic place eval code lies about itself)
-------------------------------------------------------------------
* ``precision`` for a class with NO predictions is **0.0** — not 1.0, not NaN.
  A class the model never predicts earns nothing.
* ``recall`` for a class with NO true instances is **0.0**, and that class is
  **excluded from the macro average** entirely. Averaging in a vacuous 1.0 (or a
  vacuous 0.0) for classes that are not in the ground truth silently moves
  macro-F1; excluding them is the only honest option.
* ``f1`` is 0.0 whenever ``precision + recall == 0``.
* A class with support 0 still appears in ``per_class`` (with ``support: 0``) so
  the frontend can render the full matrix axis — it is only the *macro average*
  that skips it.

Weighted averages weight by true support, so support-0 classes contribute
nothing there either (weight 0), without any special-casing.

Micro averaging pools TP/FP/FN across classes. When ``labels`` covers every
value present in ``y_true`` and ``y_pred`` — which this module enforces —
micro precision == micro recall == micro F1 == accuracy. That identity is a
useful self-check, not a bug.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from app.schemas import ConfusionMatrix, OverallMetrics, PerClassMetric

ROUNDING = 4


@dataclass(frozen=True)
class Averages:
    """One averaging strategy's precision/recall/F1 triple."""

    precision: float
    recall: float
    f1: float


@dataclass(frozen=True)
class ClassScore:
    """Per-class scores. ``support`` is the number of TRUE instances."""

    label: str
    precision: float
    recall: float
    f1: float
    support: int


@dataclass(frozen=True)
class MetricReport:
    """Everything computed for one classification target."""

    labels: list[str]
    per_class: list[ClassScore]
    macro: Averages
    weighted: Averages
    micro: Averages
    accuracy: float
    matrix: list[list[int]]
    total: int

    @property
    def macro_labels(self) -> list[str]:
        """The classes that actually took part in the macro average."""
        return [c.label for c in self.per_class if c.support > 0]


def _check_inputs(
    y_true: Sequence[str], y_pred: Sequence[str], labels: Sequence[str]
) -> None:
    """Reject anything that would force a silent drop from the denominator."""
    if len(y_true) != len(y_pred):
        raise ValueError(
            f"y_true and y_pred must be the same length ({len(y_true)} != {len(y_pred)})"
        )
    if len(set(labels)) != len(labels):
        raise ValueError(f"labels contains duplicates: {list(labels)}")

    known = set(labels)
    stray_true = sorted(set(y_true) - known)
    stray_pred = sorted(set(y_pred) - known)
    if stray_true or stray_pred:
        # Dropping these would shrink the denominator and inflate every score.
        raise ValueError(
            "values outside `labels` would be silently dropped — "
            f"unlisted in y_true: {stray_true}, in y_pred: {stray_pred}"
        )


def confusion_matrix(
    y_true: Sequence[str], y_pred: Sequence[str], labels: Sequence[str]
) -> list[list[int]]:
    """Counts of (true, predicted) pairs.

    ORIENTATION (load-bearing — the frontend heatmap reads it this way):
    ``matrix[i][j]`` is the number of samples whose TRUE label is ``labels[i]``
    and whose PREDICTED label is ``labels[j]``.

        * ROWS    = true / actual labels
        * COLUMNS = predicted labels

    So ``sum(matrix[i])`` is the support of ``labels[i]``, the column sum
    ``sum(row[j] for row in matrix)`` is how often ``labels[j]`` was predicted,
    and the diagonal is the correct predictions.

    Raises ValueError if any value is missing from ``labels`` — a value that is
    not counted anywhere is a lie by omission.
    """
    _check_inputs(y_true, y_pred, labels)
    index = {label: i for i, label in enumerate(labels)}
    matrix = [[0] * len(labels) for _ in labels]
    for actual, predicted in zip(y_true, y_pred, strict=True):
        matrix[index[actual]][index[predicted]] += 1
    return matrix


def accuracy(y_true: Sequence[str], y_pred: Sequence[str]) -> float:
    """Fraction of exactly-correct predictions. Empty input scores 0.0."""
    if len(y_true) != len(y_pred):
        raise ValueError(
            f"y_true and y_pred must be the same length ({len(y_true)} != {len(y_pred)})"
        )
    if not y_true:
        return 0.0
    hits = sum(1 for a, p in zip(y_true, y_pred, strict=True) if a == p)
    return hits / len(y_true)


def _ratio(numerator: int, denominator: int) -> float:
    """0/0 is 0.0 here, by policy. Never 1.0, never NaN."""
    return numerator / denominator if denominator else 0.0


def _f1(precision: float, recall: float) -> float:
    total = precision + recall
    return 2 * precision * recall / total if total else 0.0


def _mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def precision_recall_f1(
    y_true: Sequence[str], y_pred: Sequence[str], labels: Sequence[str]
) -> MetricReport:
    """Per-class scores plus macro, weighted and micro averages.

    See the module docstring for the zero-division policy — in short: no
    predictions => precision 0.0; no true instances => recall 0.0 AND excluded
    from the macro average.
    """
    matrix = confusion_matrix(y_true, y_pred, labels)
    size = len(labels)

    tp = [matrix[i][i] for i in range(size)]
    support = [sum(matrix[i]) for i in range(size)]  # rows = true
    predicted = [sum(matrix[r][i] for r in range(size)) for i in range(size)]  # cols = pred

    per_class: list[ClassScore] = []
    for i, label in enumerate(labels):
        precision = _ratio(tp[i], predicted[i])
        recall = _ratio(tp[i], support[i])
        per_class.append(
            ClassScore(
                label=label,
                precision=precision,
                recall=recall,
                f1=_f1(precision, recall),
                support=support[i],
            )
        )

    # Macro: unweighted mean over classes that HAVE true instances.
    present = [c for c in per_class if c.support > 0]
    macro = Averages(
        precision=_mean([c.precision for c in present]),
        recall=_mean([c.recall for c in present]),
        f1=_mean([c.f1 for c in present]),
    )

    # Weighted: by true support. Support-0 classes carry weight 0.
    total_support = sum(support)
    weighted = Averages(
        precision=_ratio_weighted(per_class, "precision", total_support),
        recall=_ratio_weighted(per_class, "recall", total_support),
        f1=_ratio_weighted(per_class, "f1", total_support),
    )

    # Micro: pool the counts, then divide once.
    micro_precision = _ratio(sum(tp), sum(predicted))
    micro_recall = _ratio(sum(tp), total_support)
    micro = Averages(
        precision=micro_precision,
        recall=micro_recall,
        f1=_f1(micro_precision, micro_recall),
    )

    return MetricReport(
        labels=list(labels),
        per_class=per_class,
        macro=macro,
        weighted=weighted,
        micro=micro,
        accuracy=accuracy(y_true, y_pred),
        matrix=matrix,
        total=len(y_true),
    )


def _ratio_weighted(per_class: list[ClassScore], field: str, total_support: int) -> float:
    if not total_support:
        return 0.0
    return sum(getattr(c, field) * c.support for c in per_class) / total_support


def observed_labels(
    y_true: Sequence[str], y_pred: Sequence[str], canonical: Sequence[str]
) -> list[str]:
    """``canonical`` filtered to the values that actually occur, order preserved.

    Keeps a confusion matrix from being mostly-empty padding while guaranteeing
    every observed value is counted. Raises if a value occurs that ``canonical``
    does not know about — that would otherwise vanish from the denominator.
    """
    seen = set(y_true) | set(y_pred)
    unknown = sorted(seen - set(canonical))
    if unknown:
        raise ValueError(f"values not present in the canonical label order: {unknown}")
    return [label for label in canonical if label in seen]


def _round(value: float) -> float:
    return round(value, ROUNDING)


def to_contract(
    report: MetricReport,
) -> tuple[OverallMetrics, list[PerClassMetric], ConfusionMatrix]:
    """Project a report onto the frozen contract §5 shapes.

    ``overall`` uses **macro** averaging. On a class-imbalanced set (CICIDS2017 is
    ~80% BENIGN) the weighted average is dominated by the majority class and
    flatters the system; macro gives every class an equal vote and is the number
    that actually says whether rare attack classes are detected. The weighted and
    micro figures are still on :class:`MetricReport` for anyone who wants them.
    """
    overall = OverallMetrics(
        precision=_round(report.macro.precision),
        recall=_round(report.macro.recall),
        f1=_round(report.macro.f1),
        accuracy=_round(report.accuracy),
    )
    per_class = [
        PerClassMetric(
            label=c.label,
            precision=_round(c.precision),
            recall=_round(c.recall),
            f1=_round(c.f1),
            support=c.support,
        )
        for c in report.per_class
    ]
    matrix = ConfusionMatrix(labels=list(report.labels), matrix=report.matrix)
    return overall, per_class, matrix


__all__ = [
    "Averages",
    "ClassScore",
    "MetricReport",
    "accuracy",
    "confusion_matrix",
    "observed_labels",
    "precision_recall_f1",
    "to_contract",
]
