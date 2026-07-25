"""Metrics tests — every expected value below is computed BY HAND in a comment.

If this file passes, the eval numbers are arithmetic. If it does not, nothing
downstream can be believed, so the fixtures here are deliberately small enough to
verify with a pen.
"""

from __future__ import annotations

import pytest

from app.evaluation.metrics import (
    accuracy,
    confusion_matrix,
    observed_labels,
    precision_recall_f1,
    to_contract,
)

# --------------------------------------------------------------------------- fixture
# A known 3x3 case. rows = TRUE, columns = PREDICTED:
#
#            pred a  pred b  pred c   | support
#   true a      3       1       0     |    4
#   true b      1       2       1     |    4
#   true c      0       1       1     |    2
#   ------------------------------------------
#   predicted   4       4       2     |   10 total, 6 correct
#
# precision = tp / column-sum : a 3/4=0.75   b 2/4=0.50   c 1/2=0.50
# recall    = tp / row-sum    : a 3/4=0.75   b 2/4=0.50   c 1/2=0.50
# f1                          : a 0.75       b 0.50       c 0.50
# accuracy  = 6/10 = 0.60
# macro P/R/F1    = (0.75+0.50+0.50)/3 = 0.5833...
# weighted P      = (4*0.75 + 4*0.50 + 2*0.50)/10 = 6/10 = 0.60
# micro P = micro R = 6/10 = 0.60 (= accuracy)

LABELS_3 = ["a", "b", "c"]
Y_TRUE_3 = ["a", "a", "a", "a", "b", "b", "b", "b", "c", "c"]
Y_PRED_3 = ["a", "a", "a", "b", "a", "b", "b", "c", "b", "c"]


def test_confusion_matrix_matches_hand_computed_counts() -> None:
    assert confusion_matrix(Y_TRUE_3, Y_PRED_3, LABELS_3) == [
        [3, 1, 0],
        [1, 2, 1],
        [0, 1, 1],
    ]


def test_matrix_orientation_is_rows_true_columns_predicted() -> None:
    """The docstring promises matrix[true][pred]; the heatmap depends on it."""
    matrix = confusion_matrix(["a"], ["b"], ["a", "b"])
    # one sample whose TRUE label is 'a' and PREDICTED label is 'b'
    assert matrix == [[0, 1], [0, 0]]
    assert matrix[0][1] == 1  # row a (true), column b (predicted)
    assert matrix[1][0] == 0  # NOT the transpose

    # asymmetric multi-count case: transposing would change the answer
    matrix = confusion_matrix(["a", "a", "b"], ["b", "b", "a"], ["a", "b"])
    assert matrix == [[0, 2], [1, 0]]


def test_per_class_precision_recall_f1_and_accuracy() -> None:
    report = precision_recall_f1(Y_TRUE_3, Y_PRED_3, LABELS_3)
    scores = {c.label: c for c in report.per_class}

    assert scores["a"].precision == pytest.approx(0.75)
    assert scores["a"].recall == pytest.approx(0.75)
    assert scores["a"].f1 == pytest.approx(0.75)
    assert scores["a"].support == 4

    assert scores["b"].precision == pytest.approx(0.5)
    assert scores["b"].recall == pytest.approx(0.5)
    assert scores["b"].f1 == pytest.approx(0.5)
    assert scores["b"].support == 4

    assert scores["c"].precision == pytest.approx(0.5)
    assert scores["c"].recall == pytest.approx(0.5)
    assert scores["c"].f1 == pytest.approx(0.5)
    assert scores["c"].support == 2

    assert report.accuracy == pytest.approx(0.6)
    assert accuracy(Y_TRUE_3, Y_PRED_3) == pytest.approx(0.6)


def test_macro_weighted_and_micro_averages() -> None:
    report = precision_recall_f1(Y_TRUE_3, Y_PRED_3, LABELS_3)

    assert report.macro.precision == pytest.approx(1.75 / 3)
    assert report.macro.recall == pytest.approx(1.75 / 3)
    assert report.macro.f1 == pytest.approx(1.75 / 3)

    assert report.weighted.precision == pytest.approx(0.6)
    assert report.weighted.recall == pytest.approx(0.6)

    # micro == accuracy in single-label multiclass when labels cover everything
    assert report.micro.precision == pytest.approx(0.6)
    assert report.micro.recall == pytest.approx(0.6)
    assert report.micro.f1 == pytest.approx(0.6)
    assert report.micro.f1 == pytest.approx(report.accuracy)


# --------------------------------------------------------------------------- extremes


def test_perfect_predictions_score_one() -> None:
    y = ["a", "b", "c", "a", "b", "c"]
    report = precision_recall_f1(y, list(y), ["a", "b", "c"])

    assert all(c.precision == 1.0 and c.recall == 1.0 and c.f1 == 1.0 for c in report.per_class)
    assert report.macro.f1 == 1.0
    assert report.weighted.f1 == 1.0
    assert report.micro.f1 == 1.0
    assert report.accuracy == 1.0
    assert report.matrix == [[2, 0, 0], [0, 2, 0], [0, 0, 2]]


def test_all_wrong_predictions_score_zero() -> None:
    y_true = ["a", "a", "b", "b"]
    y_pred = ["b", "b", "a", "a"]
    report = precision_recall_f1(y_true, y_pred, ["a", "b"])

    assert all(c.precision == 0.0 and c.recall == 0.0 and c.f1 == 0.0 for c in report.per_class)
    assert report.macro.f1 == 0.0
    assert report.weighted.f1 == 0.0
    assert report.accuracy == 0.0


# --------------------------------------------------------------------- zero-division


def test_class_with_no_predictions_gets_precision_zero_not_one() -> None:
    """The classic inflation bug: 0/0 treated as 1.0 for an unpredicted class.

    8 benign (all correct) + 2 ddos (both predicted benign):
        rows=true:  benign [8, 0]   ddos [2, 0]
        precision:  benign 8/10=0.80   ddos 0/0 -> 0.0 BY POLICY
        recall   :  benign 8/8 =1.00   ddos 0/2 = 0.0
        f1       :  benign 2*.8*1/1.8 = 0.888...   ddos 0.0
    """
    y_true = ["benign"] * 8 + ["ddos"] * 2
    y_pred = ["benign"] * 10
    report = precision_recall_f1(y_true, y_pred, ["benign", "ddos"])
    scores = {c.label: c for c in report.per_class}

    assert scores["ddos"].precision == 0.0  # NOT 1.0, NOT NaN
    assert scores["ddos"].recall == 0.0
    assert scores["ddos"].f1 == 0.0
    assert scores["ddos"].support == 2

    assert scores["benign"].precision == pytest.approx(0.8)
    assert scores["benign"].recall == pytest.approx(1.0)
    assert scores["benign"].f1 == pytest.approx(1.6 / 1.8)

    # ddos HAS true instances, so it stays in the macro average and drags it down
    assert report.macro_labels == ["benign", "ddos"]
    assert report.macro.precision == pytest.approx(0.4)
    assert report.macro.recall == pytest.approx(0.5)


def test_macro_and_weighted_diverge_on_an_imbalanced_set() -> None:
    """Weighted flatters the majority class; macro exposes the missed one."""
    y_true = ["benign"] * 8 + ["ddos"] * 2
    y_pred = ["benign"] * 10
    report = precision_recall_f1(y_true, y_pred, ["benign", "ddos"])

    # macro P 0.4 vs weighted P (8*0.8 + 2*0)/10 = 0.64
    assert report.macro.precision == pytest.approx(0.4)
    assert report.weighted.precision == pytest.approx(0.64)
    # macro R 0.5 vs weighted R (8*1.0 + 2*0)/10 = 0.8
    assert report.macro.recall == pytest.approx(0.5)
    assert report.weighted.recall == pytest.approx(0.8)
    assert report.weighted.recall > report.macro.recall
    assert report.accuracy == pytest.approx(0.8)


def test_class_with_no_true_instances_is_excluded_from_macro() -> None:
    """Support 0 => recall 0.0, still listed, but it must NOT enter the macro.

        labels a, b, z ; y_true = a a b b ; y_pred = a a b z
        rows=true: a [2,0,0]  b [0,1,1]  z [0,0,0]
        precision: a 2/2=1.0  b 1/1=1.0  z 0/1=0.0
        recall   : a 2/2=1.0  b 1/2=0.5  z 0/0 -> 0.0 (support 0)
        macro over {a, b} only: P = 1.0, R = 0.75
    """
    y_true = ["a", "a", "b", "b"]
    y_pred = ["a", "a", "b", "z"]
    report = precision_recall_f1(y_true, y_pred, ["a", "b", "z"])
    scores = {c.label: c for c in report.per_class}

    assert scores["z"].support == 0
    assert scores["z"].precision == 0.0
    assert scores["z"].recall == 0.0

    assert report.macro_labels == ["a", "b"]  # z excluded
    assert report.macro.precision == pytest.approx(1.0)
    assert report.macro.recall == pytest.approx(0.75)

    # including z would have given (1.0+1.0+0.0)/3 = 0.667 precision
    assert report.macro.precision != pytest.approx(2 / 3)


def test_empty_input_is_all_zero_not_a_crash() -> None:
    report = precision_recall_f1([], [], ["a", "b"])
    assert report.accuracy == 0.0
    assert report.macro.f1 == 0.0
    assert report.weighted.f1 == 0.0
    assert report.micro.f1 == 0.0
    assert [c.support for c in report.per_class] == [0, 0]


# ------------------------------------------------------------------------ guardrails


def test_values_outside_labels_are_rejected_not_dropped() -> None:
    with pytest.raises(ValueError, match="silently dropped"):
        confusion_matrix(["a", "zzz"], ["a", "a"], ["a"])
    with pytest.raises(ValueError, match="silently dropped"):
        confusion_matrix(["a", "a"], ["a", "zzz"], ["a"])


def test_mismatched_lengths_are_rejected() -> None:
    with pytest.raises(ValueError, match="same length"):
        confusion_matrix(["a"], ["a", "a"], ["a"])
    with pytest.raises(ValueError, match="same length"):
        accuracy(["a"], ["a", "a"])


def test_duplicate_labels_are_rejected() -> None:
    with pytest.raises(ValueError, match="duplicates"):
        confusion_matrix(["a"], ["a"], ["a", "a"])


def test_observed_labels_keeps_canonical_order_and_drops_unseen() -> None:
    canonical = ["critical", "high", "medium", "low", "info"]
    assert observed_labels(["low", "critical"], ["info"], canonical) == [
        "critical",
        "low",
        "info",
    ]
    with pytest.raises(ValueError, match="canonical"):
        observed_labels(["nope"], ["nope"], canonical)


# ------------------------------------------------------------------------- contract


def test_to_contract_emits_exact_section_5_shapes() -> None:
    report = precision_recall_f1(Y_TRUE_3, Y_PRED_3, LABELS_3)
    overall, per_class, matrix = to_contract(report)

    assert set(overall.model_dump()) == {"precision", "recall", "f1", "accuracy"}
    assert overall.accuracy == 0.6
    assert overall.f1 == round(1.75 / 3, 4)  # macro, not weighted

    assert set(per_class[0].model_dump()) == {
        "label",
        "precision",
        "recall",
        "f1",
        "support",
    }
    assert [c.support for c in per_class] == [4, 4, 2]

    assert set(matrix.model_dump()) == {"labels", "matrix"}
    assert matrix.labels == LABELS_3
    assert matrix.matrix == [[3, 1, 0], [1, 2, 1], [0, 1, 1]]
    # row sums are the supports — the orientation the frontend renders
    assert [sum(row) for row in matrix.matrix] == [c.support for c in per_class]


def test_contract_overall_uses_macro_so_imbalance_cannot_hide() -> None:
    y_true = ["benign"] * 8 + ["ddos"] * 2
    y_pred = ["benign"] * 10
    overall, _, _ = to_contract(precision_recall_f1(y_true, y_pred, ["benign", "ddos"]))

    assert overall.precision == 0.4  # macro; the weighted figure would be 0.64
    assert overall.recall == 0.5
    assert overall.accuracy == 0.8  # accuracy alone would look respectable
