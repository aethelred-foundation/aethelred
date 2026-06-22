"""Known-answer and scipy cross-validation tests for the metric primitives."""

from __future__ import annotations

import math

import pytest
from scipy import stats

import m42_stats as st


# ---------------------------------------------------------------------------
# AUROC
# ---------------------------------------------------------------------------


def test_roc_auc_perfect_separation():
    scores = [0.1, 0.2, 0.8, 0.9]
    labels = [0, 0, 1, 1]
    assert st.roc_auc(scores, labels) == 1.0


def test_roc_auc_reversed_is_zero():
    scores = [0.9, 0.8, 0.2, 0.1]
    labels = [0, 0, 1, 1]
    assert st.roc_auc(scores, labels) == 0.0


def test_roc_auc_all_ties_is_half():
    scores = [0.5, 0.5, 0.5, 0.5]
    labels = [0, 1, 0, 1]
    assert st.roc_auc(scores, labels) == 0.5


def test_roc_auc_single_class_returns_zero():
    assert st.roc_auc([0.1, 0.2, 0.3], [1, 1, 1]) == 0.0
    assert st.roc_auc([0.1, 0.2, 0.3], [0, 0, 0]) == 0.0


def test_roc_auc_matches_scipy_mannwhitney():
    rng = st.DetRandom("auroc-xval")
    scores = [rng.gauss(0.5 + 0.3 * (i % 2), 0.2) for i in range(200)]
    labels = [i % 2 for i in range(200)]
    pos = [s for s, y in zip(scores, labels) if y == 1]
    neg = [s for s, y in zip(scores, labels) if y == 0]
    u, _ = stats.mannwhitneyu(pos, neg, alternative="greater")
    expected = u / (len(pos) * len(neg))
    assert st.roc_auc(scores, labels) == pytest.approx(expected, abs=1e-9)


def test_roc_auc_handles_ties_with_average_ranks():
    # Two tied scores straddling the class boundary -> 0.5 contribution.
    scores = [0.2, 0.5, 0.5, 0.9]
    labels = [0, 0, 1, 1]
    # Hand value: pairs (neg,pos): (0.2,0.5)=1,(0.2,0.9)=1,(0.5,0.5)=0.5,(0.5,0.9)=1 -> 3.5/4
    assert st.roc_auc(scores, labels) == pytest.approx(3.5 / 4)


# ---------------------------------------------------------------------------
# PR-AUC / enrichment / BEDROC
# ---------------------------------------------------------------------------


def test_pr_auc_perfect():
    assert st.pr_auc([0.9, 0.8, 0.2, 0.1], [1, 1, 0, 0]) == pytest.approx(1.0)


def test_pr_auc_all_negative_zero():
    assert st.pr_auc([0.5, 0.4], [0, 0]) == 0.0


def test_enrichment_factor_actives_at_top():
    # 10 items, 2 actives both in top 10% (top 1) impossible; use top 20%.
    scores = list(range(20, 0, -1))
    labels = [1, 1] + [0] * 18
    ef = st.enrichment_factor(scores, labels, 0.10)  # top 2
    # top 2 are both active -> hit rate 1.0; overall 2/20=0.1 -> EF=10
    assert ef == pytest.approx(10.0)


def test_enrichment_factor_no_actives_zero():
    assert st.enrichment_factor([1, 2, 3], [0, 0, 0], 0.5) == 0.0


def test_bedroc_in_unit_interval():
    rng = st.DetRandom("bedroc")
    scores = [rng.random() for _ in range(200)]
    labels = [1 if s > 0.7 else 0 for s in scores]
    val = st.bedroc(scores, labels, alpha=20.0)
    assert 0.0 <= val <= 1.0


def test_bedroc_early_recognition_high():
    # Actives ranked first -> BEDROC near 1.
    scores = list(range(100, 0, -1))
    labels = [1] * 5 + [0] * 95
    assert st.bedroc(scores, labels, alpha=20.0) > 0.9


# ---------------------------------------------------------------------------
# Binary rates
# ---------------------------------------------------------------------------


def test_binary_rates_known_confusion():
    scores = [0.9, 0.8, 0.4, 0.1]
    labels = [1, 0, 1, 0]
    r = st.binary_rates(scores, labels, 0.5)
    assert (r["tp"], r["fp"], r["tn"], r["fn"]) == (1, 1, 1, 1)
    assert r["sensitivity"] == 0.5
    assert r["specificity"] == 0.5
    assert r["accuracy"] == 0.5


def test_mcc_perfect_is_one():
    scores = [0.9, 0.8, 0.2, 0.1]
    labels = [1, 1, 0, 0]
    assert st.binary_rates(scores, labels, 0.5)["mcc"] == pytest.approx(1.0)


def test_f1_perfect_is_one():
    scores = [0.9, 0.8, 0.2, 0.1]
    labels = [1, 1, 0, 0]
    assert st.binary_rates(scores, labels, 0.5)["f1"] == pytest.approx(1.0)


# ---------------------------------------------------------------------------
# SMD and operating-point selectors
# ---------------------------------------------------------------------------


def test_smd_identical_is_zero():
    assert st.standardized_mean_difference([1, 2, 3, 4], [1, 2, 3, 4]) == 0.0


def test_smd_known_shift():
    a = [0.0, 0.0, 0.0, 0.0]
    b = [1.0, 1.0, 1.0, 1.0]
    # pooled sd = 0 -> returns 0 (degenerate); add spread.
    a = [0.0, 1.0, 0.0, 1.0]  # mean 0.5, var 0.25
    b = [1.0, 2.0, 1.0, 2.0]  # mean 1.5, var 0.25
    # SMD = |0.5-1.5| / sqrt((0.25+0.25)/2) = 1/0.5 = 2.0
    assert st.standardized_mean_difference(a, b) == pytest.approx(2.0)


def test_youden_threshold_separates():
    scores = [0.1, 0.2, 0.8, 0.9]
    labels = [0, 0, 1, 1]
    t = st.youden_threshold(scores, labels)
    assert 0.2 <= t <= 0.8


def test_threshold_for_sensitivity_meets_target():
    rng = st.DetRandom("sens-target")
    scores = [rng.random() for _ in range(300)]
    labels = [1 if s > 0.45 else 0 for s in scores]
    t = st.threshold_for_sensitivity(scores, labels, 0.90)
    assert st.binary_rates(scores, labels, t)["sensitivity"] >= 0.90


def test_threshold_for_precision_meets_target():
    rng = st.DetRandom("prec-target")
    scores = [rng.random() for _ in range(300)]
    labels = [1 if s > 0.55 else 0 for s in scores]
    t = st.threshold_for_precision(scores, labels, 0.90)
    assert st.binary_rates(scores, labels, t)["ppv"] >= 0.90
