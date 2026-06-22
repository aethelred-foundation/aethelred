"""Tests for the statistical-inference layer: CIs, calibration, FDR, fairness."""

from __future__ import annotations

import math

import pytest
from scipy import stats

import m42_stats as st


# ---------------------------------------------------------------------------
# Wilson confidence interval
# ---------------------------------------------------------------------------


def test_wilson_ci_contains_point_estimate():
    lo, hi = st.wilson_ci(50, 100)
    assert lo < 0.5 < hi


def test_wilson_ci_known_value():
    # 50/100 at 95%: Wilson interval ~ (0.404, 0.596).
    lo, hi = st.wilson_ci(50, 100)
    assert lo == pytest.approx(0.4038, abs=1e-3)
    assert hi == pytest.approx(0.5962, abs=1e-3)


def test_wilson_ci_full_success_upper_is_one_ish():
    lo, hi = st.wilson_ci(20, 20)
    assert hi == pytest.approx(1.0, abs=1e-9)
    assert lo < 1.0


def test_wilson_ci_zero_success_lower_is_zero_ish():
    lo, hi = st.wilson_ci(0, 20)
    assert lo == pytest.approx(0.0, abs=1e-9)
    assert hi > 0.0


def test_wilson_ci_empty_is_zero():
    assert st.wilson_ci(0, 0) == (0.0, 0.0)


def test_wilson_ci_narrows_with_n():
    _, hi_small = st.wilson_ci(5, 10)
    lo_small, _ = st.wilson_ci(5, 10)
    lo_big, hi_big = st.wilson_ci(500, 1000)
    assert (hi_big - lo_big) < (hi_small - lo_small)


# ---------------------------------------------------------------------------
# Bootstrap CIs
# ---------------------------------------------------------------------------


def test_bootstrap_ci_brackets_mean():
    rng = st.DetRandom("boot-mean")
    values = [rng.gauss(10.0, 2.0) for _ in range(300)]
    mean = sum(values) / len(values)
    lo, hi = st.bootstrap_ci(values, lambda v: sum(v) / len(v), n_boot=500, seed="t")
    assert lo <= mean <= hi


def test_bootstrap_ci_deterministic():
    values = [float(i) for i in range(100)]
    a = st.bootstrap_ci(values, lambda v: sum(v) / len(v), n_boot=300, seed="same")
    b = st.bootstrap_ci(values, lambda v: sum(v) / len(v), n_boot=300, seed="same")
    assert a == b


def test_bootstrap_ci_empty():
    assert st.bootstrap_ci([], lambda v: 0.0) == (0.0, 0.0)


def test_paired_bootstrap_ci_brackets_auroc():
    rng = st.DetRandom("boot-auroc")
    scores = [rng.gauss(0.5 + 0.3 * (i % 2), 0.2) for i in range(200)]
    labels = [i % 2 for i in range(200)]
    point = st.roc_auc(scores, labels)
    lo, hi = st.paired_bootstrap_ci(scores, labels, st.roc_auc, n_boot=400, seed="t")
    assert lo <= point <= hi
    assert 0.0 <= lo <= hi <= 1.0


# ---------------------------------------------------------------------------
# Calibration
# ---------------------------------------------------------------------------


def test_brier_score_perfect_is_zero():
    assert st.brier_score([1.0, 0.0, 1.0, 0.0], [1, 0, 1, 0]) == 0.0


def test_brier_score_worst_is_one():
    assert st.brier_score([0.0, 1.0], [1, 0]) == pytest.approx(1.0)


def test_brier_matches_manual():
    probs = [0.8, 0.3, 0.6]
    labels = [1, 0, 1]
    manual = ((0.8 - 1) ** 2 + (0.3 - 0) ** 2 + (0.6 - 1) ** 2) / 3
    assert st.brier_score(probs, labels) == pytest.approx(manual)


def test_ece_perfectly_calibrated_low():
    # Construct bins where confidence == accuracy.
    probs = [0.05] * 20 + [0.95] * 20
    labels = [0] * 19 + [1] + [1] * 19 + [0]  # ~5% and ~95% accuracy
    ece = st.expected_calibration_error(probs, labels, n_bins=10)
    assert ece < 0.1


def test_ece_miscalibrated_high():
    probs = [0.99] * 50
    labels = [0] * 50  # confident but always wrong
    assert st.expected_calibration_error(probs, labels, n_bins=10) > 0.9


def test_calibration_report_has_keys():
    rep = st.calibration_report([0.2, 0.8, 0.6], [0, 1, 1])
    assert set(rep) == {"brier_score", "expected_calibration_error", "reliability_bins"}
    assert len(rep["reliability_bins"]) == 10


# ---------------------------------------------------------------------------
# Benjamini-Hochberg FDR
# ---------------------------------------------------------------------------


def test_bh_matches_scipy_rejections():
    pvalues = [0.001, 0.008, 0.02, 0.2, 0.5, 0.9, 0.04, 0.0001]
    mine = st.benjamini_hochberg(pvalues, alpha=0.05)
    adjusted = stats.false_discovery_control(pvalues, method="bh")
    scipy_rejected = [bool(p <= 0.05) for p in adjusted]
    assert mine["rejected"] == scipy_rejected


def test_bh_no_rejections_when_all_high():
    res = st.benjamini_hochberg([0.6, 0.7, 0.8, 0.9], alpha=0.05)
    assert res["n_rejected"] == 0
    assert not any(res["rejected"])


def test_bh_all_rejected_when_all_tiny():
    res = st.benjamini_hochberg([1e-9, 1e-9, 1e-9], alpha=0.05)
    assert res["n_rejected"] == 3


def test_bh_empty():
    res = st.benjamini_hochberg([], alpha=0.05)
    assert res["n_rejected"] == 0


# ---------------------------------------------------------------------------
# Subgroup / fairness analysis
# ---------------------------------------------------------------------------


def test_subgroup_disparity_detects_gap():
    items = (
        [{"g": "a", "v": 1.0} for _ in range(10)]
        + [{"g": "b", "v": 0.0} for _ in range(10)]
    )
    res = st.subgroup_analysis(items, lambda x: x["g"], lambda ms: sum(m["v"] for m in ms) / len(ms))
    assert res["disparity_gap"] == pytest.approx(1.0)
    assert res["groups"]["a"]["n"] == 10


def test_subgroup_ignores_tiny_groups_in_gap():
    items = (
        [{"g": "big", "v": 0.9} for _ in range(20)]
        + [{"g": "tiny", "v": 0.0} for _ in range(3)]
    )
    res = st.subgroup_analysis(items, lambda x: x["g"], lambda ms: sum(m["v"] for m in ms) / len(ms), min_group=8)
    # tiny group excluded from the gap (only one eligible group -> gap 0).
    assert res["disparity_gap"] == 0.0
    assert "tiny" in res["groups"]
