"""Property-based tests for calibration (Brier, ECE, reliability)."""

from __future__ import annotations

import pytest

import m42_stats as st
from conftest import SEEDS_MED, make_binary_dataset


def _calibrated_dataset(seed, n=400):
    """Draw a calibrated (probs, labels): label sampled from its own probability."""
    rng = st.DetRandom("calib", seed, n)
    probs, labels = [], []
    for _ in range(n):
        p = rng.random()
        probs.append(p)
        labels.append(1 if rng.random() < p else 0)
    return probs, labels


@pytest.mark.parametrize("seed", SEEDS_MED)
def test_brier_in_unit_interval(seed):
    scores, labels = make_binary_dataset(seed)
    assert 0.0 <= st.brier_score(scores, labels) <= 1.0


@pytest.mark.parametrize("seed", SEEDS_MED)
def test_ece_in_unit_interval(seed):
    scores, labels = make_binary_dataset(seed)
    assert 0.0 <= st.expected_calibration_error(scores, labels) <= 1.0


@pytest.mark.parametrize("seed", SEEDS_MED)
def test_calibrated_data_has_low_ece(seed):
    probs, labels = _calibrated_dataset(seed)
    # Data generated to be calibrated should have small ECE.
    assert st.expected_calibration_error(probs, labels, n_bins=10) < 0.12


@pytest.mark.parametrize("seed", SEEDS_MED)
def test_calibrated_data_has_low_brier(seed):
    probs, labels = _calibrated_dataset(seed)
    # Brier for perfectly calibrated random predictions tends toward ~p(1-p) mean.
    assert st.brier_score(probs, labels) < 0.34


@pytest.mark.parametrize("seed", SEEDS_MED)
def test_reliability_bins_cover_all_points(seed):
    scores, labels = make_binary_dataset(seed)
    bins = st.reliability_bins(scores, labels, n_bins=10)
    assert sum(b["count"] for b in bins) == len(scores)
    assert len(bins) == 10


@pytest.mark.parametrize("seed", SEEDS_MED)
def test_reliability_bin_accuracy_in_unit_interval(seed):
    scores, labels = make_binary_dataset(seed)
    for b in st.reliability_bins(scores, labels, n_bins=10):
        assert 0.0 <= b["accuracy"] <= 1.0
        assert 0.0 <= b["confidence"] <= 1.0


@pytest.mark.parametrize("seed", range(30))
def test_overconfident_wrong_predictions_high_ece(seed):
    rng = st.DetRandom("overconf", seed)
    probs = [min(0.999, max(0.6, rng.gauss(0.9, 0.05))) for _ in range(200)]
    labels = [0] * 200  # always wrong despite high confidence
    assert st.expected_calibration_error(probs, labels) > 0.5


@pytest.mark.parametrize("seed", range(30))
def test_calibration_report_structure(seed):
    scores, labels = make_binary_dataset(seed)
    rep = st.calibration_report(scores, labels)
    assert rep["brier_score"] >= 0.0
    assert 0.0 <= rep["expected_calibration_error"] <= 1.0
    assert len(rep["reliability_bins"]) == 10
