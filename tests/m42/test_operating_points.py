"""Operating-point selectors: target achievement and O(N log N) correctness."""

from __future__ import annotations

import pytest

import m42_stats as st
from conftest import SEEDS_MED, make_binary_dataset


def _brute_youden(scores, labels):
    best_t, best_j = 0.5, -2.0
    for t in sorted(set(scores)):
        r = st.binary_rates(scores, labels, t)
        j = r["sensitivity"] + r["specificity"] - 1.0
        if j > best_j:
            best_j, best_t = j, t
    return best_j


@pytest.mark.parametrize("seed", SEEDS_MED)
def test_youden_matches_brute_force_objective(seed):
    scores, labels = make_binary_dataset(seed, n=150)
    t = st.youden_threshold(scores, labels)
    r = st.binary_rates(scores, labels, t)
    fast_j = r["sensitivity"] + r["specificity"] - 1.0
    assert fast_j == pytest.approx(_brute_youden(scores, labels), abs=1e-9)


@pytest.mark.parametrize("seed", SEEDS_MED)
@pytest.mark.parametrize("target", [0.80, 0.90, 0.95])
def test_threshold_for_sensitivity_meets_target(seed, target):
    scores, labels = make_binary_dataset(seed, separation=0.8)
    t = st.threshold_for_sensitivity(scores, labels, target)
    assert st.binary_rates(scores, labels, t)["sensitivity"] >= target - 1e-9


@pytest.mark.parametrize("seed", SEEDS_MED)
@pytest.mark.parametrize("target", [0.80, 0.90])
def test_threshold_for_precision_meets_target(seed, target):
    scores, labels = make_binary_dataset(seed, separation=0.8)
    t = st.threshold_for_precision(scores, labels, target)
    rates = st.binary_rates(scores, labels, t)
    if rates["tp"] + rates["fp"] > 0:
        assert rates["ppv"] >= target - 1e-9


@pytest.mark.parametrize("seed", range(20))
def test_higher_sensitivity_target_lowers_threshold(seed):
    scores, labels = make_binary_dataset(seed, separation=0.8)
    t90 = st.threshold_for_sensitivity(scores, labels, 0.90)
    t95 = st.threshold_for_sensitivity(scores, labels, 0.95)
    assert t95 <= t90 + 1e-9


@pytest.mark.parametrize("seed", range(20))
def test_youden_threshold_within_score_range(seed):
    scores, labels = make_binary_dataset(seed)
    t = st.youden_threshold(scores, labels)
    assert min(scores) <= t <= max(scores)
