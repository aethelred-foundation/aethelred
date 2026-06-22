"""Fast DeLong AUROC confidence interval: correctness, bounds, and agreement."""

from __future__ import annotations

import math

import pytest
from scipy import stats

import m42_stats as st
from conftest import SEEDS_MED, make_binary_dataset


@pytest.mark.parametrize("seed", SEEDS_MED)
def test_delong_auc_matches_roc_auc(seed):
    scores, labels = make_binary_dataset(seed)
    auc, _, _ = st.delong_auroc_ci(scores, labels)
    assert auc == pytest.approx(st.roc_auc(scores, labels), abs=1e-9)


@pytest.mark.parametrize("seed", SEEDS_MED)
def test_delong_ci_bounds_in_unit_interval(seed):
    _, lo, hi = st.delong_auroc_ci(scores := make_binary_dataset(seed)[0], make_binary_dataset(seed)[1])
    assert 0.0 <= lo <= hi <= 1.0


@pytest.mark.parametrize("seed", SEEDS_MED)
def test_delong_ci_contains_point(seed):
    scores, labels = make_binary_dataset(seed)
    auc, lo, hi = st.delong_auroc_ci(scores, labels)
    assert lo <= auc <= hi


@pytest.mark.parametrize("seed", SEEDS_MED)
def test_delong_agrees_with_scipy_auc(seed):
    scores, labels = make_binary_dataset(seed)
    pos = [s for s, y in zip(scores, labels) if y == 1]
    neg = [s for s, y in zip(scores, labels) if y == 0]
    u, _ = stats.mannwhitneyu(pos, neg, alternative="greater")
    expected = u / (len(pos) * len(neg))
    auc, _, _ = st.delong_auroc_ci(scores, labels)
    assert auc == pytest.approx(expected, abs=1e-9)


@pytest.mark.parametrize("seed", range(20))
def test_delong_ci_narrows_with_n(seed):
    # Nested samples from the same distribution: more data must not widen the CI.
    big_s, big_l = make_binary_dataset(seed, n=4000)
    k = 150
    small_s, small_l = big_s[:k], list(big_l[:k])
    if not (0 < sum(small_l) < k):
        small_l[0], small_l[1] = 0, 1
    _, slo, shi = st.delong_auroc_ci(small_s, small_l)
    _, blo, bhi = st.delong_auroc_ci(big_s, big_l)
    assert (bhi - blo) <= (shi - slo)


def test_delong_single_class_returns_zeros():
    assert st.delong_auroc_ci([0.1, 0.2, 0.3], [1, 1, 1]) == (0.0, 0.0, 0.0)


def test_delong_perfect_separation():
    auc, lo, hi = st.delong_auroc_ci([0.1, 0.2, 0.8, 0.9], [0, 0, 1, 1])
    assert auc == 1.0
    assert hi == pytest.approx(1.0)


@pytest.mark.parametrize("seed", range(20))
def test_delong_roughly_agrees_with_bootstrap(seed):
    scores, labels = make_binary_dataset(seed, n=400)
    _, dlo, dhi = st.delong_auroc_ci(scores, labels)
    blo, bhi = st.paired_bootstrap_ci(scores, labels, st.roc_auc, n_boot=400, seed=f"b{seed}")
    # Centers and widths should be in the same ballpark (within 0.08).
    assert abs((dlo + dhi) / 2 - (blo + bhi) / 2) < 0.08
