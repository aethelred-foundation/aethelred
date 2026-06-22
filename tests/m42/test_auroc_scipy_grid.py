"""AUROC cross-validated against scipy Mann-Whitney U over a wide grid."""

from __future__ import annotations

import pytest
from scipy import stats

import m42_stats as st
from conftest import SEEDS_LARGE, make_binary_dataset


@pytest.mark.parametrize("seed", SEEDS_LARGE)
def test_roc_auc_matches_scipy(seed):
    scores, labels = make_binary_dataset(seed)
    pos = [s for s, y in zip(scores, labels) if y == 1]
    neg = [s for s, y in zip(scores, labels) if y == 0]
    u, _ = stats.mannwhitneyu(pos, neg, alternative="greater")
    assert st.roc_auc(scores, labels) == pytest.approx(u / (len(pos) * len(neg)), abs=1e-9)


@pytest.mark.parametrize("seed", range(150))
@pytest.mark.parametrize("prevalence", [0.1, 0.3, 0.5])
def test_roc_auc_matches_scipy_across_prevalence(seed, prevalence):
    scores, labels = make_binary_dataset(seed, prevalence=prevalence)
    pos = [s for s, y in zip(scores, labels) if y == 1]
    neg = [s for s, y in zip(scores, labels) if y == 0]
    u, _ = stats.mannwhitneyu(pos, neg, alternative="greater")
    assert st.roc_auc(scores, labels) == pytest.approx(u / (len(pos) * len(neg)), abs=1e-9)
