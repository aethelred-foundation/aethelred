"""Property-based invariants for the metric primitives over many random datasets.

Each property is parametrized across a grid of seeds, turning a handful of
mathematical invariants into a large, meaningful coverage net.
"""

from __future__ import annotations

import pytest

import m42_stats as st
from conftest import SEEDS_MED, make_binary_dataset


@pytest.mark.parametrize("seed", SEEDS_MED)
def test_auroc_in_unit_interval(seed):
    scores, labels = make_binary_dataset(seed)
    assert 0.0 <= st.roc_auc(scores, labels) <= 1.0


@pytest.mark.parametrize("seed", SEEDS_MED)
def test_auroc_symmetry_under_label_flip(seed):
    scores, labels = make_binary_dataset(seed)
    flipped = [1 - y for y in labels]
    assert st.roc_auc(scores, labels) == pytest.approx(1.0 - st.roc_auc(scores, flipped), abs=1e-9)


@pytest.mark.parametrize("seed", SEEDS_MED)
def test_auroc_invariant_to_monotonic_score_shift(seed):
    scores, labels = make_binary_dataset(seed)
    shifted = [s * 3.0 + 1.0 for s in scores]  # strictly increasing transform
    assert st.roc_auc(scores, labels) == pytest.approx(st.roc_auc(shifted, labels), abs=1e-9)


@pytest.mark.parametrize("seed", SEEDS_MED)
def test_pr_auc_in_unit_interval(seed):
    scores, labels = make_binary_dataset(seed)
    assert 0.0 <= st.pr_auc(scores, labels) <= 1.0


@pytest.mark.parametrize("seed", SEEDS_MED)
def test_pr_auc_at_least_prevalence(seed):
    scores, labels = make_binary_dataset(seed)
    prevalence = sum(labels) / len(labels)
    # A useful ranker's average precision should beat the random baseline.
    assert st.pr_auc(scores, labels) >= prevalence - 0.15


@pytest.mark.parametrize("seed", SEEDS_MED)
def test_bedroc_in_unit_interval(seed):
    scores, labels = make_binary_dataset(seed, prevalence=0.1)
    assert 0.0 <= st.bedroc(scores, labels, alpha=20.0) <= 1.0


@pytest.mark.parametrize("seed", SEEDS_MED)
def test_enrichment_factor_non_negative(seed):
    scores, labels = make_binary_dataset(seed, prevalence=0.05)
    for frac in (0.01, 0.05, 0.1):
        assert st.enrichment_factor(scores, labels, frac) >= 0.0


@pytest.mark.parametrize("seed", SEEDS_MED)
def test_binary_rates_partition(seed):
    scores, labels = make_binary_dataset(seed)
    r = st.binary_rates(scores, labels, 0.5)
    assert r["tp"] + r["fp"] + r["tn"] + r["fn"] == len(labels)


@pytest.mark.parametrize("seed", SEEDS_MED)
def test_mcc_in_range(seed):
    scores, labels = make_binary_dataset(seed)
    assert -1.0 <= st.binary_rates(scores, labels, 0.5)["mcc"] <= 1.0


@pytest.mark.parametrize("seed", SEEDS_MED)
def test_f1_in_unit_interval(seed):
    scores, labels = make_binary_dataset(seed)
    assert 0.0 <= st.binary_rates(scores, labels, 0.5)["f1"] <= 1.0


@pytest.mark.parametrize("seed", SEEDS_MED)
def test_accuracy_consistent_with_counts(seed):
    scores, labels = make_binary_dataset(seed)
    r = st.binary_rates(scores, labels, 0.5)
    expected = (r["tp"] + r["tn"]) / len(labels)
    assert r["accuracy"] == pytest.approx(expected, abs=1e-4)


@pytest.mark.parametrize("seed", SEEDS_MED)
def test_sensitivity_monotonic_in_threshold(seed):
    scores, labels = make_binary_dataset(seed)
    low = st.binary_rates(scores, labels, 0.3)["sensitivity"]
    high = st.binary_rates(scores, labels, 0.7)["sensitivity"]
    assert low >= high - 1e-9  # lowering the threshold cannot reduce sensitivity


@pytest.mark.parametrize("seed", SEEDS_MED)
def test_specificity_monotonic_in_threshold(seed):
    scores, labels = make_binary_dataset(seed)
    low = st.binary_rates(scores, labels, 0.3)["specificity"]
    high = st.binary_rates(scores, labels, 0.7)["specificity"]
    assert high >= low - 1e-9  # raising the threshold cannot reduce specificity


@pytest.mark.parametrize("seed", SEEDS_MED)
def test_topk_hit_rate_bounded(seed):
    scores, labels = make_binary_dataset(seed, prevalence=0.1)
    assert 0.0 <= st.topk_hit_rate(scores, labels, 50) <= 1.0
