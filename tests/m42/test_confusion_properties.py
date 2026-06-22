"""Confusion-matrix and classification-metric invariants over wide seed grids."""

from __future__ import annotations

import pytest

import m42_stats as st
from conftest import SEEDS_MED, SEEDS_XL, make_binary_dataset


@pytest.mark.parametrize("seed", SEEDS_XL)
def test_counts_non_negative(seed):
    scores, labels = make_binary_dataset(seed)
    r = st.binary_rates(scores, labels, 0.5)
    assert all(r[k] >= 0 for k in ("tp", "fp", "tn", "fn"))


@pytest.mark.parametrize("seed", SEEDS_XL)
def test_tp_plus_fn_equals_positives(seed):
    scores, labels = make_binary_dataset(seed)
    r = st.binary_rates(scores, labels, 0.5)
    assert r["tp"] + r["fn"] == sum(labels)


@pytest.mark.parametrize("seed", SEEDS_XL)
def test_tn_plus_fp_equals_negatives(seed):
    scores, labels = make_binary_dataset(seed)
    r = st.binary_rates(scores, labels, 0.5)
    assert r["tn"] + r["fp"] == len(labels) - sum(labels)


@pytest.mark.parametrize("seed", SEEDS_MED)
def test_sensitivity_specificity_in_unit_interval(seed):
    scores, labels = make_binary_dataset(seed)
    r = st.binary_rates(scores, labels, 0.5)
    assert 0.0 <= r["sensitivity"] <= 1.0
    assert 0.0 <= r["specificity"] <= 1.0


@pytest.mark.parametrize("seed", SEEDS_MED)
def test_ppv_npv_in_unit_interval(seed):
    scores, labels = make_binary_dataset(seed)
    r = st.binary_rates(scores, labels, 0.5)
    assert 0.0 <= r["ppv"] <= 1.0
    assert 0.0 <= r["npv"] <= 1.0


@pytest.mark.parametrize("seed", SEEDS_MED)
def test_f1_between_precision_and_recall(seed):
    scores, labels = make_binary_dataset(seed)
    r = st.binary_rates(scores, labels, 0.5)
    if r["ppv"] > 0 and r["sensitivity"] > 0:
        lo = min(r["ppv"], r["sensitivity"])
        hi = max(r["ppv"], r["sensitivity"])
        assert lo - 1e-9 <= r["f1"] <= hi + 1e-9


@pytest.mark.parametrize("seed", SEEDS_MED)
def test_accuracy_in_unit_interval(seed):
    scores, labels = make_binary_dataset(seed)
    assert 0.0 <= st.binary_rates(scores, labels, 0.5)["accuracy"] <= 1.0


@pytest.mark.parametrize("seed", SEEDS_MED)
def test_extreme_threshold_predicts_all_negative(seed):
    scores, labels = make_binary_dataset(seed)
    r = st.binary_rates(scores, labels, 1.01)  # nothing scores >= 1.01
    assert r["tp"] == 0 and r["fp"] == 0


@pytest.mark.parametrize("seed", SEEDS_MED)
def test_zero_threshold_predicts_all_positive(seed):
    scores, labels = make_binary_dataset(seed)
    r = st.binary_rates(scores, labels, 0.0)  # everything scores >= 0
    assert r["tn"] == 0 and r["fn"] == 0
