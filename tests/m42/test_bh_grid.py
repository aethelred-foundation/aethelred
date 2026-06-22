"""Benjamini-Hochberg FDR control cross-validated against scipy over a grid."""

from __future__ import annotations

import pytest
from scipy import stats

import m42_stats as st
from conftest import SEEDS_LARGE, make_pvalues


@pytest.mark.parametrize("seed", SEEDS_LARGE)
def test_bh_rejections_match_scipy(seed):
    pvals = make_pvalues(seed)
    mine = st.benjamini_hochberg(pvals, alpha=0.05)
    adjusted = stats.false_discovery_control(pvals, method="bh")
    scipy_rejected = [bool(p <= 0.05) for p in adjusted]
    assert mine["rejected"] == scipy_rejected


@pytest.mark.parametrize("seed", SEEDS_LARGE)
def test_bh_rejection_count_consistent(seed):
    pvals = make_pvalues(seed)
    res = st.benjamini_hochberg(pvals, alpha=0.05)
    assert res["n_rejected"] == sum(res["rejected"])


@pytest.mark.parametrize("seed", range(40))
def test_bh_monotone_in_alpha(seed):
    pvals = make_pvalues(seed)
    strict = st.benjamini_hochberg(pvals, alpha=0.01)
    loose = st.benjamini_hochberg(pvals, alpha=0.10)
    assert loose["n_rejected"] >= strict["n_rejected"]


@pytest.mark.parametrize("alpha", [0.01, 0.05, 0.10, 0.20])
def test_bh_all_null_few_rejections(alpha):
    rng = st.DetRandom("null", alpha)
    pvals = [rng.random() for _ in range(500)]
    res = st.benjamini_hochberg(pvals, alpha=alpha)
    # Under the null, BH controls FDR; rejections should be a small fraction.
    assert res["n_rejected"] <= 0.05 * len(pvals) + 5
