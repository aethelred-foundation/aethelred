"""Property-based tests for the subgroup / fairness analyzer."""

from __future__ import annotations

import pytest

import m42_stats as st
from conftest import SEEDS_MED


def _make_grouped(seed, n=240, groups=("a", "b", "c")):
    rng = st.DetRandom("subgroup", seed, n)
    items = []
    for _ in range(n):
        g = groups[rng.randint(0, len(groups) - 1)]
        items.append({"g": g, "v": rng.random()})
    return items


def _mean_v(members):
    return sum(m["v"] for m in members) / len(members) if members else None


@pytest.mark.parametrize("seed", SEEDS_MED)
def test_disparity_non_negative(seed):
    res = st.subgroup_analysis(_make_grouped(seed), lambda x: x["g"], _mean_v)
    assert res["disparity_gap"] >= 0.0


@pytest.mark.parametrize("seed", SEEDS_MED)
def test_min_le_max(seed):
    res = st.subgroup_analysis(_make_grouped(seed), lambda x: x["g"], _mean_v)
    if res["min_subgroup_value"] is not None:
        assert res["min_subgroup_value"] <= res["max_subgroup_value"]
        # All three values are independently rounded to 4 dp, so allow a rounding
        # tolerance when reconciling the gap with min/max.
        assert res["disparity_gap"] == pytest.approx(
            res["max_subgroup_value"] - res["min_subgroup_value"], abs=2e-4
        )


@pytest.mark.parametrize("seed", SEEDS_MED)
def test_group_counts_sum_to_total(seed):
    items = _make_grouped(seed)
    res = st.subgroup_analysis(items, lambda x: x["g"], _mean_v)
    assert sum(g["n"] for g in res["groups"].values()) == len(items)


@pytest.mark.parametrize("seed", range(40))
def test_tiny_groups_excluded_from_gap(seed):
    items = [{"g": "big", "v": 0.5} for _ in range(50)] + [{"g": "tiny", "v": 1.0} for _ in range(3)]
    res = st.subgroup_analysis(items, lambda x: x["g"], _mean_v, min_group=8)
    assert res["disparity_gap"] == 0.0
    assert "tiny" in res["groups"]


@pytest.mark.parametrize("seed", range(40))
def test_identical_groups_zero_disparity(seed):
    items = [{"g": g, "v": 0.5} for g in ("a", "b", "c") for _ in range(30)]
    res = st.subgroup_analysis(items, lambda x: x["g"], _mean_v)
    assert res["disparity_gap"] == pytest.approx(0.0, abs=1e-9)


# ---------------------------------------------------------------------------
# worst_stratum_miss_rate — the per-stratum blind-spot guard
# ---------------------------------------------------------------------------


def _worst(items, **kw):
    return st.worst_stratum_miss_rate(
        items,
        stratum_fn=lambda x: x["s"],
        positive_fn=lambda x: x["pos"],
        missed_fn=lambda x: x["missed"],
        **kw,
    )


def test_blind_spot_is_caught():
    # Stratum "a" is caught well (10% miss); "b" is a blind spot (80% miss).
    items = [{"s": "a", "pos": True, "missed": i < 2} for i in range(20)]
    items += [{"s": "b", "pos": True, "missed": i < 16} for i in range(20)]
    res = _worst(items)
    assert res["worst_miss_rate"] == pytest.approx(0.80)
    assert res["per_stratum"]["a"]["miss_rate"] == pytest.approx(0.10)


def test_uniform_miss_rate_equals_worst():
    items = [{"s": s, "pos": True, "missed": i < 3} for s in ("a", "b", "c") for i in range(30)]
    res = _worst(items)
    assert res["worst_miss_rate"] == pytest.approx(0.10)


def test_negatives_do_not_count_as_misses():
    # True negatives (pos=False) are irrelevant to a miss rate on positives.
    items = [{"s": "a", "pos": True, "missed": False} for _ in range(20)]
    items += [{"s": "a", "pos": False, "missed": True} for _ in range(50)]
    res = _worst(items)
    assert res["worst_miss_rate"] == 0.0
    assert res["per_stratum"]["a"]["positives"] == 20


def test_tiny_stratum_excluded_from_worst():
    # A 3-positive stratum that misses everything must not dominate the gate.
    items = [{"s": "big", "pos": True, "missed": i < 1} for i in range(40)]  # 2.5% miss
    items += [{"s": "tiny", "pos": True, "missed": True} for _ in range(3)]  # 100% miss
    res = _worst(items, min_positives=15)
    assert res["worst_miss_rate"] == pytest.approx(0.025)
    assert res["per_stratum"]["tiny"]["miss_rate"] == 1.0  # still reported


def test_no_positives_returns_zero():
    items = [{"s": "a", "pos": False, "missed": False} for _ in range(10)]
    assert _worst(items)["worst_miss_rate"] == 0.0


@pytest.mark.parametrize("seed", SEEDS_MED)
def test_worst_is_max_over_eligible_strata(seed):
    rng = st.DetRandom("missrate", seed, 0)
    items = []
    for s in ("a", "b", "c", "d"):
        n = rng.randint(20, 60)
        p = rng.random()  # this stratum's true miss probability
        for _ in range(n):
            items.append({"s": s, "pos": True, "missed": rng.random() < p})
    res = _worst(items, min_positives=15)
    eligible = [v["miss_rate"] for v in res["per_stratum"].values() if v["positives"] >= 15]
    assert 0.0 <= res["worst_miss_rate"] <= 1.0
    assert res["worst_miss_rate"] == pytest.approx(max(eligible), abs=2e-4)
