"""Wilson confidence interval over a dense (successes, n) grid."""

from __future__ import annotations

import math

import pytest

import m42_stats as st

NS = [5, 8, 10, 15, 20, 25, 30, 40, 50, 64, 80, 100, 150, 200, 300, 500, 750, 1000, 1500, 2000, 5000]
# (k, n) pairs across each n at many proportions.
FRACS = (0.0, 0.02, 0.05, 0.1, 0.2, 0.25, 0.33, 0.5, 0.66, 0.75, 0.9, 0.95, 0.98, 1.0)
GRID = []
for n in NS:
    for frac in FRACS:
        k = min(n, max(0, round(frac * n)))
        GRID.append((k, n))
GRID = sorted(set(GRID))


@pytest.mark.parametrize("k,n", GRID)
def test_wilson_bounds_ordered_and_in_unit_interval(k, n):
    lo, hi = st.wilson_ci(k, n)
    assert 0.0 <= lo <= hi <= 1.0


@pytest.mark.parametrize("k,n", GRID)
def test_wilson_contains_point_when_interior(k, n):
    p = k / n
    lo, hi = st.wilson_ci(k, n)
    if 0 < k < n:
        assert lo <= p <= hi


@pytest.mark.parametrize("k,n", GRID)
def test_wilson_center_between_p_and_half(k, n):
    # The Wilson center is shrunk toward 0.5 relative to the raw proportion.
    p = k / n
    lo, hi = st.wilson_ci(k, n)
    center = (lo + hi) / 2
    assert min(p, 0.5) - 1e-6 <= center <= max(p, 0.5) + 1e-6


@pytest.mark.parametrize("n", NS)
def test_wilson_width_shrinks_with_n_at_half(n):
    lo, hi = st.wilson_ci(round(0.5 * n), n)
    width = hi - lo
    # Width is ~ z/sqrt(n) at p=0.5; confirm it is below a generous bound.
    assert width <= 2.0 / math.sqrt(n) + 0.05


@pytest.mark.parametrize("n", NS)
def test_wilson_full_success_upper_one(n):
    _, hi = st.wilson_ci(n, n)
    assert hi == pytest.approx(1.0, abs=1e-9)


@pytest.mark.parametrize("n", NS)
def test_wilson_zero_success_lower_zero(n):
    lo, _ = st.wilson_ci(0, n)
    assert lo == pytest.approx(0.0, abs=1e-9)
