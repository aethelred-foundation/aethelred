"""Tests for the deterministic RNG that underpins reproducibility."""

from __future__ import annotations

import statistics

import pytest

import m42_stats as st


def test_random_in_unit_interval():
    rng = st.DetRandom("range")
    for _ in range(1000):
        v = rng.random()
        assert 0.0 <= v < 1.0


def test_same_seed_reproducible():
    a = [st.DetRandom("seed", 1).random() for _ in range(5)]
    b = [st.DetRandom("seed", 1).random() for _ in range(5)]
    assert a == b


def test_different_seed_differs():
    a = st.DetRandom("seed-a").random()
    b = st.DetRandom("seed-b").random()
    assert a != b


def test_stream_advances():
    rng = st.DetRandom("stream")
    first = rng.random()
    second = rng.random()
    assert first != second


def test_uniform_within_bounds():
    rng = st.DetRandom("uniform")
    for _ in range(500):
        v = rng.uniform(2.0, 5.0)
        assert 2.0 <= v <= 5.0


def test_randint_inclusive_bounds():
    rng = st.DetRandom("randint")
    seen = set()
    for _ in range(2000):
        v = rng.randint(1, 4)
        assert 1 <= v <= 4
        seen.add(v)
    assert seen == {1, 2, 3, 4}


def test_choice_in_items():
    rng = st.DetRandom("choice")
    items = ["x", "y", "z"]
    for _ in range(200):
        assert rng.choice(items) in items


def test_gauss_mean_converges():
    rng = st.DetRandom("gauss")
    samples = [rng.gauss(10.0, 2.0) for _ in range(5000)]
    assert statistics.mean(samples) == pytest.approx(10.0, abs=0.15)
    assert statistics.pstdev(samples) == pytest.approx(2.0, abs=0.15)


def test_sample_indices_range_and_size():
    rng = st.DetRandom("sample")
    idx = rng.sample_indices(50)
    assert len(idx) == 50
    assert all(0 <= i < 50 for i in idx)


def test_derive_hash_deterministic_and_distinct():
    assert st.derive_hash("a", 1) == st.derive_hash("a", 1)
    assert st.derive_hash("a", 1) != st.derive_hash("a", 2)
    assert len(st.derive_hash("x")) == 64
