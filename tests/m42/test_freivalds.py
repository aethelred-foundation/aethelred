"""Freivalds verifiable matmul: soundness, tamper rejection, and cost."""

from __future__ import annotations

import random

import pytest

import m42_freivalds as fv


def _random_layer(seed, d_out=24, d_in=18, batch=12):
    rng = random.Random(seed)
    W = [[rng.randrange(fv.PRIME) for _ in range(d_in)] for _ in range(d_out)]
    X = [[rng.randrange(fv.PRIME) for _ in range(batch)] for _ in range(d_in)]
    return W, X, fv.matmul_mod(W, X)


@pytest.mark.parametrize("seed", range(40))
def test_correct_product_is_accepted(seed):
    W, X, Y = _random_layer(seed)
    ok, err = fv.freivalds_verify(W, X, Y, rounds=2, rng=random.Random(seed).randint)
    assert ok and err < 1e-30


@pytest.mark.parametrize("seed", range(40))
def test_single_element_tamper_is_rejected(seed):
    W, X, Y = _random_layer(seed)
    rng = random.Random(seed + 1000)
    o = rng.randrange(len(Y))
    b = rng.randrange(len(Y[0]))
    Y[o][b] = (Y[o][b] + rng.randrange(1, fv.PRIME)) % fv.PRIME
    ok, _ = fv.freivalds_verify(W, X, Y, rounds=3, rng=random.Random(seed).randint)
    assert not ok


@pytest.mark.parametrize("seed", range(20))
def test_swapped_rows_rejected(seed):
    W, X, Y = _random_layer(seed, d_out=10, d_in=8, batch=6)
    Y[0], Y[1] = Y[1], Y[0]  # a real "wrong output" an attacker might submit
    ok, _ = fv.freivalds_verify(W, X, Y, rounds=3, rng=random.Random(seed).randint)
    assert not ok


def test_matmul_matches_naive_reference():
    W = [[1, 2], [3, 4], [5, 6]]
    X = [[7, 8], [9, 10]]
    # naive
    expected = [[1 * 7 + 2 * 9, 1 * 8 + 2 * 10],
                [3 * 7 + 4 * 9, 3 * 8 + 4 * 10],
                [5 * 7 + 6 * 9, 5 * 8 + 6 * 10]]
    got = fv.matmul_mod(W, X)
    assert got == [[v % fv.PRIME for v in row] for row in expected]


def test_soundness_error_shrinks_with_rounds():
    W, X, Y = _random_layer(1)
    _, e1 = fv.freivalds_verify(W, X, Y, rounds=1)
    _, e3 = fv.freivalds_verify(W, X, Y, rounds=3)
    assert e3 < e1
    assert e1 < 1e-15  # one round over a 2^61 field already negligible


def test_quantize_is_field_reduced():
    q = fv.quantize([1.0, -1.0, 0.5, 12345.678])
    assert all(0 <= v < fv.PRIME for v in q)


def test_cost_ratio_favors_verifier_at_scale():
    c = fv.verify_cost_ratio(2048, 512, 64, rounds=3)
    assert c["speedup"] > 5.0
    assert c["soundness_error"] < 1e-50
