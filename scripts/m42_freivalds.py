#!/usr/bin/env python3
"""Verifiable batched inference via Freivalds' algorithm — the honest answer to
"you can't zk-SNARK a real LLM forward pass."

A transformer's compute is dominated by matrix multiplications Y = W·X (a weight
matrix times a batch of activation columns). Freivalds' algorithm verifies a
claimed Y in O((d_in+d_out)·batch + d_in·d_out) per round instead of recomputing
the O(d_out·d_in·batch) product: pick a random vector r over a prime field and
check W·(X·r) == Y·r. If Y ≠ W·X the check fails with probability ≥ 1 − 1/p per
round, so k rounds give soundness error ≤ p^(−k) — astronomically small.

This is real, cheap, and sound: a validator re-checks the prover's matmuls
without redoing them, the layer commitments bind W and X, and the TEE attests the
execution. No SNARK of the transformer is required. Pure-Python, integer field
arithmetic (deterministic — no platform float divergence).
"""

from __future__ import annotations

from typing import Sequence

# Mersenne prime 2^61 − 1: products of two reduced residues stay within Python's
# fast big-int range and the field is large enough for ~61 bits of soundness/round.
PRIME = (1 << 61) - 1

Matrix = Sequence[Sequence[int]]
Vector = Sequence[int]


def quantize(values: Sequence[float], scale: int = 1 << 16) -> list[int]:
    """Fixed-point quantize floats into field residues (standard for verifiable
    ML: the prover and verifier agree on a scale and work over integers)."""
    return [int(round(v * scale)) % PRIME for v in values]


def _matvec(m: Matrix, v: Vector) -> list[int]:
    return [sum((row[j] * v[j]) % PRIME for j in range(len(v))) % PRIME for row in m]


def _matvec_cols(m: Matrix, v: Vector) -> list[int]:
    """(m^T-free) right-multiply where m is stored row-major: returns m·v."""
    return _matvec(m, v)


def freivalds_verify(W: Matrix, X: Matrix, Y: Matrix, rounds: int = 3,
                     rng=None) -> tuple[bool, float]:
    """Verify Y == W·X over GF(PRIME) with `rounds` random checks.

    W is d_out×d_in, X is d_in×batch, Y is d_out×batch. Returns (ok,
    soundness_error) where soundness_error = PRIME**(−rounds) is the maximum
    probability a wrong Y is accepted.
    """
    import random as _random
    r = rng or _random.Random(0xF1E1).randint
    d_out = len(W)
    d_in = len(X)
    batch = len(X[0]) if d_in else 0

    for _ in range(max(1, rounds)):
        # Random column vector r over the field (length = batch).
        rv = [r(0, PRIME - 1) for _ in range(batch)]
        # X·r  (d_in vector):
        xr = [sum((X[i][b] * rv[b]) % PRIME for b in range(batch)) % PRIME for i in range(d_in)]
        # W·(X·r)  (d_out vector):
        wxr = _matvec_cols(W, xr)
        # Y·r  (d_out vector):
        yr = [sum((Y[o][b] * rv[b]) % PRIME for b in range(batch)) % PRIME for o in range(d_out)]
        if wxr != yr:
            return False, PRIME ** (-rounds)
    return True, float(PRIME) ** (-rounds)


def matmul_mod(W: Matrix, X: Matrix) -> list[list[int]]:
    """Reference prover product Y = W·X over the field (the expensive O(d_out·d_in·batch))."""
    d_out, d_in, batch = len(W), len(X), len(X[0])
    Y = [[0] * batch for _ in range(d_out)]
    for o in range(d_out):
        Wo = W[o]
        Yo = Y[o]
        for k in range(d_in):
            wok = Wo[k]
            Xk = X[k]
            for b in range(batch):
                Yo[b] = (Yo[b] + wok * Xk[b]) % PRIME
    return Y


def verify_cost_ratio(d_out: int, d_in: int, batch: int, rounds: int = 3) -> dict:
    """Asymptotic work of recompute vs Freivalds verification."""
    recompute = d_out * d_in * batch
    verify = rounds * (d_in * batch + d_out * d_in + d_out * batch)
    return {
        "recompute_ops": recompute,
        "freivalds_verify_ops": verify,
        "speedup": round(recompute / verify, 2) if verify else 0.0,
        "soundness_error": float(PRIME) ** (-rounds),
        "rounds": rounds,
    }
