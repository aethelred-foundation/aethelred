#!/usr/bin/env python3
"""Probabilistic verification of selected transformer linear-algebra operations.

SCOPE (read this first). This verifies exactly one claim: that a stated output
matrix Y equals W·X for committed W and X, over a prime field, with soundness
error p^(-rounds). It does NOT verify nonlinear operations (softmax, activations,
normalization), quantization, tokenization/preprocessing, model loading, control
flow, or end-to-end semantic correctness of an inference. It is the linear-algebra
gate that dominates transformer FLOPs; the surrounding guarantees (which model,
which container, which inputs) come from the TEE attestation and the IO
commitments, not from this check.

Freivalds' algorithm: to verify Y = W·X, draw a random vector r and check
W·(X·r) == Y·r in O((d_in+d_out)·batch + d_in·d_out) per round instead of
recomputing the O(d_out·d_in·batch) product. A wrong Y survives one round with
probability at most 1/p, so k rounds give soundness error <= p^(-k).

CHALLENGE UNPREDICTABILITY (the soundness-critical part). The challenge vectors
are NOT a fixed or prover-known seed. They are derived by Fiat-Shamir from a
hash of the committed W, X, and Y plus a verifier-supplied nonce, so:
  * the prover must commit Y before the challenge exists (commit-then-challenge);
  * the verifier nonce prevents precomputation and enables freshness/replay
    protection when bound to a per-batch value;
  * the derivation is domain-separated to this protocol version.
A caller may inject an explicit `rng` for reproducible unit tests, but production
paths use the bound derivation. Integer field arithmetic keeps it deterministic
across platforms.
"""

from __future__ import annotations

import hashlib
from typing import Iterator, Sequence

# Mersenne prime 2^61 − 1: products of two reduced residues stay within Python's
# fast big-int range and the field is large enough for ~61 bits of soundness/round.
PRIME = (1 << 61) - 1

# Domain separator for the Fiat-Shamir challenge derivation.
_CHALLENGE_DOMAIN = b"aethelred/freivalds/challenge/v1"

Matrix = Sequence[Sequence[int]]
Vector = Sequence[int]


def _hash_matrix(m: Matrix) -> bytes:
    """A commitment to a matrix: SHA3-256 over its shape and field residues."""
    h = hashlib.sha3_256()
    h.update(len(m).to_bytes(4, "big"))
    for row in m:
        h.update(len(row).to_bytes(4, "big"))
        for v in row:
            h.update(int(v % PRIME).to_bytes(8, "big"))
    return h.digest()


def _field_stream(seed: bytes) -> Iterator[int]:
    """Unpredictable field elements from SHA3-256 in counter mode."""
    counter = 0
    while True:
        block = hashlib.sha3_256(seed + counter.to_bytes(8, "big")).digest()
        counter += 1
        for i in range(0, len(block), 8):
            yield int.from_bytes(block[i:i + 8], "big") % PRIME


def challenge_seed(W: Matrix, X: Matrix, Y: Matrix, nonce: bytes) -> bytes:
    """The Fiat-Shamir seed binding the challenge to committed W, X, Y and a nonce."""
    return (_CHALLENGE_DOMAIN + b"|" + _hash_matrix(W) + _hash_matrix(X)
            + _hash_matrix(Y) + b"|" + nonce)


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
                     nonce: bytes = b"", rng=None) -> tuple[bool, float]:
    """Verify Y == W·X over GF(PRIME) with `rounds` unpredictable challenges.

    W is d_out×d_in, X is d_in×batch, Y is d_out×batch. By default the challenge
    vectors are derived by Fiat-Shamir from a commitment to (W, X, Y) and `nonce`,
    so a prover who must commit Y first cannot predict them. Pass `rng` (a
    callable like random.Random(seed).randint) only for reproducible tests.
    Returns (ok, soundness_error) with soundness_error = PRIME**(-rounds).
    """
    d_out = len(W)
    d_in = len(X)
    batch = len(X[0]) if d_in else 0
    rounds = max(1, rounds)

    if rng is not None:
        challenges = [[rng(0, PRIME - 1) for _ in range(batch)] for _ in range(rounds)]
    else:
        stream = _field_stream(challenge_seed(W, X, Y, nonce))
        challenges = [[next(stream) for _ in range(batch)] for _ in range(rounds)]

    for rv in challenges:
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
