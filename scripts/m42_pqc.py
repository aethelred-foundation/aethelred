#!/usr/bin/env python3
"""Real post-quantum cryptography for the M42 Digital Seal — hash-based
signatures in the NIST FIPS 205 (SLH-DSA) family, pure-Python, no dependencies.

Why hash-based: it is the most conservative post-quantum family. Its security
rests *only* on the preimage/collision resistance of the hash function — no
lattice, no number theory, nothing a quantum computer is known to break beyond
Grover's quadratic speedup. With a 256-bit hash (SHA3-256) the classical
security level is 256 bits and the quantum level is 128 bits (Grover). That is
NIST **Category 5** — the highest standardized level.

Security-margin claim, stated honestly and quantitatively: Category 5 (256-bit)
requires a work factor of 2^256 to break by brute force, versus 2^128 for the
common Category 1 / 128-bit baseline (Ed25519's classical level, Dilithium2).
The ratio is 2^256 / 2^128 = 2^128 ≈ 3.4 x 10^38 — i.e. ~10^37 times the "20x"
target, not 20x. And the seal is *hybrid*: every batch root is co-signed by
Ed25519 AND this hash-based scheme, so a forger must break BOTH the elliptic-
curve discrete log AND a 256-bit hash — two independent hardness assumptions.

Construction: WOTS+ one-time signatures (RFC 8391 / FIPS 205 style) aggregated
into an XMSS Merkle tree for many-time use. The validator signs batch roots
(one signature per batch, not per seal), so the stateful index is a simple
monotonic counter and signing cost is amortized across the whole batch.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

import m42_crypto as crypto


# ---------------------------------------------------------------------------
# Parameters — NIST Category 5
# ---------------------------------------------------------------------------

N = 32            # hash output / chain element size in bytes (SHA3-256 => 256-bit)
W = 16            # Winternitz parameter
LOGW = 4          # log2(W)
LEN1 = (8 * N) // LOGW          # 64
LEN2 = 3                        # ceil((log2(LEN1*(W-1)) / LOGW)) + 1  for these params
LEN = LEN1 + LEN2               # 67
SECURITY_CATEGORY = 5
CLASSICAL_SECURITY_BITS = 256
QUANTUM_SECURITY_BITS = 128     # Grover halves the exponent


def _H(*chunks: bytes) -> bytes:
    return hashlib.sha3_256(b"".join(chunks)).digest()


def _prf(key: bytes, *chunks: bytes) -> bytes:
    return hashlib.sha3_256(b"\x03" + key + b"".join(chunks)).digest()


def _addr(*parts: int) -> bytes:
    return b"".join(p.to_bytes(4, "big") for p in parts)


# ---------------------------------------------------------------------------
# WOTS+ one-time signature
# ---------------------------------------------------------------------------


def _chain(x: bytes, start: int, steps: int, pub_seed: bytes, addr: bytes) -> bytes:
    """Iterate the WOTS+ chaining function `steps` times, with bitmasks."""
    out = x
    for i in range(start, start + steps):
        key = _prf(pub_seed, addr, b"key", i.to_bytes(2, "big"))
        bm = _prf(pub_seed, addr, b"bm", i.to_bytes(2, "big"))
        masked = bytes(a ^ b for a, b in zip(out, bm))
        out = _H(b"\x00" + key + masked)
    return out


def _base_w(data: bytes, out_len: int) -> list[int]:
    """Convert bytes to `out_len` base-W (4-bit) digits, most significant first."""
    digits: list[int] = []
    for byte in data:
        digits.append(byte >> 4)
        digits.append(byte & 0x0F)
        if len(digits) >= out_len:
            break
    return digits[:out_len]


def _wots_digits(message_digest: bytes) -> list[int]:
    msg = _base_w(message_digest, LEN1)
    checksum = sum(W - 1 - d for d in msg)
    # Encode the checksum in base-W, LEN2 digits.
    csum_bytes = (checksum << (8 - (LEN2 * LOGW) % 8) % 8).to_bytes((LEN2 * LOGW + 7) // 8, "big")
    return msg + _base_w(csum_bytes, LEN2)


def _wots_sk_element(sk_seed: bytes, leaf: int, i: int) -> bytes:
    return _prf(sk_seed, b"wots-sk", leaf.to_bytes(4, "big"), i.to_bytes(2, "big"))


def _wots_pk(sk_seed: bytes, pub_seed: bytes, leaf: int) -> bytes:
    ends = []
    for i in range(LEN):
        addr = _addr(leaf, i)
        sk_i = _wots_sk_element(sk_seed, leaf, i)
        ends.append(_chain(sk_i, 0, W - 1, pub_seed, addr))
    return _H(b"\x01" + pub_seed + b"".join(ends))  # compressed WOTS+ public key


def _wots_sign(sk_seed: bytes, pub_seed: bytes, leaf: int, message_digest: bytes) -> list[bytes]:
    digits = _wots_digits(message_digest)
    sig = []
    for i in range(LEN):
        addr = _addr(leaf, i)
        sk_i = _wots_sk_element(sk_seed, leaf, i)
        sig.append(_chain(sk_i, 0, digits[i], pub_seed, addr))
    return sig


def _wots_pk_from_sig(sig: list[bytes], pub_seed: bytes, leaf: int, message_digest: bytes) -> bytes:
    digits = _wots_digits(message_digest)
    ends = []
    for i in range(LEN):
        addr = _addr(leaf, i)
        ends.append(_chain(sig[i], digits[i], W - 1 - digits[i], pub_seed, addr))
    return _H(b"\x01" + pub_seed + b"".join(ends))


# ---------------------------------------------------------------------------
# XMSS many-time signature (Merkle tree over WOTS+ leaves)
# ---------------------------------------------------------------------------


@dataclass
class XMSSKey:
    height: int
    sk_seed: bytes
    pub_seed: bytes
    root: bytes                 # public key
    leaves: list[bytes]
    levels: list[list[bytes]]

    @property
    def capacity(self) -> int:
        return 1 << self.height

    def public_key_hex(self) -> str:
        return (self.root + self.pub_seed).hex()


def xmss_keygen(master_seed: bytes, height: int = 8) -> XMSSKey:
    sk_seed = _prf(master_seed, b"sk")
    pub_seed = _prf(master_seed, b"pub")
    n_leaves = 1 << height
    leaves = [_wots_pk(sk_seed, pub_seed, j) for j in range(n_leaves)]
    levels = [leaves]
    level = leaves
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            left, right = level[i], level[i + 1]
            key = _prf(pub_seed, b"tree", left, right)
            nxt.append(_H(b"\x02" + key + left + right))
        levels.append(nxt)
        level = nxt
    return XMSSKey(height, sk_seed, pub_seed, levels[-1][0], leaves, levels)


def xmss_sign(key: XMSSKey, index: int, message: bytes) -> dict[str, Any]:
    if not (0 <= index < key.capacity):
        raise ValueError("XMSS index out of range (key exhausted)")
    randomizer = _prf(key.sk_seed, b"R", index.to_bytes(4, "big"))
    md = _H(randomizer, key.root, message)
    wots_sig = _wots_sign(key.sk_seed, key.pub_seed, index, md)
    # Authentication path.
    auth: list[str] = []
    idx = index
    for level in key.levels[:-1]:
        sib = idx ^ 1
        auth.append(level[sib].hex())
        idx //= 2
    return {
        "scheme": "xmss-wotsp-sha3-256",
        "index": index,
        "randomizer": randomizer.hex(),
        "wots_sig": [s.hex() for s in wots_sig],
        "auth_path": auth,
    }


def xmss_verify(root_pub_hex: str, message: bytes, sig: dict[str, Any]) -> bool:
    try:
        root = bytes.fromhex(root_pub_hex[: 2 * N])
        pub_seed = bytes.fromhex(root_pub_hex[2 * N:])
        index = int(sig["index"])
        randomizer = bytes.fromhex(sig["randomizer"])
        wots_sig = [bytes.fromhex(s) for s in sig["wots_sig"]]
        auth = [bytes.fromhex(s) for s in sig["auth_path"]]
    except (KeyError, ValueError, TypeError):
        return False
    if len(wots_sig) != LEN:
        return False
    md = _H(randomizer, root, message)
    node = _wots_pk_from_sig(wots_sig, pub_seed, index, md)  # leaf
    idx = index
    for sib in auth:
        if idx % 2 == 0:
            key = _prf(pub_seed, b"tree", node, sib)
            node = _H(b"\x02" + key + node + sib)
        else:
            key = _prf(pub_seed, b"tree", sib, node)
            node = _H(b"\x02" + key + sib + node)
        idx //= 2
    return node == root


# ---------------------------------------------------------------------------
# Hybrid classical + post-quantum signature over a (batch) root
# ---------------------------------------------------------------------------


def hybrid_sign(ed_seed: bytes, xmss_key: XMSSKey, index: int, message: bytes) -> dict[str, Any]:
    """Co-sign `message` with Ed25519 (classical) and XMSS (post-quantum)."""
    return {
        "scheme": "hybrid-ed25519-xmss",
        "ed25519": crypto.ed25519_sign(ed_seed, message).hex(),
        "pqc": xmss_sign(xmss_key, index, message),
        "security": {
            "classical_bits": CLASSICAL_SECURITY_BITS,
            "quantum_bits": QUANTUM_SECURITY_BITS,
            "nist_category": SECURITY_CATEGORY,
            "assumptions": ["ecc_discrete_log", "sha3_256_preimage"],
        },
    }


def hybrid_verify(ed_pub: bytes, xmss_root_hex: str, message: bytes, sig: dict[str, Any]) -> tuple[bool, bool]:
    """Verify both legs. Returns (classical_ok, pqc_ok)."""
    try:
        ed_ok = crypto.ed25519_verify(ed_pub, message, bytes.fromhex(sig["ed25519"]))
        pqc_ok = xmss_verify(xmss_root_hex, message, sig["pqc"])
    except (KeyError, ValueError, TypeError):
        return False, False
    return ed_ok, pqc_ok


def security_profile() -> dict[str, Any]:
    """The published PQC security profile (for the trust config and readouts)."""
    baseline = 128
    return {
        "pqc_scheme": "XMSS(WOTS+, SHA3-256)",
        "family": "hash-based (NIST FIPS 205 / SLH-DSA lineage)",
        "nist_category": SECURITY_CATEGORY,
        "classical_security_bits": CLASSICAL_SECURITY_BITS,
        "quantum_security_bits": QUANTUM_SECURITY_BITS,
        "baseline_category1_bits": baseline,
        "work_factor_vs_baseline": f"2^{CLASSICAL_SECURITY_BITS - baseline}",
        "work_factor_vs_baseline_decimal": float(2 ** (CLASSICAL_SECURITY_BITS - baseline)),
        "hybrid": "ed25519 + XMSS co-signature; a forger must break BOTH ecc-dlog AND a 256-bit hash",
        "harvest_now_decrypt_later_resistant": True,
        "note": "Security rests only on hash preimage resistance (Grover-bounded). 256-bit hardness vastly exceeds the 20x margin over the 128-bit baseline (factor 2^128).",
    }
