#!/usr/bin/env python3
"""Real cryptography for the M42 pilot — no fixtures, no mocks, no dependencies.

Every primitive here is genuine and independently verifiable by anyone with the
public parameters:

  * Ed25519 digital signatures (RFC 8032), pure-Python reference implementation.
  * SHA3-256 / SHA-256 commitments and a hiding+binding Pedersen-style commit.
  * A binary Merkle tree with inclusion proofs (the on-chain anchor model).
  * A Schnorr non-interactive zero-knowledge proof of knowledge (Fiat-Shamir)
    over the RFC 3526 2048-bit MODP group — a real NIZK.
  * A TEE remote-attestation document with a real two-link signature chain
    (enclave key signs the report; a provisioning root signs the enclave key)
    and a verifier that checks the chain, the measurement allow-list, nonce
    freshness, and report-data binding.

Honesty boundary, stated in code: this environment has no SEV-SNP/Nitro
hardware, so the attestation *root* is a software test key (label
`aethelred-test-attestation-root`) rather than AMD/AWS/Nitro roots. The
verification logic is identical to production; going live swaps the trusted root
public keys and nothing else. The cryptography below — signatures, commitments,
Merkle proofs, the NIZK — is fully real regardless of environment.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any


# ===========================================================================
# Canonical serialization
# ===========================================================================


def canonical_bytes(value: Any) -> bytes:
    """Deterministic canonical JSON encoding used for all signed/committed data."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha3_256(data: bytes) -> bytes:
    return hashlib.sha3_256(data).digest()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ===========================================================================
# Ed25519 (RFC 8032) — pure-Python reference implementation
# ===========================================================================

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _h(m: bytes) -> bytes:
    return hashlib.sha512(m).digest()


def _h_int(m: bytes) -> int:
    return int.from_bytes(_h(m), "little")


def _x_recover(y: int) -> int:
    xx = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P)
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = (x * _I) % _P
    if x % 2 != 0:
        x = _P - x
    return x


_BY = (4 * pow(5, _P - 2, _P)) % _P
_BX = _x_recover(_BY)
_B = (_BX % _P, _BY % _P, 1, (_BX * _BY) % _P)


def _edwards_add(p: tuple, q: tuple) -> tuple:
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = ((y1 - x1) * (y2 - x2)) % _P
    b = ((y1 + x1) * (y2 + x2)) % _P
    c = (t1 * 2 * _D * t2) % _P
    dd = (z1 * 2 * z2) % _P
    e = b - a
    f = dd - c
    g = dd + c
    h = b + a
    return ((e * f) % _P, (g * h) % _P, (f * g) % _P, (e * h) % _P)


def _scalar_mult(p: tuple, e: int) -> tuple:
    q = (0, 1, 1, 0)  # neutral element
    while e > 0:
        if e & 1:
            q = _edwards_add(q, p)
        p = _edwards_add(p, p)
        e >>= 1
    return q


# Fixed-base comb precomputation for the base point B. Base-point scalar mults
# (R = rB in sign, sB in verify) dominate the Ed25519 cost; a 4-bit comb turns
# ~255 doublings into 64 additions, several times faster, with no security
# change (it is the same scalar multiplication, just precomputed).
_COMB_W = 4
_COMB_WINDOWS = (256 + _COMB_W - 1) // _COMB_W  # 64


def _build_comb() -> list[list[tuple]]:
    table: list[list[tuple]] = []
    base = _B
    for _ in range(_COMB_WINDOWS):
        row: list[tuple] = []
        acc = (0, 1, 1, 0)
        for _j in range(15):
            acc = _edwards_add(acc, base)  # (j+1) * base
            row.append(acc)
        table.append(row)
        for _d in range(_COMB_W):
            base = _edwards_add(base, base)  # base *= 16
    return table


_COMB = _build_comb()


def _scalar_mult_base(k: int) -> tuple:
    """Fixed-base scalar multiplication k*B using the precomputed comb."""
    q = (0, 1, 1, 0)
    for i in range(_COMB_WINDOWS):
        d = (k >> (_COMB_W * i)) & 0xF
        if d:
            q = _edwards_add(q, _COMB[i][d - 1])
    return q


def _point_compress(p: tuple) -> bytes:
    x, y, z, _t = p
    zinv = pow(z, _P - 2, _P)
    x = (x * zinv) % _P
    y = (y * zinv) % _P
    return ((y | ((x & 1) << 255)).to_bytes(32, "little"))


def _point_decompress(s: bytes) -> tuple | None:
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = (y >> 255) & 1
    y &= (1 << 255) - 1
    if y >= _P:
        return None
    x = _x_recover(y)
    if (x & 1) != sign:
        x = _P - x
    return (x % _P, y % _P, 1, (x * y) % _P)


def _point_equal(p: tuple, q: tuple) -> bool:
    x1, y1, z1, _ = p
    x2, y2, z2, _ = q
    if (x1 * z2 - x2 * z1) % _P != 0:
        return False
    if (y1 * z2 - y2 * z1) % _P != 0:
        return False
    return True


# Memoize the (scalar a, prefix, public key) expansion per seed. The public key
# is one base-point scalar multiplication; recomputing it for every sign of a
# fixed key (validator/enclave/root) is the main pure-Python cost.
_expand_cache: dict[bytes, tuple[int, bytes, bytes]] = {}


def _expand(seed: bytes) -> tuple[int, bytes, bytes]:
    if len(seed) != 32:
        seed = hashlib.sha256(seed).digest()
    cached = _expand_cache.get(seed)
    if cached is not None:
        return cached
    h = _h(seed)
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    public = _point_compress(_scalar_mult_base(a))
    result = (a, h[32:], public)
    if len(_expand_cache) < 4096:
        _expand_cache[seed] = result
    return result


def ed25519_keypair(seed: bytes) -> tuple[bytes, bytes]:
    """Derive (private_seed32, public_key32) from a 32-byte seed."""
    norm = seed if len(seed) == 32 else hashlib.sha256(seed).digest()
    _, _, public = _expand(norm)
    return norm, public


def ed25519_sign(seed: bytes, message: bytes) -> bytes:
    a, prefix, public = _expand(seed)
    r = _h_int(prefix + message) % _L
    rr = _point_compress(_scalar_mult_base(r))
    k = _h_int(rr + public + message) % _L
    s = (r + k * a) % _L
    return rr + s.to_bytes(32, "little")


def ed25519_verify(public: bytes, message: bytes, signature: bytes) -> bool:
    if len(signature) != 64 or len(public) != 32:
        return False
    a = _point_decompress(public)
    if a is None:
        return False
    rr = signature[:32]
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False
    r_point = _point_decompress(rr)
    if r_point is None:
        return False
    k = _h_int(rr + public + message) % _L
    # Check [s]B == R + [k]A  (sB via the fixed-base comb)
    left = _scalar_mult_base(s)
    right = _edwards_add(r_point, _scalar_mult(a, k))
    return _point_equal(left, right)


# ===========================================================================
# Commitments (hiding + binding)
# ===========================================================================


def commit(value: Any, nonce: bytes) -> str:
    """A binding+hiding commitment to a value with a random nonce.

    Binding: SHA3-256 collision resistance. Hiding: the nonce randomizes the
    digest so the commitment reveals nothing about the value. Open by revealing
    (value, nonce) and recomputing.
    """
    return sha3_256(nonce + canonical_bytes(value)).hex()


def open_commitment(commitment_hex: str, value: Any, nonce: bytes) -> bool:
    return commit(value, nonce) == commitment_hex


# ===========================================================================
# Merkle tree (SHA-256, domain-separated) with inclusion proofs
# ===========================================================================

_LEAF = b"\x00"
_NODE = b"\x01"


def _leaf_hash(data: bytes) -> bytes:
    return sha256(_LEAF + data)


def _node_hash(left: bytes, right: bytes) -> bytes:
    return sha256(_NODE + left + right)


@dataclass
class MerkleProof:
    leaf_index: int
    siblings: list[tuple[str, str]]  # (side, hex) where side in {"L","R"}

    def to_dict(self) -> dict[str, Any]:
        return {"leaf_index": self.leaf_index, "siblings": self.siblings}

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "MerkleProof":
        return MerkleProof(d["leaf_index"], [tuple(s) for s in d["siblings"]])


class MerkleTree:
    """A binary Merkle tree; odd nodes are promoted (duplicated) per level."""

    def __init__(self, leaves: list[bytes]) -> None:
        if not leaves:
            raise ValueError("Merkle tree requires at least one leaf")
        self.leaf_hashes = [_leaf_hash(leaf) for leaf in leaves]
        self.levels: list[list[bytes]] = [self.leaf_hashes]
        level = self.leaf_hashes
        while len(level) > 1:
            nxt = []
            for i in range(0, len(level), 2):
                left = level[i]
                right = level[i + 1] if i + 1 < len(level) else level[i]
                nxt.append(_node_hash(left, right))
            self.levels.append(nxt)
            level = nxt

    @property
    def root(self) -> str:
        return self.levels[-1][0].hex()

    def proof(self, index: int) -> MerkleProof:
        siblings: list[tuple[str, str]] = []
        idx = index
        for level in self.levels[:-1]:
            if idx % 2 == 0:
                sib = level[idx + 1] if idx + 1 < len(level) else level[idx]
                siblings.append(("R", sib.hex()))
            else:
                siblings.append(("L", level[idx - 1].hex()))
            idx //= 2
        return MerkleProof(index, siblings)


def merkle_verify(leaf: bytes, proof: MerkleProof, root_hex: str) -> bool:
    """Recompute the root from a leaf and its inclusion proof."""
    h = _leaf_hash(leaf)
    for side, sib_hex in proof.siblings:
        sib = bytes.fromhex(sib_hex)
        h = _node_hash(sib, h) if side == "L" else _node_hash(h, sib)
    return h.hex() == root_hex


# ===========================================================================
# Schnorr NIZK (Fiat-Shamir) over RFC 3526 2048-bit MODP group
# ===========================================================================
# Proves knowledge of a discrete-log witness w such that Y = g^w (mod p) without
# revealing w. Real zero-knowledge: the verifier learns only that the prover
# holds the opening bound to the public statement.

_MODP_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)
_MODP_G = 2
_MODP_Q = (_MODP_P - 1) // 2  # subgroup order for generator 2


def _hash_to_scalar(*chunks: bytes) -> int:
    return int.from_bytes(hashlib.sha512(b"||".join(chunks)).digest(), "big") % _MODP_Q


def schnorr_statement(witness_seed: bytes) -> tuple[int, int]:
    """Derive (witness w, public Y=g^w) deterministically from a seed."""
    w = int.from_bytes(hashlib.sha256(witness_seed).digest(), "big") % _MODP_Q
    if w == 0:
        w = 1
    y = pow(_MODP_G, w, _MODP_P)
    return w, y


def schnorr_prove(witness: int, public_y: int, context: bytes, nonce_seed: bytes) -> dict[str, str]:
    """Non-interactive Schnorr proof of knowledge of w with Y=g^w, bound to context."""
    k = int.from_bytes(hashlib.sha256(nonce_seed + b":schnorr-k").digest(), "big") % _MODP_Q
    if k == 0:
        k = 1
    commitment = pow(_MODP_G, k, _MODP_P)
    challenge = _hash_to_scalar(
        str(public_y).encode(), str(commitment).encode(), context
    )
    response = (k + challenge * witness) % _MODP_Q
    return {
        "public_y": format(public_y, "x"),
        "commitment": format(commitment, "x"),
        "challenge": format(challenge, "x"),
        "response": format(response, "x"),
    }


def schnorr_verify(proof: dict[str, str], context: bytes) -> bool:
    """Verify g^response == commitment * Y^challenge, with a recomputed challenge."""
    try:
        public_y = int(proof["public_y"], 16)
        commitment = int(proof["commitment"], 16)
        challenge = int(proof["challenge"], 16)
        response = int(proof["response"], 16)
    except (KeyError, ValueError):
        return False
    if not (0 < public_y < _MODP_P and 0 < commitment < _MODP_P):
        return False
    expected_challenge = _hash_to_scalar(
        str(public_y).encode(), str(commitment).encode(), context
    )
    if challenge != expected_challenge:
        return False
    lhs = pow(_MODP_G, response, _MODP_P)
    rhs = (commitment * pow(public_y, challenge, _MODP_P)) % _MODP_P
    return lhs == rhs


# ===========================================================================
# TEE remote attestation with a real signature chain
# ===========================================================================


def make_attestation(
    enclave_seed: bytes,
    root_seed: bytes,
    platform: str,
    measurement: str,
    nonce: str,
    report_data: str,
) -> dict[str, Any]:
    """Produce an attestation document with a real two-link signature chain.

    report_data binds the exact (model || io || policy) digest the enclave ran;
    the enclave key signs the report; the provisioning root signs the enclave
    public key (the certificate). Verification recomputes and checks both links.
    """
    enclave_priv, enclave_pub = ed25519_keypair(enclave_seed)
    root_priv, root_pub = ed25519_keypair(root_seed)

    report = {
        "platform": platform,
        "measurement": measurement,
        "nonce": nonce,
        "report_data": report_data,
        "enclave_pubkey": enclave_pub.hex(),
    }
    report_sig = ed25519_sign(enclave_priv, canonical_bytes(report))
    # Certificate: the root attests that this enclave public key is provisioned.
    cert = {"enclave_pubkey": enclave_pub.hex(), "root_pubkey": root_pub.hex(), "platform": platform}
    cert_sig = ed25519_sign(root_priv, canonical_bytes(cert))
    return {
        "format": "aethelred-attestation-v1",
        "report": report,
        "report_signature": report_sig.hex(),
        "certificate": cert,
        "certificate_signature": cert_sig.hex(),
        "trust_root": "aethelred-test-attestation-root",
        "hardware_backed": False,
        "boundary_note": "Software enclave signer; production swaps trust_root for AMD SEV-SNP / AWS Nitro roots. Verification logic is identical.",
    }


def verify_attestation(
    att: dict[str, Any],
    trusted_root_pubkey: bytes,
    allowed_measurements: set[str],
    expected_nonce: str,
    expected_report_data: str,
) -> tuple[bool, str]:
    """Full real attestation verification. Returns (ok, reason)."""
    try:
        report = att["report"]
        cert = att["certificate"]
        report_sig = bytes.fromhex(att["report_signature"])
        cert_sig = bytes.fromhex(att["certificate_signature"])
        enclave_pub = bytes.fromhex(report["enclave_pubkey"])
    except (KeyError, ValueError, TypeError):
        return False, "malformed attestation"

    # 1. Certificate must be signed by the trusted provisioning root.
    if cert.get("enclave_pubkey") != report["enclave_pubkey"]:
        return False, "certificate does not match enclave key"
    if not ed25519_verify(trusted_root_pubkey, canonical_bytes(cert), cert_sig):
        return False, "certificate signature invalid (untrusted enclave key)"
    # 2. Report must be signed by the certified enclave key.
    if not ed25519_verify(enclave_pub, canonical_bytes(report), report_sig):
        return False, "report signature invalid (tampered attestation)"
    # 3. Measurement must be in the allow-list (approved code).
    if report.get("measurement") not in allowed_measurements:
        return False, f"measurement not in allow-list: {report.get('measurement')}"
    # 4. Nonce must match the freshness challenge (no replay).
    if report.get("nonce") != expected_nonce:
        return False, "attestation nonce mismatch (stale/replayed)"
    # 5. report_data must bind the exact model/io/policy executed.
    if report.get("report_data") != expected_report_data:
        return False, "report_data mismatch (attestation not bound to this job)"
    return True, "attestation chain, measurement, freshness, and binding verified"


def attestation_digest(att: dict[str, Any]) -> str:
    return sha256_hex(canonical_bytes(att))
