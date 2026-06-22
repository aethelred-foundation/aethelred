"""Tests for the real cryptographic primitives: RFC vectors, roundtrips, tamper."""

from __future__ import annotations

import hashlib

import pytest

import m42_crypto as c
from conftest import SEEDS_SMALL, SEEDS_MED as _FULL
# Ed25519/attestation are pure-Python; use the small grid for those.
SEEDS_MED = SEEDS_SMALL
SEEDS_LARGE = SEEDS_SMALL


# ---------------------------------------------------------------------------
# Ed25519 — RFC 8032 test vectors (interoperability)
# ---------------------------------------------------------------------------

RFC_VECTORS = [
    # (seed_hex, pubkey_hex, msg_hex, sig_hex)
    ("9d61b19deff1c8c7c1c4f0e7e1ff5e1e7f2f9c1a2b3c4d5e6f7081920a1b2c3d",  # 31 bytes -> hashed, skip exact
     None, "", None),
]


def test_ed25519_zero_seed_matches_libsodium():
    _, pub = c.ed25519_keypair(bytes(32))
    assert pub.hex() == "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"


def test_ed25519_rfc8032_test3_pubkey_and_signature():
    sk = bytes.fromhex("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7")
    _, pub = c.ed25519_keypair(sk)
    assert pub.hex() == "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"
    sig = c.ed25519_sign(sk, bytes.fromhex("af82"))
    assert sig.hex() == ("6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
                         "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a")
    assert c.ed25519_verify(pub, bytes.fromhex("af82"), sig)


@pytest.mark.parametrize("seed", SEEDS_LARGE)
def test_ed25519_sign_verify_roundtrip(seed):
    sk = hashlib.sha256(f"key-{seed}".encode()).digest()
    _, pub = c.ed25519_keypair(sk)
    msg = f"message-{seed}".encode()
    sig = c.ed25519_sign(sk, msg)
    assert c.ed25519_verify(pub, msg, sig)


@pytest.mark.parametrize("seed", SEEDS_MED)
def test_ed25519_rejects_tampered_message(seed):
    sk = hashlib.sha256(f"k{seed}".encode()).digest()
    _, pub = c.ed25519_keypair(sk)
    sig = c.ed25519_sign(sk, b"original")
    assert not c.ed25519_verify(pub, b"original!", sig)


@pytest.mark.parametrize("seed", SEEDS_MED)
def test_ed25519_rejects_tampered_signature(seed):
    sk = hashlib.sha256(f"k{seed}".encode()).digest()
    _, pub = c.ed25519_keypair(sk)
    msg = b"payload"
    sig = bytearray(c.ed25519_sign(sk, msg))
    sig[0] ^= 0x01
    assert not c.ed25519_verify(pub, msg, bytes(sig))


@pytest.mark.parametrize("seed", SEEDS_MED)
def test_ed25519_rejects_wrong_key(seed):
    sk1 = hashlib.sha256(f"a{seed}".encode()).digest()
    sk2 = hashlib.sha256(f"b{seed}".encode()).digest()
    _, pub2 = c.ed25519_keypair(sk2)
    sig = c.ed25519_sign(sk1, b"m")
    assert not c.ed25519_verify(pub2, b"m", sig)


def test_ed25519_deterministic():
    sk = hashlib.sha256(b"det").digest()
    assert c.ed25519_sign(sk, b"x") == c.ed25519_sign(sk, b"x")


# ---------------------------------------------------------------------------
# Commitments
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("seed", SEEDS_MED)
def test_commitment_binding_and_opening(seed):
    nonce = hashlib.sha256(f"n{seed}".encode()).digest()
    value = {"variant": f"v{seed}", "class": "pathogenic"}
    comm = c.commit(value, nonce)
    assert c.open_commitment(comm, value, nonce)
    assert not c.open_commitment(comm, {"class": "benign"}, nonce)
    assert not c.open_commitment(comm, value, b"wrong-nonce")


@pytest.mark.parametrize("seed", SEEDS_MED)
def test_commitment_hiding(seed):
    # Same value, different nonces -> different commitments (hiding).
    value = {"x": seed}
    a = c.commit(value, hashlib.sha256(b"n1").digest())
    b = c.commit(value, hashlib.sha256(b"n2").digest())
    assert a != b


# ---------------------------------------------------------------------------
# Merkle tree
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("n", [1, 2, 3, 5, 8, 13, 50, 120])
def test_merkle_all_leaves_included(n):
    leaves = [f"leaf-{i}".encode() for i in range(n)]
    tree = c.MerkleTree(leaves)
    for i in range(n):
        assert c.merkle_verify(leaves[i], tree.proof(i), tree.root)


@pytest.mark.parametrize("n", [2, 4, 7, 16, 31])
def test_merkle_rejects_forged_leaf(n):
    leaves = [f"leaf-{i}".encode() for i in range(n)]
    tree = c.MerkleTree(leaves)
    proof = tree.proof(0)
    assert not c.merkle_verify(b"forged", proof, tree.root)


@pytest.mark.parametrize("n", [3, 8, 20])
def test_merkle_rejects_wrong_root(n):
    leaves = [f"x{i}".encode() for i in range(n)]
    tree = c.MerkleTree(leaves)
    assert not c.merkle_verify(leaves[1], tree.proof(1), "00" * 32)


def test_merkle_root_changes_with_any_leaf():
    a = c.MerkleTree([b"a", b"b", b"c"]).root
    b = c.MerkleTree([b"a", b"b", b"c2"]).root
    assert a != b


# ---------------------------------------------------------------------------
# Schnorr NIZK
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("seed", SEEDS_LARGE)
def test_schnorr_proof_verifies(seed):
    w, y = c.schnorr_statement(f"witness-{seed}".encode())
    proof = c.schnorr_prove(w, y, b"ctx", f"nonce-{seed}".encode())
    assert c.schnorr_verify(proof, b"ctx")


@pytest.mark.parametrize("seed", SEEDS_MED)
def test_schnorr_rejects_wrong_context(seed):
    w, y = c.schnorr_statement(f"w{seed}".encode())
    proof = c.schnorr_prove(w, y, b"context-a", f"n{seed}".encode())
    assert not c.schnorr_verify(proof, b"context-b")


@pytest.mark.parametrize("seed", SEEDS_MED)
def test_schnorr_rejects_forged_response(seed):
    w, y = c.schnorr_statement(f"w{seed}".encode())
    proof = c.schnorr_prove(w, y, b"c", f"n{seed}".encode())
    proof["response"] = format(int(proof["response"], 16) + 1, "x")
    assert not c.schnorr_verify(proof, b"c")


@pytest.mark.parametrize("seed", SEEDS_MED)
def test_schnorr_rejects_forged_commitment(seed):
    w, y = c.schnorr_statement(f"w{seed}".encode())
    proof = c.schnorr_prove(w, y, b"c", f"n{seed}".encode())
    proof["commitment"] = format(int(proof["commitment"], 16) + 1, "x")
    assert not c.schnorr_verify(proof, b"c")


def test_schnorr_zero_knowledge_no_witness_leak():
    # The proof must not contain the witness value.
    w, y = c.schnorr_statement(b"secret-witness")
    proof = c.schnorr_prove(w, y, b"c", b"n")
    assert format(w, "x") not in proof.values()


# ---------------------------------------------------------------------------
# TEE attestation chain
# ---------------------------------------------------------------------------


@pytest.fixture
def att_setup():
    enclave = hashlib.sha256(b"enclave").digest()
    root = hashlib.sha256(b"root").digest()
    _, root_pub = c.ed25519_keypair(root)
    return enclave, root, root_pub


@pytest.mark.parametrize("seed", SEEDS_MED)
def test_attestation_verifies(seed, att_setup):
    enclave, root, root_pub = att_setup
    att = c.make_attestation(enclave, root, "sev-snp", "m1", f"nonce{seed}", f"rd{seed}")
    ok, _ = c.verify_attestation(att, root_pub, {"m1"}, f"nonce{seed}", f"rd{seed}")
    assert ok


def test_attestation_rejects_bad_measurement(att_setup):
    enclave, root, root_pub = att_setup
    att = c.make_attestation(enclave, root, "sev-snp", "evil", "n", "rd")
    ok, reason = c.verify_attestation(att, root_pub, {"approved"}, "n", "rd")
    assert not ok and "measurement" in reason


def test_attestation_rejects_stale_nonce(att_setup):
    enclave, root, root_pub = att_setup
    att = c.make_attestation(enclave, root, "sev-snp", "m1", "old-nonce", "rd")
    ok, reason = c.verify_attestation(att, root_pub, {"m1"}, "fresh-nonce", "rd")
    assert not ok and "nonce" in reason


def test_attestation_rejects_wrong_report_data(att_setup):
    enclave, root, root_pub = att_setup
    att = c.make_attestation(enclave, root, "sev-snp", "m1", "n", "real-binding")
    ok, reason = c.verify_attestation(att, root_pub, {"m1"}, "n", "different-binding")
    assert not ok and "report_data" in reason


def test_attestation_rejects_untrusted_root(att_setup):
    enclave, root, _ = att_setup
    att = c.make_attestation(enclave, root, "sev-snp", "m1", "n", "rd")
    _, attacker_pub = c.ed25519_keypair(hashlib.sha256(b"attacker").digest())
    ok, reason = c.verify_attestation(att, attacker_pub, {"m1"}, "n", "rd")
    assert not ok and "certificate" in reason


@pytest.mark.parametrize("seed", SEEDS_MED)
def test_attestation_rejects_tampered_report(seed, att_setup):
    enclave, root, root_pub = att_setup
    att = c.make_attestation(enclave, root, "sev-snp", "m1", "n", "rd")
    att["report"]["report_data"] = f"tampered-{seed}"  # breaks the report signature
    ok, _ = c.verify_attestation(att, root_pub, {"m1"}, "n", "rd")
    assert not ok
