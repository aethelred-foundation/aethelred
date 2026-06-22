"""Post-quantum cryptography tests: WOTS+/XMSS hash-based signatures, hybrid, security."""

from __future__ import annotations

import copy

import pytest

import m42_crypto as crypto
import m42_pqc as pqc

# A small XMSS key (height 4 -> 16 one-time leaves) keeps the suite fast while
# exercising the full Merkle structure.
KEY = pqc.xmss_keygen(b"test-master-seed", height=4)
ROOT = KEY.public_key_hex()
INDICES = list(range(KEY.capacity))


@pytest.mark.parametrize("index", INDICES)
def test_xmss_sign_verify_roundtrip(index):
    msg = f"batch-root-{index}".encode()
    sig = pqc.xmss_sign(KEY, index, msg)
    assert pqc.xmss_verify(ROOT, msg, sig)


@pytest.mark.parametrize("index", INDICES)
def test_xmss_rejects_wrong_message(index):
    sig = pqc.xmss_sign(KEY, index, b"original")
    assert not pqc.xmss_verify(ROOT, b"forged", sig)


@pytest.mark.parametrize("index", INDICES)
def test_xmss_rejects_tampered_wots_element(index):
    msg = b"m"
    sig = pqc.xmss_sign(KEY, index, msg)
    bad = copy.deepcopy(sig)
    bad["wots_sig"][0] = "00" * pqc.N
    assert not pqc.xmss_verify(ROOT, msg, bad)


@pytest.mark.parametrize("index", INDICES)
def test_xmss_rejects_tampered_auth_path(index):
    msg = b"m"
    sig = pqc.xmss_sign(KEY, index, msg)
    bad = copy.deepcopy(sig)
    if bad["auth_path"]:
        bad["auth_path"][0] = "ff" * pqc.N
        assert not pqc.xmss_verify(ROOT, msg, bad)


@pytest.mark.parametrize("index", INDICES)
def test_xmss_rejects_wrong_index(index):
    msg = b"m"
    sig = pqc.xmss_sign(KEY, index, msg)
    bad = copy.deepcopy(sig)
    bad["index"] = (index + 1) % KEY.capacity
    assert not pqc.xmss_verify(ROOT, msg, bad)


def test_xmss_rejects_wrong_root():
    other = pqc.xmss_keygen(b"different-master", height=4)
    sig = pqc.xmss_sign(KEY, 0, b"m")
    assert not pqc.xmss_verify(other.public_key_hex(), b"m", sig)


def test_xmss_index_out_of_range_raises():
    with pytest.raises(ValueError):
        pqc.xmss_sign(KEY, KEY.capacity, b"m")


# ---------------------------------------------------------------------------
# WOTS+ chaining and checksum invariants
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("index", range(8))
def test_wots_digits_length(index):
    md = crypto.sha3_256(f"msg-{index}".encode())
    digits = pqc._wots_digits(md)
    assert len(digits) == pqc.LEN
    assert all(0 <= d < pqc.W for d in digits)


@pytest.mark.parametrize("index", range(8))
def test_wots_pk_from_sig_matches_keygen(index):
    md = crypto.sha3_256(f"x-{index}".encode())
    sk_seed = pqc._prf(b"master", b"sk")
    pub_seed = pqc._prf(b"master", b"pub")
    pk = pqc._wots_pk(sk_seed, pub_seed, index)
    sig = pqc._wots_sign(sk_seed, pub_seed, index, md)
    assert pqc._wots_pk_from_sig(sig, pub_seed, index, md) == pk


# ---------------------------------------------------------------------------
# Hybrid classical + post-quantum signature
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("index", range(12))
def test_hybrid_both_legs_verify(index):
    ed_seed, ed_pub = crypto.ed25519_keypair(f"ed-{index}".encode())
    msg = f"root-{index}".encode()
    sig = pqc.hybrid_sign(ed_seed, KEY, index, msg)
    classical_ok, pqc_ok = pqc.hybrid_verify(ed_pub, ROOT, msg, sig)
    assert classical_ok and pqc_ok


@pytest.mark.parametrize("index", range(12))
def test_hybrid_detects_broken_classical_leg(index):
    ed_seed, ed_pub = crypto.ed25519_keypair(f"ed2-{index}".encode())
    msg = b"root"
    sig = pqc.hybrid_sign(ed_seed, KEY, index, msg)
    sig["ed25519"] = "00" * 64
    classical_ok, pqc_ok = pqc.hybrid_verify(ed_pub, ROOT, msg, sig)
    assert not classical_ok and pqc_ok


@pytest.mark.parametrize("index", range(12))
def test_hybrid_detects_broken_pqc_leg(index):
    ed_seed, ed_pub = crypto.ed25519_keypair(f"ed3-{index}".encode())
    msg = b"root"
    sig = pqc.hybrid_sign(ed_seed, KEY, index, msg)
    sig["pqc"]["wots_sig"][0] = "00" * pqc.N
    classical_ok, pqc_ok = pqc.hybrid_verify(ed_pub, ROOT, msg, sig)
    assert classical_ok and not pqc_ok


# ---------------------------------------------------------------------------
# Security profile — the honest, defensible PQC claim
# ---------------------------------------------------------------------------


def test_security_is_category_5():
    prof = pqc.security_profile()
    assert prof["nist_category"] == 5
    assert prof["classical_security_bits"] == 256
    assert prof["quantum_security_bits"] == 128


def test_work_factor_far_exceeds_20x():
    prof = pqc.security_profile()
    # 256-bit vs the 128-bit baseline is a 2^128 work factor — astronomically
    # more than the 20x target.
    assert prof["work_factor_vs_baseline"] == "2^128"
    assert prof["work_factor_vs_baseline_decimal"] > 20.0
    assert prof["work_factor_vs_baseline_decimal"] > 1e37


def test_hybrid_binds_two_independent_assumptions():
    prof = pqc.security_profile()
    assert "ed25519" in prof["hybrid"] and "hash" in prof["hybrid"].lower()
    assert prof["harvest_now_decrypt_later_resistant"] is True


def test_keygen_is_deterministic():
    a = pqc.xmss_keygen(b"seed-x", height=3)
    b = pqc.xmss_keygen(b"seed-x", height=3)
    assert a.public_key_hex() == b.public_key_hex()
