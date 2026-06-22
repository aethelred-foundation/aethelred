"""Digital Seal v2 (batch-aggregated) tests: real crypto, forgery rejection, fast/full paths."""

from __future__ import annotations

import copy

import pytest

import m42_crypto as crypto
import m42_seal as s
from conftest import SEEDS_MED, SEEDS_SMALL

TRUST = s.published_trust_config()


def _seal(i, tractable=True, chain="aethelred-m42-pilot-1"):
    return s.build_seal(
        workload="genomic-variant-interpretation" if tractable else "med42-clinical-evaluation",
        model_hash="a" * 64, circuit_hash="b" * 64,
        input_value={"variant": f"v{i}"}, output_value={"acmg": "pathogenic", "i": i},
        chain_id=chain, timestamp="2026-06-12T00:00:00Z",
        nonce=f"nonce-{i}", platform="sev-snp", zkml_tractable=tractable, seed_label=f"job-{i}")


def _batch(seeds, index=100, tractable=True):
    seals = [_seal(i, tractable) for i in seeds]
    bp = s.anchor_batch(seals, batch_index=index)
    return seals, bp


# ---------------------------------------------------------------------------
# Valid evidence verifies (batch + per-seal)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("seed", SEEDS_MED)
def test_seal_verifies_in_batch(seed):
    seals, bp = _batch([seed, seed + 1, seed + 2], index=(seed % 200))
    ok, summary = s.verify_evidence(seals, bp, TRUST, full=True)
    assert ok and summary["verified_count"] == len(seals)


@pytest.mark.parametrize("seed", SEEDS_MED)
def test_fast_and_full_paths_agree_on_valid(seed):
    seals, bp = _batch([seed, seed + 7], index=(seed % 200))
    full_ok, _ = s.verify_evidence(seals, bp, TRUST, full=True)
    fast_ok, _ = s.verify_evidence(seals, bp, TRUST, full=False)
    assert full_ok and fast_ok


@pytest.mark.parametrize("seed", range(80))
def test_large_model_uses_honest_mode(seed):
    seals, bp = _batch([seed], index=(300 + seed % 100), tractable=False)
    assert seals[0]["evidence_mode"] == "tee_attested_commitments"
    assert seals[0]["zk_proof"] is None
    ok, _ = s.verify_evidence(seals, bp, TRUST, full=True)
    assert ok


@pytest.mark.parametrize("seed", range(80))
def test_tractable_has_real_zk_proof(seed):
    seal = _seal(seed, tractable=True)
    assert seal["evidence_mode"] == "hybrid_tee_zkml"
    assert seal["zk_proof"] and "response" in seal["zk_proof"]


# ---------------------------------------------------------------------------
# Forgery matrix — every attack must be rejected
# ---------------------------------------------------------------------------

SEAL_FORGERIES = {
    "output_substitution": lambda seal: seal.update(output_commitment=crypto.commit({"acmg": "benign"}, b"f")),
    "model_substitution": lambda seal: seal.update(model_hash="f" * 64),
    "policy_fallback": lambda seal: seal["policy"].update(fallback_allowed=True),
    "forged_inclusion": lambda seal: seal["seal_inclusion_proof"]["siblings"].__setitem__(0, ["L", "00" * 32]),
    "forged_zk": lambda seal: seal["zk_proof"].update(response=format(int(seal["zk_proof"]["response"], 16) + 1, "x")),
    "tampered_timestamp": lambda seal: seal.update(timestamp="2099-01-01T00:00:00Z"),
}

BATCH_FORGERIES = {
    "forged_ed25519_leg": lambda bp: bp["validator_hybrid_signature"].update(ed25519="00" * 64),
    "forged_pqc_leg": lambda bp: bp["validator_hybrid_signature"]["pqc"]["wots_sig"].__setitem__(0, "00" * 32),
    "tampered_seal_root": lambda bp: bp.update(seal_batch_root="0" * 64),
    "untrusted_attestation": lambda bp: bp.update(attestation=crypto.make_attestation(
        crypto.sha256(b"e"), crypto.sha256(b"r"), "sev-snp",
        next(iter(TRUST.allowed_measurements)), bp["batch_nonce"], bp["attestation_batch_root"])),
}


@pytest.mark.parametrize("seed", SEEDS_SMALL)
@pytest.mark.parametrize("name", list(SEAL_FORGERIES))
def test_seal_forgery_rejected(seed, name):
    seals, bp = _batch([seed, seed + 1, seed + 2, seed + 3], index=(seed % 150))
    _, _, roots = s.verify_batch(bp, TRUST)
    forged = copy.deepcopy(seals[0])
    SEAL_FORGERIES[name](forged)
    ok, checks = s.verify_seal(forged, roots, full=True)
    assert not ok, f"{name} should be rejected: {[c.name for c in checks if not c.passed]}"


@pytest.mark.parametrize("seed", SEEDS_SMALL)
@pytest.mark.parametrize("name", list(BATCH_FORGERIES))
def test_batch_forgery_rejected(seed, name):
    seals, bp = _batch([seed, seed + 1], index=(seed % 150))
    forged_bp = copy.deepcopy(bp)
    BATCH_FORGERIES[name](forged_bp)
    ok, checks, _ = s.verify_batch(forged_bp, TRUST)
    assert not ok, f"{name} should be rejected: {[c.name for c in checks if not c.passed]}"


# ---------------------------------------------------------------------------
# Anti-replay, key binding, batch isolation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("seed", range(60))
def test_replayed_nonce_rejected(seed):
    a = _seal(seed)
    b = _seal(seed + 1)
    b["nonce"] = a["nonce"]
    b["seal_id"] = crypto.sha256_hex(crypto.canonical_bytes(s._seal_body(b)))
    bp = s.anchor_batch([a, b], batch_index=(seed % 100))
    ok, _ = s.verify_evidence([a, b], bp, TRUST, full=True)
    assert not ok  # replay detected


@pytest.mark.parametrize("seed", range(60))
def test_seal_not_valid_in_another_batch(seed):
    seals_a, _ = _batch([seed, seed + 1], index=(seed % 100))
    _, bp_b = _batch([seed + 50, seed + 51], index=((seed + 1) % 100))
    _, _, roots_b = s.verify_batch(bp_b, TRUST)
    ok, _ = s.verify_seal(seals_a[0], roots_b, full=True)
    assert not ok


def test_trust_config_has_no_secrets():
    blob = str(s.published_trust_config().to_dict())
    # No actual private key material may appear in the published trust config.
    assert s.VALIDATOR_PRIV.hex() not in blob
    assert s.ROOT_PRIV.hex() not in blob
    assert s.VALIDATOR_XMSS.sk_seed.hex() not in blob


def test_hybrid_signature_requires_both_legs():
    seals, bp = _batch([1, 2], index=5)
    broken = copy.deepcopy(bp)
    broken["validator_hybrid_signature"]["pqc"]["wots_sig"][0] = "00" * 32
    ok, checks, _ = s.verify_batch(broken, TRUST)
    assert not ok
    assert any(c.name == "validator_pqc_signature" and not c.passed for c in checks)
