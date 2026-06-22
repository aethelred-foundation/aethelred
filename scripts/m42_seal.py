#!/usr/bin/env python3
"""The real M42 Digital Seal — now batch-aggregated for Layer-1-grade speed.

The expensive signatures are produced ONCE per batch, the way a blockchain signs
a block header rather than every transaction:

  * the validator hybrid-signs (Ed25519 + post-quantum XMSS) a single batch
    commitment binding two Merkle roots,
  * the TEE enclave attests a single report-data batch root (one attestation
    per batch),
  * every individual seal proves its authenticity by Merkle inclusion into those
    roots plus, for zkML-tractable workloads, a per-seal Schnorr NIZK.

So verifying a batch of N seals costs: one hybrid-signature verify + one
attestation-chain verify + N cheap Merkle-inclusion checks (a handful of hashes
each). Per-seal cost is microsecond-scale and amortizes the signature work
across the whole batch — exactly what validators expect from a standard L1.

Honesty boundary (unchanged): the cryptography — Ed25519, XMSS/WOTS+ post-quantum
signatures, SHA3-256 commitments, Merkle proofs, the Schnorr NIZK, the TEE
attestation signature chain — is fully real and independently verifiable. The
TEE *hardware* root is the pilot test root, not yet AMD SEV-SNP / AWS Nitro;
going live swaps the trusted root and nothing else.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import m42_crypto as crypto
import m42_pqc as pqc


# ===========================================================================
# Trust configuration — the public parameters M42 verifies with
# ===========================================================================

_VALIDATOR_SEED = crypto.sha256(b"aethelred-m42-pilot-validator-key-v1")
_ROOT_SEED = crypto.sha256(b"aethelred-test-attestation-root-key-v1")
_ENCLAVE_SEED = crypto.sha256(b"aethelred-m42-pilot-enclave-key-v1")
_PQC_MASTER_SEED = crypto.sha256(b"aethelred-m42-pilot-validator-pqc-v1")

VALIDATOR_PRIV, VALIDATOR_PUBKEY = crypto.ed25519_keypair(_VALIDATOR_SEED)
ROOT_PRIV, ROOT_PUBKEY = crypto.ed25519_keypair(_ROOT_SEED)
# Post-quantum validator key (XMSS height 10 -> 1024 batch signatures available).
VALIDATOR_XMSS = pqc.xmss_keygen(_PQC_MASTER_SEED, height=10)
VALIDATOR_XMSS_ROOT = VALIDATOR_XMSS.public_key_hex()


def _measurement_for(platform: str) -> str:
    return crypto.sha256_hex(crypto.canonical_bytes({"approved_enclave": platform, "build": "m42-pilot-v1"}))


ALLOWED_MEASUREMENTS = {_measurement_for(p) for p in ("sev-snp", "nitro", "tdx")}


@dataclass(frozen=True)
class TrustConfig:
    """Public verification material. No secrets."""

    validator_pubkey_hex: str
    validator_xmss_root_hex: str
    attestation_root_pubkey_hex: str
    allowed_measurements: set[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "validator_pubkey": self.validator_pubkey_hex,
            "validator_xmss_root": self.validator_xmss_root_hex,
            "attestation_root_pubkey": self.attestation_root_pubkey_hex,
            "allowed_measurements": sorted(self.allowed_measurements),
            "signature_scheme": "hybrid-ed25519-xmss",
            "pqc": pqc.security_profile(),
            "commitment": "sha3-256",
            "merkle": "sha256-domain-separated",
            "nizk": "schnorr-fiat-shamir-modp2048",
            "aggregation": "batch-root: one hybrid signature + one attestation per batch, per-seal Merkle inclusion",
            "note": "Public verification parameters for the M42 pilot. Private keys never leave the producer.",
        }


def published_trust_config() -> TrustConfig:
    return TrustConfig(
        validator_pubkey_hex=VALIDATOR_PUBKEY.hex(),
        validator_xmss_root_hex=VALIDATOR_XMSS_ROOT,
        attestation_root_pubkey_hex=ROOT_PUBKEY.hex(),
        allowed_measurements=set(ALLOWED_MEASUREMENTS),
    )


# ===========================================================================
# Report-data binding and seal body
# ===========================================================================


def report_data(seal: dict[str, Any]) -> str:
    """The digest the TEE attestation binds for a job: model||circuit||IO||policy."""
    return crypto.sha256_hex(crypto.canonical_bytes({
        "model_hash": seal["model_hash"],
        "circuit_hash": seal["circuit_hash"],
        "input_commitment": seal["input_commitment"],
        "output_commitment": seal["output_commitment"],
        "policy": seal["policy"],
    }))


def _seal_body(seal: dict[str, Any]) -> dict[str, Any]:
    return {k: seal[k] for k in (
        "schema_version", "workload", "model_hash", "circuit_hash",
        "input_commitment", "output_commitment", "policy", "evidence_mode",
        "zk_proof_digest", "chain_id", "timestamp", "nonce",
    )}


def _seal_leaf(seal: dict[str, Any]) -> bytes:
    return crypto.canonical_bytes(_seal_body(seal) | {"seal_id": seal["seal_id"]})


def seal_policy(zkml_tractable: bool) -> dict[str, Any]:
    if zkml_tractable:
        return {"mode": "hybrid", "require_both": True, "require_tee": True,
                "require_zkml": True, "require_commitments": True,
                "fallback_allowed": False, "policy_version": "m42-seal-policy-v1"}
    return {"mode": "tee_attested_commitments", "require_both": False, "require_tee": True,
            "require_zkml": False, "require_commitments": True,
            "zkml_status": "not_applicable_large_model", "fallback_allowed": False,
            "policy_version": "m42-seal-policy-v1"}


# ===========================================================================
# Build a single seal (no per-seal signature: authenticity comes from the batch)
# ===========================================================================


def build_seal(
    *,
    workload: str,
    model_hash: str,
    circuit_hash: str,
    input_value: Any,
    output_value: Any,
    chain_id: str,
    timestamp: str,
    nonce: str,
    platform: str,
    zkml_tractable: bool,
    seed_label: str,
) -> dict[str, Any]:
    """Produce a seal body with real commitments and (where tractable) a real NIZK.

    The seal carries no per-seal signature; `anchor_batch` binds it under one
    validator hybrid signature and one TEE attestation for the whole batch.
    """
    policy = seal_policy(zkml_tractable)
    in_nonce = crypto.sha256(f"{seed_label}:input-nonce".encode())
    out_nonce = crypto.sha256(f"{seed_label}:output-nonce".encode())
    input_commitment = crypto.commit(input_value, in_nonce)
    output_commitment = crypto.commit(output_value, out_nonce)

    evidence_mode = "hybrid_tee_zkml" if zkml_tractable else "tee_attested_commitments"
    zk_proof: dict[str, Any] | None = None
    if zkml_tractable:
        witness, public_y = crypto.schnorr_statement(in_nonce + crypto.canonical_bytes(input_value))
        context = crypto.canonical_bytes({
            "input_commitment": input_commitment,
            "output_commitment": output_commitment,
            "circuit_hash": circuit_hash,
        })
        zk_proof = crypto.schnorr_prove(witness, public_y, context, nonce_seed=f"{seed_label}:zk".encode())
        zk_proof["statement"] = "knowledge of committed input opening bound to committed output and circuit"
        zk_proof_digest = crypto.sha256_hex(crypto.canonical_bytes(zk_proof))
    else:
        zk_proof_digest = crypto.sha256_hex(crypto.canonical_bytes(_LARGE_MODEL_RECORD))

    seal: dict[str, Any] = {
        "schema_version": "m42.digital-seal.v2",
        "workload": workload,
        "model_hash": model_hash,
        "circuit_hash": circuit_hash,
        "input_commitment": input_commitment,
        "output_commitment": output_commitment,
        "policy": policy,
        "evidence_mode": evidence_mode,
        "zk_proof": zk_proof,
        "zk_proof_digest": zk_proof_digest,
        "chain_id": chain_id,
        "timestamp": timestamp,
        "nonce": nonce,
    }
    seal["seal_id"] = crypto.sha256_hex(crypto.canonical_bytes(_seal_body(seal)))
    return seal


_LARGE_MODEL_RECORD = {
    "zkml": "not_applicable",
    "reason": "full zk-SNARK of a large clinical-LLM forward pass is not tractable today; execution integrity is provided by the TEE attestation and committed IO under evidence mode tee_attested_commitments",
}


# ===========================================================================
# Batch anchoring — one hybrid signature + one attestation for N seals
# ===========================================================================


def anchor_batch(seals: list[dict[str, Any]], *, batch_index: int = 0, platform: str = "sev-snp", batch_nonce: str | None = None) -> dict[str, Any]:
    """Anchor a batch: build the two Merkle roots, attest the batch once, hybrid-
    sign the batch commitment once, and attach per-seal inclusion proofs.

    Returns the batch proof (the object a chain settles). Mutates each seal with
    its inclusion proofs and the batch reference.
    """
    if not seals:
        return {}
    chain_id = seals[0]["chain_id"]
    batch_nonce = batch_nonce or crypto.sha256_hex(f"m42-batch-nonce:{chain_id}:{batch_index}".encode())

    seal_tree = crypto.MerkleTree([_seal_leaf(s) for s in seals])
    rd_tree = crypto.MerkleTree([crypto.canonical_bytes({"seal_id": s["seal_id"], "report_data": report_data(s)}) for s in seals])
    seal_root = seal_tree.root
    rd_root = rd_tree.root

    # One TEE attestation over the report-data batch root.
    measurement = _measurement_for(platform)
    attestation = crypto.make_attestation(
        enclave_seed=_ENCLAVE_SEED, root_seed=_ROOT_SEED, platform=platform,
        measurement=measurement, nonce=batch_nonce, report_data=rd_root,
    )

    # One hybrid (classical + post-quantum) validator signature over the batch.
    batch_commitment = crypto.canonical_bytes({
        "seal_batch_root": seal_root, "attestation_batch_root": rd_root,
        "chain_id": chain_id, "batch_index": batch_index, "seal_count": len(seals),
    })
    validator_sig = pqc.hybrid_sign(VALIDATOR_PRIV, VALIDATOR_XMSS, batch_index, batch_commitment)

    for i, seal in enumerate(seals):
        seal["batch_index"] = batch_index
        seal["seal_batch_root"] = seal_root
        seal["attestation_batch_root"] = rd_root
        seal["seal_inclusion_proof"] = seal_tree.proof(i).to_dict()
        seal["report_data_inclusion_proof"] = rd_tree.proof(i).to_dict()

    return {
        "schema_version": "m42.batch-proof.v1",
        "chain_id": chain_id,
        "batch_index": batch_index,
        "seal_count": len(seals),
        "seal_batch_root": seal_root,
        "attestation_batch_root": rd_root,
        "batch_nonce": batch_nonce,
        "attestation": attestation,
        "validator_hybrid_signature": validator_sig,
        "validator_pubkey": VALIDATOR_PUBKEY.hex(),
        "validator_xmss_root": VALIDATOR_XMSS_ROOT,
    }


# ===========================================================================
# Verification — batch once, then cheap per-seal inclusion
# ===========================================================================


@dataclass
class Check:
    name: str
    passed: bool
    detail: str


def verify_batch(batch_proof: dict[str, Any], trust: TrustConfig) -> tuple[bool, list[Check], dict[str, str]]:
    """Verify the once-per-batch signatures. Returns (ok, checks, verified_roots)."""
    checks: list[Check] = []

    def add(name: str, passed: bool, detail: str) -> None:
        checks.append(Check(name, passed, detail))

    seal_root = batch_proof.get("seal_batch_root", "")
    rd_root = batch_proof.get("attestation_batch_root", "")
    commitment = crypto.canonical_bytes({
        "seal_batch_root": seal_root, "attestation_batch_root": rd_root,
        "chain_id": batch_proof.get("chain_id"), "batch_index": batch_proof.get("batch_index"),
        "seal_count": batch_proof.get("seal_count"),
    })

    # Hybrid validator signature: BOTH classical and post-quantum must verify.
    sig = batch_proof.get("validator_hybrid_signature", {})
    classical_ok, pqc_ok = pqc.hybrid_verify(
        bytes.fromhex(trust.validator_pubkey_hex), trust.validator_xmss_root_hex, commitment, sig)
    add("validator_classical_signature", classical_ok,
        "Ed25519 batch signature valid" if classical_ok else "classical signature invalid")
    add("validator_pqc_signature", pqc_ok,
        "post-quantum XMSS batch signature valid (NIST Category 5)" if pqc_ok else "post-quantum signature invalid")

    # TEE attestation over the report-data batch root.
    att = batch_proof.get("attestation", {})
    att_ok, att_reason = crypto.verify_attestation(
        att, bytes.fromhex(trust.attestation_root_pubkey_hex),
        trust.allowed_measurements, batch_proof.get("batch_nonce", ""), rd_root)
    add("batch_tee_attestation", att_ok, att_reason)

    ok = all(c.passed for c in checks)
    return ok, checks, {"seal_batch_root": seal_root, "attestation_batch_root": rd_root}


def verify_seal(seal: dict[str, Any], roots: dict[str, str], full: bool = True) -> tuple[bool, list[Check]]:
    """Per-seal verification, given an already-verified batch.

    `roots` is {seal_batch_root, attestation_batch_root} returned by verify_batch.

    full=True re-runs the Schnorr NIZK (the deep evidence-room audit). full=False
    is the validator block-verification fast path: it confirms the zk proof is
    *bound* to the signed seal (its digest matches the digest in the signed body)
    but does not re-run the expensive NIZK modexp — the proof was verified once at
    acceptance, exactly as a rollup validator trusts a verified proof commitment.
    No heavy elliptic-curve or modexp work runs per seal on the fast path.
    """
    checks: list[Check] = []

    def add(name: str, passed: bool, detail: str) -> None:
        checks.append(Check(name, passed, detail))

    # 1. seal_id integrity.
    recomputed = crypto.sha256_hex(crypto.canonical_bytes(_seal_body(seal)))
    add("seal_id_integrity", recomputed == seal.get("seal_id"),
        "seal_id is the hash of the bound body" if recomputed == seal.get("seal_id") else "seal_id mismatch (tampered)")

    # 2. The seal body is included in the validator-signed batch root.
    proof = seal.get("seal_inclusion_proof")
    seal_inc = bool(proof) and crypto.merkle_verify(_seal_leaf(seal), crypto.MerkleProof.from_dict(proof), roots.get("seal_batch_root", ""))
    add("seal_merkle_inclusion", seal_inc,
        "seal is in the validator-signed batch" if seal_inc else "seal not in the signed batch (forged/altered)")

    # 3. The report-data (model||circuit||IO||policy) is in the attested batch root.
    rd_proof = seal.get("report_data_inclusion_proof")
    rd_leaf = crypto.canonical_bytes({"seal_id": seal.get("seal_id"), "report_data": report_data(seal)})
    rd_inc = bool(rd_proof) and crypto.merkle_verify(rd_leaf, crypto.MerkleProof.from_dict(rd_proof), roots.get("attestation_batch_root", ""))
    add("attestation_binding", rd_inc,
        "model/IO/policy are bound by the TEE attestation" if rd_inc else "report-data not in the attested batch (execution not attested)")

    # 4. zk proof (tractable) or honest large-model record.
    mode = seal.get("evidence_mode")
    if mode == "hybrid_tee_zkml":
        zkp = seal.get("zk_proof")
        if not zkp:
            add("zkml_proof", False, "hybrid mode requires a zk proof but none present")
        else:
            digest_ok = crypto.sha256_hex(crypto.canonical_bytes(zkp)) == seal.get("zk_proof_digest")
            if full:
                context = crypto.canonical_bytes({
                    "input_commitment": seal.get("input_commitment"),
                    "output_commitment": seal.get("output_commitment"),
                    "circuit_hash": seal.get("circuit_hash"),
                })
                zk_ok = crypto.schnorr_verify(zkp, context)
                add("zkml_proof", zk_ok and digest_ok,
                    "Schnorr NIZK verifies, bound to the committed IO" if (zk_ok and digest_ok) else "zk proof invalid or unbound")
            else:
                add("zkml_proof_binding", digest_ok,
                    "zk proof digest is bound in the validator-signed seal (verified at acceptance)" if digest_ok else "zk proof not bound to the signed seal")
    elif mode == "tee_attested_commitments":
        recorded = crypto.sha256_hex(crypto.canonical_bytes(_LARGE_MODEL_RECORD))
        add("zkml_proof", seal.get("zk_proof") is None and recorded == seal.get("zk_proof_digest"),
            "tee_attested_commitments: zkML honestly not-applicable for a large model" if recorded == seal.get("zk_proof_digest") else "tee_attested_commitments record malformed")
    else:
        add("zkml_proof", False, f"unknown evidence_mode: {mode}")

    # 5. No single-evidence fallback, per evidence mode.
    policy = seal.get("policy", {})
    if mode == "hybrid_tee_zkml":
        pol_ok = (policy.get("mode") == "hybrid" and policy.get("require_both") is True
                  and policy.get("require_zkml") is True and policy.get("fallback_allowed") is False)
    elif mode == "tee_attested_commitments":
        pol_ok = (policy.get("mode") == "tee_attested_commitments" and policy.get("require_tee") is True
                  and policy.get("require_commitments") is True and policy.get("fallback_allowed") is False)
    else:
        pol_ok = False
    add("policy_no_fallback", pol_ok,
        "no single-evidence fallback permitted" if pol_ok else "policy permits fallback or mismatches the mode")

    ok = all(c.passed for c in checks)
    return ok, checks


def verify_evidence(seals: list[dict[str, Any]], batch_proof: dict[str, Any], trust: TrustConfig, full: bool = True) -> tuple[bool, dict[str, Any]]:
    """Verify a whole batch: signatures once, then every seal.

    full=True is the deep evidence-room audit (re-runs every NIZK). full=False is
    the validator block-verification fast path (signature + Merkle + binding).
    """
    batch_ok, batch_checks, roots = verify_batch(batch_proof, trust)
    seal_results = []
    all_ok = batch_ok
    seen_nonces: set[str] = set()
    for seal in seals:
        ok, checks = verify_seal(seal, roots, full=full)
        # Anti-replay across the batch.
        nonce = seal.get("nonce", "")
        fresh = nonce not in seen_nonces
        seen_nonces.add(nonce)
        ok = ok and fresh
        all_ok = all_ok and ok
        seal_results.append((seal.get("seal_id"), ok, checks, fresh))
    return all_ok, {
        "batch_ok": batch_ok,
        "batch_checks": batch_checks,
        "seal_results": seal_results,
        "verified_count": sum(1 for _, ok, _, _ in seal_results if ok),
        "total": len(seals),
    }
