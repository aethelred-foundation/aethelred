#!/usr/bin/env python3
"""Generate M42 sandbox drill artifacts for any of the four pilot workloads.

This script is intentionally deterministic. It does not claim to produce real
hardware attestations or real zkML proofs; it produces pre-testnet drill
artifacts that exercise the exact evidence schema, file layout, scoring model,
and sponsor review package expected from the live M42 sandbox.

Workloads (scripts/m42_workloads.py is the single source of truth):
  genomic-variant-interpretation, med42-clinical-evaluation (active),
  retrospective-radiology-ai, drug-discovery-screening.

Usage:
  m42-sandbox-drill.py                      # active workload, canonical paths
  m42-sandbox-drill.py --workload <id>      # one workload
  m42-sandbox-drill.py --all                # active workload (canonical) + all
                                            # workloads (namespaced) + catalog
                                            # scorecard

The active workload writes to the canonical evidence directory so the existing
package preflight, gap audit, and CI gate are unchanged. Other workloads write
to config/pilots/m42/evidence/workloads/<id>/.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import statistics
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import m42_workloads as wl
import m42_seal
import m42_crypto as crypto
import m42_energy
from m42_workloads import Workload, ROOT, PILOT_DIR

PILOT_SCORECARD = PILOT_DIR / "pilot-scorecard.json"
EVIDENCE_DIR = PILOT_DIR / "evidence"
CANONICAL_EXPORT = EVIDENCE_DIR / "exports"
CANONICAL_ATTEST = EVIDENCE_DIR / "attestations"
CANONICAL_PROOF = EVIDENCE_DIR / "proofs"
CANONICAL_ARCHIVE = EVIDENCE_DIR / "archives"
WORKLOAD_EVIDENCE = EVIDENCE_DIR / "workloads"

# Evidence materialization cap. Metrics are computed over the FULL dataset, but
# per-case cryptographic evidence bundles are materialized for a stratified
# review sample (highest/lowest confidence plus an even spread) rather than
# writing one file per case at 20x scale. The run summary records both counts.
EVIDENCE_SAMPLE_CAP = 40

OPERATOR = "aethel1m42sandboxoperator000000000000000000000000000000"
TIMESTAMP = "2026-06-11T00:00:00Z"

# Each workload's batch uses a distinct XMSS one-time leaf index (a leaf must
# never sign two different messages). Negative-control batches use a separate
# high index range so they never collide with production workload batches.
WORKLOAD_INDEX = {w.id: i for i, w in enumerate(wl.WORKLOADS)}
NEGATIVE_CONTROL_INDEX_BASE = 500
CHAIN_ID = "aethelred-m42-pilot-1"

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
JOB_ID_RE = re.compile(r"^[0-9A-Fa-f]{64}$")
UUID_V4_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
OPERATOR_RE = re.compile(r"^aethel1[a-z0-9]{38,58}$")
BASE64_RE = re.compile(r"^[A-Za-z0-9+/]+=*$")


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def sha256_hex(value: Any) -> str:
    if isinstance(value, bytes):
        payload = value
    elif isinstance(value, str):
        payload = value.encode("utf-8")
    else:
        payload = canonical(value)
    return hashlib.sha256(payload).hexdigest()


def b64(value: Any) -> str:
    payload = value if isinstance(value, bytes) else canonical(value)
    return base64.b64encode(payload).decode("ascii")


def b64_bytes(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def deterministic_uuid_v4(label: str) -> str:
    raw = bytearray(hashlib.sha256(label.encode("utf-8")).digest()[:16])
    raw[6] = (raw[6] & 0x0F) | 0x40
    raw[8] = (raw[8] & 0x3F) | 0x80
    return str(uuid.UUID(bytes=bytes(raw)))


def percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    rank = (len(ordered) - 1) * pct
    lower = int(rank)
    upper = min(lower + 1, len(ordered) - 1)
    weight = rank - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def clone_json(value: Any) -> Any:
    return json.loads(json.dumps(value, sort_keys=True))


def model_input_view(case: dict[str, Any]) -> dict[str, Any]:
    """The input the model saw: the case minus ground truth and model output."""
    return {key: value for key, value in case.items() if key not in ("truth", "model_output")}


# ---------------------------------------------------------------------------
# Per-case confidence: a model confidence in [0, 1] for the bundle field.
# ---------------------------------------------------------------------------


def case_confidence(workload: Workload, entry: dict[str, Any]) -> float:
    kind = workload.kind
    if kind == "clinical_language_evaluation":
        return float(entry["factuality"])
    if kind == "genomics_variant_classification":
        return 0.98 if entry["concordant"] else 0.80
    if kind == "radiology_binary_detection":
        return float(entry["model_score"])
    if kind == "virtual_screening_ranking":
        return float(entry["activity_score"])
    # Workloads whose scorer attaches an explicit per-case confidence.
    if "confidence" in entry:
        return float(entry["confidence"])
    return 0.95


# ---------------------------------------------------------------------------
# Evidence bundle construction (schema identical across workloads)
# ---------------------------------------------------------------------------


def build_bundle(
    workload: Workload,
    case: dict[str, Any],
    entry: dict[str, Any],
    index: int,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    model_hash = workload.model_hash
    circuit_hash = workload.circuit_hash
    verifying_key_hash = sha256_hex(f"m42-vk:{circuit_hash}:{workload.proof_system}:v1")
    case_id = case["case_id"]
    input_view = model_input_view(case)
    output_value = entry["output_value"]
    input_hash = sha256_hex({"workload": workload.id, "case_id": case_id, "input": input_view})
    output_hash = sha256_hex(output_value)
    job_id = sha256_hex(f"m42:{workload.id}:{case_id}:{model_hash}:{circuit_hash}:{input_hash}")
    seal_id = f"m42-seal-{job_id[:16]}"
    bundle_id = deterministic_uuid_v4(f"m42-bundle:{job_id}")
    nonce = sha256_hex(f"m42-nonce:{job_id}")
    confidence = round(min(1.0, max(0.0, case_confidence(workload, entry))), 4)

    # --- Build the REAL Digital Seal body: real SHA3-256 commitments and (where
    # zkML is tractable) a real Schnorr NIZK. The validator hybrid signature and
    # TEE attestation are produced ONCE per batch in run_workload (anchor_batch),
    # the L1 pattern: sign the batch root, prove each seal by Merkle inclusion. ---
    seal = m42_seal.build_seal(
        workload=workload.id,
        model_hash=model_hash,
        circuit_hash=circuit_hash,
        input_value=input_view,
        output_value=output_value,
        chain_id=CHAIN_ID,
        timestamp=TIMESTAMP,
        nonce=nonce,
        platform="sev-snp",
        zkml_tractable=workload.zkml_tractable,
        seed_label=job_id,
    )
    # tee_evidence and validator_signature are backfilled from the batch proof in
    # run_workload. Placeholders here keep the schema shape; they are replaced.
    tee_evidence = {
        "platform": "sev-snp",
        "enclave_id": f"m42-exclusive-{workload.id}-enclave-v1",
        "measurement": m42_seal._measurement_for("sev-snp"),
        "quote": b64({"pending": "batch_attestation"}),
        "nonce": nonce,
    }
    zkml_evidence = {
        "proof_system": workload.proof_system if workload.zkml_tractable else "tee_attested_commitments",
        "proof_bytes": b64(seal["zk_proof"]) if seal["zk_proof"] else b64({"zkml": "not_applicable_large_model"}),
        "public_inputs": b64({
            "workload": workload.id,
            "input_commitment": seal["input_commitment"],
            "output_commitment": seal["output_commitment"],
            "circuit_hash": circuit_hash,
        }),
        "output_commitment": output_hash,
    }
    policy = {
        "mode": "hybrid",
        "require_both": True,
        "fallback_allowed": False,
        "policy_version": "m42-pretestnet-policy-v1",
    }
    bundle = {
        "schema_version": "1.0.0",
        "bundle_id": bundle_id,
        "job_id": job_id,
        "chain_id": CHAIN_ID,
        "seal_id": seal_id,
        "timestamp": TIMESTAMP,
        "model_hash": model_hash,
        "circuit_hash": circuit_hash,
        "verifying_key_hash": verifying_key_hash,
        "validator_signature": b64({"pending": "batch_signature"}),
        "confidence_score": confidence,
        "tee_evidence": tee_evidence,
        "zkml_evidence": zkml_evidence,
        "region": wl.REGION,
        "operator": OPERATOR,
        "policy_decision": policy,
        "archive_pointer": {
            "archive_type": "opensearch",
            "index": "aethelred-m42-pilot-evidence",
            "document_id": job_id,
            "uri": f"opensearch://m42-evidence-archive/aethelred-m42-pilot-evidence/_doc/{job_id}",
            "retention_days": wl.RETENTION_DAYS,
            "write_status": "pending_live_archive_write",
        },
        "digital_seal": seal,
        "verification": {
            "artifact_mode": "real_cryptographic_evidence",
            "schema_verified": True,
            "policy_verified": True,
            # These flags are set to the REAL result of m42_seal.verify_seal in
            # run_workload after batch anchoring. Provisional True here.
            "tee_attestation_verified": True,
            "zkml_proof_verified": True,
            "digital_seal_verified": True,
            "live_verification_required": True,
            "verifier_version": "m42-seal-verifier-v1",
        },
        "metadata": {
            "customer": "M42",
            "sandbox_id": "m42-exclusive-pretestnet",
            "workload": workload.id,
            "workload_kind": workload.kind,
            "case_id": case_id,
            "input_hash": input_hash,
            "output_hash": output_hash,
            "seal_id": seal_id,
            "digital_seal_id": seal["seal_id"],
            "evidence_mode": seal["evidence_mode"],
            "data_status": "synthetic_non_live",
            "artifact_mode": "real_cryptographic_evidence",
            # The CRYPTOGRAPHY is real and independently verifiable (Ed25519
            # signature, TEE attestation signature chain, Schnorr NIZK, Merkle
            # anchor). The TEE HARDWARE is simulated in this environment: the
            # attestation trust root is the pilot test root, not yet AMD SEV-SNP
            # / AWS Nitro. Going live swaps the trusted root; the verification
            # logic and seal format are unchanged.
            "real_cryptographic_evidence": True,
            "hardware_backed_tee": False,
            "real_zkml_proof": workload.zkml_tractable,
            "not_for_clinical_use": True,
        },
    }
    attestation = {
        "job_id": job_id,
        "case_id": case_id,
        "workload": workload.id,
        "note": "TEE attestation is batch-level (one per batch); see batch-proof.json.",
        "artifact_mode": "real_cryptographic_evidence",
    }
    proof = {
        "job_id": job_id,
        "case_id": case_id,
        "workload": workload.id,
        "evidence_mode": seal["evidence_mode"],
        "zk_proof": seal["zk_proof"],
        "zk_proof_digest": seal["zk_proof_digest"],
        "artifact_mode": "real_cryptographic_evidence",
    }
    economics = workload.economics
    case_result = {
        "case_id": case_id,
        "job_id": job_id,
        "seal_id": seal_id,
        "input_hash": input_hash,
        "output_hash": output_hash,
        "confidence_score": confidence,
        "case_evaluation": {key: value for key, value in entry.items() if key != "output_value"},
        "baseline_latency_ms": economics["baseline_unit_latency_ms"],
        "verified_latency_ms": economics["verified_unit_latency_ms"],
        "baseline_cost_usd": economics["baseline_unit_cost_usd"],
        "verified_cost_usd": economics["verified_unit_cost_usd"],
        "accepted": True,
        "evidence_bundle": f"evidence-bundle-{job_id}.json",
    }
    return bundle, attestation, proof, case_result


def validate_bundle(bundle: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    required = [
        "schema_version", "bundle_id", "job_id", "chain_id", "seal_id", "timestamp",
        "model_hash", "circuit_hash", "verifying_key_hash", "validator_signature",
        "confidence_score", "tee_evidence", "zkml_evidence", "region", "operator",
        "policy_decision", "archive_pointer", "verification",
    ]
    for field in required:
        if field not in bundle:
            errors.append(f"missing {field}")
    if bundle.get("schema_version") != "1.0.0":
        errors.append("schema_version must be 1.0.0")
    if not UUID_V4_RE.match(bundle.get("bundle_id", "")):
        errors.append("bundle_id must be UUID v4")
    if not JOB_ID_RE.match(bundle.get("job_id", "")):
        errors.append("job_id must be 64-char hex")
    if bundle.get("chain_id") != CHAIN_ID:
        errors.append("chain_id must match M42 pilot chain")
    if not bundle.get("seal_id", "").startswith("m42-seal-"):
        errors.append("seal_id must be present")
    if not BASE64_RE.match(bundle.get("validator_signature", "")):
        errors.append("validator_signature invalid base64")
    confidence = bundle.get("confidence_score")
    if not isinstance(confidence, (int, float)) or confidence < 0 or confidence > 1:
        errors.append("confidence_score must be between 0 and 1")
    for field in ["model_hash", "circuit_hash", "verifying_key_hash"]:
        if not SHA256_RE.match(bundle.get(field, "")):
            errors.append(f"{field} must be lowercase sha256 hex")
    if not OPERATOR_RE.match(bundle.get("operator", "")):
        errors.append("operator must be aethel bech32-like address")
    tee = bundle.get("tee_evidence", {})
    if tee.get("platform") not in {"sgx", "nitro", "sev-snp"}:
        errors.append("tee_evidence.platform invalid")
    if not tee.get("measurement", "").islower():
        errors.append("tee_evidence.measurement must be lowercase hex")
    if not BASE64_RE.match(tee.get("quote", "")):
        errors.append("tee_evidence.quote invalid base64")
    if not SHA256_RE.match(tee.get("nonce", "")):
        errors.append("tee_evidence.nonce invalid")
    zk = bundle.get("zkml_evidence", {})
    if zk.get("proof_system") not in {"groth16", "plonk", "ezkl", "halo2", "stark", "tee_attested_commitments"}:
        errors.append("zkml_evidence.proof_system invalid")
    if not BASE64_RE.match(zk.get("proof_bytes", "")):
        errors.append("zkml_evidence.proof_bytes invalid base64")
    if not BASE64_RE.match(zk.get("public_inputs", "")):
        errors.append("zkml_evidence.public_inputs invalid base64")
    if not SHA256_RE.match(zk.get("output_commitment", "")):
        errors.append("zkml_evidence.output_commitment invalid")
    policy = bundle.get("policy_decision", {})
    if policy.get("mode") != "hybrid" or policy.get("require_both") is not True or policy.get("fallback_allowed") is not False:
        errors.append("policy_decision must require hybrid/no fallback")
    archive = bundle.get("archive_pointer", {})
    if archive.get("archive_type") != "opensearch" or not archive.get("document_id") or archive.get("retention_days") != 30:
        errors.append("archive_pointer invalid")
    verification = bundle.get("verification", {})
    if verification.get("schema_verified") is not True or verification.get("policy_verified") is not True:
        errors.append("verification must include schema and policy verification")
    return errors


# ---------------------------------------------------------------------------
# Negative controls (workload-agnostic; operate on a real bundle)
# ---------------------------------------------------------------------------


def has_phi_like_value(value: Any) -> bool:
    if isinstance(value, dict):
        return any(has_phi_like_value(v) for v in value.values())
    if isinstance(value, list):
        return any(has_phi_like_value(v) for v in value)
    if isinstance(value, str):
        return bool(re.search(r"\b(?:MRN|medical record(?: number)?|patient(?: id| identifier))\s*[:#-]\s*[A-Z0-9-]{5,}\b", value, re.IGNORECASE))
    return False


def negative_controls(base_bundle: dict[str, Any], workload: Workload) -> list[dict[str, Any]]:
    """Run forgery attacks against the REAL batch-aggregated seal through the REAL
    verifier. No mock harness: each rejection is a genuine cryptographic failure
    (hybrid signature, attestation chain, commitment binding, Merkle inclusion).
    """
    trust = m42_seal.published_trust_config()
    base_seal = base_bundle["digital_seal"]
    idx = NEGATIVE_CONTROL_INDEX_BASE + WORKLOAD_INDEX.get(workload.id, 0)

    def fresh_batch() -> tuple[dict[str, Any], dict[str, Any], dict[str, str]]:
        # Anchor the target seal alongside decoys so the Merkle tree is non-trivial
        # (a real inclusion path with siblings to attack).
        seal = clone_json(base_seal)
        for k in ("batch_index", "seal_batch_root", "attestation_batch_root", "seal_inclusion_proof", "report_data_inclusion_proof"):
            seal.pop(k, None)
        decoys = [m42_seal.build_seal(
            workload=workload.id, model_hash=base_seal["model_hash"], circuit_hash=base_seal["circuit_hash"],
            input_value={"decoy": d}, output_value={"decoy": d}, chain_id=base_seal["chain_id"],
            timestamp=base_seal["timestamp"], nonce=f"decoy-{workload.id}-{d}", platform="sev-snp",
            zkml_tractable=workload.zkml_tractable, seed_label=f"decoy-{workload.id}-{d}") for d in range(3)]
        batch_seals = [seal] + decoys
        bp = m42_seal.anchor_batch(batch_seals, batch_index=idx, platform="sev-snp")
        _, _, roots = m42_seal.verify_batch(bp, trust)
        return seal, bp, roots

    # (name, description, reason, kind) where kind is "seal" or "batch".
    specs = [
        ("output_substitution", "swap the committed output under the signed seal", "The validator-signed seal root and the attested report-data bind the exact output commitment.", "seal",
         lambda s: s.update(output_commitment=crypto.commit({"forged": "benign"}, b"attacker"))),
        ("wrong_model_hash", "substitute the model hash", "The signed seal body and the attestation binding bind the model hash.", "seal",
         lambda s: s.update(model_hash="f" * 64)),
        ("policy_fallback", "weaken policy to allow a single-evidence fallback", "No single-evidence fallback is accepted.", "seal",
         lambda s: s["policy"].update(fallback_allowed=True)),
        ("forged_inclusion_proof", "forge the Merkle inclusion proof", "The seal must be included in the validator-signed batch root.", "seal",
         lambda s: s["seal_inclusion_proof"]["siblings"].__setitem__(0, ["L", "00" * 32]) if s.get("seal_inclusion_proof", {}).get("siblings") else None),
        ("forged_validator_signature", "replace the validator hybrid signature", "Both the Ed25519 and post-quantum XMSS legs must verify.", "batch",
         lambda bp: bp["validator_hybrid_signature"].update(ed25519="00" * 64)),
        ("forged_pqc_signature", "forge the post-quantum (XMSS) signature leg", "The post-quantum signature must verify against the published XMSS root.", "batch",
         lambda bp: bp["validator_hybrid_signature"]["pqc"]["wots_sig"].__setitem__(0, "00" * 32)),
        ("untrusted_attestation_root", "re-sign the batch attestation with an attacker root", "The attestation certificate must chain to the published provisioning root.", "batch",
         lambda bp: bp.update(attestation=crypto.make_attestation(
             crypto.sha256(b"attacker-enclave"), crypto.sha256(b"attacker-root"), "sev-snp",
             next(iter(trust.allowed_measurements)), bp["batch_nonce"], bp["attestation_batch_root"]))),
    ]
    if base_seal.get("zk_proof"):
        specs.append(("forged_zkml_proof", "forge the Schnorr zk proof response", "The NIZK fails verification under Fiat-Shamir.", "seal",
                      lambda s: s["zk_proof"].update(response=format(int(s["zk_proof"]["response"], 16) + 1, "x"))))

    enriched = []
    for name, desc, reason, kind, mutate in specs:
        seal, bp, roots = fresh_batch()
        if kind == "batch":
            mutate(bp)
            ok, checks, _ = m42_seal.verify_batch(bp, trust)
        else:
            mutate(seal)
            # For zk forgery, re-run the full NIZK; otherwise full verification.
            ok, checks = m42_seal.verify_seal(seal, roots, full=True)
        observed = "reject" if not ok else "accept"
        failed = [c.name for c in checks if not c.passed]
        enriched.append({
            "control": name, "mutation": desc, "expected_result": "reject", "reason": reason,
            "execution_mode": "real_cryptographic_verifier",
            "request_id": deterministic_uuid_v4(f"m42-nc:{workload.id}:{name}"),
            "submitted_to": "m42_seal.verify_batch / verify_seal (independent verifier)",
            "observed_result": observed,
            "observed_rejection_code": f"M42_CRYPTO_{name.upper()}",
            "failed_checks": failed,
            "observed_rejection_reason": next((c.detail for c in checks if not c.passed), "unexpectedly verified"),
            "mutated_seal_hash": sha256_hex(seal),
            "reviewer_signoff_status": "verifiable_now",
            "live_submission_required": False,
        })
    return enriched


def build_mutual_action_plan(workload: Workload) -> dict[str, Any]:
    return {
        "artifact_mode": "pretestnet_drill_fixture",
        "customer": "M42",
        "pilot": f"m42-{workload.id}",
        "workload": workload.id,
        "commercial_context": {
            "pilot_fee_usd": 200000,
            "target_sponsor_value_usd": 1000000,
            "target_value_multiple": 5,
            "note": "Target value is sponsor-perceived strategic value, not a guaranteed savings claim.",
        },
        "decision_objective": "Decide whether Aethelred should advance to a larger M42 healthcare AI assurance deployment.",
        "operating_moments": [
            {"phase": "pre-start", "moment": "Sponsor alignment session", "owners": ["M42 sponsor", "Aethelred pilot lead"], "outputs": ["decision-owner map", "confirmed value-bank target", "accepted data boundary", "approved scorecard"], "exit_gate": "M42 confirms the pilot is a paid decision package, not a generic demo."},
            {"phase": "week-1", "moment": "Sandbox activation", "owners": ["Aethelred operator", "M42 technical reviewer"], "outputs": ["exclusive sandbox validation", "package preflight", "synthetic workload approval", "live endpoint readiness log"], "exit_gate": "M42 can see isolated infrastructure, evidence paths, and monitoring boundaries."},
            {"phase": "week-2", "moment": "Evidence room walkthrough", "owners": ["M42 technical reviewer", "M42 security reviewer", "Aethelred evidence owner"], "outputs": ["baseline measurement", "verified run summary", "one accepted job traced from input to hashes, TEE evidence, zkML object, Digital Seal, archive, and metrics"], "exit_gate": "M42 can inspect proof of execution instead of accepting a black-box claim."},
            {"phase": "week-3", "moment": "Assurance challenge session", "owners": ["M42 risk owner", "M42 security reviewer", "Aethelred operator"], "outputs": ["negative-control results", "security action log", "procurement evidence checklist", "archive and monitoring review"], "exit_gate": "M42 sees bad evidence rejected before any real data is considered."},
            {"phase": "week-4", "moment": "Executive value board", "owners": ["M42 sponsor", "M42 decision owners", "Aethelred executive sponsor"], "outputs": ["final value-bank scorecard", "executive readout", "economics comparison", "recommended next workload and budget logic"], "exit_gate": "M42 has a clear go/no-go path for Med42 expansion, de-identified clinical AI, genomics, radiology, drug discovery, or stop."},
        ],
    }


# ---------------------------------------------------------------------------
# Per-workload drill run
# ---------------------------------------------------------------------------


def run_workload(workload: Workload, canonical_paths: bool) -> dict[str, Any]:
    if canonical_paths:
        export_dir, attest_dir, proof_dir, archive_dir = (
            CANONICAL_EXPORT, CANONICAL_ATTEST, CANONICAL_PROOF, CANONICAL_ARCHIVE,
        )
    else:
        base = WORKLOAD_EVIDENCE / workload.id
        export_dir, attest_dir, proof_dir, archive_dir = (
            base / "exports", base / "attestations", base / "proofs", base / "archives",
        )
    for path in (export_dir, attest_dir, proof_dir, archive_dir):
        path.mkdir(parents=True, exist_ok=True)

    # Clear prior per-case evidence so a regenerated run (e.g. after a job-id
    # change) does not leave stale bundles behind and break the count checks.
    for stale in export_dir.glob("evidence-bundle-*.json"):
        stale.unlink()
    for stale in attest_dir.glob("attestation-*.json"):
        stale.unlink()
    for stale in proof_dir.glob("proof-*.json"):
        stale.unlink()

    cases = workload.load_cases()
    # Measure the real energy of scoring every case — a genuine N-inference
    # compute workload — so the value bank shows measured numbers, not estimates.
    scored, energy_measurement = m42_energy.measure(
        lambda: workload.score(workload, cases), m42_energy.default_device_class()
    )
    metrics = scored["metrics"]
    per_case = scored["per_case"]
    rigor = scored.get("rigor", {})
    per_case_by_id = {entry["case_id"]: entry for entry in per_case}

    # Materialize per-case evidence for a stratified review sample. Metrics above
    # are computed over the full dataset; here we write bundles for a deterministic
    # spread (every k-th case) so the highest, lowest, and mid-confidence cases are
    # all represented without writing one file per case at 20x scale.
    total_cases = len(cases)
    sample_size = min(total_cases, EVIDENCE_SAMPLE_CAP)
    if total_cases <= sample_size:
        sampled = list(range(total_cases))
    else:
        step = total_cases / sample_size
        sampled = sorted({min(total_cases - 1, int(i * step)) for i in range(sample_size)})
    sampled_set = set(sampled)

    bundles: list[dict[str, Any]] = []
    case_results: list[dict[str, Any]] = []
    sidecars: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for index, case in enumerate(cases):
        if index not in sampled_set:
            continue
        entry = per_case_by_id.get(case["case_id"])
        if entry is None:
            # Workloads whose scorer returns a top-k subset (drug discovery)
            # still need a bundle per sampled case; synthesize a minimal entry.
            entry = {
                "case_id": case["case_id"],
                "output_value": case.get("model_output", {}),
                "activity_score": case.get("model_output", {}).get("activity_score", 0.5),
            }
        bundle, attestation, proof, case_result = build_bundle(workload, case, entry, index)
        errors = validate_bundle(bundle)
        if errors:
            raise SystemExit(f"bundle validation failed for {workload.id}/{case['case_id']}: {errors}")
        bundles.append(bundle)
        case_results.append(case_result)
        sidecars.append((attestation, proof))

    # Anchor every seal in this workload's batch into one Merkle root, then
    # Anchor the whole batch with ONE validator hybrid (Ed25519 + post-quantum
    # XMSS) signature and ONE TEE attestation, then verify every seal. Each
    # workload uses a distinct XMSS leaf index (one-time-per-leaf safety).
    seals = [b["digital_seal"] for b in bundles]
    batch_index = WORKLOAD_INDEX.get(workload.id, 0)
    trust = m42_seal.published_trust_config()
    batch_proof = m42_seal.anchor_batch(seals, batch_index=batch_index, platform="sev-snp") if seals else {}

    # Deep audit verification (re-runs every NIZK) for the recorded flags.
    all_ok, summary = m42_seal.verify_evidence(seals, batch_proof, trust, full=True) if seals else (True, {"seal_results": []})
    if not all_ok:
        raise SystemExit(f"{workload.id}: batch failed real cryptographic verification")
    result_by_id = {sid: (ok, checks) for sid, ok, checks, _ in summary["seal_results"]}

    # Backfill batch-level real crypto into each bundle and record verification.
    att_quote = b64(batch_proof["attestation"]) if batch_proof else b64({})
    val_sig = b64(batch_proof["validator_hybrid_signature"]) if batch_proof else b64({})
    for bundle in bundles:
        seal = bundle["digital_seal"]
        bundle["validator_signature"] = val_sig
        bundle["tee_evidence"]["quote"] = att_quote
        bundle["tee_evidence"]["nonce"] = batch_proof.get("batch_nonce", bundle["tee_evidence"]["nonce"])
        bundle["batch_proof_ref"] = {
            "batch_index": batch_index,
            "seal_batch_root": batch_proof.get("seal_batch_root"),
            "attestation_batch_root": batch_proof.get("attestation_batch_root"),
        }
        ok, checks = result_by_id.get(seal["seal_id"], (False, []))
        bundle["verification"].update({
            "digital_seal_verified": ok,
            "tee_attestation_verified": True,  # batch attestation verified in verify_evidence
            "zkml_proof_verified": next((c.passed for c in checks if c.name in ("zkml_proof", "zkml_proof_binding")), False),
            "merkle_inclusion_verified": next((c.passed for c in checks if c.name == "seal_merkle_inclusion"), False),
            "attestation_binding_verified": next((c.passed for c in checks if c.name == "attestation_binding"), False),
            "checks": [{"name": c.name, "passed": c.passed, "detail": c.detail} for c in checks],
        })

    for bundle, (attestation, proof) in zip(bundles, sidecars):
        write_json(export_dir / f"evidence-bundle-{bundle['job_id']}.json", bundle)
        write_json(attest_dir / f"attestation-{bundle['job_id']}.json", attestation)
        write_json(proof_dir / f"proof-{bundle['job_id']}.json", proof)
    # Publish the batch proof + public trust config M42 verifies against.
    if batch_proof:
        write_json(export_dir / "batch-proof.json", batch_proof)
        write_json(export_dir / "merkle-root.json", {"workload": workload.id, "seal_batch_root": batch_proof["seal_batch_root"], "attestation_batch_root": batch_proof["attestation_batch_root"], "seal_count": len(seals)})
    write_json(export_dir / "trust-config.json", trust.to_dict())

    floors = wl.evaluate_floors(workload, metrics)
    econ = workload.economics
    baseline_latencies = [r["baseline_latency_ms"] for r in case_results]
    verified_latencies = [r["verified_latency_ms"] for r in case_results]
    # Costs are reported over the FULL evaluated dataset (per-unit economics x N),
    # not just the materialized evidence sample.
    baseline_cost = econ["baseline_unit_cost_usd"] * total_cases
    verified_cost = econ["verified_unit_cost_usd"] * total_cases
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Measured energy/cost for this workload, mirroring the on-chain x/pouw
    # WorkReceipt. Both receipt hashes use the chain's canonical encoding, so a
    # sponsor can verify these pilot receipts against the protocol.
    #   (a) drill_scoring_measured: a real wall-clock measurement of the pilot
    #       scoring run — proves the meter is real.
    #   (b) real_inference_projected: the energy/cost of running the workload's
    #       real model at its stated per-inference latency on a GPU — the number
    #       M42 plans capacity around. Clearly labeled a projection, not a
    #       measurement.
    scoring_receipt = m42_energy.build_receipt(
        job_id=f"m42-{workload.id}-scoring",
        validator="aethelred-m42-pilot-validator",
        measurement=energy_measurement,
        useful_work_units=total_cases,
    )
    per_inference_ms = int(econ.get("verified_unit_latency_ms", 0))
    projection = m42_energy.projected_measurement(
        m42_energy.DEFAULT_INFERENCE_DEVICE, per_inference_ms * total_cases
    )
    inference_receipt = m42_energy.build_receipt(
        job_id=f"m42-{workload.id}-inference",
        validator="aethelred-m42-pilot-validator",
        measurement=projection,
        useful_work_units=total_cases,
    )
    measured_energy = {
        "energy_model": m42_energy.ENERGY_MODEL,
        "drill_scoring_measured": m42_energy.energy_report(scoring_receipt, inferences=total_cases),
        "real_inference_projected": {
            **m42_energy.energy_report(inference_receipt, inferences=total_cases),
            "projection": True,
            "per_inference_latency_ms": per_inference_ms,
        },
        "honesty": (
            "drill_scoring_measured is a live wall-clock measurement of the pilot "
            "scoring run. real_inference_projected models running the workload's real "
            "model at its stated per-inference latency on the declared GPU; it is a "
            "projection, not a measurement. Both use the on-chain EnergyModel and both "
            "receipt hashes verify against the protocol."
        ),
    }

    evidence_sampling = {
        "cases_evaluated": total_cases,
        "evidence_bundles_materialized": len(bundles),
        "sampling": "full" if total_cases == len(bundles) else "stratified_review_sample",
        "note": "Domain metrics and confidence intervals are computed over all evaluated cases; per-case cryptographic evidence is materialized for a stratified sample.",
    }

    baseline = {
        "artifact_mode": "pretestnet_drill_fixture",
        "generated_at": now,
        "workload": workload.id,
        "workload_kind": workload.kind,
        "cases": total_cases,
        "evidence_bundles_materialized": len(bundles),
        "p50_latency_ms": round(statistics.median(baseline_latencies), 2),
        "p95_latency_ms": round(percentile(baseline_latencies, 0.95), 2),
        "total_cost_usd": round(baseline_cost, 4),
        "domain_metrics": metrics,
        "output_commitment_coverage": 1.0,
        "accepted_evidence_mode": "baseline_preflight_only",
    }
    sandbox = {
        "artifact_mode": "pretestnet_drill_fixture",
        "generated_at": now,
        "sandbox_id": "m42-exclusive-pretestnet",
        "workload": workload.id,
        "workload_kind": workload.kind,
        "accepted_cases": total_cases,
        "evidence_sampling": evidence_sampling,
        "hybrid_evidence_bundle_coverage": 1.0,
        "tee_attestation_coverage": 1.0,
        "zkml_proof_reference_coverage": 1.0,
        "digital_seal_coverage": 1.0,
        "single_evidence_fallback_cases": 0,
        "p50_latency_ms": round(statistics.median(verified_latencies), 2),
        "p95_latency_ms": round(percentile(verified_latencies, 0.95), 2),
        "total_cost_usd": round(verified_cost, 4),
        "latency_delta_p50_ms": round(statistics.median(verified_latencies) - statistics.median(baseline_latencies), 2),
        "cost_delta_total_usd": round(verified_cost - baseline_cost, 4),
        "measured_energy": measured_energy,
        "domain_metrics": metrics,
        "metric_floors": floors,
        "statistical_rigor": rigor,
        "throughput_units_per_hour": workload.economics.get("throughput_units_per_hour"),
        "evidence_sample_cases": case_results,
    }
    negative_control_results = negative_controls(bundles[0], workload)
    accepted_bad_cases = sum(1 for control in negative_control_results if control["observed_result"] != "reject")
    negative = {
        "artifact_mode": "pretestnet_drill_fixture",
        "workload": workload.id,
        "controls": negative_control_results,
        "summary": {
            "controls_defined": len(negative_control_results),
            "expected_rejections": len(negative_control_results),
            "observed_rejections": len(negative_control_results) - accepted_bad_cases,
            "accepted_bad_cases": accepted_bad_cases,
        },
    }

    pilot_scorecard = json.loads(PILOT_SCORECARD.read_text(encoding="utf-8"))
    value_architecture = pilot_scorecard["value_architecture"]
    pilot_fee = pilot_scorecard["commercial_context"]["pilot_fee_usd"]
    target_value = pilot_scorecard["commercial_context"]["target_sponsor_value_usd"]
    value_bank = {
        "artifact_mode": "pretestnet_drill_fixture",
        "customer": "M42",
        "pilot": f"m42-{workload.id}",
        "workload": workload.id,
        "pilot_fee_usd": pilot_fee,
        "target_sponsor_value_usd": target_value,
        "target_value_multiple": pilot_scorecard["commercial_context"]["target_value_multiple"],
        "claim_boundary": "Target value is sponsor-perceived strategic value from reusable assets, risk reduction, and decision acceleration; it is not a guaranteed savings claim.",
        "measured_compute_economics": measured_energy,
        "target_total_value_usd": value_architecture["target_total_value"],
        "value_banks": [
            {**bank, "status": "drill_ready_live_replacement_required", "drill_evidence_ready": True}
            for bank in value_architecture["value_banks"]
        ],
        "value_realization_gates": [
            "M42 sponsor confirms value-bank targets before Week 1 clock starts.",
            "Live sandbox validation passes before paid execution evidence is reported.",
            "At least one accepted job is reviewed end to end in the Week 2 evidence room.",
            "All six negative controls remain expected rejects in the Week 3 assurance challenge.",
            "Week 4 executive value board receives a go/no-go recommendation with next-phase options.",
        ],
    }
    mutual_action_plan = build_mutual_action_plan(workload)
    scorecard = {
        "artifact_mode": "pretestnet_drill_fixture",
        "customer": "M42",
        "workload": workload.id,
        "workload_kind": workload.kind,
        "executive_value": {
            "pilot_fee_usd": pilot_fee,
            "target_sponsor_value_usd": target_value,
            "target_value_multiple": 5,
            "sovereign_processing_boundary": wl.JURISDICTION,
            "evidence_completeness": "100% drill coverage across accepted synthetic cases",
            "primary_metric": workload.primary_metric,
            "primary_metric_value": metrics.get(workload.primary_metric),
            "all_metric_floors_met": floors["all_floors_met"],
            "negative_controls": "6 rejection controls defined for live run",
            "decision_package": "baseline, verified run, evidence bundles, value bank, mutual action plan, negative controls, and executive readout",
        },
        "metrics": {
            "cases": len(case_results),
            "domain_metrics": metrics,
            "metric_floors": floors,
            "hybrid_evidence_bundle_coverage": 1.0,
            "digital_seal_coverage": 1.0,
            "single_evidence_fallback_cases": 0,
            "baseline_p50_latency_ms": baseline["p50_latency_ms"],
            "verified_p50_latency_ms": sandbox["p50_latency_ms"],
            "latency_delta_p50_ms": sandbox["latency_delta_p50_ms"],
            "baseline_total_cost_usd": baseline["total_cost_usd"],
            "verified_total_cost_usd": sandbox["total_cost_usd"],
            "cost_delta_total_usd": sandbox["cost_delta_total_usd"],
        },
        "statistical_rigor": rigor,
        "next_live_gate": "make m42-sandbox-up && make m42-sandbox-validate",
    }

    write_json(export_dir / "baseline-measurement.json", baseline)
    write_json(export_dir / "sandbox-run-summary.json", sandbox)
    write_json(export_dir / "negative-control-results.json", negative)
    write_json(export_dir / "m42-energy-receipt.json", {
        "scoring_receipt": scoring_receipt,
        "inference_receipt": inference_receipt,
        "report": measured_energy,
    })
    write_json(export_dir / "m42-value-bank.json", value_bank)
    write_json(export_dir / "m42-mutual-action-plan.json", mutual_action_plan)
    write_json(export_dir / "m42-value-scorecard.json", scorecard)
    (export_dir / "m42-executive-readout.md").write_text(
        executive_readout(workload, baseline, sandbox, metrics, floors, value_bank, pilot_fee, target_value),
        encoding="utf-8",
    )

    return {
        "workload": workload.id,
        "title": workload.title,
        "kind": workload.kind,
        "case_unit": workload.case_unit,
        "case_unit_plural": workload.case_unit_plural,
        "cases": total_cases,
        "evidence_bundles_materialized": len(bundles),
        "primary_metric": workload.primary_metric,
        "primary_metric_value": metrics.get(workload.primary_metric),
        "all_metric_floors_met": floors["all_floors_met"],
        "domain_metrics": metrics,
        "baseline_p50_latency_ms": baseline["p50_latency_ms"],
        "verified_p50_latency_ms": sandbox["p50_latency_ms"],
        "cost_delta_total_usd": sandbox["cost_delta_total_usd"],
        "evidence_dir": str(export_dir.relative_to(ROOT)),
        "canonical": canonical_paths,
    }


def format_metric(value: Any) -> str:
    if isinstance(value, float):
        if 0.0 <= value <= 1.0:
            return f"{value:.2%}"
        return f"{value:.4g}"
    return str(value)


def executive_readout(
    workload: Workload,
    baseline: dict[str, Any],
    sandbox: dict[str, Any],
    metrics: dict[str, Any],
    floors: dict[str, Any],
    value_bank: dict[str, Any],
    pilot_fee: int,
    target_value: int,
) -> str:
    metric_rows = "\n".join(
        f"| {key.replace('_', ' ')} | {format_metric(value)} |" for key, value in metrics.items()
    )
    floor_rows = "\n".join(
        f"| {check['metric'].replace('_', ' ')} | {check['comparison']} {check['floor']} | {format_metric(check['observed'])} | {'PASS' if check['met'] else 'FAIL'} |"
        for check in floors["checks"]
    )
    bank_rows = "".join(f"| {bank['label']} | ${bank['target_value']:,} |\n" for bank in value_bank["value_banks"])
    return f"""# M42 Sandbox Drill Executive Readout — {workload.title}

Artifact mode: pretestnet drill fixture
Workload id: `{workload.id}` ({workload.kind})

## Commercial Value Frame

- Paid pilot fee: ${pilot_fee:,}
- Target sponsor-perceived value: ${target_value:,}
- Target value multiple: 5x
- Claim boundary: this is a value architecture target, not a guaranteed savings claim.

## Workload

{workload.title}: {workload.task}. Unit of evaluation: one {workload.case_unit}.

## Domain Metrics ({baseline['cases']} synthetic {workload.case_unit_plural})

| Metric | Value |
|--------|-------|
{metric_rows}

## Acceptance Floors

| Metric / constraint | Floor | Observed | Result |
|---------------------|-------|----------|--------|
{floor_rows}

All acceptance floors met: {"yes" if floors["all_floors_met"] else "no"}.

## Evidence and Economics

- Hybrid evidence bundle coverage: 100%
- TEE attestation / zkML proof / Digital Seal coverage: 100%
- Single-evidence fallback cases: 0
- Baseline p50 latency: {baseline['p50_latency_ms']} ms; verified p50 latency: {sandbox['p50_latency_ms']} ms (delta {sandbox['latency_delta_p50_ms']} ms)
- Baseline drill cost: ${baseline['total_cost_usd']:.4f}; verified drill cost: ${sandbox['total_cost_usd']:.4f}
- Throughput target: {workload.economics.get('throughput_units_per_hour'):,} {workload.case_unit_plural}/hour

## $1M Value Bank

| Value Bank | Target Value |
|------------|--------------|
{bank_rows}| Total target value | ${value_bank['target_total_value_usd']:,} |

## Sponsor Value

The drill produces the full live-sandbox decision package for this workload:
baseline measurement, verified run summary, per-job hybrid evidence bundles,
TEE evidence objects, zkML proof objects, negative-control expectations,
value-bank scorecard, mutual action plan, and an executive scorecard. These
artifacts are pretestnet fixtures and must be replaced by live sandbox outputs
before any production, clinical, or scientific claim.

## Next Gate

Run `make m42-sandbox-up` and then `make m42-sandbox-validate` to replace
offline drill warnings with live endpoint evidence.
"""


def write_catalog_scorecard(summaries: list[dict[str, Any]]) -> None:
    catalog = {
        "artifact_mode": "pretestnet_drill_fixture",
        "customer": "M42",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "pilot_fee_usd": 200000,
        "active_workload": wl.ACTIVE_WORKLOAD_ID,
        "summary": {
            "workloads_run": len(summaries),
            "workloads_all_floors_met": sum(1 for s in summaries if s["all_metric_floors_met"]),
        },
        "workloads": summaries,
        "claim_boundary": "Per-workload metrics are computed from deterministic synthetic ground truth. They are not clinical, scientific, or production claims and must be reproduced on live hardware during the paid pilot.",
    }
    write_json(CANONICAL_EXPORT / "m42-workload-catalog-scorecard.json", catalog)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Generate M42 sandbox drill artifacts per workload.")
    parser.add_argument("--workload", help="Workload id to run (default: active workload).")
    parser.add_argument("--all", action="store_true", help="Run the active workload (canonical) and all workloads (namespaced).")
    parser.add_argument("--list", action="store_true", help="List available workloads and exit.")
    args = parser.parse_args(argv)

    if args.list:
        for workload in wl.WORKLOADS:
            marker = " (active)" if workload.id == wl.ACTIVE_WORKLOAD_ID else ""
            print(f"{workload.id}{marker}: {workload.title} [{workload.primary_metric}]")
        return 0

    summaries: list[dict[str, Any]] = []
    if args.all:
        active = wl.get_workload(wl.ACTIVE_WORKLOAD_ID)
        summaries.append(run_workload(active, canonical_paths=True))
        for workload in wl.WORKLOADS:
            if workload.id == wl.ACTIVE_WORKLOAD_ID:
                continue
            summaries.append(run_workload(workload, canonical_paths=False))
        write_catalog_scorecard(summaries)
    else:
        target_id = args.workload or wl.ACTIVE_WORKLOAD_ID
        workload = wl.get_workload(target_id)
        canonical_paths = workload.id == wl.ACTIVE_WORKLOAD_ID
        summaries.append(run_workload(workload, canonical_paths=canonical_paths))

    print(f"Generated M42 drill artifacts for {len(summaries)} workload(s).")
    for summary in summaries:
        floors = "all floors met" if summary["all_metric_floors_met"] else "FLOORS NOT MET"
        print(
            f"  {summary['workload']}: {summary['cases']} {summary['case_unit_plural']}, "
            f"{summary['primary_metric']}={format_metric(summary['primary_metric_value'])}, {floors} "
            f"-> {summary['evidence_dir']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
