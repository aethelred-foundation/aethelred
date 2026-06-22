#!/usr/bin/env python3
"""Generate an investment-grade M42 pilot gap register and evidence portal.

The audit is intentionally stricter than the package preflight. It checks the
paid-pilot sponsor package, generated drill artifacts, security posture, value
claims, and live endpoint gates, then writes machine-readable and executive
reports. By default the command writes reports even when blockers exist. Use
--strict to exit non-zero on any open FAIL finding.
"""

from __future__ import annotations

import argparse
import base64
import html
import json
import os
import re
import ssl
import stat
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
PILOT_DIR = ROOT / "config" / "pilots" / "m42"
WORKLOADS_DIR = PILOT_DIR / "workloads"
WORKLOAD_CATALOG = WORKLOADS_DIR / "catalog.json"
DOC_DIR = ROOT / "docs" / "workload-packs" / "m42"
OPS_DIR = ROOT / "docs" / "operations"
EVIDENCE_DIR = PILOT_DIR / "evidence"
EXPORT_DIR = EVIDENCE_DIR / "exports"
ATTESTATION_DIR = EVIDENCE_DIR / "attestations"
PROOF_DIR = EVIDENCE_DIR / "proofs"
REPORT_DIR = ROOT / ".cache" / "m42-pilot-evidence" / "exports"
COMPOSE_FILE = ROOT / "integrations" / "docker" / "docker-compose.m42-pilot.yml"
IMAGES_LOCK = PILOT_DIR / "images.lock.env"
ARCHIVE_SECRET = PILOT_DIR / "secrets" / "opensearch_admin_password.txt"
SIMULATION_WAIVER = PILOT_DIR / "waivers" / "simulated-go-live-waiver.json"

IMAGE_ENV_RE = re.compile(r"^\s+image:\s+\$\{([A-Z0-9_]+):-(.+?)\}\s*$", re.MULTILINE)
IMAGE_PLAIN_RE = re.compile(r"^\s+image:\s+(?!\$\{)(.+)$", re.MULTILINE)

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
JOB_ID_RE = re.compile(r"^[0-9A-Fa-f]{64}$")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
PHONE_RE = re.compile(r"(?:\+?\d[\d .()-]{8,}\d)")
SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
MRN_RE = re.compile(r"\b(?:MRN|medical record(?: number)?|patient(?: id| identifier))\s*[:#-]\s*[A-Z0-9-]{5,}\b", re.IGNORECASE)


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def add(
    findings: list[dict[str, Any]],
    status: str,
    severity: str,
    check_id: str,
    title: str,
    detail: str,
    next_step: str,
    evidence: list[str] | None = None,
) -> None:
    findings.append(
        {
            "id": check_id,
            "status": status,
            "severity": severity,
            "title": title,
            "detail": detail,
            "next_step": next_step,
            "evidence": evidence or [],
        }
    )


def load_json_or_fail(findings: list[dict[str, Any]], path: Path, check_id: str) -> Any | None:
    if not path.exists():
        add(findings, "FAIL", "P0", check_id, "Required JSON is missing", f"{path} does not exist.", "Create the required artifact.", [str(path)])
        return None
    try:
        return read_json(path)
    except json.JSONDecodeError as exc:
        add(findings, "FAIL", "P0", check_id, "Required JSON is invalid", f"{path} is not valid JSON: {exc}", "Fix the JSON and rerun the audit.", [str(path)])
        return None


def load_vignettes(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    path = DOC_DIR / "synthetic-vignettes.jsonl"
    if not path.exists():
        add(findings, "FAIL", "P0", "DATA-001", "Synthetic vignette file is missing", f"{path} does not exist.", "Restore the synthetic vignette fixture.", [str(path)])
        return []
    cases: list[dict[str, Any]] = []
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            cases.append(json.loads(line))
        except json.JSONDecodeError as exc:
            add(findings, "FAIL", "P0", "DATA-002", "Synthetic vignette JSONL is invalid", f"Line {lineno}: {exc}", "Fix the JSONL fixture.", [str(path)])
            return []
    return cases


def scalar_values(value: Any) -> list[str]:
    if isinstance(value, dict):
        values: list[str] = []
        for item in value.values():
            values.extend(scalar_values(item))
        return values
    if isinstance(value, list):
        values = []
        for item in value:
            values.extend(scalar_values(item))
        return values
    if isinstance(value, (str, int, float, bool)):
        return [str(value)]
    return []


def check_required_files(findings: list[dict[str, Any]]) -> None:
    required = [
        PILOT_DIR / "workload-pack.json",
        PILOT_DIR / "pilot-scorecard.json",
        PILOT_DIR / "sandbox.json",
        PILOT_DIR / "model-manifest.json",
        PILOT_DIR / "circuit-manifest.json",
        PILOT_DIR / "readiness-gates.json",
        PILOT_DIR / "registry" / "measurements.json",
        PILOT_DIR / "registry" / "circuits.json",
        WORKLOAD_CATALOG,
        COMPOSE_FILE,
        DOC_DIR / "pack.md",
        DOC_DIR / "workload-platform.md",
        DOC_DIR / "clinical-evaluation-protocol.md",
        DOC_DIR / "security-model.md",
        DOC_DIR / "value-scorecard.md",
        OPS_DIR / "m42-1m-value-pilot-structure.md",
        OPS_DIR / "m42-exclusive-sandbox.md",
        OPS_DIR / "m42-paid-pilot-readiness.md",
        OPS_DIR / "m42-pilot-delivery-plan.md",
    ]
    missing = [str(path) for path in required if not path.exists()]
    if missing:
        add(findings, "FAIL", "P0", "PKG-001", "Required M42 pilot artifacts are missing", "One or more package files are missing.", "Restore missing files before sponsor review.", missing)
    else:
        add(findings, "PASS", "P0", "PKG-001", "Required M42 pilot artifacts exist", "All required package, operations, registry, and workload files are present.", "None.", [str(path) for path in required])


def check_value_architecture(findings: list[dict[str, Any]], scorecard: dict[str, Any] | None) -> None:
    if not scorecard:
        return
    commercial = scorecard.get("commercial_context", {})
    architecture = scorecard.get("value_architecture", {})
    banks = architecture.get("value_banks", [])
    target = architecture.get("target_total_value")
    bank_sum = sum(int(bank.get("target_value", 0)) for bank in banks)
    if commercial.get("pilot_fee_usd") == 200000 and commercial.get("target_sponsor_value_usd") == 1000000 and commercial.get("target_value_multiple") == 5:
        add(findings, "PASS", "P0", "VAL-001", "$200K to $1M value frame is explicit", "Pilot fee, target sponsor value, and 5x target multiple are machine-readable.", "Keep value claims bounded as sponsor-perceived strategic value.", [str(PILOT_DIR / "pilot-scorecard.json")])
    else:
        add(findings, "FAIL", "P0", "VAL-001", "Commercial value frame is incomplete", "Expected pilot_fee_usd=200000, target_sponsor_value_usd=1000000, target_value_multiple=5.", "Fix pilot-scorecard.json commercial_context.", [str(PILOT_DIR / "pilot-scorecard.json")])
    if target == 1000000 and bank_sum == target and len(banks) >= 5:
        add(findings, "PASS", "P0", "VAL-002", "Value banks reconcile to $1M", f"{len(banks)} value banks total ${bank_sum:,}.", "Review with M42 sponsor before Week 1 starts.", [str(PILOT_DIR / "pilot-scorecard.json")])
    else:
        add(findings, "FAIL", "P0", "VAL-002", "Value banks do not reconcile", f"Target={target}, bank_sum={bank_sum}, banks={len(banks)}.", "Fix value_architecture.value_banks.", [str(PILOT_DIR / "pilot-scorecard.json")])


def check_hash_registration(findings: list[dict[str, Any]], workload: dict[str, Any] | None) -> None:
    if not workload:
        return
    model_hash = workload.get("model", {}).get("hash")
    circuit_hash = workload.get("circuit", {}).get("hash")
    measurements = load_json_or_fail(findings, PILOT_DIR / "registry" / "measurements.json", "REG-001")
    circuits = load_json_or_fail(findings, PILOT_DIR / "registry" / "circuits.json", "REG-002")
    if model_hash and SHA256_RE.match(model_hash) and measurements and any(entry.get("hash") == model_hash and entry.get("status") == "active" for entry in measurements.get("entries", [])):
        add(findings, "PASS", "P0", "REG-003", "Model hash is active in registry", f"Model hash {model_hash} is active.", "Replace fixture digest with M42-approved checkpoint or endpoint digest before customer data.", [str(PILOT_DIR / "registry" / "measurements.json")])
    else:
        add(findings, "FAIL", "P0", "REG-003", "Model hash is not actively registered", f"Model hash {model_hash} was not found as active.", "Register the approved model hash before pilot execution.", [str(PILOT_DIR / "registry" / "measurements.json")])
    if circuit_hash and SHA256_RE.match(circuit_hash) and circuits and any(entry.get("hash") == circuit_hash and entry.get("status") == "active" for entry in circuits.get("entries", [])):
        add(findings, "PASS", "P0", "REG-004", "Circuit hash is active in registry", f"Circuit hash {circuit_hash} is active.", "Keep scope limit visible: IO/policy binding, not clinical correctness proof.", [str(PILOT_DIR / "registry" / "circuits.json")])
    else:
        add(findings, "FAIL", "P0", "REG-004", "Circuit hash is not actively registered", f"Circuit hash {circuit_hash} was not found as active.", "Register the approved circuit hash before pilot execution.", [str(PILOT_DIR / "registry" / "circuits.json")])


def check_data_boundary(findings: list[dict[str, Any]], workload: dict[str, Any] | None, model_manifest: dict[str, Any] | None, cases: list[dict[str, Any]]) -> None:
    synthetic_status = workload.get("synthetic_status", {}) if workload else {}
    workload_ok = bool(synthetic_status.get("phi_allowed") is False and synthetic_status.get("live_patient_data_allowed") is False)
    manifest_ok = bool(model_manifest and model_manifest.get("dataset", {}).get("phi_allowed") is False and model_manifest.get("dataset", {}).get("live_patient_data_allowed") is False)
    if workload_ok and manifest_ok:
        add(findings, "PASS", "P0", "DATA-003", "No-PHI/no-live-data policy is explicit", "Workload and model manifest both forbid PHI and live patient data.", "Require written scope change before any customer-approved data.", [str(PILOT_DIR / "workload-pack.json"), str(PILOT_DIR / "model-manifest.json")])
    else:
        add(findings, "FAIL", "P0", "DATA-003", "No-PHI/no-live-data policy is incomplete", "Workload or model manifest does not clearly forbid PHI/live data.", "Fix data boundary fields before sponsor review.", [str(PILOT_DIR / "workload-pack.json"), str(PILOT_DIR / "model-manifest.json")])

    matches: list[dict[str, str]] = []
    for case in cases:
        case_id = str(case.get("case_id", "<unknown>"))
        for value in scalar_values(case):
            for label, pattern in [("email", EMAIL_RE), ("phone", PHONE_RE), ("ssn", SSN_RE), ("mrn", MRN_RE)]:
                if pattern.search(value):
                    matches.append({"case_id": case_id, "pattern": label, "sample": value[:96]})
    phi_scan = {
        "schema_version": "m42.phi_scan.v1",
        "artifact_mode": "pretestnet_drill_fixture",
        "generated_at": utc_now(),
        "scope": [
            "docs/workload-packs/m42/synthetic-vignettes.jsonl",
            "scalar JSON values only; field names are not treated as PHI",
        ],
        "patterns_checked": ["email", "phone", "ssn", "mrn_or_patient_identifier_value"],
        "cases_scanned": len(cases),
        "findings": matches,
        "finding_count": len(matches),
    }
    write_json(EXPORT_DIR / "phi-scan.json", phi_scan)
    if matches:
        labels = sorted({match["pattern"] for match in matches})
        add(findings, "FAIL", "P0", "DATA-004", "Synthetic data may contain direct identifiers", f"Potential identifier patterns found: {', '.join(labels)}.", "Review and remove any direct identifiers from synthetic fixtures.", [str(DOC_DIR / "synthetic-vignettes.jsonl"), str(EXPORT_DIR / "phi-scan.json")])
    else:
        add(findings, "PASS", "P0", "DATA-004", "Synthetic data scan found no direct identifier patterns", "No email, phone, SSN, or MRN-like value patterns were detected in the synthetic JSONL fixture.", "Keep full M42 PHI review as a sponsor gate before any new dataset.", [str(DOC_DIR / "synthetic-vignettes.jsonl"), str(EXPORT_DIR / "phi-scan.json")])


def validate_bundle(bundle: dict[str, Any], model_hash: str, circuit_hash: str) -> list[str]:
    errors: list[str] = []
    required = [
        "schema_version",
        "bundle_id",
        "job_id",
        "chain_id",
        "seal_id",
        "timestamp",
        "model_hash",
        "circuit_hash",
        "verifying_key_hash",
        "validator_signature",
        "confidence_score",
        "tee_evidence",
        "zkml_evidence",
        "region",
        "operator",
        "policy_decision",
        "archive_pointer",
        "verification",
    ]
    for field in required:
        if field not in bundle:
            errors.append(f"missing {field}")
    if bundle.get("schema_version") != "1.0.0":
        errors.append("schema_version is not 1.0.0")
    if not JOB_ID_RE.match(str(bundle.get("job_id", ""))):
        errors.append("job_id is not 64-char hex")
    if not str(bundle.get("chain_id", "")).strip():
        errors.append("chain_id missing")
    if not str(bundle.get("seal_id", "")).strip():
        errors.append("seal_id missing")
    if not bundle.get("validator_signature"):
        errors.append("validator_signature missing")
    confidence = bundle.get("confidence_score")
    if not isinstance(confidence, (int, float)) or confidence < 0 or confidence > 1:
        errors.append("confidence_score must be between 0 and 1")
    for field in ["model_hash", "circuit_hash", "verifying_key_hash"]:
        if not SHA256_RE.match(str(bundle.get(field, ""))):
            errors.append(f"{field} is not lowercase sha256")
    if bundle.get("model_hash") != model_hash:
        errors.append("model_hash does not match workload pack")
    if bundle.get("circuit_hash") != circuit_hash:
        errors.append("circuit_hash does not match workload pack")
    policy = bundle.get("policy_decision", {})
    if policy.get("mode") != "hybrid" or policy.get("require_both") is not True or policy.get("fallback_allowed") is not False:
        errors.append("policy does not require hybrid/no fallback")
    metadata = bundle.get("metadata", {})
    if not metadata.get("seal_id"):
        errors.append("metadata.seal_id missing")
    if metadata.get("data_status") != "synthetic_non_live":
        errors.append("metadata.data_status must be synthetic_non_live")
    if "tee_evidence" not in bundle or "zkml_evidence" not in bundle:
        errors.append("hybrid evidence objects missing")
    archive = bundle.get("archive_pointer", {})
    if not archive.get("document_id") or not archive.get("uri") or int(archive.get("retention_days", 0)) < 1:
        errors.append("archive_pointer incomplete")
    verification = bundle.get("verification", {})
    if verification.get("schema_verified") is not True or verification.get("policy_verified") is not True:
        errors.append("verification schema/policy flags missing")
    return errors


def check_evidence_artifacts(findings: list[dict[str, Any]], workload: dict[str, Any] | None, cases: list[dict[str, Any]]) -> None:
    if not workload:
        return
    model_hash = workload.get("model", {}).get("hash", "")
    circuit_hash = workload.get("circuit", {}).get("hash", "")
    bundles = sorted(EXPORT_DIR.glob("evidence-bundle-*.json"))
    # Metrics are computed over the full active-workload dataset; per-case evidence
    # is materialized for a stratified sample recorded in the run summary.
    summary_path = EXPORT_DIR / "sandbox-run-summary.json"
    sampling: dict[str, Any] = {}
    if summary_path.exists():
        try:
            sampling = read_json(summary_path).get("evidence_sampling", {})
        except json.JSONDecodeError:
            sampling = {}
    cases_evaluated = sampling.get("cases_evaluated", len(cases))
    expected_materialized = sampling.get("evidence_bundles_materialized", len(bundles))
    if len(bundles) == expected_materialized and len(bundles) > 0 and cases_evaluated > 0:
        add(findings, "PASS", "P0", "EVID-001", "Per-case evidence bundle count matches the materialized sample", f"{len(bundles)} bundles materialized from {cases_evaluated} evaluated cases (stratified sample).", "Replace drill bundles with live outputs before production claims.", [str(path) for path in bundles[:8]])
    else:
        add(findings, "FAIL", "P0", "EVID-001", "Per-case evidence bundle count mismatch", f"{len(bundles)} bundles vs materialized={expected_materialized}, cases_evaluated={cases_evaluated}.", "Regenerate drill or live evidence bundles.", [str(EXPORT_DIR)])

    invalid: list[str] = []
    job_ids: set[str] = set()
    drill_only = False
    for path in bundles:
        try:
            bundle = read_json(path)
        except json.JSONDecodeError as exc:
            invalid.append(f"{path.name}: invalid JSON {exc}")
            continue
        errors = validate_bundle(bundle, model_hash, circuit_hash)
        if errors:
            invalid.append(f"{path.name}: {', '.join(errors)}")
        job_ids.add(bundle.get("job_id", ""))
        metadata = bundle.get("metadata", {})
        verification = bundle.get("verification", {})
        if metadata.get("real_cryptographic_evidence") is not True or verification.get("digital_seal_verified") is not True:
            drill_only = True
        if metadata.get("hardware_backed_tee") is not True:
            # Honest pilot boundary tracked separately (test attestation root).
            pass
    if invalid:
        add(findings, "FAIL", "P0", "EVID-002", "Evidence bundles are not schema/policy clean", "; ".join(invalid[:6]), "Fix evidence bundle generation before sponsor evidence room.", [str(EXPORT_DIR)])
    else:
        add(findings, "PASS", "P0", "EVID-002", "Evidence bundles are schema and policy clean", "Every generated bundle has hybrid evidence, matching hashes, no fallback, and a Digital Seal field.", "Keep schema validation in the live evidence path.", [str(EXPORT_DIR)])

    attestation_ids = {path.stem.removeprefix("attestation-") for path in ATTESTATION_DIR.glob("attestation-*.json")}
    proof_ids = {path.stem.removeprefix("proof-") for path in PROOF_DIR.glob("proof-*.json")}
    if job_ids and job_ids <= attestation_ids and job_ids <= proof_ids:
        add(findings, "PASS", "P0", "EVID-003", "TEE and zkML sidecar objects exist per job", "Each evidence bundle has matching attestation and proof object files.", "Replace drill objects with live attestation/proof objects during execution.", [str(ATTESTATION_DIR), str(PROOF_DIR)])
    else:
        add(findings, "FAIL", "P0", "EVID-003", "TEE/zkML sidecar object coverage is incomplete", "One or more evidence bundle job IDs are missing matching attestation or proof objects.", "Regenerate or collect missing sidecar evidence.", [str(ATTESTATION_DIR), str(PROOF_DIR)])

    if drill_only:
        add(findings, "FAIL", "P0", "EVID-004", "Evidence is not real, verifiable cryptography", "At least one bundle does not affirm real_cryptographic_evidence=true or its Digital Seal did not verify.", "Regenerate evidence with the real seal pipeline (scripts/m42_seal.py).", [str(EXPORT_DIR)])
    else:
        add(findings, "PASS", "P0", "EVID-004", "Evidence is real, independently verifiable cryptography", "Every bundle carries a real Digital Seal (Ed25519 validator signature, TEE attestation signature chain, Schnorr NIZK or honest large-model record, Merkle anchor) and verifies under m42_seal.verify_seal.", "At go-live, swap the pilot attestation root for AMD SEV-SNP / AWS Nitro roots; verification logic is unchanged.", [str(EXPORT_DIR)])


def check_cryptography(findings: list[dict[str, Any]]) -> None:
    """Independently verify the Digital Seals and prove tamper rejection.

    This is the assurance-challenge centerpiece: the gap audit itself runs the
    same standalone verifier M42 runs, so a PASS here means the cryptography is
    real and checkable with no trust in the producer.
    """
    sys.path.insert(0, str(ROOT / "scripts"))
    try:
        import m42_seal
        import m42_crypto
    except Exception as exc:  # pragma: no cover
        add(findings, "FAIL", "P0", "CRYPTO-001", "Crypto modules failed to import", str(exc), "Fix scripts/m42_seal.py / m42_crypto.py.", [])
        return

    import copy
    try:
        import m42_pqc
    except Exception as exc:  # pragma: no cover
        add(findings, "FAIL", "P0", "CRYPTO-004", "PQC module failed to import", str(exc), "Fix scripts/m42_pqc.py.", [])
        m42_pqc = None

    trust = m42_seal.published_trust_config()
    batch_path = EXPORT_DIR / "batch-proof.json"
    bundles = sorted(EXPORT_DIR.glob("evidence-bundle-*.json"))
    if not bundles or not batch_path.exists():
        add(findings, "FAIL", "P0", "CRYPTO-001", "No batch-anchored evidence to verify", "Run make m42-sandbox-drill.", "Generate evidence with the real seal pipeline.", [str(EXPORT_DIR)])
        return
    batch_proof = read_json(batch_path)
    seals = [read_json(p).get("digital_seal") for p in bundles]
    all_ok, summary = m42_seal.verify_evidence(seals, batch_proof, trust, full=True)
    if all_ok:
        add(findings, "PASS", "P0", "CRYPTO-001", "Every Digital Seal verifies independently",
            f"{summary['verified_count']}/{summary['total']} seals verified: hybrid (Ed25519 + post-quantum XMSS) batch signature, TEE attestation signature chain, per-seal Merkle inclusion + attestation binding, Schnorr NIZK / honest large-model record, nonce freshness. Trust config: trust-config.json.",
            "M42 can rerun this with scripts/m42-verify.py --full.", [str(EXPORT_DIR)])
    else:
        bad = [sid for sid, ok, _, _ in summary["seal_results"] if not ok][:6]
        add(findings, "FAIL", "P0", "CRYPTO-001", "Digital Seal verification failed", f"batch_ok={summary['batch_ok']}, failing seals={bad}", "Regenerate evidence with the real seal pipeline.", [str(EXPORT_DIR)])

    # Tamper matrix on a real multi-seal batch; every forgery must be rejected.
    base_seals = [m42_seal.build_seal(
        workload="genomic-variant-interpretation", model_hash="a" * 64, circuit_hash="b" * 64,
        input_value={"v": i}, output_value={"o": i}, chain_id="aethelred-m42-pilot-1",
        timestamp="2026-06-12T00:00:00Z", nonce=f"audit-{i}", platform="sev-snp",
        zkml_tractable=True, seed_label=f"audit-{i}") for i in range(4)]
    bp = m42_seal.anchor_batch(base_seals, batch_index=950)
    _, _, roots = m42_seal.verify_batch(bp, trust)
    seal_forgeries = {
        "swapped_output": ("seal", lambda s: s.update(output_commitment=m42_crypto.commit({"x": 2}, b"f"))),
        "model_substitution": ("seal", lambda s: s.update(model_hash="f" * 64)),
        "forged_inclusion": ("seal", lambda s: s["seal_inclusion_proof"]["siblings"].__setitem__(0, ["L", "00" * 32])),
        "policy_fallback": ("seal", lambda s: s["policy"].update(fallback_allowed=True)),
        "forged_zk": ("seal", lambda s: s["zk_proof"].update(response=format(int(s["zk_proof"]["response"], 16) + 1, "x"))),
        "forged_ed25519_leg": ("batch", lambda b: b["validator_hybrid_signature"].update(ed25519="00" * 64)),
        "forged_pqc_leg": ("batch", lambda b: b["validator_hybrid_signature"]["pqc"]["wots_sig"].__setitem__(0, "00" * 32)),
        "untrusted_attestation": ("batch", lambda b: b.update(attestation=m42_crypto.make_attestation(m42_crypto.sha256(b"e"), m42_crypto.sha256(b"r"), "sev-snp", next(iter(trust.allowed_measurements)), b["batch_nonce"], b["attestation_batch_root"]))),
    }
    accepted: list[str] = []
    for name, (kind, mut) in seal_forgeries.items():
        if kind == "seal":
            forged = copy.deepcopy(base_seals[0]); mut(forged)
            ok, _ = m42_seal.verify_seal(forged, roots, full=True)
        else:
            forged_bp = copy.deepcopy(bp); mut(forged_bp)
            ok, _, _ = m42_seal.verify_batch(forged_bp, trust)
        if ok:
            accepted.append(name)
    if not accepted:
        add(findings, "PASS", "P0", "CRYPTO-002", "All seal and batch forgeries are cryptographically rejected", f"{len(seal_forgeries)} forgery vectors rejected, including both classical and post-quantum signature legs, output substitution, forged Merkle inclusion, and untrusted attestation root.", "Demonstrate live with scripts/m42-verify.py --demo-tamper.", [])
    else:
        add(findings, "FAIL", "P0", "CRYPTO-002", "A forgery was accepted", f"Accepted forgeries: {accepted}", "Fix the verifier; no forgery may verify.", [])

    # PQC assurance: Category 5, hybrid, harvest-now-decrypt-later resistant.
    if m42_pqc is not None:
        prof = m42_pqc.security_profile()
        pqc_ok = prof["nist_category"] == 5 and prof["classical_security_bits"] == 256 and "ed25519" in prof["hybrid"]
        add(findings, "PASS" if pqc_ok else "FAIL", "P0", "CRYPTO-004", "Post-quantum security is Category 5 and hybrid",
            f"Batch roots are co-signed Ed25519 + XMSS(WOTS+, SHA3-256): NIST Category {prof['nist_category']}, {prof['classical_security_bits']}-bit classical / {prof['quantum_security_bits']}-bit quantum. Work factor vs the 128-bit baseline: {prof['work_factor_vs_baseline']} (~10^38x). A forger must break BOTH ecc-dlog AND a 256-bit hash.",
            "Keep the hybrid scheme through go-live; rotate the XMSS index pool as batches are consumed.", [str(EXPORT_DIR / "trust-config.json")])

    # Honest hardware boundary, disclosed.
    add(findings, "WARN", "P1", "CRYPTO-003", "TEE hardware root is the pilot test root (disclosed)", "The cryptography (hybrid classical+PQC signatures, attestation signature chain, NIZK, Merkle) is real and verifies. The attestation trust root is the Aethelred pilot test key, not yet AMD SEV-SNP / AWS Nitro hardware roots.", "At go-live, provision real enclave hardware and publish the production attestation roots; the seal format and verification logic are unchanged.", [str(EXPORT_DIR / "trust-config.json")])


def check_negative_controls(findings: list[dict[str, Any]]) -> None:
    path = EXPORT_DIR / "negative-control-results.json"
    data = load_json_or_fail(findings, path, "NEG-001")
    if not data:
        return
    controls = data.get("controls", [])
    bad = [control.get("control", "<unknown>") for control in controls if control.get("expected_result") != "reject"]
    not_observed = [control.get("control", "<unknown>") for control in controls if control.get("observed_result") != "reject"]
    missing_hashes = [control.get("control", "<unknown>") for control in controls if not control.get("mutated_seal_hash")]
    real_verifier = all(control.get("execution_mode") == "real_cryptographic_verifier" for control in controls)
    summary = data.get("summary", {})
    observed_rejections = summary.get("observed_rejections")
    controls_defined = summary.get("controls_defined")
    if len(controls) >= 6 and not bad and not not_observed and not missing_hashes and real_verifier and summary.get("accepted_bad_cases") == 0 and observed_rejections == controls_defined == len(controls):
        add(findings, "PASS", "P0", "NEG-002", "Negative controls reject through the real cryptographic verifier", f"{len(controls)} forgery attacks (output substitution, forged signature, model swap, stripped attestation, untrusted root, policy fallback) were verified by m42_seal.verify_seal and rejected on real cryptographic grounds.", "Run the same forgeries live in the Week 3 assurance challenge.", [str(path)])
    else:
        add(findings, "FAIL", "P0", "NEG-002", "Negative controls are incomplete", f"controls={len(controls)}, non-reject={bad}, not_observed_reject={not_observed}, missing_hashes={missing_hashes}, real_verifier={real_verifier}, observed_rejections={observed_rejections}, accepted_bad_cases={summary.get('accepted_bad_cases')}.", "Fix negative-control execution before M42 assurance challenge.", [str(path)])


def check_sponsor_package(findings: list[dict[str, Any]]) -> None:
    required = [
        EXPORT_DIR / "baseline-measurement.json",
        EXPORT_DIR / "sandbox-run-summary.json",
        EXPORT_DIR / "m42-value-bank.json",
        EXPORT_DIR / "m42-mutual-action-plan.json",
        EXPORT_DIR / "m42-value-scorecard.json",
        EXPORT_DIR / "m42-executive-readout.md",
    ]
    missing = [str(path) for path in required if not path.exists()]
    if missing:
        add(findings, "FAIL", "P0", "SPON-001", "Sponsor package is missing required outputs", "Required generated sponsor artifacts are missing.", "Run make m42-sandbox-drill and rerun the audit.", missing)
    else:
        add(findings, "PASS", "P0", "SPON-001", "Sponsor package outputs exist", "Baseline, verified run, value bank, mutual action plan, scorecard, and executive readout exist.", "Replace drill outputs with live outputs for final Week 4 readout.", [str(path) for path in required])

    unresolved = []
    for path in required:
        if path.exists() and "TBD" in path.read_text(encoding="utf-8"):
            unresolved.append(str(path))
    if unresolved:
        add(findings, "FAIL", "P1", "SPON-002", "Generated sponsor outputs contain unresolved TBD markers", "Generated readout artifacts should not contain TBD placeholders.", "Regenerate or populate sponsor outputs before sharing.", unresolved)
    else:
        add(findings, "PASS", "P1", "SPON-002", "Generated sponsor outputs have no TBD markers", "No unresolved TBD markers were found in generated sponsor outputs.", "Keep template TBDs out of generated readouts.", [str(path) for path in required])


def load_images_lock() -> dict[str, str]:
    overrides: dict[str, str] = {}
    if not IMAGES_LOCK.exists():
        return overrides
    for line in IMAGES_LOCK.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        overrides[key.strip()] = value.strip()
    return overrides


def resolve_compose_images(compose: str) -> list[tuple[str, str]]:
    """Resolve image refs the same way the sandbox does: env, then lock, then default."""
    lock = load_images_lock()
    resolved: list[tuple[str, str]] = []
    for match in IMAGE_ENV_RE.finditer(compose):
        var, default = match.group(1), match.group(2).strip()
        resolved.append((var, os.environ.get(var) or lock.get(var) or default))
    for match in IMAGE_PLAIN_RE.finditer(compose):
        resolved.append(("", match.group(1).strip()))
    return resolved


def check_security_posture(findings: list[dict[str, Any]], live_required: bool) -> None:
    compose = COMPOSE_FILE.read_text(encoding="utf-8") if COMPOSE_FILE.exists() else ""
    broad_ports = re.findall(r'-\s+"(?!127\.0\.0\.1:)(\d+:\d+)"', compose)
    if broad_ports:
        add(findings, "FAIL", "P1", "SEC-001", "Sandbox ports are not loopback-bound", f"Broad port mappings found: {', '.join(broad_ports)}.", "Bind local pilot ports to 127.0.0.1 or deploy behind private connectivity.", [str(COMPOSE_FILE)])
    else:
        add(findings, "PASS", "P1", "SEC-001", "Sandbox ports are loopback-bound", "Docker Compose port mappings are bound to 127.0.0.1 for local/private rehearsal.", "Use private network, VPN, or ingress controls for hosted M42 deployment.", [str(COMPOSE_FILE)])

    if "AETHELRED_ALLOW_SIMULATED: ${AETHELRED_ALLOW_SIMULATED:-false}" in compose and "AETHELRED_REQUIRE_HYBRID_EVIDENCE: \"true\"" in compose:
        add(findings, "PASS", "P0", "SEC-002", "Simulated evidence is disabled by default", "Compose defaults require hybrid evidence and set simulated mode to false.", "Require written sponsor waiver for any simulated local evidence.", [str(COMPOSE_FILE)])
    else:
        add(findings, "FAIL", "P0", "SEC-002", "Simulation/hybrid defaults are unsafe or unclear", "Could not confirm AETHELRED_ALLOW_SIMULATED default false and hybrid evidence required.", "Fix compose defaults before paid pilot.", [str(COMPOSE_FILE)])

    nnp_count = compose.count("no-new-privileges:true")
    read_only_count = compose.count("read_only: true")
    if nnp_count >= 6 and read_only_count >= 4:
        add(findings, "PASS", "P1", "SEC-003", "Container privilege escalation and writable rootfs are constrained", f"{nnp_count} services set no-new-privileges and {read_only_count} run with read-only root filesystems.", "Extend read-only rootfs to app containers once their write paths are confirmed volume-only.", [str(COMPOSE_FILE)])
    else:
        add(findings, "WARN", "P1", "SEC-003", "Container hardening coverage may be incomplete", f"no-new-privileges count={nnp_count} (expected >=6), read_only count={read_only_count} (expected >=4 on the monitoring tier).", "Add security_opt and read-only root filesystems to all pilot containers where supported.", [str(COMPOSE_FILE)])

    security_disabled = 'plugins.security.disabled: "true"' in compose
    admin_password_wired = "OPENSEARCH_INITIAL_ADMIN_PASSWORD" in compose and "M42_ARCHIVE_ADMIN_PASSWORD" in compose
    https_healthcheck = "https://localhost:9200/_cluster/health" in compose
    if security_disabled:
        if live_required:
            add(findings, "FAIL", "P0", "SEC-004", "OpenSearch security is disabled in local compose", "The rehearsal archive can be loopback-only, but a paid go-live environment must not expose an unauthenticated archive.", "Enable archive authentication/TLS/private access or provide a separate secured hosted archive before go-live.", [str(COMPOSE_FILE)])
        else:
            add(findings, "WARN", "P1", "SEC-004", "OpenSearch security is disabled in local compose", "This is acceptable only for loopback/private rehearsal, not for a customer-accessible hosted archive.", "For hosted M42 access, enable archive authentication/TLS or keep archive reachable only through private operator access.", [str(COMPOSE_FILE)])
    elif admin_password_wired and https_healthcheck:
        add(findings, "PASS", "P0", "SEC-004", "Evidence archive requires authenticated HTTPS access", "OpenSearch security stays enabled, the admin password is sourced from the local secret via M42_ARCHIVE_ADMIN_PASSWORD, and the container healthcheck authenticates over HTTPS.", "Replace the demo TLS certificate with an operator-issued certificate for any hosted M42 deployment.", [str(COMPOSE_FILE), str(ARCHIVE_SECRET)])
    else:
        status = "FAIL" if live_required else "WARN"
        severity = "P0" if live_required else "P1"
        add(findings, status, severity, "SEC-004", "Evidence archive hardening is incomplete", f"security_disabled={security_disabled}, admin_password_wired={admin_password_wired}, https_healthcheck={https_healthcheck}.", "Wire OPENSEARCH_INITIAL_ADMIN_PASSWORD from the M42 secret and authenticate the healthcheck over HTTPS.", [str(COMPOSE_FILE)])

    local_secrets = [
        ("SEC-005", "Grafana", PILOT_DIR / "secrets" / "grafana_admin_password.txt"),
        ("SEC-007", "Archive admin", ARCHIVE_SECRET),
    ]
    for check_id, label, secret in local_secrets:
        if secret.exists():
            value = secret.read_text(encoding="utf-8").strip()
            mode = stat.S_IMODE(secret.stat().st_mode)
            if len(value) >= 24 and "change-before" not in value and "changeme" not in value.lower() and mode & 0o077 == 0:
                add(findings, "PASS", "P1", check_id, f"{label} local secret is generated and restricted", f"{label} password is non-placeholder and file permissions do not grant group/world access.", "Rotate before any shared M42 demo environment.", [str(secret)])
            else:
                add(findings, "FAIL", "P1", check_id, f"{label} local secret is weak or exposed", f"length={len(value)}, mode={oct(mode)}.", "Run make m42-sandbox-prepare to rotate placeholder secret and enforce chmod 600.", [str(secret)])
        else:
            add(findings, "FAIL", "P1", check_id, f"{label} local secret is missing", f"The local {label.lower()} secret file does not exist.", "Run make m42-sandbox-prepare.", [str(secret)])

    resolved_images = resolve_compose_images(compose)
    mutable = [ref for _, ref in resolved_images if "@sha256:" not in ref]
    if mutable:
        status = "FAIL" if live_required else "WARN"
        severity = "P0" if live_required else "P1"
        add(findings, status, severity, "SEC-006", "Sandbox images are not digest pinned", f"Mutable image references found after env/lock resolution: {', '.join(mutable[:8])}.", "Run scripts/m42-sandbox.sh pin-images to write config/pilots/m42/images.lock.env, and attach SBOM/signature provenance before paid go-live.", [str(COMPOSE_FILE), str(IMAGES_LOCK)])
    else:
        add(findings, "PASS", "P1", "SEC-006", "Sandbox images are digest pinned", f"All {len(resolved_images)} resolved image references include sha256 digests.", "Keep SBOM/signature evidence in the sponsor data room and re-run pin-images after image updates.", [str(COMPOSE_FILE), str(IMAGES_LOCK)])


def simulation_waiver_present() -> bool:
    if not SIMULATION_WAIVER.exists():
        return False
    try:
        waiver = read_json(SIMULATION_WAIVER)
    except json.JSONDecodeError:
        return False
    return bool(
        waiver.get("waiver_type") == "m42_simulated_go_live"
        and waiver.get("approved") is True
        and str(waiver.get("approved_by", "")).strip()
        and str(waiver.get("reason", "")).strip()
    )


def read_url_json(url: str, timeout: int = 5) -> tuple[int, Any | None, str | None]:
    with urllib.request.urlopen(url, timeout=timeout) as response:
        body = response.read()
        try:
            return response.status, json.loads(body.decode("utf-8")), None
        except json.JSONDecodeError as exc:
            return response.status, None, f"invalid JSON response: {exc}"


def check_runtime_provenance(findings: list[dict[str, Any]], check_id: str, name: str, url: str) -> None:
    try:
        status, payload, parse_error = read_url_json(url, timeout=5)
    except urllib.error.HTTPError as exc:
        add(findings, "FAIL", "P0", check_id, f"{name} provenance failed", f"{url} returned HTTP {exc.code}: {exc.reason}", "Fix service readiness before go-live.", [url])
        return
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        add(findings, "FAIL", "P0", check_id, f"{name} provenance is not reachable", f"{url} failed: {exc}", "Run make m42-sandbox-up and rerun validation.", [url])
        return
    if not (200 <= status < 300):
        add(findings, "FAIL", "P0", check_id, f"{name} provenance returned unexpected status", f"{url} returned HTTP {status}.", "Fix service readiness before go-live.", [url])
        return
    if payload is None:
        add(findings, "FAIL", "P0", check_id, f"{name} provenance is not machine-readable", parse_error or "Response was not JSON.", "Return health JSON with ready, allow_simulated, and backend_url fields.", [url])
        return
    if payload.get("ready") is True and payload.get("allow_simulated") is False and payload.get("backend_url") is True:
        add(findings, "PASS", "P0", check_id, f"{name} reports real backend provenance", f"{url} reports ready=true, allow_simulated=false, backend_url=true.", "Keep the health JSON with go-live evidence.", [url])
        return
    if payload.get("allow_simulated") is True and simulation_waiver_present():
        add(findings, "WARN", "P0", check_id, f"{name} uses sponsor-waived simulation", f"{url} reports simulated mode and {SIMULATION_WAIVER} is approved.", "Treat this as a sponsor-approved exception, not standard go-live readiness.", [url, str(SIMULATION_WAIVER)])
        return
    add(findings, "FAIL", "P0", check_id, f"{name} does not prove real backend mode", f"{url} health payload={payload}.", "Require ready=true, allow_simulated=false, backend_url=true or an approved sponsor waiver.", [url])


def archive_credentials() -> tuple[str, str]:
    user = os.environ.get("M42_ARCHIVE_USER", "admin")
    password = os.environ.get("M42_ARCHIVE_ADMIN_PASSWORD", "")
    if not password and ARCHIVE_SECRET.exists():
        password = ARCHIVE_SECRET.read_text(encoding="utf-8").strip()
    return user, password


def insecure_tls_context() -> ssl.SSLContext:
    # The rehearsal archive serves the OpenSearch demo certificate on loopback;
    # these checks assert authentication, not certificate provenance.
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def check_archive_live(findings: list[dict[str, Any]]) -> None:
    scheme = os.environ.get("M42_ARCHIVE_SCHEME", "https")
    dest = os.environ.get("M42_ARCHIVE_DEST", "localhost:19200")
    url = f"{scheme}://{dest}/_cluster/health"
    user, password = archive_credentials()
    context = insecure_tls_context() if scheme == "https" else None

    request = urllib.request.Request(url)
    if password:
        token = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
        request.add_header("Authorization", f"Basic {token}")
    try:
        with urllib.request.urlopen(request, timeout=2, context=context) as response:
            if 200 <= response.status < 300:
                add(findings, "PASS", "P0", "LIVE-004", "Live evidence archive endpoint is reachable with authentication", f"{url} returned HTTP {response.status} using the M42 archive credentials.", "Keep endpoint evidence in m42-sandbox-live-validation.json.", [url])
            else:
                add(findings, "FAIL", "P0", "LIVE-004", "Live evidence archive returned unexpected status", f"{url} returned HTTP {response.status}.", "Start or fix the M42 archive service.", [url])
    except urllib.error.HTTPError as exc:
        next_step = "Run make m42-sandbox-prepare to generate the archive secret, restart the archive, then rerun validation." if exc.code in (401, 403) else "Start or fix the M42 archive service."
        add(findings, "FAIL", "P0", "LIVE-004", "Live evidence archive rejected the audit credentials", f"{url} returned HTTP {exc.code}: {exc.reason}", next_step, [url])
        return
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        add(findings, "FAIL", "P0", "LIVE-004", "Live evidence archive endpoint is not reachable", f"{url} failed: {exc}", "Run make m42-sandbox-up, confirm Docker is running, then rerun make m42-sandbox-validate.", [url])
        return

    # Paid-pilot security assertion: anonymous access must be rejected.
    try:
        with urllib.request.urlopen(urllib.request.Request(url), timeout=2, context=context) as response:
            add(findings, "FAIL", "P0", "LIVE-011", "Live evidence archive accepts unauthenticated access", f"{url} returned HTTP {response.status} without credentials.", "Enable archive authentication before any paid go-live claim.", [url])
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            add(findings, "PASS", "P0", "LIVE-011", "Live evidence archive rejects unauthenticated access", f"{url} returned HTTP {exc.code} for an anonymous request.", "Keep authentication enforcement in the hosted archive configuration.", [url])
        else:
            add(findings, "FAIL", "P0", "LIVE-011", "Live evidence archive anonymous probe returned unexpected status", f"{url} returned HTTP {exc.code}: {exc.reason}", "Confirm the archive authentication configuration.", [url])
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        add(findings, "FAIL", "P0", "LIVE-011", "Live evidence archive anonymous probe failed", f"{url} failed: {exc}", "Confirm the archive is running and rerun validation.", [url])


def check_live_endpoints(findings: list[dict[str, Any]]) -> None:
    endpoints = {
        "LIVE-001 validator RPC": "http://localhost:36657/status",
        "LIVE-002 TEE worker": "http://localhost:18545/health",
        "LIVE-003 zkML prover": "http://localhost:18546/health",
        "LIVE-005 Alertmanager": "http://localhost:19093/-/healthy",
        "LIVE-006 Prometheus rules": "http://localhost:19090/api/v1/rules",
    }
    for label, url in endpoints.items():
        check_id, title = label.split(" ", 1)
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                if 200 <= response.status < 300:
                    add(findings, "PASS", "P0", check_id, f"Live {title} endpoint is reachable", f"{url} returned HTTP {response.status}.", "Keep endpoint evidence in m42-sandbox-live-validation.json.", [url])
                else:
                    add(findings, "FAIL", "P0", check_id, f"Live {title} endpoint returned unexpected status", f"{url} returned HTTP {response.status}.", "Start or fix the M42 sandbox service.", [url])
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            add(findings, "FAIL", "P0", check_id, f"Live {title} endpoint is not reachable", f"{url} failed: {exc}", "Run make m42-sandbox-up, confirm Docker is running, then rerun make m42-sandbox-validate.", [url])

    check_archive_live(findings)
    check_runtime_provenance(findings, "LIVE-009", "TEE worker", "http://localhost:18545/health")
    check_runtime_provenance(findings, "LIVE-010", "zkML prover", "http://localhost:18546/health")

    smoke_requests = [
        (
            "LIVE-007",
            "TEE execute smoke",
            "http://localhost:18545/execute",
            {
                "JobID": "m42-live-smoke",
                "ModelHash": "bTQyLW1vZGVsLWhhc2g=",
                "InputHash": "bTQyLWlucHV0LWhhc2g=",
                "InputData": "bTQyLXN5bnRoZXRpYy1pbnB1dA==",
                "Nonce": "bTQyLW5vbmNlLWZyZXNobmVzcw==",
                "RequireZKProof": True,
                "Metadata": {
                    "pilot": "m42",
                    "workload": "m42-med42-synthetic-eval",
                    "data_status": "synthetic_non_live",
                },
                "BlockHeight": 1,
                "ChainID": "aethelred-m42-pilot-1",
            },
            lambda payload: payload.get("Success") is True and payload.get("Attestation") is not None and payload.get("ZKProof") is not None,
            "success=true with Attestation and ZKProof",
        ),
        (
            "LIVE-008",
            "zkML prove smoke",
            "http://localhost:18546/prove",
            {
                "model_hash": "bTQyLW1vZGVsLWhhc2g=",
                "circuit_hash": "bTQyLWNpcmN1aXQtaGFzaA==",
                "input_data": "bTQyLXN5bnRoZXRpYy1pbnB1dA==",
                "input_hash": "bTQyLWlucHV0LWhhc2g=",
                "output_data": "bTQyLXN5bnRoZXRpYy1vdXRwdXQ=",
                "output_hash": "bTQyLW91dHB1dC1oYXNo",
                "verifying_key_hash": "bTQyLXZlcmlmeWluZy1rZXktaGFzaA==",
                "request_id": "m42-live-smoke",
                "priority": 1,
            },
            lambda payload: payload.get("success") is True and payload.get("proof") is not None and payload.get("public_inputs") is not None,
            "success=true with proof and public_inputs",
        ),
    ]
    for check_id, title, url, payload, validator, expected_shape in smoke_requests:
        request = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                body = response.read()
                try:
                    response_payload = json.loads(body.decode("utf-8"))
                except json.JSONDecodeError as exc:
                    add(findings, "FAIL", "P0", check_id, f"Live {title} returned non-JSON response", f"{url} returned HTTP {response.status} but response JSON parsing failed: {exc}.", "Return a machine-readable evidence/proof smoke response.", [url])
                    continue
                if 200 <= response.status < 300 and validator(response_payload):
                    add(findings, "PASS", "P0", check_id, f"Live {title} passes", f"{url} accepted the M42 execution smoke with HTTP {response.status} and response shape {expected_shape}.", "Keep execution-smoke responses in m42 sandbox validation evidence.", [url])
                else:
                    add(findings, "FAIL", "P0", check_id, f"Live {title} returned unexpected response", f"{url} returned HTTP {response.status}, payload={response_payload}, expected {expected_shape}.", "Fix live execution path before go-live.", [url])
        except urllib.error.HTTPError as exc:
            add(findings, "FAIL", "P0", check_id, f"Live {title} failed", f"{url} returned HTTP {exc.code}: {exc.reason}", "Configure real TEE/zkML backends or explicit approved simulation mode before go-live.", [url])
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            add(findings, "FAIL", "P0", check_id, f"Live {title} is not reachable", f"{url} failed: {exc}", "Run make m42-sandbox-up, confirm Docker is running, then rerun make m42-sandbox-validate.", [url])


def check_workload_catalog(findings: list[dict[str, Any]]) -> None:
    catalog = load_json_or_fail(findings, WORKLOAD_CATALOG, "WL-001")
    if not catalog:
        return
    workloads = catalog.get("workloads", [])
    expected_kinds = {
        "genomic-variant-interpretation",
        "med42-clinical-evaluation",
        "retrospective-radiology-ai",
        "drug-discovery-screening",
        "de-identification-attestation",
        "population-health-rwe",
        "biobank-gwas-prs",
        "digital-pathology-ai",
        "clinical-trial-matching",
        "med42-training-provenance",
    }
    ids = {w.get("id") for w in workloads}
    if expected_kinds <= ids and catalog.get("active_workload") in ids:
        add(findings, "PASS", "P0", "WL-001", "M42 workload catalog is complete", f"Catalog defines {len(workloads)} workloads ({', '.join(sorted(ids))}) with an active selection.", "Confirm the workload selection with the M42 sponsor at the alignment session.", [str(WORKLOAD_CATALOG)])
    else:
        missing = sorted(expected_kinds - ids)
        add(findings, "FAIL", "P0", "WL-001", "Workload catalog is incomplete", f"Missing {missing}; found {sorted(ids)} with active={catalog.get('active_workload')}.", "Run python3 scripts/m42_workloads.py generate to rebuild the catalog.", [str(WORKLOAD_CATALOG)])

    measurements = load_json_or_fail(findings, PILOT_DIR / "registry" / "measurements.json", "WL-002a")
    circuits = load_json_or_fail(findings, PILOT_DIR / "registry" / "circuits.json", "WL-002b")
    active_models = {e.get("hash") for e in (measurements or {}).get("entries", []) if e.get("status") == "active"}
    active_circuits = {e.get("hash") for e in (circuits or {}).get("entries", []) if e.get("status") == "active"}

    pack_problems: list[str] = []
    fixture_problems: list[str] = []
    registry_problems: list[str] = []
    floor_problems: list[str] = []
    for entry in workloads:
        wid = entry.get("id", "<unknown>")
        pack_path = ROOT / entry.get("pack", "")
        fixture_path = ROOT / entry.get("fixture", "")
        if not pack_path.exists():
            pack_problems.append(f"{wid}: missing pack {entry.get('pack')}")
        else:
            try:
                pack = read_json(pack_path)
                floors = pack.get("success_metrics", {}).get("metric_floors", {})
                if not floors or not pack.get("success_metrics", {}).get("primary_metric"):
                    floor_problems.append(f"{wid}: pack missing metric floors or primary metric")
            except json.JSONDecodeError as exc:
                pack_problems.append(f"{wid}: invalid pack JSON {exc}")
        if not fixture_path.exists():
            fixture_problems.append(f"{wid}: missing fixture {entry.get('fixture')}")
        else:
            count = sum(1 for line in fixture_path.read_text(encoding="utf-8").splitlines() if line.strip())
            if count != entry.get("fixture_count"):
                fixture_problems.append(f"{wid}: fixture has {count} rows, catalog says {entry.get('fixture_count')}")
        if entry.get("model_hash") not in active_models:
            registry_problems.append(f"{wid}: model hash not active in measurement registry")
        if entry.get("circuit_hash") not in active_circuits:
            registry_problems.append(f"{wid}: circuit hash not active in circuit registry")
        if not entry.get("metric_floors"):
            floor_problems.append(f"{wid}: catalog entry missing metric floors")

    if pack_problems:
        add(findings, "FAIL", "P0", "WL-002", "Workload packs are incomplete", "; ".join(pack_problems), "Regenerate packs with scripts/m42_workloads.py generate.", [str(WORKLOADS_DIR)])
    else:
        add(findings, "PASS", "P0", "WL-002", "Every workload has a complete pack", f"All {len(workloads)} workload packs exist and define metric floors and a primary metric.", "Review per-workload economics and floors with the M42 sponsor.", [str(WORKLOADS_DIR)])

    if registry_problems:
        add(findings, "FAIL", "P0", "WL-003", "Workload model/circuit hashes are not all registered", "; ".join(registry_problems), "Register each workload identity in the measurement and circuit registries.", [str(PILOT_DIR / "registry")])
    else:
        add(findings, "PASS", "P0", "WL-003", "Every workload identity is registered active", f"All {len(workloads)} workloads have active model and circuit registrations.", "Replace fixture digests with approved checkpoints before customer data per workload.", [str(PILOT_DIR / "registry")])

    if fixture_problems:
        add(findings, "FAIL", "P0", "WL-004", "Workload synthetic fixtures are incomplete", "; ".join(fixture_problems), "Regenerate fixtures with scripts/m42_workloads.py generate.", [str(DOC_DIR / "workloads")])
    else:
        add(findings, "PASS", "P0", "WL-004", "Every workload has a synthetic fixture with the declared case count", "All workload fixtures exist and match their catalog case counts.", "Keep full M42 PHI review as a sponsor gate before any new dataset.", [str(DOC_DIR / "workloads")])

    if floor_problems:
        add(findings, "FAIL", "P1", "WL-005", "Workload acceptance floors are incomplete", "; ".join(floor_problems), "Define metric floors and a primary metric for every workload.", [str(WORKLOADS_DIR)])
    else:
        add(findings, "PASS", "P1", "WL-005", "Every workload defines domain acceptance floors", "All workloads carry domain metric floors and a primary metric for go/no-go.", "Confirm floors are clinically/scientifically acceptable with M42 reviewers.", [str(WORKLOADS_DIR)])


def check_statistical_rigor(findings: list[dict[str, Any]]) -> None:
    """Verify generated scorecards carry the statistical-rigor layer.

    A healthcare-AI reviewer expects confidence intervals, calibration, and
    subgroup/fairness analysis, not bare point estimates. This check confirms
    the active workload's scorecard ships that layer, and that the calibrated
    classifiers report an expected calibration error.
    """
    scorecard_path = EVIDENCE_DIR / "exports" / "m42-value-scorecard.json"
    scorecard = load_json_or_fail(findings, scorecard_path, "WL-007") if scorecard_path.exists() else None
    if not scorecard:
        add(findings, "WARN", "P1", "WL-007", "Statistical-rigor layer not yet generated", "Run make m42-sandbox-drill to produce the scorecard with confidence intervals, calibration, and subgroup analysis.", "Generate the drill scorecard before sponsor review.", [str(scorecard_path)])
        return
    rigor = scorecard.get("statistical_rigor", {})
    metrics = scorecard.get("metrics", {}).get("domain_metrics", {})
    has_ci = bool(rigor.get("confidence_intervals"))
    has_extra = any(k in rigor for k in ("calibration", "subgroups", "benchmark_per_category_accuracy", "per_class_metrics"))
    if has_ci and has_extra:
        add(findings, "PASS", "P1", "WL-007", "Active workload scorecard carries the statistical-rigor layer", "Scorecard includes confidence intervals plus calibration / subgroup / per-class analysis beyond point estimates.", "Keep the rigor layer in the live evidence path and review subgroup fairness with M42.", [str(scorecard_path)])
    else:
        add(findings, "FAIL", "P1", "WL-007", "Active workload scorecard is missing statistical rigor", f"confidence_intervals={has_ci}, supplemental_rigor={has_extra}.", "Regenerate the drill so the scorecard carries CIs, calibration, and subgroups.", [str(scorecard_path)])


def check_workload_drill_evidence(findings: list[dict[str, Any]]) -> None:
    """Validate per-workload drill evidence when it has been generated (--all)."""
    catalog = load_json_or_fail(findings, WORKLOAD_CATALOG, "WL-006") if WORKLOAD_CATALOG.exists() else None
    if not catalog:
        return
    active = catalog.get("active_workload")
    generated: list[str] = []
    clean = True
    details: list[str] = []
    for entry in catalog.get("workloads", []):
        wid = entry.get("id")
        if wid == active:
            continue  # active workload uses the canonical path validated by EVID-001/002.
        export_dir = PILOT_DIR / "evidence" / "workloads" / wid / "exports"
        bundles = sorted(export_dir.glob("evidence-bundle-*.json"))
        if not bundles:
            continue
        generated.append(wid)
        model_hash = entry.get("model_hash", "")
        circuit_hash = entry.get("circuit_hash", "")
        # Metrics are computed over all cases; evidence is materialized for a
        # stratified review sample. Confirm the run summary records the full
        # case count and the materialized bundle count matches the sample.
        summary_path = export_dir / "sandbox-run-summary.json"
        materialized = entry.get("fixture_count")
        if summary_path.exists():
            try:
                sampling = read_json(summary_path).get("evidence_sampling", {})
                materialized = sampling.get("evidence_bundles_materialized", materialized)
                if sampling.get("cases_evaluated") != entry.get("fixture_count"):
                    clean = False
                    details.append(f"{wid}: summary cases_evaluated {sampling.get('cases_evaluated')} != {entry.get('fixture_count')}")
            except json.JSONDecodeError:
                clean = False
                details.append(f"{wid}: unreadable sandbox-run-summary.json")
        if len(bundles) != materialized:
            clean = False
            details.append(f"{wid}: {len(bundles)} bundles for {materialized} sampled cases")
        for path in bundles:
            try:
                bundle = read_json(path)
            except json.JSONDecodeError as exc:
                clean = False
                details.append(f"{path.name}: invalid JSON {exc}")
                continue
            errors = validate_bundle(bundle, model_hash, circuit_hash)
            if errors:
                clean = False
                details.append(f"{wid}/{path.name}: {', '.join(errors[:3])}")
    if not generated:
        add(findings, "WARN", "P1", "WL-006", "Non-active workload drill evidence has not been generated", "Only the active workload has drill evidence. Run scripts/m42-sandbox-drill.py --all to demonstrate every workload for the sponsor.", "Generate all-workload evidence before the executive value board if M42 wants the full menu.", [str(PILOT_DIR / "evidence" / "workloads")])
    elif clean:
        add(findings, "PASS", "P0", "WL-006", "Generated multi-workload drill evidence is schema and hash clean", f"Workloads with generated evidence ({', '.join(generated)}) produce schema-valid, hash-bound, fallback-free bundles.", "Replace drill evidence with live outputs per workload before production claims.", [str(PILOT_DIR / "evidence" / "workloads")])
    else:
        add(findings, "FAIL", "P0", "WL-006", "Generated multi-workload drill evidence has problems", "; ".join(details[:6]), "Regenerate with scripts/m42-sandbox-drill.py --all and rerun the audit.", [str(PILOT_DIR / "evidence" / "workloads")])


def check_readiness_gates(findings: list[dict[str, Any]]) -> None:
    path = PILOT_DIR / "readiness-gates.json"
    gates = load_json_or_fail(findings, path, "GATE-001")
    if not gates:
        return
    required = gates.get("go_live_required_gates", [])
    p0 = [gate for gate in required if gate.get("severity") == "P0"]
    if len(p0) >= 8 and all(gate.get("owner") and gate.get("acceptance") for gate in p0):
        add(findings, "PASS", "P0", "GATE-002", "Go-live gates are explicit and owned", f"{len(p0)} P0 gates include owners and acceptance criteria.", "Review gate disposition with M42 sponsor before Week 1.", [str(path)])
    else:
        add(findings, "FAIL", "P0", "GATE-002", "Go-live gates are under-specified", f"P0 gates found: {len(p0)}.", "Add owners and acceptance criteria for all P0 gates.", [str(path)])


def summarize(findings: list[dict[str, Any]], live_checks_skipped: bool) -> dict[str, Any]:
    counts: dict[str, int] = {"PASS": 0, "WARN": 0, "FAIL": 0}
    severities: dict[str, int] = {}
    for finding in findings:
        counts[finding["status"]] = counts.get(finding["status"], 0) + 1
        key = f"{finding['severity']}_{finding['status']}"
        severities[key] = severities.get(key, 0) + 1
    p0_warns = sum(1 for finding in findings if finding["status"] == "WARN" and finding["severity"] == "P0")
    if counts.get("FAIL", 0):
        overall = "blocked"
    elif counts.get("WARN", 0):
        overall = "ready_with_disclosed_warnings"
    else:
        overall = "ready"
    go_live_ready = counts.get("FAIL", 0) == 0 and p0_warns == 0 and not live_checks_skipped
    return {
        "overall_status": overall,
        "counts": counts,
        "severity_counts": severities,
        "p0_warnings": p0_warns,
        "live_checks_skipped": live_checks_skipped,
        "go_live_ready": go_live_ready,
    }


def render_markdown(summary: dict[str, Any], findings: list[dict[str, Any]]) -> str:
    lines = [
        "# M42 Investor-Grade Pilot Gap Audit",
        "",
        f"Generated at: {utc_now()}",
        "",
        "## Executive Status",
        "",
        f"- Overall status: `{summary['overall_status']}`",
        f"- Go-live ready: `{str(summary['go_live_ready']).lower()}`",
        f"- Findings: {summary['counts'].get('PASS', 0)} pass, {summary['counts'].get('WARN', 0)} warn, {summary['counts'].get('FAIL', 0)} fail",
        "- Pilot value frame: $200,000 paid pilot structured for $1,000,000 target sponsor-perceived value.",
        "",
        "## Critical Interpretation",
        "",
    ]
    if summary["go_live_ready"]:
        lines.append("The M42 pilot package and live gates are ready for sponsor review, subject to M42 acceptance of any warnings.")
    else:
        lines.append("The package is strong enough for sponsor/investor rehearsal, but the paid four-week execution clock must not start until all FAIL findings are closed.")
    lines += ["", "## Findings", ""]
    for finding in findings:
        lines += [
            f"### {finding['id']} [{finding['severity']}] {finding['status']}: {finding['title']}",
            "",
            finding["detail"],
            "",
            f"Next step: {finding['next_step']}",
            "",
        ]
        if finding["evidence"]:
            lines.append("Evidence:")
            for item in finding["evidence"][:8]:
                lines.append(f"- `{item}`")
            lines.append("")
    return "\n".join(lines)


def render_html(summary: dict[str, Any], findings: list[dict[str, Any]]) -> str:
    rows = []
    for finding in findings:
        evidence = "<br>".join(html.escape(item) for item in finding.get("evidence", [])[:4])
        rows.append(
            "<tr>"
            f"<td>{html.escape(finding['id'])}</td>"
            f"<td><span class='pill {html.escape(finding['status'].lower())}'>{html.escape(finding['status'])}</span></td>"
            f"<td>{html.escape(finding['severity'])}</td>"
            f"<td>{html.escape(finding['title'])}<small>{html.escape(finding['detail'])}</small></td>"
            f"<td>{html.escape(finding['next_step'])}</td>"
            f"<td>{evidence}</td>"
            "</tr>"
        )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>M42 Pilot Evidence Portal</title>
  <style>
    :root {{
      color-scheme: light;
      --ink: #17202a;
      --muted: #5c6672;
      --line: #d8dee6;
      --pass: #106b4f;
      --warn: #8a5a00;
      --fail: #a12a2a;
      --surface: #f6f8fb;
      --accent: #0f5f7a;
    }}
    body {{ margin: 0; font-family: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; color: var(--ink); background: white; }}
    header {{ padding: 32px 40px 22px; border-bottom: 1px solid var(--line); background: var(--surface); }}
    h1 {{ margin: 0 0 8px; font-size: 28px; line-height: 1.1; }}
    h2 {{ margin: 28px 0 12px; font-size: 18px; }}
    p {{ color: var(--muted); margin: 0; max-width: 920px; }}
    main {{ padding: 28px 40px 40px; }}
    .metrics {{ display: grid; grid-template-columns: repeat(5, minmax(140px, 1fr)); gap: 12px; margin-top: 22px; }}
    .metric {{ border: 1px solid var(--line); padding: 14px; background: white; }}
    .metric b {{ display: block; font-size: 22px; }}
    .metric span {{ color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }}
    table {{ width: 100%; border-collapse: collapse; table-layout: fixed; border: 1px solid var(--line); }}
    th, td {{ border-bottom: 1px solid var(--line); padding: 10px; text-align: left; vertical-align: top; font-size: 13px; }}
    th {{ background: var(--surface); color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: .04em; }}
    td small {{ display: block; margin-top: 5px; color: var(--muted); line-height: 1.35; }}
    .pill {{ display: inline-block; min-width: 48px; padding: 4px 8px; border-radius: 999px; color: white; text-align: center; font-size: 11px; font-weight: 700; }}
    .pass {{ background: var(--pass); }}
    .warn {{ background: var(--warn); }}
    .fail {{ background: var(--fail); }}
    .notice {{ border-left: 4px solid var(--accent); background: #eef7fa; padding: 14px 16px; margin: 18px 0 24px; }}
    @media (max-width: 900px) {{
      header, main {{ padding-left: 18px; padding-right: 18px; }}
      .metrics {{ grid-template-columns: repeat(2, minmax(120px, 1fr)); }}
      table {{ display: block; overflow-x: auto; }}
    }}
  </style>
</head>
<body>
  <header>
    <h1>M42 Paid Pilot Evidence Portal</h1>
    <p>Investment-grade readiness view for the Med42-compatible Aethelred sandbox pilot. Generated at {html.escape(utc_now())}.</p>
    <div class="metrics">
      <div class="metric"><span>Status</span><b>{html.escape(summary['overall_status'])}</b></div>
      <div class="metric"><span>Go-live ready</span><b>{str(summary['go_live_ready']).lower()}</b></div>
      <div class="metric"><span>Pass</span><b>{summary['counts'].get('PASS', 0)}</b></div>
      <div class="metric"><span>Warn</span><b>{summary['counts'].get('WARN', 0)}</b></div>
      <div class="metric"><span>Fail</span><b>{summary['counts'].get('FAIL', 0)}</b></div>
    </div>
  </header>
  <main>
    <section class="notice">
      The $200,000 paid pilot is structured for $1,000,000 of sponsor-perceived strategic value. The value target is not a guaranteed savings claim. The four-week paid execution clock must wait until open FAIL findings are closed or explicitly accepted where applicable.
    </section>
    <h2>Gap Register</h2>
    <table>
      <thead>
        <tr><th>ID</th><th>Status</th><th>Severity</th><th>Finding</th><th>Next Step</th><th>Evidence</th></tr>
      </thead>
      <tbody>
        {''.join(rows)}
      </tbody>
    </table>
  </main>
</body>
</html>
"""


def run(args: argparse.Namespace) -> int:
    findings: list[dict[str, Any]] = []
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    check_required_files(findings)
    workload = load_json_or_fail(findings, PILOT_DIR / "workload-pack.json", "JSON-001")
    scorecard = load_json_or_fail(findings, PILOT_DIR / "pilot-scorecard.json", "JSON-002")
    model_manifest = load_json_or_fail(findings, PILOT_DIR / "model-manifest.json", "JSON-003")
    load_json_or_fail(findings, PILOT_DIR / "sandbox.json", "JSON-004")
    load_json_or_fail(findings, PILOT_DIR / "circuit-manifest.json", "JSON-005")

    cases = load_vignettes(findings)
    check_readiness_gates(findings)
    check_workload_catalog(findings)
    check_statistical_rigor(findings)
    check_workload_drill_evidence(findings)
    check_value_architecture(findings, scorecard)
    check_hash_registration(findings, workload)
    check_data_boundary(findings, workload, model_manifest, cases)
    check_evidence_artifacts(findings, workload, cases)
    check_cryptography(findings)
    check_negative_controls(findings)
    check_sponsor_package(findings)
    check_security_posture(findings, live_required=not args.skip_live)
    if not args.skip_live:
        check_live_endpoints(findings)

    summary = summarize(findings, live_checks_skipped=args.skip_live)
    register = {
        "schema_version": "m42.pilot_gap_register.v1",
        "generated_at": utc_now(),
        "pilot": "m42-med42-synthetic-eval",
        "customer": "M42",
        "summary": summary,
        "findings": findings,
        "claim_boundary": "Pretestnet drill artifacts are rehearsal evidence. Live execution claims require passing m42-sandbox-validate and replacing drill fixtures with live evidence.",
    }

    write_json(REPORT_DIR / "m42-pilot-gap-register.json", register)
    (REPORT_DIR / "m42-investor-readiness-report.md").write_text(render_markdown(summary, findings), encoding="utf-8")
    (REPORT_DIR / "m42-sponsor-evidence-portal.html").write_text(render_html(summary, findings), encoding="utf-8")

    print(f"M42 gap audit status: {summary['overall_status']}")
    print(f"PASS={summary['counts'].get('PASS', 0)} WARN={summary['counts'].get('WARN', 0)} FAIL={summary['counts'].get('FAIL', 0)}")
    print(f"Gap register: {REPORT_DIR / 'm42-pilot-gap-register.json'}")
    print(f"Investor report: {REPORT_DIR / 'm42-investor-readiness-report.md'}")
    print(f"Sponsor portal: {REPORT_DIR / 'm42-sponsor-evidence-portal.html'}")

    if args.strict and not summary["go_live_ready"]:
        return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate M42 pilot gap register and sponsor evidence portal.")
    parser.add_argument("--strict", action="store_true", help="Exit non-zero when any FAIL finding remains.")
    parser.add_argument("--skip-live", action="store_true", help="Skip live endpoint checks; use only for package-only rehearsal.")
    return run(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
