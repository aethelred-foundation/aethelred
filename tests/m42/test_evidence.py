"""Tests for the evidence drill: bundle schema, hybrid contract, negative controls."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

import m42_workloads as wl

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"


def _load_drill():
    spec = importlib.util.spec_from_file_location("m42_drill", SCRIPTS / "m42-sandbox-drill.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["m42_drill"] = module
    spec.loader.exec_module(module)
    return module


drill = _load_drill()

# A representative spread: a classifier, a ranker, an attestation, a genomics one.
SAMPLE_IDS = [
    "med42-clinical-evaluation",
    "retrospective-radiology-ai",
    "drug-discovery-screening",
    "de-identification-attestation",
    "biobank-gwas-prs",
    "clinical-trial-matching",
]


import m42_seal  # noqa: E402

_BATCHES = {}


@pytest.fixture(scope="module")
def sample_bundles():
    out = {}
    for wid in SAMPLE_IDS:
        workload = wl.WORKLOAD_BY_ID[wid]
        cases = workload.load_cases()
        result = workload.score(workload, cases)
        per_case = {e["case_id"]: e for e in result["per_case"]}
        case = next(c for c in cases if c["case_id"] in per_case)
        entry = per_case[case["case_id"]]
        bundle, attestation, proof, _ = drill.build_bundle(workload, case, entry, 0)
        # Anchor the seal into a real batch (mutates the seal with inclusion proofs)
        # so it is independently verifiable; expose the batch proof via _BATCHES.
        _BATCHES[wid] = m42_seal.anchor_batch([bundle["digital_seal"]], batch_index=700)
        out[wid] = (workload, bundle, attestation, proof)
    return out


@pytest.mark.parametrize("wid", SAMPLE_IDS)
def test_bundle_is_schema_valid(wid, sample_bundles):
    _, bundle, _, _ = sample_bundles[wid]
    errors = drill.validate_bundle(bundle)
    assert errors == [], f"{wid} bundle errors: {errors}"


@pytest.mark.parametrize("wid", SAMPLE_IDS)
def test_bundle_is_hybrid_no_fallback(wid, sample_bundles):
    _, bundle, _, _ = sample_bundles[wid]
    assert bundle["tee_evidence"] and bundle["zkml_evidence"]
    policy = bundle["policy_decision"]
    assert policy["mode"] == "hybrid"
    assert policy["require_both"] is True
    assert policy["fallback_allowed"] is False
    assert bundle["seal_id"].startswith("m42-seal-")


@pytest.mark.parametrize("wid", SAMPLE_IDS)
def test_bundle_binds_workload_hashes(wid, sample_bundles):
    workload, bundle, _, _ = sample_bundles[wid]
    assert bundle["model_hash"] == workload.model_hash
    assert bundle["circuit_hash"] == workload.circuit_hash


@pytest.mark.parametrize("wid", SAMPLE_IDS)
def test_sidecars_match_job_id(wid, sample_bundles):
    _, bundle, attestation, proof = sample_bundles[wid]
    assert attestation["job_id"] == bundle["job_id"]
    assert proof["job_id"] == bundle["job_id"]


@pytest.mark.parametrize("wid", SAMPLE_IDS)
def test_confidence_score_in_range(wid, sample_bundles):
    _, bundle, _, _ = sample_bundles[wid]
    assert 0.0 <= bundle["confidence_score"] <= 1.0


@pytest.mark.parametrize("wid", SAMPLE_IDS)
def test_all_negative_controls_reject(wid, sample_bundles):
    workload, bundle, _, _ = sample_bundles[wid]
    controls = drill.negative_controls(bundle, workload)
    assert len(controls) >= 6
    for control in controls:
        assert control["observed_result"] == "reject", f"{wid} control {control['control']} did not reject"
        assert control["execution_mode"] == "real_cryptographic_verifier"
        assert control["mutated_seal_hash"]


@pytest.mark.parametrize("wid", SAMPLE_IDS)
def test_drill_is_honest_about_hardware_boundary(wid, sample_bundles):
    workload, bundle, _, _ = sample_bundles[wid]
    meta = bundle["metadata"]
    # The cryptography is real and verifies; the TEE HARDWARE is not yet real.
    assert meta["artifact_mode"] == "real_cryptographic_evidence"
    assert meta["real_cryptographic_evidence"] is True
    assert meta["hardware_backed_tee"] is False  # honest: pilot test attestation root
    assert meta["data_status"] == "synthetic_non_live"
    assert meta["not_for_clinical_use"] is True
    # zkML is only claimed where it is tractable.
    assert meta["real_zkml_proof"] == workload.zkml_tractable


@pytest.mark.parametrize("wid", SAMPLE_IDS)
def test_bundle_carries_verified_real_seal(wid, sample_bundles):
    _, bundle, _, _ = sample_bundles[wid]
    assert bundle["metadata"]["real_cryptographic_evidence"] is True
    assert "digital_seal" in bundle
    seal = bundle["digital_seal"]
    # The seal commits to the IO and is independently verifiable under the real
    # batch verifier (validator hybrid signature is batch-level in v2).
    assert seal["input_commitment"] and seal["output_commitment"] and seal["seal_id"]
    trust = m42_seal.published_trust_config()
    batch_ok, _, roots = m42_seal.verify_batch(_BATCHES[wid], trust)
    seal_ok, checks = m42_seal.verify_seal(seal, roots, full=True)
    assert batch_ok and seal_ok, f"{wid}: {[c.name for c in checks if not c.passed]}"


def test_output_substitution_control_rejects(sample_bundles):
    workload, bundle, _, _ = sample_bundles["retrospective-radiology-ai"]
    controls = drill.negative_controls(bundle, workload)
    sub = next(c for c in controls if c["control"] == "output_substitution")
    assert sub["observed_result"] == "reject"
    assert sub["failed_checks"]
