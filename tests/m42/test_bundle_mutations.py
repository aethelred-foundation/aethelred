"""Adversarial evidence-bundle tests: every required field and contract is enforced."""

from __future__ import annotations

import copy
import importlib.util
import sys
from pathlib import Path

import pytest

import m42_workloads as wl

ROOT = Path(__file__).resolve().parents[2]


def _load_drill():
    spec = importlib.util.spec_from_file_location("m42_drill_mut", ROOT / "scripts" / "m42-sandbox-drill.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["m42_drill_mut"] = module
    spec.loader.exec_module(module)
    return module


drill = _load_drill()

SAMPLE_IDS = [
    "retrospective-radiology-ai",
    "drug-discovery-screening",
    "de-identification-attestation",
    "biobank-gwas-prs",
]

REQUIRED_FIELDS = [
    "schema_version", "bundle_id", "job_id", "chain_id", "seal_id", "timestamp",
    "model_hash", "circuit_hash", "verifying_key_hash", "validator_signature",
    "confidence_score", "tee_evidence", "zkml_evidence", "region", "operator",
    "policy_decision", "archive_pointer", "verification",
]


@pytest.fixture(scope="module")
def base_bundles():
    out = {}
    for wid in SAMPLE_IDS:
        workload = wl.WORKLOAD_BY_ID[wid]
        cases = workload.load_cases()
        result = workload.score(workload, cases)
        per_case = {e["case_id"]: e for e in result["per_case"]}
        case = next(c for c in cases if c["case_id"] in per_case)
        bundle, _, _, _ = drill.build_bundle(workload, case, per_case[case["case_id"]], 0)
        out[wid] = (workload, bundle)
    return out


@pytest.mark.parametrize("wid", SAMPLE_IDS)
def test_clean_bundle_validates(wid, base_bundles):
    _, bundle = base_bundles[wid]
    assert drill.validate_bundle(bundle) == []


@pytest.mark.parametrize("wid", SAMPLE_IDS)
@pytest.mark.parametrize("field", REQUIRED_FIELDS)
def test_removing_required_field_is_rejected(wid, field, base_bundles):
    _, bundle = base_bundles[wid]
    mutated = copy.deepcopy(bundle)
    mutated.pop(field, None)
    assert drill.validate_bundle(mutated), f"removing {field} should fail validation"


@pytest.mark.parametrize("wid", SAMPLE_IDS)
def test_corrupt_model_hash_rejected(wid, base_bundles):
    _, bundle = base_bundles[wid]
    mutated = copy.deepcopy(bundle)
    mutated["model_hash"] = "ZZZ"
    assert drill.validate_bundle(mutated)


@pytest.mark.parametrize("wid", SAMPLE_IDS)
def test_confidence_out_of_range_rejected(wid, base_bundles):
    _, bundle = base_bundles[wid]
    for bad in (-0.1, 1.5):
        mutated = copy.deepcopy(bundle)
        mutated["confidence_score"] = bad
        assert drill.validate_bundle(mutated)


@pytest.mark.parametrize("wid", SAMPLE_IDS)
def test_fallback_policy_rejected(wid, base_bundles):
    _, bundle = base_bundles[wid]
    mutated = copy.deepcopy(bundle)
    mutated["policy_decision"]["require_both"] = False
    assert drill.validate_bundle(mutated)


@pytest.mark.parametrize("wid", SAMPLE_IDS)
def test_wrong_chain_id_rejected(wid, base_bundles):
    _, bundle = base_bundles[wid]
    mutated = copy.deepcopy(bundle)
    mutated["chain_id"] = "ethereum-mainnet"
    assert drill.validate_bundle(mutated)


@pytest.mark.parametrize("wid", SAMPLE_IDS)
def test_all_negative_controls_reject_via_real_verifier(wid, base_bundles):
    workload, bundle = base_bundles[wid]
    controls = drill.negative_controls(bundle, workload)
    assert len(controls) >= 6
    for control in controls:
        assert control["observed_result"] == "reject", f"{wid}/{control['control']} should reject"
        assert control["execution_mode"] == "real_cryptographic_verifier"
