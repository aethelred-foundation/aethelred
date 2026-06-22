"""Parametrized tests over all ten M42 workloads.

Every workload must: generate the declared number of synthetic cases, score to a
well-formed result, clear its acceptance floors, be deterministic, expose a
statistical-rigor block, keep proportion metrics in range, and carry no PHI.
"""

from __future__ import annotations

import re

import pytest

import m42_stats as st
import m42_workloads as wl
from conftest import WORKLOAD_IDS


PHI_PATTERNS = [
    re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    re.compile(r"\bMRN\s*[:#-]?\s*[A-Z0-9-]{5,}\b", re.IGNORECASE),
]

# Metric keys that are bounded proportions in [0, 1].
PROPORTION_HINTS = (
    "recall", "precision", "specificity", "sensitivity", "auroc", "auc",
    "concordance", "coverage", "rate", "accuracy", "compliance", "completeness",
)


@pytest.mark.parametrize("wid", WORKLOAD_IDS)
def test_fixture_count_matches_catalog(wid, scored):
    workload, cases, _ = scored[wid]
    assert len(cases) == workload.fixture_count


@pytest.mark.parametrize("wid", WORKLOAD_IDS)
def test_score_result_structure(wid, scored):
    _, _, result = scored[wid]
    assert "metrics" in result and isinstance(result["metrics"], dict)
    assert "per_case" in result and isinstance(result["per_case"], list)
    assert "confidence_field" in result
    assert result["confidence_field"] in result["metrics"]


@pytest.mark.parametrize("wid", WORKLOAD_IDS)
def test_clears_all_metric_floors(wid, scored):
    workload, _, result = scored[wid]
    floors = wl.evaluate_floors(workload, result["metrics"])
    failed = [c for c in floors["checks"] if not c["met"]]
    assert floors["all_floors_met"], f"{wid} failed floors: {failed}"


@pytest.mark.parametrize("wid", WORKLOAD_IDS)
def test_primary_metric_present_and_valued(wid, scored):
    workload, _, result = scored[wid]
    assert workload.primary_metric in result["metrics"]
    assert result["metrics"][workload.primary_metric] is not None


@pytest.mark.parametrize("wid", WORKLOAD_IDS)
def test_scoring_is_deterministic(wid, scored, workloads_module):
    workload, cases, result = scored[wid]
    again = workload.score(workload, cases)
    assert again["metrics"] == result["metrics"]


@pytest.mark.parametrize("wid", WORKLOAD_IDS)
def test_has_statistical_rigor_block(wid, scored):
    _, _, result = scored[wid]
    assert "rigor" in result, f"{wid} is missing the rigor block"
    assert isinstance(result["rigor"], dict) and result["rigor"]


@pytest.mark.parametrize("wid", WORKLOAD_IDS)
def test_proportion_metrics_in_unit_interval(wid, scored):
    _, _, result = scored[wid]
    for key, value in result["metrics"].items():
        if not isinstance(value, float):
            continue
        if any(hint in key for hint in PROPORTION_HINTS) and "error" not in key and "gap" not in key:
            assert 0.0 <= value <= 1.0001, f"{wid}.{key}={value} out of [0,1]"


@pytest.mark.parametrize("wid", WORKLOAD_IDS)
def test_no_phi_in_fixture(wid, scored):
    import json

    _, cases, _ = scored[wid]
    blob = json.dumps(cases)
    for pattern in PHI_PATTERNS:
        assert not pattern.search(blob), f"{wid} fixture matched PHI pattern {pattern.pattern}"


@pytest.mark.parametrize("wid", WORKLOAD_IDS)
def test_every_case_has_truth_and_output(wid, scored):
    _, cases, _ = scored[wid]
    for case in cases:
        assert "truth" in case and "model_output" in case
        assert case.get("data_status") == "synthetic_non_live"


@pytest.mark.parametrize("wid", WORKLOAD_IDS)
def test_per_case_entries_have_output_value(wid, scored):
    _, _, result = scored[wid]
    for entry in result["per_case"]:
        assert "case_id" in entry
        assert "output_value" in entry


# ---------------------------------------------------------------------------
# Workload-specific guarantees a healthcare reviewer would insist on
# ---------------------------------------------------------------------------


def test_genomics_zero_dangerous_discordance(scored):
    _, _, result = scored["genomic-variant-interpretation"]
    assert result["metrics"]["clinically_significant_discordance"] == 0
    assert result["metrics"]["pathogenic_recall"] >= 0.98


def test_deid_zero_released_residual_phi(scored):
    _, _, result = scored["de-identification-attestation"]
    assert result["metrics"]["residual_phi_count"] == 0
    assert result["metrics"]["k_anonymity"] >= 5


def test_provenance_zero_unapproved_inclusion(scored):
    _, _, result = scored["med42-training-provenance"]
    assert result["metrics"]["unapproved_data_inclusion"] == 0


def test_rwe_full_small_cell_suppression(scored):
    _, _, result = scored["population-health-rwe"]
    assert result["metrics"]["small_cell_suppression_compliance"] == 1.0


def test_gwas_lambda_near_one(scored):
    _, _, result = scored["biobank-gwas-prs"]
    assert 0.9 <= result["metrics"]["genomic_inflation_lambda"] <= 1.10


def test_calibrated_workloads_report_low_ece(scored):
    for wid in ("retrospective-radiology-ai", "digital-pathology-ai"):
        _, _, result = scored[wid]
        assert result["metrics"]["expected_calibration_error"] <= 0.10


def test_calibrated_workloads_report_fairness_gap(scored):
    for wid in ("retrospective-radiology-ai", "digital-pathology-ai", "clinical-trial-matching"):
        _, _, result = scored[wid]
        assert "fairness_auroc_gap" in result["metrics"]
        assert result["rigor"]["subgroups"]


def test_drug_discovery_per_target_enrichment(scored):
    _, _, result = scored["drug-discovery-screening"]
    assert "per_target_enrichment_5pct" in result["rigor"]
    assert result["metrics"]["bedroc_alpha20"] >= 0.5


def test_trial_control_arm_balanced(scored):
    _, _, result = scored["clinical-trial-matching"]
    assert result["metrics"]["synthetic_control_smd"] <= 0.10
    assert "per_covariate_smd" in result["rigor"]


def test_confidence_intervals_present_where_expected(scored):
    expected_ci = {
        "genomic-variant-interpretation": "concordance_95ci",
        "retrospective-radiology-ai": "auroc_95ci",
        "drug-discovery-screening": "roc_auc_95ci",
        "biobank-gwas-prs": "prs_auc_95ci",
        "de-identification-attestation": "phi_recall_95ci",
        "population-health-rwe": "count_relative_error_95ci",
        "med42-clinical-evaluation": "benchmark_accuracy_95ci",
        "med42-training-provenance": "approved_data_coverage_95ci",
    }
    for wid, key in expected_ci.items():
        _, _, result = scored[wid]
        cis = result["rigor"].get("confidence_intervals", {})
        assert key in cis, f"{wid} missing CI {key}"
        lo, hi = cis[key]
        assert lo <= hi
