"""Per-workload, per-metric and per-floor matrix tests.

Parametrizing over (workload, metric) and (workload, floor) pairs turns the ten
workloads into a broad grid that pins every reported metric and every acceptance
floor individually.
"""

from __future__ import annotations

import pytest

import m42_workloads as wl

# Expected metric keys per workload (documents the contract each one must honor).
EXPECTED_METRICS = {
    "genomic-variant-interpretation": [
        "concordance", "pathogenic_recall", "benign_specificity",
        "clinically_significant_discordance", "vus_rate", "ancestry_concordance_gap",
    ],
    "med42-clinical-evaluation": [
        "clinical_factuality", "safety_flag_recall", "escalation_match_rate",
        "benchmark_accuracy", "adverse_prompt_rejection_rate",
        "safety_recall_specialty_gap",
    ],
    "retrospective-radiology-ai": [
        "auroc", "pr_auc", "sensitivity", "specificity", "ppv", "npv", "mcc",
        "expected_calibration_error", "fairness_auroc_gap",
    ],
    "drug-discovery-screening": [
        "roc_auc", "enrichment_factor_1pct", "enrichment_factor_5pct",
        "bedroc_alpha20", "top100_hit_rate",
    ],
    "de-identification-attestation": [
        "phi_recall", "phi_precision", "residual_phi_count", "k_anonymity",
        "l_diversity", "re_identification_risk", "membership_inference_advantage",
        "hipaa_safe_harbor_coverage",
    ],
    "population-health-rwe": [
        "count_relative_error", "mean_count_accuracy", "dp_epsilon",
        "small_cell_suppression_compliance", "query_determinism",
    ],
    "biobank-gwas-prs": [
        "association_power", "false_discovery_rate", "genomic_inflation_lambda",
        "replication_rate", "prs_auc", "bh_fdr_controlled_power",
    ],
    "digital-pathology-ai": [
        "slide_auroc", "slide_pr_auc", "slide_sensitivity", "slide_specificity",
        "tile_localization_auroc", "expected_calibration_error", "fairness_auroc_gap",
    ],
    "clinical-trial-matching": [
        "matching_sensitivity", "matching_specificity", "matching_precision",
        "matching_auroc", "matching_f1", "false_match_rate", "synthetic_control_smd",
        "fairness_auroc_gap",
    ],
    "med42-training-provenance": [
        "approved_data_coverage", "unapproved_data_inclusion",
        "data_lineage_completeness", "consent_coverage", "checkpoint_hash_binding",
        "data_card_completeness", "poisoning_detection_rate",
    ],
}

METRIC_PAIRS = [(wid, key) for wid, keys in EXPECTED_METRICS.items() for key in keys]
FLOOR_PAIRS = [
    (w.id, floor) for w in wl.WORKLOADS for floor in w.metric_floors if floor != "operating_threshold"
]


@pytest.mark.parametrize("wid,metric", METRIC_PAIRS)
def test_expected_metric_present(wid, metric, scored):
    _, _, result = scored[wid]
    assert metric in result["metrics"], f"{wid} missing metric {metric}"


@pytest.mark.parametrize("wid,metric", METRIC_PAIRS)
def test_expected_metric_not_none(wid, metric, scored):
    _, _, result = scored[wid]
    assert result["metrics"][metric] is not None


@pytest.mark.parametrize("wid,floor_key", FLOOR_PAIRS)
def test_each_floor_individually_cleared(wid, floor_key, scored):
    workload, _, result = scored[wid]
    floor = workload.metric_floors[floor_key]
    metrics = result["metrics"]
    if floor_key.endswith("_max"):
        observed = metrics.get(floor_key[:-4])
        assert observed is not None and observed <= floor, f"{wid}.{floor_key}: {observed} > {floor}"
    else:
        observed = metrics.get(floor_key)
        assert observed is not None and observed >= floor, f"{wid}.{floor_key}: {observed} < {floor}"


@pytest.mark.parametrize("wid", list(EXPECTED_METRICS))
def test_evaluated_case_count_is_scaled(wid, scored):
    workload, cases, _ = scored[wid]
    # The active Med42 vignette set is intentionally small; the rest are at scale.
    if wid == "med42-clinical-evaluation":
        assert len(cases) == workload.fixture_count
    else:
        assert len(cases) >= 900, f"{wid} only has {len(cases)} cases"
