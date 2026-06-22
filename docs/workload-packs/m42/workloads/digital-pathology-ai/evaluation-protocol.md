# M42 Workload Evaluation Protocol — Digital pathology AI

Workload id: `digital-pathology-ai`
Kind: `pathology_wsi_detection`
Unit of evaluation: one slide

## Scope

whole-slide-image malignancy detection with tile-level localization. Synthetic, non-live data only: no PHI, no live patient records,
no M42 production data. Metrics are computed from the embedded ground truth in
`docs/workload-packs/m42/workloads/digital-pathology-ai/synthetic.jsonl` and are reproducible from the fixture.

## Success metrics and acceptance floors

| Metric / constraint | Floor |
|---------------------|-------|
| slide_auroc | 0.92 |
| slide_sensitivity | 0.95 |
| slide_specificity | 0.8 |
| worst_tissue_miss_rate_max | 0.1 |
| expected_calibration_error_max | 0.1 |
| fairness_auroc_gap_max | 0.2 |

Primary metric: `slide_auroc`.

## Evidence contract

Each accepted case produces a hybrid evidence bundle (TEE attestation + zkML
proof + Digital Seal), binding model hash `1444cf5e014402bd150deecf466717368a8d153c0a9d896ae9087f228fc53747` and circuit
hash `4d8a8e31d0e8e91a0afca2c07868341d46e145a4313083d350695b437f083ba4`. TEE-only, commitments-only, and single-evidence
fallback are out of scope for accepted paid-pilot evidence.

## Economics measured

Baseline vs verified unit cost and latency, and effective throughput
(1200 slides/hour
target), reported as deltas against the M42 baseline. No production performance
claim is made until the live hardware run is complete.

## Boundary

The circuit binds inputs, outputs, policy, and TEE measurement. It does not
prove scientific or clinical correctness of the model output; correctness is
measured separately by the metrics above against synthetic ground truth.
