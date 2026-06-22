# M42 Workload Evaluation Protocol — Retrospective radiology AI evaluation

Workload id: `retrospective-radiology-ai`
Kind: `radiology_binary_detection`
Unit of evaluation: one study

## Scope

binary detection of a target finding on synthetic retrospective studies. Synthetic, non-live data only: no PHI, no live patient records,
no M42 production data. Metrics are computed from the embedded ground truth in
`docs/workload-packs/m42/workloads/retrospective-radiology-ai/synthetic.jsonl` and are reproducible from the fixture.

## Success metrics and acceptance floors

| Metric / constraint | Floor |
|---------------------|-------|
| auroc | 0.9 |
| sensitivity | 0.9 |
| specificity | 0.8 |
| worst_finding_type_miss_rate_max | 0.12 |
| expected_calibration_error_max | 0.1 |
| fairness_auroc_gap_max | 0.2 |

Primary metric: `auroc`.

## Evidence contract

Each accepted case produces a hybrid evidence bundle (TEE attestation + zkML
proof + Digital Seal), binding model hash `941b2c5312d81f8b135da7bbbfdffbaee2a3fe32e9016077268a16bc8f203276` and circuit
hash `c1af7b352c311118de0654c2b7d998a49e4d19672da4bf5b4b356a0602967970`. TEE-only, commitments-only, and single-evidence
fallback are out of scope for accepted paid-pilot evidence.

## Economics measured

Baseline vs verified unit cost and latency, and effective throughput
(1800 studies/hour
target), reported as deltas against the M42 baseline. No production performance
claim is made until the live hardware run is complete.

## Boundary

The circuit binds inputs, outputs, policy, and TEE measurement. It does not
prove scientific or clinical correctness of the model output; correctness is
measured separately by the metrics above against synthetic ground truth.
