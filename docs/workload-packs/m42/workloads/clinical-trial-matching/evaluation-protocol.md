# M42 Workload Evaluation Protocol — Clinical-trial matching & synthetic control arms

Workload id: `clinical-trial-matching`
Kind: `clinical_trial_matching`
Unit of evaluation: one candidate

## Scope

patient-trial eligibility matching with a balanced synthetic control arm. Synthetic, non-live data only: no PHI, no live patient records,
no M42 production data. Metrics are computed from the embedded ground truth in
`docs/workload-packs/m42/workloads/clinical-trial-matching/synthetic.jsonl` and are reproducible from the fixture.

## Success metrics and acceptance floors

| Metric / constraint | Floor |
|---------------------|-------|
| matching_sensitivity | 0.75 |
| matching_auroc | 0.9 |
| false_match_rate_max | 0.05 |
| synthetic_control_smd_max | 0.1 |
| fairness_auroc_gap_max | 0.2 |

Primary metric: `matching_sensitivity`.

## Evidence contract

Each accepted case produces a hybrid evidence bundle (TEE attestation + zkML
proof + Digital Seal), binding model hash `8068d398542c61758c26267db2dcaf731abb5c0e4684a7312b43f83151f70951` and circuit
hash `24ae4cd69dc1d0ed63821bc9e0d9a76a53e52c171a35e3dd360bec26e27a8d1b`. TEE-only, commitments-only, and single-evidence
fallback are out of scope for accepted paid-pilot evidence.

## Economics measured

Baseline vs verified unit cost and latency, and effective throughput
(14000 candidates/hour
target), reported as deltas against the M42 baseline. No production performance
claim is made until the live hardware run is complete.

## Boundary

The circuit binds inputs, outputs, policy, and TEE measurement. It does not
prove scientific or clinical correctness of the model output; correctness is
measured separately by the metrics above against synthetic ground truth.
