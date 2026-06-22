# M42 Workload Evaluation Protocol — De-identification & data-egress attestation

Workload id: `de-identification-attestation`
Kind: `deidentification_attestation`
Unit of evaluation: one record

## Scope

proof that PHI is removed and the residual dataset meets k-anonymity before egress. Synthetic, non-live data only: no PHI, no live patient records,
no M42 production data. Metrics are computed from the embedded ground truth in
`docs/workload-packs/m42/workloads/de-identification-attestation/synthetic.jsonl` and are reproducible from the fixture.

## Success metrics and acceptance floors

| Metric / constraint | Floor |
|---------------------|-------|
| phi_recall | 0.98 |
| residual_phi_count_max | 0 |
| k_anonymity | 5 |
| l_diversity | 2 |
| re_identification_risk_max | 0.2 |
| membership_inference_advantage_max | 0.1 |
| hipaa_safe_harbor_coverage | 0.95 |

Primary metric: `phi_recall`.

## Evidence contract

Each accepted case produces a hybrid evidence bundle (TEE attestation + zkML
proof + Digital Seal), binding model hash `720b741ea9c8d2b8b0cce2429cd31a3039de8a5acced47fd7f18c67291adb2b5` and circuit
hash `f62122a2b16a578c5971024baa73d8e9633816ab4afc139ce112443ad09dfbf0`. TEE-only, commitments-only, and single-evidence
fallback are out of scope for accepted paid-pilot evidence.

## Economics measured

Baseline vs verified unit cost and latency, and effective throughput
(180000 records/hour
target), reported as deltas against the M42 baseline. No production performance
claim is made until the live hardware run is complete.

## Boundary

The circuit binds inputs, outputs, policy, and TEE measurement. It does not
prove scientific or clinical correctness of the model output; correctness is
measured separately by the metrics above against synthetic ground truth.
