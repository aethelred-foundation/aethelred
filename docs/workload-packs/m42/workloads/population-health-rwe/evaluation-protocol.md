# M42 Workload Evaluation Protocol — Malaffi population-health & real-world evidence

Workload id: `population-health-rwe`
Kind: `population_health_rwe`
Unit of evaluation: one cohort query

## Scope

differential-privacy cohort analytics and regulatory-grade real-world evidence. Synthetic, non-live data only: no PHI, no live patient records,
no M42 production data. Metrics are computed from the embedded ground truth in
`docs/workload-packs/m42/workloads/population-health-rwe/synthetic.jsonl` and are reproducible from the fixture.

## Success metrics and acceptance floors

| Metric / constraint | Floor |
|---------------------|-------|
| query_determinism | 0.99 |
| count_relative_error_max | 0.05 |
| dp_epsilon_max | 1.0 |
| small_cell_suppression_compliance | 1.0 |

Primary metric: `count_relative_error`.

## Evidence contract

Each accepted case produces a hybrid evidence bundle (TEE attestation + zkML
proof + Digital Seal), binding model hash `4811724cf2270c437c9bdb433b62dbf64e10203b443f2e2fa03a06ac84523354` and circuit
hash `a2e85c08414945e91d50c36461260f34e361202e9e4494790fa9d20838b7d0d1`. TEE-only, commitments-only, and single-evidence
fallback are out of scope for accepted paid-pilot evidence.

## Economics measured

Baseline vs verified unit cost and latency, and effective throughput
(900 cohort queries/hour
target), reported as deltas against the M42 baseline. No production performance
claim is made until the live hardware run is complete.

## Boundary

The circuit binds inputs, outputs, policy, and TEE measurement. It does not
prove scientific or clinical correctness of the model output; correctness is
measured separately by the metrics above against synthetic ground truth.
