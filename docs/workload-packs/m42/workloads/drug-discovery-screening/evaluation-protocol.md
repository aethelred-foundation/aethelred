# M42 Workload Evaluation Protocol — Drug-discovery screening

Workload id: `drug-discovery-screening`
Kind: `virtual_screening_ranking`
Unit of evaluation: one compound

## Scope

activity ranking of a synthetic compound library against a target. Synthetic, non-live data only: no PHI, no live patient records,
no M42 production data. Metrics are computed from the embedded ground truth in
`docs/workload-packs/m42/workloads/drug-discovery-screening/synthetic.jsonl` and are reproducible from the fixture.

## Success metrics and acceptance floors

| Metric / constraint | Floor |
|---------------------|-------|
| roc_auc | 0.8 |
| enrichment_factor_1pct | 10.0 |
| bedroc_alpha20 | 0.5 |
| top100_hit_rate | 0.1 |

Primary metric: `enrichment_factor_1pct`.

## Evidence contract

Each accepted case produces a hybrid evidence bundle (TEE attestation + zkML
proof + Digital Seal), binding model hash `f6e0f50c0e05f104c0d07a8fee3f04fbdb5765d14bea4ae84882fd5052855593` and circuit
hash `7c5ae005fa54b4104a3f29cfa5da280e23c221660c5ca82aa6448b7526a15ed1`. TEE-only, commitments-only, and single-evidence
fallback are out of scope for accepted paid-pilot evidence.

## Economics measured

Baseline vs verified unit cost and latency, and effective throughput
(96000 compounds/hour
target), reported as deltas against the M42 baseline. No production performance
claim is made until the live hardware run is complete.

## Boundary

The circuit binds inputs, outputs, policy, and TEE measurement. It does not
prove scientific or clinical correctness of the model output; correctness is
measured separately by the metrics above against synthetic ground truth.
