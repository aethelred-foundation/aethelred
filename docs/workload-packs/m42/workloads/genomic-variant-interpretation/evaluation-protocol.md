# M42 Workload Evaluation Protocol — Genomic variant interpretation

Workload id: `genomic-variant-interpretation`
Kind: `genomics_variant_classification`
Unit of evaluation: one variant

## Scope

ACMG-style classification of synthetic germline variants. Synthetic, non-live data only: no PHI, no live patient records,
no M42 production data. Metrics are computed from the embedded ground truth in
`docs/workload-packs/m42/workloads/genomic-variant-interpretation/synthetic.jsonl` and are reproducible from the fixture.

## Success metrics and acceptance floors

| Metric / constraint | Floor |
|---------------------|-------|
| concordance | 0.95 |
| pathogenic_recall | 0.98 |
| clinically_significant_discordance_max | 0 |
| ancestry_concordance_gap_max | 0.12 |

Primary metric: `pathogenic_recall`.

## Evidence contract

Each accepted case produces a hybrid evidence bundle (TEE attestation + zkML
proof + Digital Seal), binding model hash `1fec2363b3a262501fe3de09381126f933b1b95b3852a786c31ec8b6e28025bd` and circuit
hash `517a90e54e9a0082487266bd572f4d413f5b59f5b05e8f2839c2b8c40247fe4d`. TEE-only, commitments-only, and single-evidence
fallback are out of scope for accepted paid-pilot evidence.

## Economics measured

Baseline vs verified unit cost and latency, and effective throughput
(4200 variants/hour
target), reported as deltas against the M42 baseline. No production performance
claim is made until the live hardware run is complete.

## Boundary

The circuit binds inputs, outputs, policy, and TEE measurement. It does not
prove scientific or clinical correctness of the model output; correctness is
measured separately by the metrics above against synthetic ground truth.
