# M42 Workload Evaluation Protocol — Biobank GWAS & polygenic risk scores

Workload id: `biobank-gwas-prs`
Kind: `genomics_cohort_association`
Unit of evaluation: one association test

## Scope

cohort-scale variant-association testing and polygenic risk scoring. Synthetic, non-live data only: no PHI, no live patient records,
no M42 production data. Metrics are computed from the embedded ground truth in
`docs/workload-packs/m42/workloads/biobank-gwas-prs/synthetic.jsonl` and are reproducible from the fixture.

## Success metrics and acceptance floors

| Metric / constraint | Floor |
|---------------------|-------|
| association_power | 0.8 |
| false_discovery_rate_max | 0.05 |
| genomic_inflation_lambda_max | 1.1 |
| prs_auc | 0.65 |

Primary metric: `prs_auc`.

## Evidence contract

Each accepted case produces a hybrid evidence bundle (TEE attestation + zkML
proof + Digital Seal), binding model hash `1cbe3b54b2930007bf7040ae8905e28bc8a4ff5fa23544375450ac6877a7fdd2` and circuit
hash `04145136d93d7217604515cd47fb2ff041116f26133ee8bce3e77f3e49bec640`. TEE-only, commitments-only, and single-evidence
fallback are out of scope for accepted paid-pilot evidence.

## Economics measured

Baseline vs verified unit cost and latency, and effective throughput
(72000 association tests/hour
target), reported as deltas against the M42 baseline. No production performance
claim is made until the live hardware run is complete.

## Boundary

The circuit binds inputs, outputs, policy, and TEE measurement. It does not
prove scientific or clinical correctness of the model output; correctness is
measured separately by the metrics above against synthetic ground truth.
