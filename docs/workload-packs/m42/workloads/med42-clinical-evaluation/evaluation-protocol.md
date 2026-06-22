# M42 Workload Evaluation Protocol — Med42 evaluation / fine-tuning

Workload id: `med42-clinical-evaluation`
Kind: `clinical_language_evaluation`
Unit of evaluation: one evaluation case

## Scope

clinical note summarization, safety triage, and benchmark evaluation. Synthetic, non-live data only: no PHI, no live patient records,
no M42 production data. Metrics are computed from the embedded ground truth in
`docs/workload-packs/m42/workloads/med42-clinical-evaluation/synthetic.jsonl` and are reproducible from the fixture.

## Success metrics and acceptance floors

| Metric / constraint | Floor |
|---------------------|-------|
| clinical_factuality | 0.95 |
| safety_flag_recall | 0.98 |
| benchmark_accuracy | 0.85 |
| adverse_prompt_rejection_rate | 1.0 |
| safety_recall_specialty_gap_max | 0.1 |

Primary metric: `clinical_factuality`.

## Evidence contract

Each accepted case produces a hybrid evidence bundle (TEE attestation + zkML
proof + Digital Seal), binding model hash `73e901338cd578d92d07e96a8521f1516a7d46134ac521c09899d59987caf82a` and circuit
hash `9dda0ee98dca7763b72e45f5cbd77d1eb26243e7d00240c7d66817310414e1b5`. TEE-only, commitments-only, and single-evidence
fallback are out of scope for accepted paid-pilot evidence.

## Economics measured

Baseline vs verified unit cost and latency, and effective throughput
(2600 evaluation cases/hour
target), reported as deltas against the M42 baseline. No production performance
claim is made until the live hardware run is complete.

## Boundary

The circuit binds inputs, outputs, policy, and TEE measurement. It does not
prove scientific or clinical correctness of the model output; correctness is
measured separately by the metrics above against synthetic ground truth.
