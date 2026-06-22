# M42 Workload Evaluation Protocol — Med42 training / fine-tuning provenance

Workload id: `med42-training-provenance`
Kind: `training_provenance_attestation`
Unit of evaluation: one training shard

## Scope

proof of which approved, consented data trained a Med42 checkpoint. Synthetic, non-live data only: no PHI, no live patient records,
no M42 production data. Metrics are computed from the embedded ground truth in
`docs/workload-packs/m42/workloads/med42-training-provenance/synthetic.jsonl` and are reproducible from the fixture.

## Success metrics and acceptance floors

| Metric / constraint | Floor |
|---------------------|-------|
| approved_data_coverage | 0.99 |
| unapproved_data_inclusion_max | 0 |
| data_lineage_completeness | 0.95 |
| consent_coverage | 0.95 |
| poisoning_detection_rate | 0.9 |
| data_card_completeness | 0.95 |

Primary metric: `approved_data_coverage`.

## Evidence contract

Each accepted case produces a hybrid evidence bundle (TEE attestation + zkML
proof + Digital Seal), binding model hash `ca2538791effd85bec8872f1e92a05987659ead8b5fcc46351e775637198a155` and circuit
hash `901e40088e6258e1399b1c23cf35116c4c1736202d3ce0cca8b232579eb13c0f`. TEE-only, commitments-only, and single-evidence
fallback are out of scope for accepted paid-pilot evidence.

## Economics measured

Baseline vs verified unit cost and latency, and effective throughput
(48000 training shards/hour
target), reported as deltas against the M42 baseline. No production performance
claim is made until the live hardware run is complete.

## Boundary

The circuit binds inputs, outputs, policy, and TEE measurement. It does not
prove scientific or clinical correctness of the model output; correctness is
measured separately by the metrics above against synthetic ground truth.
