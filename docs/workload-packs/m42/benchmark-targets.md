# M42 Pilot Benchmark Targets

## Measurement Scope

The benchmark compares a baseline Med42-compatible synthetic evaluation run against an Aethelred sandbox run for the same six synthetic vignettes. Results are pilot measurements only and must not be used as public production claims.

## Baseline Outputs

| Metric | Target |
|--------|--------|
| Cases processed | 6 synthetic cases |
| Baseline latency | Capture p50 and p95 |
| Baseline cost | Capture per-case and total estimate |
| Clinical factuality | >= 95% against synthetic reference |
| Safety flag recall | >= 98% against synthetic reference |
| Output commitment coverage | 100% baseline/preflight coverage; not accepted evidence by itself |

## Aethelred Sandbox Outputs

| Metric | Target |
|--------|--------|
| Accepted cases | 6 synthetic cases |
| Hybrid evidence bundle coverage | 100% |
| TEE attestation coverage | 100% |
| zkML proof reference coverage | 100% |
| Digital Seal coverage | 100% |
| TEE-only or commitments-only fallback | 0 accepted cases |
| Replay determinism | >= 99% matching output commitments |
| Validator signature coverage | 100% |
| Archive export success | 100% when archive endpoint is live |
| Alerting readiness | Alertmanager healthy and Prometheus rules queryable |
| Negative-control expected rejects | 6 of 6 controls |

## Business-Case Measures

| Measure | How to Report |
|---------|---------------|
| Assurance uplift | Hybrid TEE + zkML/Digital Seal evidence objects produced per accepted job and verification failures caught |
| Latency delta | Aethelred p50/p95 minus baseline p50/p95 |
| Cost delta | Aethelred per-case estimate minus baseline per-case estimate |
| Security posture | Controls satisfied, residual risks, and go-live blockers |
| Operating model | Roles for M42 operator, Aethelred operator, and audit reviewer |
| Sponsor value package | Baseline, verified run summary, per-job evidence, negative controls, value bank, mutual action plan, and executive readout generated for review |
