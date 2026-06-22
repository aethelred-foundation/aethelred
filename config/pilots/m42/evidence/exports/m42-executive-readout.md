# M42 Sandbox Drill Executive Readout — Med42 evaluation / fine-tuning

Artifact mode: pretestnet drill fixture
Workload id: `med42-clinical-evaluation` (clinical_language_evaluation)

## Commercial Value Frame

- Paid pilot fee: $200,000
- Target sponsor-perceived value: $1,000,000
- Target value multiple: 5x
- Claim boundary: this is a value architecture target, not a guaranteed savings claim.

## Workload

Med42 evaluation / fine-tuning: clinical note summarization, safety triage, and benchmark evaluation. Unit of evaluation: one evaluation case.

## Domain Metrics (10000 synthetic evaluation cases)

| Metric | Value |
|--------|-------|
| cases evaluated | 10000 |
| clinical factuality | 96.34% |
| safety flag recall | 99.02% |
| escalation match rate | 97.44% |
| benchmark accuracy | 92.70% |
| adverse prompt rejection rate | 100.00% |
| safety recall specialty gap | 0.44% |

## Acceptance Floors

| Metric / constraint | Floor | Observed | Result |
|---------------------|-------|----------|--------|
| clinical factuality | >= 0.95 | 96.34% | PASS |
| safety flag recall | >= 0.98 | 99.02% | PASS |
| benchmark accuracy | >= 0.85 | 92.70% | PASS |
| adverse prompt rejection rate | >= 1.0 | 100.00% | PASS |
| safety recall specialty gap max | <= 0.1 | 0.44% | PASS |

All acceptance floors met: yes.

## Evidence and Economics

- Hybrid evidence bundle coverage: 100%
- TEE attestation / zkML proof / Digital Seal coverage: 100%
- Single-evidence fallback cases: 0
- Baseline p50 latency: 1010.0 ms; verified p50 latency: 1450.0 ms (delta 440.0 ms)
- Baseline drill cost: $420.0000; verified drill cost: $610.0000
- Throughput target: 2,600 evaluation cases/hour

## $1M Value Bank

| Value Bank | Target Value |
|------------|--------------|
| Sovereign AI assurance blueprint | $250,000 |
| Verifiable clinical AI evidence pack | $250,000 |
| Security and procurement acceleration | $200,000 |
| Clinical safety protocol | $150,000 |
| Scale decision business case | $150,000 |
| Total target value | $1,000,000 |

## Sponsor Value

The drill produces the full live-sandbox decision package for this workload:
baseline measurement, verified run summary, per-job hybrid evidence bundles,
TEE evidence objects, zkML proof objects, negative-control expectations,
value-bank scorecard, mutual action plan, and an executive scorecard. These
artifacts are pretestnet fixtures and must be replaced by live sandbox outputs
before any production, clinical, or scientific claim.

## Next Gate

Run `make m42-sandbox-up` and then `make m42-sandbox-validate` to replace
offline drill warnings with live endpoint evidence.
