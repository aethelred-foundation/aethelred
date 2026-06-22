# M42 Pilot Business-Case Report

## Status

This report is a paid-pilot readiness template for `m42-med42-synthetic-eval`. It is not a completed production result. Populate the measured fields after the baseline and Aethelred sandbox runs.

## Pilot Thesis

M42 can evaluate a Med42-compatible clinical AI workload in a sovereign sandbox where every accepted synthetic case produces hybrid TEE + zkML/Digital Seal evidence: model hash, circuit hash, input and output commitments, TEE attestation, zkML proof reference, validator signature, chain id, job id, and seal id.

TEE-only, commitments-only, or single-evidence fallback output is baseline/preflight material only. It is not an accepted paid-pilot evidence mode.

The $200,000 pilot is structured to deliver a $1,000,000 target value package: sovereign AI assurance blueprint, verifiable clinical AI evidence pack, security/procurement acceleration, clinical safety protocol, and scale-decision business case. The value target is sponsor-perceived strategic value, not a guaranteed savings claim.

## Required Results

| Result | Target | Measured |
|--------|--------|----------|
| Synthetic data boundary | 0 live records, 0 PHI | TBD |
| Baseline cases | 6 | TBD |
| Aethelred accepted cases | 6 | TBD |
| Hybrid evidence completeness | 100% TEE attestation + zkML proof + Digital Seal coverage | TBD |
| Replay determinism | >= 99% | TBD |
| Clinical factuality | >= 95% | TBD |
| Safety flag recall | >= 98% | TBD |
| Archive export success | 100% with live archive endpoint | TBD |
| Alerting readiness | Alertmanager healthy, rules queryable | TBD |
| Negative controls | 100% expected rejection | TBD |
| Sponsor value scorecard | Produced and reviewed | TBD |
| Value-bank scorecard | $1,000,000 target value architecture reviewed | TBD |

## Decision Gates

| Gate | Pass Condition |
|------|----------------|
| Package readiness | Pilot validator passes with package paths, registry fixtures, evidence path, archive, and Alertmanager |
| Security readiness | Residual risks in `security-model.md` accepted or remediated |
| Evidence readiness | One schema-valid hybrid evidence bundle per accepted synthetic case; TEE-only or commitments-only output excluded |
| Negative-control readiness | Missing TEE, missing zkML, wrong model hash, PHI injection, fallback mode, and stale nonce replay are all expected rejects |
| Commercial readiness | Baseline versus verified run delta is acceptable to M42 pilot sponsor |

## Executive Summary Template

After the sandbox run, summarize:

1. Whether verified execution produced complete hybrid TEE + zkML/Digital Seal evidence for every accepted synthetic case.
2. How latency and cost compare with the baseline.
3. Whether sovereign processing, auditability, and monitoring controls are sufficient for the next pilot phase.
4. Which blockers must be closed before live or retrospective data is introduced.

## Drill Artifacts

Before live services are available, run:

```bash
make m42-sandbox-drill
```

This generates a sponsor-review package under `config/pilots/m42/evidence/exports`. The artifacts are pre-testnet fixtures, not real hardware attestations or real zkML proofs, but they exercise the evidence schema, evaluation scorecard, negative controls, and executive readout expected from the live pilot.
