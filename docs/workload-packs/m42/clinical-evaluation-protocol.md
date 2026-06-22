# M42 Clinical Evaluation Protocol

## Objective

Evaluate a Med42-compatible clinical AI workload in an exclusive Aethelred sandbox and produce a sponsor-ready evidence package for M42. The pilot measures quality, safety-triage behavior, latency/cost deltas, evidence completeness, and policy rejection behavior.

## Workload Selection

Chosen workload: `m42-med42-synthetic-eval`.

Rationale:

- It matches the proposal's Med42/clinical AI path.
- It avoids live PHI and M42 production-system integration.
- It exercises hybrid TEE + zkML + Digital Seal evidence end to end.
- It produces a clear business-case comparison within four weeks.

Deferred workloads:

- Genomics retrospective workload.
- Broader clinical AI workload beyond summarization/safety triage.

## Evaluation Design

| Lane | Purpose | Output |
|------|---------|--------|
| Baseline | Run the same synthetic cases without Aethelred verification | `baseline-measurement.json` |
| Verified sandbox | Run accepted cases through the M42 exclusive sandbox | `sandbox-run-summary.json` |
| Evidence review | Inspect per-job evidence bundle, TEE object, zkML proof object, and Digital Seal fields | `evidence-bundle-<job_id>.json` |
| Negative controls | Confirm forbidden modes are rejected | `negative-control-results.json` |
| Sponsor readout | Summarize value, risks, and next gate | `m42-value-bank.json`, `m42-mutual-action-plan.json`, `m42-value-scorecard.json`, `m42-executive-readout.md` |

## Measures

| Measure | Target |
|---------|--------|
| Synthetic/live-data boundary | 0 live records, 0 PHI |
| Accepted cases | 6 synthetic cases |
| Hybrid evidence coverage | 100% |
| TEE attestation object coverage | 100% |
| zkML proof object coverage | 100% |
| Digital Seal coverage | 100% |
| Single-evidence fallback | 0 accepted cases |
| Clinical factuality | >= 95% against synthetic reference |
| Safety flag recall | >= 98% against synthetic reference |
| Replay determinism | >= 99% matching output commitments |
| Negative controls | 100% expected rejection before live acceptance |

## Negative Controls

The live sandbox must reject:

- missing TEE attestation
- missing zkML proof
- wrong or unregistered model hash
- PHI/customer-data injection into synthetic lane
- fallback mode with `require_both=false`
- stale nonce replay across jobs

## Acceptance

The pilot is accepted only if M42 receives the complete decision package and the live sandbox validation gate passes or remaining warnings are explicitly accepted by the M42 pilot sponsor.
