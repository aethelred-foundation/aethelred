# M42 Four-Week Pilot Delivery Plan

Status date: 2026-06-11

## Commercial Frame

This plan treats the M42 engagement as a $200,000 paid pilot. The deliverable is not only a running sandbox; it is a defensible decision package M42 can use to decide whether Aethelred should advance to a larger healthcare AI assurance deployment.

The operating target is that M42 should feel it received $1,000,000 of strategic value from the four weeks. That target is a value-architecture goal, not a guaranteed savings claim.

## Value Architecture

| Value Bank | Target Value | Concrete Asset M42 Keeps |
|------------|--------------|--------------------------|
| Sovereign AI assurance blueprint | $250,000 | Exclusive sandbox topology, data-boundary policy, monitoring, archive, and go-live gate package |
| Verifiable clinical AI evidence pack | $250,000 | Per-case TEE + zkML + Digital Seal evidence bundle drill and live-run replacement path |
| Security and procurement acceleration | $200,000 | Security model, negative controls, evidence object manifest, and audit export shape |
| Clinical safety protocol | $150,000 | Synthetic clinical evaluation protocol with quality, safety, and escalation metrics |
| Scale decision business case | $150,000 | Value scorecard, executive readout, economics comparison, and next-phase recommendation |

Target total: $1,000,000 of sponsor-perceived value from a $200,000 pilot.

## Workload

Selected workload: `m42-med42-synthetic-eval`.

The workload is a Med42-compatible synthetic clinical summarization and safety-triage evaluation. It is deliberately narrow so the pilot can produce strong evidence in four weeks instead of spreading effort across genomics, Med42, and general clinical AI at once.

## Week-by-Week Plan

| Week | Theme | Deliverables | Conversion track (`m42-conversion-plan.md`) |
|------|-------|--------------|---------------------------------------------|
| Pre-start | Sponsor value alignment | Mutual action plan, decision-owner map, value-bank confirmation, data boundary signoff | Decision-owner map includes LOI signer and corporate development contact |
| 1 | Sandbox activation and data boundary | Exclusive sandbox up, package preflight, synthetic data approval, scorecard reviewed | None — value accumulation only |
| 2 | Baseline and verified evidence room | Baseline measurement, verified sandbox run, first evidence bundle walkthrough | Differentiation dossier delivered to reviewers; corp-dev introduction requested |
| 3 | Assurance challenge and procurement packet | Negative-control run, archive/monitoring evidence, security-model review, risk/action log | LOI draft socialized with sponsor 1:1; first corp-dev call on investment memo |
| 4 | Executive value board and go/no-go | Final value-bank scorecard, executive readout, economics comparison, next-phase recommendation | LOI presented as the recommended next step; investment track acknowledged in one sentence |

## Review Cadence

| Meeting | Audience | Purpose |
|---------|----------|---------|
| Sponsor alignment session | M42 sponsor, Aethelred operator, decision owners | Confirm value-bank target, next-phase decision, owners, dates, and acceptance gates |
| Kickoff | M42 sponsor, Aethelred operator, clinical reviewer, security reviewer | Confirm scope, workload, data boundary, and evidence contract |
| Evidence room walkthrough | M42 technical/security reviewers | Inspect one accepted job from prompt to hashes, TEE evidence, zkML object, Digital Seal, archive, and metrics |
| Assurance challenge session | M42 technical/security reviewers and risk owner | Review rejection behavior for missing evidence, wrong hashes, PHI injection, fallback mode, and replay |
| Clinical readout | Clinical AI stakeholder | Review synthetic factuality, safety flags, and escalation behavior |
| Executive value board | Sponsor and decision owners | Review value-bank scorecard, risks, economics, and go/no-go |

## Artifact Checklist

- `config/pilots/m42/workload-pack.json`
- `config/pilots/m42/pilot-scorecard.json`
- `config/pilots/m42/evidence/exports/baseline-measurement.json`
- `config/pilots/m42/evidence/exports/sandbox-run-summary.json`
- `config/pilots/m42/evidence/exports/evidence-bundle-<job_id>.json`
- `config/pilots/m42/evidence/exports/negative-control-results.json`
- `config/pilots/m42/evidence/exports/m42-value-scorecard.json`
- `config/pilots/m42/evidence/exports/m42-value-bank.json`
- `config/pilots/m42/evidence/exports/m42-mutual-action-plan.json`
- `config/pilots/m42/evidence/exports/m42-executive-readout.md`
- `config/pilots/m42/evidence/exports/m42-sandbox-live-validation.json`
- `docs/operations/m42-conversion-plan.md`
- `docs/operations/m42-loi-draft.md` (legal-reviewed before Week 3)
- `docs/operations/m42-mou-draft.md` (fallback instrument)
- `docs/operations/m42-preseed-investment-memo.md` (corp-dev channel only)
- `docs/workload-packs/m42/differentiation-dossier.md`

## Value Test

At the end of the paid pilot, M42 should have a specific answer to:

1. Whether hybrid TEE + zkML + Digital Seal evidence is complete enough for clinical AI assurance review.
2. Whether the measured latency/cost overhead is acceptable for a next-phase workload.
3. Which controls are already usable and which must be hardened before real data.
4. Whether M42 wants the next workload to be genomics, de-identified retrospective clinical AI, or a larger Med42 evaluation.

## Non-Negotiables

- No live PHI without explicit written scope change.
- No production-system modification during this pilot.
- No accepted paid-pilot result without hybrid evidence.
- No production or clinical claim from pre-testnet drill artifacts.
