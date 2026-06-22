# M42 Value Scorecard

This scorecard defines the value M42 should receive from the paid sandbox, beyond a technical demo. The commercial design is a $200,000 paid pilot that should feel like a $1,000,000 strategic decision package.

The $1,000,000 figure is a value-architecture target, not a guaranteed savings claim.

## Value Pillars

| Pillar | Target Value | What M42 Gets | Artifact |
|--------|--------------|---------------|----------|
| Sovereign AI assurance blueprint | $250,000 | Region, data class, egress, retention, monitoring, archive, and no-PHI controls are explicit | `sandbox.json`, `workload-pack.json`, `security-model.md` |
| Verifiable clinical AI evidence pack | $250,000 | Every accepted case maps to TEE + zkML + Digital Seal evidence | `evidence-bundle-<job_id>.json` |
| Security and procurement acceleration | $200,000 | Audit shape, negative controls, and security posture are packaged for internal review | `negative-control-results.json`, `evidence-objects.json` |
| Clinical safety protocol | $150,000 | Factuality, safety flag recall, and escalation match are measured | `clinical-evaluation-protocol.md`, `sandbox-run-summary.json` |
| Scale decision business case | $150,000 | Sponsor can decide go/no-go and choose the next workload | `m42-value-scorecard.json`, `m42-executive-readout.md` |

## Success Threshold

The paid pilot should be considered valuable only if it gives M42 a credible answer to three questions:

1. Can Aethelred produce complete, reviewable evidence for clinical AI execution?
2. What latency/cost overhead is introduced by verified execution?
3. Which security, data, and operational controls must be closed before real M42 data is introduced?

## Generated Drill Output

Run:

```bash
make m42-sandbox-drill
```

Primary output:

```text
config/pilots/m42/evidence/exports/m42-value-scorecard.json
config/pilots/m42/evidence/exports/m42-value-bank.json
config/pilots/m42/evidence/exports/m42-mutual-action-plan.json
config/pilots/m42/evidence/exports/m42-executive-readout.md
```
