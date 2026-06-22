# M42 Pilot Demo Flow

## Objective

Demonstrate a synthetic Med42-compatible clinical evaluation workload moving from baseline measurement to Aethelred sandbox execution with verifiable evidence outputs.

## Steps

1. Confirm data boundary.
   - Use only `docs/workload-packs/m42/synthetic-vignettes.jsonl`.
   - Confirm the run has no patient records, no PHI, and no retrospective M42 data.

2. Capture baseline measurement.
   - Run the same prompts against the approved Med42-compatible baseline environment without Aethelred verification.
   - Record latency, cost, clinical factuality score, safety flag recall, and output commitments for baseline/preflight comparison only.
   - Export `baseline-measurement.json`.

3. Execute Aethelred sandbox run.
   - Submit each synthetic vignette as a sandbox job bound to `m42-med42-synthetic-eval`.
   - Require hybrid TEE attestation plus zkML proof evidence and Digital Seal output for every accepted job.
   - Reject TEE-only, commitments-only, or single-evidence fallback output as out of scope for paid-pilot acceptance.
   - Export `sandbox-run-summary.json`.

4. Review evidence objects.
   - Confirm one evidence bundle per accepted job.
   - Confirm model hash `73e901338cd578d92d07e96a8521f1516a7d46134ac521c09899d59987caf82a`.
   - Confirm circuit hash `9dda0ee98dca7763b72e45f5cbd77d1eb26243e7d00240c7d66817310414e1b5`.
   - Confirm TEE attestation, zkML proof reference, validator signature, chain id, job id, and Digital Seal seal id.

5. Archive and alerting check.
   - Confirm archive endpoint accepts evidence objects.
   - Confirm Alertmanager is reachable and pilot-relevant rules are loaded through Prometheus.

6. Business-case readout.
   - Compare baseline and verified runs.
   - Report assurance uplift, latency/cost delta, evidence completeness, operational risks, and go-live blockers.
