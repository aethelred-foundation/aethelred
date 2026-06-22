# M42 Pilot Security Model

## Boundary

The M42 pilot package is a synthetic, non-live healthcare AI evaluation. The only included data is `docs/workload-packs/m42/synthetic-vignettes.jsonl`. The package does not permit live patient data, PHI, or retrospective M42 records.

## Trust Assumptions

| Area | Assumption |
|------|------------|
| Model artifact | The pilot operator approves the Med42-compatible checkpoint or hosted endpoint digest before live activation |
| Hybrid evidence contract | Accepted paid-pilot jobs require `require_both=true`: TEE attestation, zkML proof evidence, and Digital Seal output |
| Backend readiness | TEE worker and zkML prover health and execution-smoke checks fail closed unless a real backend is configured or simulation is explicitly approved |
| TEE lane | Each accepted job produces a fresh Nitro attestation bound to a per-job nonce |
| zkML lane | Each accepted job produces a proof reference bound to input, output, policy, and TEE measurement commitments |
| Registry | Model and circuit hashes are registered as active before sandbox submission |
| Archive | Evidence archive is reachable and immutable retention is configured by the operator |
| Monitoring | Alertmanager and Prometheus are reachable for pilot health checks |

## Controls

| Control | Implementation |
|---------|----------------|
| Data minimization | Synthetic-only fixture with six cases |
| Egress control | `deny_by_default` policy in workload pack |
| Evidence binding | Model hash, circuit hash, input hash, output hash, TEE attestation, zkML proof reference, validator signature, chain id, job id, and Digital Seal seal_id |
| Replay support | Output commitments can be replayed against the same synthetic inputs as preflight support, but commitments alone are not accepted evidence |
| Retention | 30-day pilot evidence retention target |
| Fallback prevention | Single-evidence fallback disabled |
| Live execution gate | `make m42-sandbox-validate` submits TEE `/execute` and zkML `/prove` smoke requests before paid go-live |

## Residual Risks

| Risk | Mitigation Before Paid Live Run |
|------|---------------------------------|
| Manifest hash is not a production model weight hash | Replace the external artifact digest with the approved checkpoint or endpoint digest and re-register the measurement |
| Circuit fixture does not prove clinical correctness | Keep clinical quality scoring as benchmark evidence, separate from cryptographic IO binding |
| Archive and alerting are deployment services | Validate against live archive, Alertmanager, and Prometheus endpoints before go-live |
| Health checks do not prove execution | Require TEE `/execute` and zkML `/prove` live smoke checks before starting the four-week paid clock |
| Synthetic sample is small | Expand the synthetic suite or add approved retrospective de-identified data under M42 governance before production claims |
| TEE-only or commitments-only execution is requested | Treat as baseline or preflight only; do not count it as accepted paid-pilot evidence |
