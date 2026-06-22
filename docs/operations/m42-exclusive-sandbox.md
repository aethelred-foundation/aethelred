# M42 Exclusive Sandbox

Status date: 2026-06-11

## Decision

The M42 pilot uses a dedicated private sandbox instead of the generic devnet or public-testnet path. The selected workload is:

```text
m42-med42-synthetic-eval
```

This is a Med42-compatible synthetic clinical AI evaluation workload. Genomics and broader clinical AI workloads are deferred so the four-week paid pilot has one clear evidence contract, one data boundary, and one business-case report.

## Sandbox Assets

- Sandbox manifest: `config/pilots/m42/sandbox.json`
- Docker Compose overlay: `integrations/docker/docker-compose.m42-pilot.yml`
- Workload pack: `config/pilots/m42/workload-pack.json`
- KPI scorecard: `config/pilots/m42/pilot-scorecard.json`
- Go-live gate register: `config/pilots/m42/readiness-gates.json`
- Evidence path: `config/pilots/m42/evidence`
- Synthetic vignettes: `docs/workload-packs/m42/synthetic-vignettes.jsonl`
- Clinical evaluation protocol: `docs/workload-packs/m42/clinical-evaluation-protocol.md`
- Value scorecard definition: `docs/workload-packs/m42/value-scorecard.md`
- $1M value structure: `docs/operations/m42-1m-value-pilot-structure.md`
- Prometheus config: `config/pilots/m42/prometheus.yml`
- Alertmanager config: `config/pilots/m42/alertmanager.yml`
- Four-week delivery plan: `docs/operations/m42-pilot-delivery-plan.md`

## Dedicated Endpoints

| Service | Host Endpoint |
|---------|---------------|
| M42 node RPC | `localhost:36657` |
| M42 node P2P | `localhost:36656` |
| M42 REST API | `localhost:31317` |
| M42 gRPC | `localhost:39090` |
| M42 gRPC-Web | `localhost:39091` |
| M42 TEE worker | `localhost:18545` |
| M42 zkML prover | `localhost:18546` |
| M42 evidence archive | `localhost:19200` |
| M42 Prometheus | `localhost:19090` |
| M42 Alertmanager | `localhost:19093` |
| M42 Grafana | `localhost:13001` |

## Commands

Prepare local evidence directories and secrets:

```bash
make m42-sandbox-prepare
```

Run package preflight without requiring live services:

```bash
make m42-sandbox-preflight
```

Generate the M42 sponsor evidence/value drill package:

```bash
make m42-sandbox-drill
```

Generate the investor-grade gap register and sponsor evidence portal:

```bash
make m42-pilot-gap-audit
```

Pin every sandbox image by digest (required before the strict go-live gate):

```bash
bash scripts/m42-sandbox.sh pin-images
```

This resolves the current image digests into `config/pilots/m42/images.lock.env`, which is sourced automatically before every compose and validation command. Rerun it after any image update.

Start the exclusive sandbox:

```bash
make m42-sandbox-up
```

Validate live sandbox endpoints and pilot package:

```bash
make m42-sandbox-validate
```

Run the strict paid-pilot go-live gate:

```bash
make m42-pilot-go-live
```

Stop the sandbox:

```bash
make m42-sandbox-down
```

## Pilot Boundaries

- Dedicated M42 containers, volumes, networks, ports, evidence path, archive, and monitoring.
- The evidence archive runs with the OpenSearch security plugin enabled: access requires HTTPS and the admin credential generated into `config/pilots/m42/secrets/opensearch_admin_password.txt` by `make m42-sandbox-prepare`. Anonymous archive access is a validation failure.
- Compose images are env-overridable and digest-pinnable via `scripts/m42-sandbox.sh pin-images`; the strict go-live gate fails while any image reference resolves to a mutable tag.
- No live patient data or PHI.
- No M42 production system changes.
- Accepted paid-pilot evidence requires hybrid TEE + zkML + Digital Seal output.
- TEE-only, commitments-only, and single-evidence fallback are preflight/baseline only.
- The current model hash binds the pilot manifest; replace it with the approved Med42 checkpoint or endpoint digest before introducing any customer-approved data.
- Health checks for the TEE worker and zkML prover fail closed when simulation is disabled and no real backend URL is configured.

## Sponsor Value Package

`make m42-sandbox-drill` generates:

- `baseline-measurement.json`
- `sandbox-run-summary.json`
- one `evidence-bundle-<job_id>.json` per synthetic case
- one `attestation-<job_id>.json` per synthetic case
- one `proof-<job_id>.json` per synthetic case
- `negative-control-results.json`
- `m42-value-bank.json`
- `m42-mutual-action-plan.json`
- `m42-value-scorecard.json`
- `m42-executive-readout.md`
- `.cache/m42-pilot-evidence/exports/m42-pilot-gap-register.json`
- `.cache/m42-pilot-evidence/exports/m42-investor-readiness-report.md`
- `.cache/m42-pilot-evidence/exports/m42-sponsor-evidence-portal.html`

These are pre-testnet drill artifacts. They prove the evaluation protocol, evidence shape, scorecard, and sponsor package before live endpoints are available. They must be replaced by live sandbox outputs before any production, clinical, or real-attestation claim.

The strict go-live gate treats drill-only evidence as blocking. `make m42-pilot-go-live` will fail until live evidence replaces the pre-testnet fixtures and live services validate.

## Go-Live Rule

`make m42-sandbox-preflight` proves package readiness. `make m42-sandbox-drill` proves sponsor-package readiness. `make m42-pilot-gap-audit` proves the gap register and sponsor portal are current. `make m42-sandbox-validate` is the live exclusive-sandbox gate and now requires validator RPC, TEE `/execute`, zkML `/prove`, archive, Prometheus, and Alertmanager checks. `make m42-pilot-go-live` is the strict paid-pilot gate. Do not start the four-week paid execution clock until the strict gate passes or any remaining warnings are explicitly accepted by the M42 pilot sponsor.
