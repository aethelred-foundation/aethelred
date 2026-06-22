# M42 Paid Pilot Readiness

Status date: 2026-06-11

## Position

The repository is ready for a private, paid, pre-testnet M42 pilot package preflight using the synthetic Med42 evaluation workload in `config/pilots/m42`.

This is not a public-testnet, production, clinical, or live-patient-data readiness statement. The pilot boundary remains the one described in the M42 materials: one four-week sandbox study, no change to M42 production systems, no live PHI, and evidence outputs used for baseline comparison, security review, and go/no-go reporting.

## What Is Ready

- Ten-workload pilot platform — M42 can run any of ten workloads spanning models, data, diagnostics, trials, and governance: the four business-case candidates (genomic variant interpretation, Med42 evaluation, retrospective radiology AI, drug-discovery screening) plus six workloads mapped to M42's flagship assets (de-identification & data-egress attestation, Malaffi population-health/RWE, biobank GWAS & polygenic risk scores, digital pathology AI, clinical-trial matching & synthetic control arms, Med42 training/fine-tuning provenance). Each carries domain-correct synthetic data, genuinely computed metrics, its own model/circuit identity, and per-workload hybrid evidence: `scripts/m42_workloads.py`, `config/pilots/m42/workloads/`, `docs/workload-packs/m42/workload-platform.md`
- Per-workload acceptance floors enforced in CI (`make m42-workloads-score`): e.g. genomics pathogenic recall, radiology/pathology AUROC and sensitivity, drug-discovery enrichment factor, de-identification zero-residual-PHI + k-anonymity, RWE differential-privacy budget + suppression, GWAS genomic inflation lambda, trial-matching control-arm balance (SMD), Med42 training-data provenance (zero unapproved inclusion)
- Balanced scale: each of the ten workloads is evaluated over 10,000 synthetic cases (100,000 total), with a statistical-rigor layer (confidence intervals incl. fast DeLong AUROC, calibration, subgroup fairness) and ~20,800 automated tests (`make m42-test`). Fixtures are deterministic and generated on demand (`make m42-workloads-generate`); the generator is the committed source of truth.
- Machine-readable active M42 workload pack: `config/pilots/m42/workload-pack.json`
- Workload documentation pack: `docs/workload-packs/m42`
- Synthetic data fixture: `docs/workload-packs/m42/synthetic-vignettes.jsonl`
- Active model and circuit registry fixtures: `config/pilots/m42/registry`
- Local evidence directory structure: `config/pilots/m42/evidence/{attestations,proofs,exports,archives}`
- Hybrid evidence contract: every accepted paid-pilot job requires TEE attestation, zkML proof evidence, validator fields, and Digital Seal `seal_id`
- Canonical evidence bundle parity across JSON Schema, Go validation, OpenAPI, TypeScript SDK types, SDK runtime assertions, and generated M42 drill bundles
- M42 Pilot Required Gate workflow: `.github/workflows/m42-pilot-readiness.yml`
- TEE-only, commitments-only, and single-evidence fallback are explicitly baseline/preflight only
- Digital Seal and enterprise evidence bundle query/export paths are implemented for external consumers
- Dedicated M42 sandbox manifest and compose overlay: `config/pilots/m42/sandbox.json` and `integrations/docker/docker-compose.m42-pilot.yml`
- Secured evidence archive: OpenSearch security plugin enabled, admin credential generated into `config/pilots/m42/secrets/`, HTTPS health checks, and validation that rejects anonymous archive access
- Digest pinning path for every sandbox image: `make m42-pin-images` writes `config/pilots/m42/images.lock.env`; the strict gate fails on mutable tags
- Owned go-live gate register: `config/pilots/m42/readiness-gates.json`
- One-command M42 pre-testnet validator: `make m42-pilot-pretestnet`
- Exclusive sandbox commands: `make m42-sandbox-preflight`, `make m42-sandbox-drill`, `make m42-pilot-gap-audit`, `make m42-sandbox-up`, `make m42-sandbox-validate`, and `make m42-pilot-go-live`
- $1,000,000 target value structure for the $200,000 paid pilot: `docs/operations/m42-1m-value-pilot-structure.md`
- Sponsor-review drill artifacts: baseline, verified run summary, per-job evidence bundles, negative controls, value bank, mutual action plan, value scorecard, and executive readout
- Four-week paid-pilot delivery plan: `docs/operations/m42-pilot-delivery-plan.md`
- Conversion plan (pilot to LOI/MOU to pre-seed): `docs/operations/m42-conversion-plan.md`
- LOI and MOU drafts for the Week 4 executive value board: `docs/operations/m42-loi-draft.md`, `docs/operations/m42-mou-draft.md`
- $2M pre-seed investment memo for the corporate development track: `docs/operations/m42-preseed-investment-memo.md`
- Evidence-anchored differentiation dossier for M42 reviewers: `docs/workload-packs/m42/differentiation-dossier.md`
- Rendered conversion deliverables under `M42/` (dossier and memo PDFs, LOI/MOU Word drafts): `make m42-conversion-docs`
- Investor-grade gap register and sponsor portal generated under `.cache/m42-pilot-evidence/exports`

## Primary Preflight

Run:

```bash
make m42-pilot-pretestnet
```

The command validates the workload documentation pack, prepares the local M42 evidence directory, reads the current model and circuit hashes from the workload JSON, and writes a JSON report to:

```text
.cache/m42-pilot-evidence/exports/m42-pretestnet-validation.json
```

Current result:

```text
Workload pack: 33 PASS, 0 FAIL, 0 WARN
Pilot validator: 21 PASS, 0 FAIL, 4 WARN, 1 SKIP
```

The four warnings are expected local deployment gates when archive and monitoring are not running:

- audit archive `localhost:19200` unreachable
- Alertmanager `localhost:19093` unreachable
- Alertmanager API not responding
- Prometheus rules not queryable at `localhost:19090`

The skipped check is intentional for this pre-testnet package preflight: enterprise baseline validation is skipped with `--skip-enterprise`.

## Paid Pilot Go-Live Gates

Before starting the four-week paid execution clock with M42, run the same package against live pilot infrastructure and remove the pre-testnet skip:

```bash
bash scripts/validate-pilot-deployment.sh \
  --pilot-name m42-med42-synthetic-eval \
  --workload-pack config/pilots/m42/workload-pack.json \
  --model-hash "$(jq -r '.model.hash' config/pilots/m42/workload-pack.json)" \
  --circuit-hash "$(jq -r '.circuit.hash' config/pilots/m42/workload-pack.json)" \
  --registry-dir config/pilots/m42/registry \
  --evidence-path config/pilots/m42/evidence \
  --archive-dest <live-archive-host:port> \
  --alertmanager <live-alertmanager-host:port> \
  --prometheus <live-prometheus-host:port> \
  --validator-rpc <live-validator-rpc> \
  --validator-grpc <live-validator-grpc> \
  --tee-endpoint <live-tee-worker> \
  --attestation <live-attestation-verifier> \
  --prover-ezkl <live-zkml-prover> \
  --bridge <live-bridge-endpoint>
```

Go-live requires zero failures and an accepted disposition for any remaining warnings. Health checks are not enough: the live gate also submits a minimal TEE `/execute` request and a minimal zkML `/prove` request for the M42 workload lane.

The strict wrapper for the same idea is:

```bash
make m42-pilot-go-live
```

This target first runs the investment-grade gap audit and then runs live sandbox validation. It is expected to fail until live services are running and all P0 findings are closed.

## Still Not Ready

- Public testnet launch remains blocked by the public-testnet readiness gate.
- Production/live enterprise validation is not green until real archive, Alertmanager, Prometheus, validator, TEE, attestation, prover, and bridge endpoints are running.
- The local Docker daemon is not currently reachable on this machine, so the exclusive sandbox containers were not started in this validation pass.
- The M42 model hash currently binds a repository pilot manifest, not final production Med42 weights. Replace the external artifact digest with the approved M42/Med42 checkpoint or hosted endpoint digest before any customer data is introduced.
- The circuit fixture binds IO, policy, and evidence commitments. It does not prove clinical correctness of free-text model output.
- The synthetic sample is intentionally small. Expanding the set or adding approved de-identified retrospective data is an M42 governance decision, not a repository-only change.

## Current Non-Green Gates

`python3 scripts/validate-public-testnet-readiness.py` currently fails because:

- validation is running from `ramesh/audit-readiness-20260524`, not `release/testnet-v1.0`
- `genesis_time` is `2026-04-01T14:00:00Z`, which is stale as of 2026-06-11
- bridge is enabled with a zero Ethereum contract address
- seed node and persistent peer entries are placeholders rather than real `nodeID@host:port` values
- audit scope `/contracts/ethereum` is not completed or waived
- audit scope `Consensus + vote extensions` is not completed or waived

Production-mode pilot validation with local placeholder endpoints now runs the enterprise baseline and currently reports:

```text
PASS: 21 | FAIL: 3 | WARN: 2 | SKIP: 0
```

The failures are enterprise baseline validation, audit archive reachability at `localhost:19200`, and Alertmanager reachability at `localhost:19093`. The warnings are Alertmanager API response and Prometheus rule queryability at `localhost:19090`.

The full exclusive sandbox live endpoint gate also fails closed while services are stopped:

```text
validator_rpc, tee_worker, zkml_prover, archive, alertmanager, prometheus_rules: FAIL
```

The investor-grade gap audit currently reports (live mode, services stopped):

```text
PASS: 20 | WARN: 1 | FAIL: 11
```

Ten of the eleven failures are live endpoint reachability while Docker/services are not running. The eleventh is image digest pinning (SEC-006), which closes by running `make m42-pin-images` once the pilot images are pushed or pulled. The P0 warning is that current evidence artifacts are pre-testnet drill fixtures and must be replaced by live evidence before go-live. Archive security (SEC-004) now passes: the OpenSearch security plugin stays enabled, the admin credential is secret-sourced, and live validation requires authenticated access plus rejection of anonymous requests (LIVE-011).

In package-only mode (`--skip-live`, the CI gate) the audit reports:

```text
PASS: 20 | WARN: 2 | FAIL: 0
```

The two disclosed warnings are drill-fixture provenance (EVID-004) and digest pinning pending a Docker-connected `make m42-pin-images` run (SEC-006).

## Kickoff Checklist

- M42 approves synthetic-only or approved de-identified retrospective data boundary.
- M42 sponsor accepts the $1,000,000 target value architecture and mutual action plan for the $200,000 paid pilot.
- M42/Aethelred agree the paid pilot evidence mode is hybrid TEE + zkML + Digital Seal.
- Live archive and monitoring endpoints are available and retained for the agreed pilot period.
- Live TEE and prover endpoints are configured with simulation disabled where required by the pilot statement.
- Baseline run produces `baseline-measurement.json`.
- Sandbox run produces one evidence bundle, TEE attestation, zkML proof object, and Digital Seal per accepted job.
- Final report populates `docs/workload-packs/m42/business-case-report.md`.
- Decision-owner map identifies both the LOI signer and the corporate development contact (two-track conversion, `docs/operations/m42-conversion-plan.md`).
- LOI draft is socialized with the sponsor by Week 3 so the Week 4 executive value board reacts to paper, not to a concept.
