# M42 Pilot Package

This directory contains the machine-readable package for the M42 paid-pilot readiness fixture.

## Ten-Workload Platform

The pilot runs any of ten M42 workloads — the four business-case candidates (Exhibit 9) plus six data/diagnostics/trials/governance workloads mapped to M42's Malaffi, BioBank, genome-programme, NRL, IROS, and Med42 assets:

| Workload id | Title | Primary metric |
|-------------|-------|----------------|
| `genomic-variant-interpretation` | Genomic variant interpretation | pathogenic recall |
| `med42-clinical-evaluation` | Med42 evaluation / fine-tuning (active) | clinical factuality |
| `retrospective-radiology-ai` | Retrospective radiology AI evaluation | AUROC |
| `drug-discovery-screening` | Drug-discovery screening | enrichment factor at 1% |
| `de-identification-attestation` | De-identification & data-egress attestation | PHI recall |
| `population-health-rwe` | Malaffi population-health & real-world evidence | count relative error |
| `biobank-gwas-prs` | Biobank GWAS & polygenic risk scores | PRS AUC |
| `digital-pathology-ai` | Digital pathology AI | slide AUROC |
| `clinical-trial-matching` | Clinical-trial matching & synthetic control arms | matching sensitivity |
| `med42-training-provenance` | Med42 training / fine-tuning provenance | approved-data coverage |

Catalog: `config/pilots/m42/workloads/catalog.json`. Per-workload packs: `config/pilots/m42/workloads/<id>.json`. Synthetic fixtures and evaluation protocols: `docs/workload-packs/m42/workloads/<id>/`. Engine and metrics: `scripts/m42_workloads.py`. Full description: `docs/workload-packs/m42/workload-platform.md`.

```bash
python3 scripts/m42-sandbox-drill.py --list     # list workloads
make m42-sandbox-drill                           # active workload (canonical)
make m42-sandbox-drill-all                        # all four workloads + catalog scorecard
make m42-workloads-score                          # compute metrics, enforce acceptance floors
```

## Active Workload Package

- Pilot: `m42-med42-synthetic-eval`
- Workload pack: `config/pilots/m42/workload-pack.json`
- KPI scorecard: `config/pilots/m42/pilot-scorecard.json`
- Readiness gates: `config/pilots/m42/readiness-gates.json`
- Registry fixtures: `config/pilots/m42/registry/measurements.json` and `config/pilots/m42/registry/circuits.json`
- Evidence path: `config/pilots/m42/evidence`
- Documentation pack: `docs/workload-packs/m42`
- Proof contract: accepted paid-pilot jobs require hybrid TEE attestation plus zkML proof evidence, chain ID, validator signature, archive pointer, verification flags, and a Digital Seal (`seal_id`)
- Required CI gate: `.github/workflows/m42-pilot-readiness.yml`
- Exclusive sandbox: `integrations/docker/docker-compose.m42-pilot.yml`
- Delivery plan: `docs/operations/m42-pilot-delivery-plan.md`
- $1M value structure: `docs/operations/m42-1m-value-pilot-structure.md`
- Conversion plan (LOI/MOU + pre-seed tracks): `docs/operations/m42-conversion-plan.md`
- Differentiation dossier for reviewers: `docs/workload-packs/m42/differentiation-dossier.md`

The package is synthetic and non-live. It contains no M42 patient records, no PHI, and no retrospective patient data. The model hash binds the pilot model manifest in this repository. Before any paid live run, the operator must replace the external model artifact digest with the approved checkpoint or hosted endpoint digest and re-register the resulting measurement.

TEE-only, commitments-only, or single-evidence fallback runs are out of scope for accepted paid-pilot evidence. They may be used only as baseline or preflight checks before sandbox submission.

Exclusive sandbox commands:

```bash
make m42-sandbox-prepare
make m42-sandbox-preflight
make m42-sandbox-drill
make m42-pilot-gap-audit
make m42-pin-images
make m42-sandbox-up
make m42-sandbox-validate
make m42-pilot-go-live
```

Security posture enforced by the package:

- The evidence archive (OpenSearch) runs with the security plugin enabled. `make m42-sandbox-prepare` generates the admin credential into `config/pilots/m42/secrets/opensearch_admin_password.txt`; live validation authenticates over HTTPS and fails if anonymous access is accepted.
- `make m42-pin-images` resolves every compose image to a sha256 digest in `config/pilots/m42/images.lock.env`. The strict go-live gate fails while any image reference resolves to a mutable tag.
- Monitoring-tier containers (Prometheus, Alertmanager, Grafana, alert webhook) run with read-only root filesystems and no-new-privileges.

Package validator command:

```bash
bash scripts/validate-pilot-deployment.sh \
  --pre-testnet \
  --skip-enterprise \
  --pilot-name m42-med42-synthetic-eval \
  --workload-pack config/pilots/m42/workload-pack.json \
  --model-hash 73e901338cd578d92d07e96a8521f1516a7d46134ac521c09899d59987caf82a \
  --circuit-hash 9dda0ee98dca7763b72e45f5cbd77d1eb26243e7d00240c7d66817310414e1b5 \
  --registry-dir config/pilots/m42/registry \
  --evidence-path config/pilots/m42/evidence \
  --archive-dest localhost:19200 \
  --alertmanager localhost:19093 \
  --prometheus localhost:19090
```

The command above validates the package strictly and reports archive, Alertmanager, and Prometheus reachability as pre-testnet warnings when those services are not running. For paid-pilot go-live, remove `--pre-testnet`, keep the same package paths and hashes, and run it against live validator, TEE `/execute`, zkML `/prove`, archive, and monitoring endpoints. The repository already includes the shared monitoring configuration under `infrastructure/monitoring`.
