# M42 Med42 Synthetic Evaluation Workload Pack

## Pack Metadata

| Field | Value |
|-------|-------|
| **Pack Name** | m42-med42-synthetic-eval |
| **Version** | 1.0.0 |
| **Status** | review |
| **Vertical** | healthcare |
| **Customer** | M42 |
| **Data Status** | synthetic_non_live |
| **Evidence Schema** | evidence_schema_version: "v1" |
| **Evidence Mode** | Hybrid TEE + zkML / Digital Seal |
| **Proof Contract** | `require_both=true`; no single-evidence fallback |
| **Workload JSON** | config/pilots/m42/workload-pack.json |

This pack prepares one concrete M42 pilot workload: a Med42-compatible clinical note summarization and safety-triage evaluation using only synthetic clinical vignettes. It is not a live clinical deployment and does not include patient records, PHI, or retrospective M42 data.

Accepted paid-pilot jobs require the hybrid evidence contract implemented by the enterprise path: TEE attestation plus zkML proof evidence plus Digital Seal output. TEE-only, commitments-only, or single-evidence fallback runs are out of scope for accepted pilot evidence and may be used only for baseline or preflight checks.

## Model Specification

| Field | Value |
|-------|-------|
| Model family | Med42 |
| Workload | Synthetic clinical summarization and safety-triage evaluation |
| Manifest | config/pilots/m42/model-manifest.json |
| Model hash | 73e901338cd578d92d07e96a8521f1516a7d46134ac521c09899d59987caf82a |
| Weights status | External, not vendored in repository |
| Synthetic status | Non-live fixture only |

The model hash binds the repository model manifest. A live paid pilot must replace the external artifact digest with the approved M42/Med42 checkpoint or hosted endpoint digest and re-register the resulting measurement before any customer data is processed.

## Circuit Specification

| Field | Value |
|-------|-------|
| Circuit | m42-clinical-eval-io-commitment |
| Manifest | config/pilots/m42/circuit-manifest.json |
| Proof system | halo2 |
| Circuit hash | 9dda0ee98dca7763b72e45f5cbd77d1eb26243e7d00240c7d66817310414e1b5 |
| Scope | IO, policy, and evidence binding |

The circuit fixture binds prompt inputs, model output commitments, policy decisions, and TEE measurements inside the zkML proof path for replayable Digital Seal evidence. These commitments are bound evidence inputs, not an alternate commitments-only acceptance mode. The circuit does not prove clinical correctness of free-text model output.

## TEE Lane Specification

| Field | Value |
|-------|-------|
| Platform | nitro |
| Execution mode | Aethelred sandbox hybrid |
| Region | me-central-1 |
| Attestation | Required for every accepted job |
| zkML proof | Required for every accepted job |
| Digital Seal | Required for every accepted job |
| Contract | `require_both=true` |
| Freshness | Per-job nonce bound into the evidence bundle |
| TEE-only / commitments-only | Preflight or baseline only; not accepted pilot evidence |

The pilot lane requires both TEE attestation and zkML proof evidence. The resulting evidence bundle must include the Digital Seal `seal_id`. Single-evidence fallback is disabled.

## Policy Bundle

| Control | Value |
|---------|-------|
| Jurisdiction | UAE / Abu Dhabi pilot sandbox |
| Data class | synthetic-healthcare-no-phi |
| Live patient data | Not allowed |
| PHI | Not allowed |
| Egress | deny_by_default |
| Retention | 30 days for pilot evidence exports |
| Fallback | Not allowed |
| Accepted evidence mode | Hybrid TEE + zkML / Digital Seal only |

Security model details are in `docs/workload-packs/m42/security-model.md`.

## Evidence Output Specification

Evidence outputs conform to `docs/api/evidence-bundle-v1.schema.json`. The local evidence path is `config/pilots/m42/evidence`. An accepted job is complete only when the bundle contains both TEE attestation and zkML proof evidence plus validator and Digital Seal fields.

| Evidence Field | Populated | Source |
|----------------|-----------|--------|
| evidence.model_hash | Yes | workload pack model hash |
| evidence.input_hash | Yes | canonical synthetic vignette payload |
| evidence.output_hash | Yes | canonical model response payload |
| evidence.zk_proof | Yes | required zkML proof object in `config/pilots/m42/evidence/proofs` |
| evidence.tee_attestation | Yes | attestation object in `config/pilots/m42/evidence/attestations` |
| evidence.tee_platform | Yes | nitro |
| evidence.tee_measurement | Yes | attested sandbox measurement |
| evidence.timestamp | Yes | UTC bundle timestamp |
| evidence.validator_signature | Yes | validator signature over evidence bundle |
| evidence.confidence_score | Yes | synthetic evaluation score |
| evidence.chain_id | Yes | sandbox chain id |
| evidence.job_id | Yes | sandbox job id |
| evidence.seal_id | Yes | required Digital Seal id |

Declared evidence_schema_version: "v1".

Expected object names are captured in `config/pilots/m42/evidence/exports/evidence-objects.json`.

## Compliance Mapping

| Requirement | Pack Control |
|-------------|--------------|
| Synthetic/non-live status | Workload JSON `synthetic_status` and dataset fixture labels |
| No PHI | Policy data class `synthetic-healthcare-no-phi` and acceptance criterion `zero_live_data_findings` |
| Sovereign processing | Region `me-central-1`, egress deny by default, no external callback during sandbox run |
| Auditability | Hybrid evidence bundle, TEE attestation, zkML proof, archive pointer, validator signature, Digital Seal |
| Security review | Threat boundaries and residual risks in `security-model.md` |
| Business case | Baseline and sandbox comparison in `business-case-report.md` |

## Demo Flow

The demo flow is defined in `docs/workload-packs/m42/demo-flow.md` and covers baseline measurement, Aethelred sandbox execution, evidence review, archive export, and business-case readout.

## Benchmark Targets

Benchmark targets are defined in `docs/workload-packs/m42/benchmark-targets.md`.

## Deployment Configuration

| Setting | Value |
|---------|-------|
| Workload pack | config/pilots/m42/workload-pack.json |
| Registry dir | config/pilots/m42/registry |
| Evidence path | config/pilots/m42/evidence |
| Archive destination | localhost:9200 |
| Alertmanager | localhost:9093 |
| Prometheus | localhost:9099 |

For package fixture validation, run the pilot validator with `--pre-testnet --skip-enterprise`. For paid-pilot go-live, remove `--pre-testnet` and run the enterprise baseline checks as well. TEE-only or commitments-only runs remain preflight-only and cannot be reported as accepted paid-pilot evidence.

## Acceptance Criteria

| Criterion | Target |
|-----------|--------|
| Workload pack JSON validity | Passes `jq empty` and pilot validator required fields |
| Readiness gates | `config/pilots/m42/readiness-gates.json` has owned P0 go-live gates |
| Registry fixtures | Model and circuit hashes registered with status `active` |
| Evidence path | `attestations`, `proofs`, `exports`, and `archives` exist and are writable |
| Synthetic data boundary | 0 live records and 0 PHI findings |
| Evidence completeness | 100% hybrid TEE attestation + zkML proof + Digital Seal coverage for accepted synthetic cases |
| Single-evidence fallback | 0 accepted jobs |
| Replay determinism | >= 99% matching output commitments on replay |
| Clinical factuality | >= 95% on synthetic reference answers |
| Safety flag recall | >= 98% on synthetic reference flags |
| Business-case report | Baseline versus verified run report produced |
| Negative controls | Missing evidence, wrong hash, PHI injection, fallback mode, and nonce replay controls defined |
| Sponsor value package | `m42-value-bank.json`, `m42-mutual-action-plan.json`, `m42-value-scorecard.json`, and `m42-executive-readout.md` generated |
| Investor-grade gap audit | `m42-pilot-gap-register.json`, `m42-investor-readiness-report.md`, and `m42-sponsor-evidence-portal.html` generated |
