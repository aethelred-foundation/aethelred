# Aethelred Sovereign Public Proof Path

Docker-runnable proof path for the first institutional Aethelred Seal demo.

This package is intentionally shaped for sovereign and regulated buyers. It does
not just prove that a job ran. It proves that a high-stakes AI decision can be
packaged with policy, identity, jurisdiction, verifier quorum, liability, audit
export, and explicit production-readiness boundaries.

```text
Regulated AI request
  -> institutional context
  -> policy receipt
  -> jurisdiction report
  -> external compute proof normalization
  -> Docker attestation transcript
  -> evidence bundle
  -> regulated verifier quorum
  -> liability route
  -> Aethelred Seal
  -> key custody manifest
  -> anchor manifest
  -> pilot readiness gate
  -> sovereign differentiation scorecard
  -> auditor attestation
  -> regulatory evidence index
  -> audit pack and append-only ledger
```

This is a public proof path. It proves the product architecture, verifier UX,
artifact model, and regulator-pack workflow. It does not claim production TEE or
production zkML execution.

## Run

```bash
cd docs/demo/public-proof-path
docker compose up --build
```

Open:

- Sovereign proof console: `http://localhost:8088`
- Seal verification: `http://localhost:8088/v1/seals/latest/verify`
- Regulator pack: `http://localhost:8088/v1/regulator-pack/latest`
- External compute report: `http://localhost:8088/v1/external-compute/latest`
- 10x sovereign scorecard: `http://localhost:8088/v1/sovereign-differentiation/latest`
- Anchor manifest: `http://localhost:8088/v1/anchor/latest`
- Pilot readiness: `http://localhost:8088/v1/readiness/latest`
- Auditor attestation: `http://localhost:8088/v1/auditor/latest`
- Audit report: `http://localhost:8088/v1/audit/latest.md`
- Ledger verification: `http://localhost:8088/v1/ledger/verify`

Artifacts are written to:

```text
docs/demo/public-proof-path/out/
```

## API Surface

| Endpoint | Purpose |
|---|---|
| `/v1/scenarios` | Available sovereign scenario packs |
| `/v1/proof-path/latest` | Full public proof record |
| `/v1/seals/latest` | Portable Aethelred Seal |
| `/v1/seals/latest/verify` | Machine verifier report |
| `/v1/external-compute/latest` | Normalized Docker, external confidential-compute, sovereign-cloud, or on-prem compute proof report |
| `/v1/institutional/context` | Tenant, model, agent, policy, deployment, and governance context |
| `/v1/assurance/latest` | Assurance tier, readiness posture, production blockers |
| `/v1/quorum/latest` | Signed verifier quorum votes |
| `/v1/jurisdiction/latest` | Data residency and jurisdiction report |
| `/v1/liability/latest` | Sponsor, human controller, model-risk owner, operator, and auditor route |
| `/v1/key-custody/latest` | Signer custody posture and production HSM/KMS requirements |
| `/v1/anchor/latest` | Local anchor and chain-ready payload |
| `/v1/auditor/latest` | Signed simulated auditor attestation |
| `/v1/readiness/latest` | Pilot readiness gate and production blockers |
| `/v1/sovereign-differentiation/latest` | Signed Aethelred-vs-generic-verifiable-cloud scorecard |
| `/v1/evidence-index/latest` | Regulator-readable artifact index with hashes |
| `/v1/regulator-pack/latest` | Combined regulator export bundle |
| `/v1/ledger/verify` | Append-only ledger verification |

## Scenario Packs

The console and CLI support three regulated verticals plus an external-compute
interop path:

| Scenario | Use case |
|---|---|
| `finance` | High-value banking transaction review |
| `healthcare` | Clinical decision-support audit trail |
| `carbon` | Carbon MRV evidence seal |
| `external-finance` | External confidential-compute proof wrapped by Aethelred policy, jurisdiction, liability, quorum, audit, and anchor controls |

```bash
npm run run:finance
npm run run:healthcare
npm run run:carbon
npm run run:external
```

## Institutional Artifacts

Every run writes a complete evidence set:

| Artifact | Why it matters |
|---|---|
| `proof-record.json` | Full public proof record |
| `aethelred-seal.json` | Portable AI decision seal |
| `policy-receipt.json` | Signed policy engine decision and control checklist |
| `institutional-context.json` | Registry-backed buyer, model, agent, policy, and deployment context |
| `jurisdiction-report.json` | Data residency, execution region, and public-data boundary evidence |
| `external-compute-report.json` | Normalized upstream compute proof report for Docker, external confidential compute, sovereign cloud, or on-prem execution |
| `docker-attestation.json` | Docker demo attestation transcript and container measurement |
| `evidence-bundle.json` | TEE-shaped and zkML-shaped evidence bundle |
| `validator-quorum.json` | Signed multi-verifier quorum votes across regulated categories |
| `liability-route.json` | Accountability and escalation path |
| `assurance-plan.json` | Tier target, current proof posture, blockers, and promotion path |
| `key-custody-manifest.json` | Signer custody posture and production HSM/KMS requirements |
| `anchor-manifest.json` | Local ledger anchor and chain-ready payload |
| `pilot-readiness-gate.json` | Conditional pilot readiness gates |
| `sovereign-differentiation-scorecard.json` | Signed scorecard showing where Aethelred adds sovereign controls above generic verifiable compute |
| `regulatory-evidence-index.json` | Artifact index with SHA-256 commitments |
| `auditor-attestation.json` | Signed simulated external-auditor attestation over artifact consistency |
| `public-verifier-manifest.json` | Public endpoints, claims, and claim boundaries |
| `audit-pack.json` | Machine-readable regulator/auditor pack |
| `audit-report.md` | Human-readable audit report |

## What The Verifier Checks

- input hash recomputes from the public proof request
- model output hash recomputes
- institutional context hash matches the seal
- policy receipt hash and Ed25519 signature verify
- required policy controls pass
- model, agent, and sponsor are present in registries
- jurisdiction and data residency controls pass
- liability route is formed
- external compute report hash, signature, provider policy, and seal binding verify
- Docker attestation hash and signature verify
- evidence bundle hash matches the seal
- validator quorum hash, threshold, vote hashes, and vote signatures verify
- assurance tier meets the policy floor
- Aethelred Seal hash and signature verify
- key custody manifest hash and signature verify
- anchor manifest hash, signature, and seal binding verify
- pilot readiness gate hash and signature verify
- regulatory evidence index hash, signature, and artifact hashes verify
- auditor attestation hash, signature, and artifact hashes verify
- append-only ledger hash chain verifies

## Assurance Posture

The default run targets:

```text
Tier 4 - Sovereign Regulated AI Decision
```

The public Docker path intentionally remains non-production. The verifier reports
warnings for:

- production hardware TEE quote not present
- production zkML proof not present
- governed KMS/HSM key custody not present

Those warnings are deliberate. This is the correct public posture: prove the
institutional evidence path now, then promote the same path into sovereign cloud,
on-prem, TEE, zkML, HSM, validator, and auditor-backed production environments.

## Run Without Docker

```bash
cd docs/demo/public-proof-path
npm test
npm run run
npm run validate
npm start
```

CLI:

```bash
node src/cli.mjs list-scenarios
node src/cli.mjs run --scenario=healthcare
node src/cli.mjs run --scenario=external-finance
node src/cli.mjs verify
node src/cli.mjs external-report
node src/cli.mjs regulator-pack
node src/cli.mjs sovereign-scorecard
node src/cli.mjs anchor
```

## Operator Docs

- [Schema catalog](./SCHEMA_CATALOG.md)
- [External compute interop strategy](./EXTERNAL_COMPUTE_INTEROP.md)
- [Sovereign pilot runbook](./SOVEREIGN_PILOT_RUNBOOK.md)
- [Production readiness gap register](./PRODUCTION_READINESS.md)
- [OpenAPI contract](./openapi.yaml)

## Machine-Readable Schemas

Core schema contracts live in [`schemas/`](./schemas/):

- `aethelred-seal-v0.2.schema.json`
- `aethelred-verifier-report-v0.2.schema.json`
- `aethelred-anchor-manifest-v0.2.schema.json`
- `aethelred-pilot-readiness-gate-v0.2.schema.json`
- `aethelred-external-compute-report-v0.2.schema.json`
- `aethelred-sovereign-differentiation-scorecard-v0.2.schema.json`

## Container Posture

The Docker service runs as a non-root user, drops Linux capabilities, enables
`no-new-privileges`, uses a read-only filesystem, mounts `/data` only for
artifacts, and exposes a healthcheck.

## Production Promotion Path

To turn this from public proof into regulated pilot infrastructure:

1. Run the same workflow in a sovereign cloud confidential VM or approved on-prem enclave.
2. Replace the Docker attestation transcript with Nitro, SGX, SEV-SNP, Intel TDX, or approved sovereign-cloud evidence.
3. Replace the demo zkML transcript with workflow-appropriate zkML or deterministic verifier evidence.
4. Bind signing keys to KMS/HSM custody and publish key rotation policy.
5. Bind verifier identities to legal entities, service terms, and validator/auditor obligations.
6. Anchor seal commitments to Aethelred testnet or a permissioned institutional zone.
