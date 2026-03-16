# AETHEL-MR-003 Repo Auditability Rollout Matrix

Date: 2026-02-24
Purpose: Track repo-local auditability/CI baseline presence and rollout readiness across the public Aethelred repos.

Baseline required in every repo:
- `SECURITY.md`
- `docs/security/threat-model.md`
- `.github/workflows/docs-hygiene.yml`
- `.github/workflows/repo-security-baseline.yml`

| Repo | Role | Baseline | Tracked | Advanced | Push Readiness | Notes |
|---|---|---:|---:|---:|---|---|
| `aethelred-foundation/aethelred-core` | `chain-go-transitional-mirror` | 4/4 | 4/4 | 2/2 | ready (push may require workflow-scope PAT) | baseline tracked locally |
| `aethelred-foundation/aethelred-cosmos-node` | `chain-go-canonical` | 4/4 | 4/4 | 1/1 | ready (push may require workflow-scope PAT) | baseline tracked locally |
| `aethelred-foundation/aethelred-rust-node` | `chain-rust-implementation-track` | 4/4 | 4/4 | 2/2 | ready (push may require workflow-scope PAT) | baseline tracked locally |
| `aethelred-foundation/aethelred-tee-worker` | `tee-worker-runtime` | 4/4 | 4/4 | 0/3 | ready (push may require workflow-scope PAT) | baseline tracked locally; missing advanced: 3 |
| `aethelred-foundation/aethelred-contracts` | `contracts` | 4/4 | 4/4 | 0/0 | ready (push may require workflow-scope PAT) | baseline tracked locally |
| `aethelred-foundation/aethelred-sdks` | `sdk-monorepo` | 4/4 | 4/4 | 2/8 | ready (push may require workflow-scope PAT) | baseline tracked locally; missing advanced: 6 |
| `aethelred-foundation/aethelred-developer-tools` | `developer-tools` | 4/4 | 4/4 | 0/1 | ready (push may require workflow-scope PAT) | baseline tracked locally; missing advanced: 1 |
| `aethelred-foundation/aethelred-integrations` | `framework-integrations` | 4/4 | 4/4 | 0/2 | ready (push may require workflow-scope PAT) | baseline tracked locally; missing advanced: 2 |
| `aethelred-foundation/aethelred-dashboard` | `frontend-dashboard` | 4/4 | 4/4 | 0/0 | ready (push may require workflow-scope PAT) | baseline tracked locally |

Notes:
- `Tracked` means the baseline files are tracked in the local git clone (not just present on disk).
- Workflow pushes may be rejected by GitHub if the token lacks `workflow` scope.
- This matrix is generated from local clones using `scripts/validate-repo-auditability.py`.
