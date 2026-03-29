# AETHEL-MR-003 Repo Auditability Rollout Matrix

Date: 2026-03-13
Purpose: Track repo-local auditability/CI baseline presence and rollout readiness across the public Aethelred repos.

Baseline required in every repo:
- `README.md`
- `LICENSE`
- `SECURITY.md`
- `SUPPORT.md`
- `CODE_OF_CONDUCT.md`
- `repo-role.json`
- `docs/security/threat-model.md`
- `docs/security/release-provenance.md`
- `.github/workflows/docs-hygiene.yml`
- `.github/workflows/repo-security-baseline.yml`

| Repo | Role | Baseline | Tracked | Advanced | Push Readiness | Notes |
|---|---|---:|---:|---:|---|---|
| `aethelred-foundation/aethelred` | `canonical-monorepo` | 10/10 | 10/10 | 6/6 | ready (push may require workflow-scope PAT) | baseline tracked locally |
| `aethelred-foundation/contracts` | `smart-contracts` | n/a | n/a | n/a | registry-only | not evaluated in this environment |
| `aethelred-foundation/aethelred-sdk-ts` | `sdk-typescript` | n/a | n/a | n/a | registry-only | not evaluated in this environment |
| `aethelred-foundation/aethelred-sdk-py` | `sdk-python` | n/a | n/a | n/a | registry-only | not evaluated in this environment |
| `aethelred-foundation/aethelred-sdk-go` | `sdk-go` | n/a | n/a | n/a | registry-only | not evaluated in this environment |
| `aethelred-foundation/aethelred-sdk-rs` | `sdk-rust` | n/a | n/a | n/a | registry-only | not evaluated in this environment |
| `aethelred-foundation/aethelred-cli` | `developer-cli` | n/a | n/a | n/a | registry-only | not evaluated in this environment |
| `aethelred-foundation/vscode-aethelred` | `editor-extension` | n/a | n/a | n/a | registry-only | not evaluated in this environment |
| `aethelred-foundation/aethelred-docs` | `documentation-site` | n/a | n/a | n/a | registry-only | not evaluated in this environment |
| `aethelred-foundation/AIPs` | `governance-specs` | n/a | n/a | n/a | registry-only | not evaluated in this environment |
| `aethelred-foundation/cruzible` | `application-frontend` | n/a | n/a | n/a | registry-only | not evaluated in this environment |
| `aethelred-foundation/.github` | `org-control-plane` | n/a | n/a | n/a | registry-only | not evaluated in this environment |

Notes:
- `Tracked` means the baseline files are tracked in the local git clone (not just present on disk).
- Workflow pushes may be rejected by GitHub if the token lacks `workflow` scope.
- `registry-only` means the repo remains in the registry but was not available as a local clone in the current execution environment.
- This matrix is generated from the current checkout plus any available local sibling clones using `scripts/validate-repo-auditability.py`.
