# Aethelred Multi-Repo Findings Disposition (AETHEL-MR-001..010)

Date: 2026-02-24
Purpose: One-by-one disposition for the strict multi-repo snapshot findings, distinguishing code/doc fixes from governance/process actions.

## AETHEL-MR-001 - Duplicate chain repos with same Go module path
Status: Partially Remediated (Authority registry/manifests/docs pushed to both repos; workflow push/enablement + Foundation ratification still pending)
Severity: Critical

Why it still matters:
- Both `aethelred-core` and `aethelred-cosmos-node` present as authoritative chain repos and declare the same module path (`github.com/aethelred/aethelred`).

Evidence:
- `/tmp/aethelred-core-audit/go.mod:1`
- `aethelred-cosmos-node/go.mod:1`

What was implemented now:
1. Interim authority policy published in `docs/governance/repo-authority-policy-2026-02-24.md` (designates `aethelred-cosmos-node` as interim canonical chain repo).
2. Repo authority notices added to:
   - `aethelred-cosmos-node/README.md`
   - `/tmp/aethelred-core-audit/README.md`
3. Chain repos now include repo-local security scope docs:
   - `SECURITY.md`
   - `docs/security/repo-authority.md`
4. Machine-readable authority registry added: `docs/governance/repo-authority-registry.json`
5. Authority validation script + umbrella CI guard added:
   - `scripts/validate-repo-authority.py`
   - `.github/workflows/repo-authority-guard.yml`
6. Repo-local `repo-authority.json` manifests added to both chain repos and repo-local release guard workflows prepared (canonical validation in `aethelred-cosmos-node`, release block in `aethelred-core`).
7. Foundation ratification decision records prepared:
   - `docs/governance/adr-0001-chain-repo-authority-canonicalization.md`
   - `aethelred-cosmos-node/docs/governance/adr-0001-chain-repo-authority-canonicalization.md`
8. `aethelred-core` final disposition hardened to `release-frozen-transitional-mirror` with mirror drift-check workflow (prepared in local clone):
   - `/tmp/aethelred-core-audit/docs/governance/core-disposition-ratification.md`
   - `/tmp/aethelred-core-audit/.github/workflows/mirror-drift-check.yml`
9. Workflow-free authority/disposition branches were pushed to both public repos (docs/manifests/security scope only):
   - `aethelred-foundation/aethelred-cosmos-node`: `codex/repo-authority-aethel-mr-001-noworkflows-20260224`
   - `aethelred-foundation/aethelred-core`: `codex/repo-authority-aethel-mr-001-noworkflows-20260224`

Remaining required action:
1. Ratify ADR-0001 at Foundation/org level (human sign-off; cannot be automated from this workspace).
2. Push and enable the workflow-bearing branches (`repo-authority-guard`, `mirror-drift-check`) using a GitHub token with `workflow` scope.
3. Apply GitHub repo settings for `aethelred-core` final disposition (archive or mirror-only + branch protections + repo description banner).
4. Enforce no duplicate release tags across both repos at org release process level (CI guards prepared but not enabled in public repos yet).

What can be automated later:
- Cross-repo tag/version registry check that blocks duplicate semantic versions across both repos.

## AETHEL-MR-002 - `aethelred-rust-node` conceptual/non-buildable repo
Status: Remediated Locally (crate baseline created; build/test/CI enabled in local clone)
Severity: Critical

Why it mattered:
- The repo lacked `Cargo.toml`, so it could not be built/tested as an auditable crate.

Evidence (original snapshot):
- `/tmp/aethelred-rust-node-audit/mod.rs:1`
- No `Cargo.toml` in repo root (checked during review)

What was implemented now:
1. `Cargo.toml` manifest added with library + binary targets.
2. `src/lib.rs` and `src/main.rs` added; existing pillar modules are compiled as a real crate.
3. Compile blockers fixed (serde large-array support, borrow-check issue, missing trait derives, local hex encoding helper).
4. `cargo check --offline` and `cargo test --offline` pass in `/tmp/aethelred-rust-node-audit`.
5. Repo-local CI workflow added (`cargo fmt/check/test`): `/tmp/aethelred-rust-node-audit/.github/workflows/rust-node-ci.yml`.
6. Repo-local baseline security files added to `/tmp/aethelred-rust-node-audit/`:
   - `SECURITY.md`
   - `docs/security/threat-model.md`
   - `.github/workflows/docs-hygiene.yml`
   - `.github/workflows/repo-security-baseline.yml`
7. README and repo-authority docs updated to reflect buildable/testable (non-canonical) status.

Remaining action:
1. Push the local clone changes to the actual public `aethelred-rust-node` repo.
2. Add `clippy` and coverage gates after baseline warning cleanup.
3. Define runtime/networking scope if this repo is intended to evolve into a validator node implementation (vs protocol simulation crate).

## AETHEL-MR-003 - Repo-level audit evidence fragmented outside public repos
Status: Partially Remediated (baseline is now registry-backed, measurable, and committed across all 9 local repo clones; public pushes of workflow files remain blocked by PAT scope)
Severity: Critical

Why it still matters:
- Strong CI/guards exist in the umbrella workspace, but many are not present in each public repo.

What was implemented now:
1. Repo-local baseline security CI added across all 9 local repo snapshots:
   - `.github/workflows/docs-hygiene.yml`
   - `.github/workflows/repo-security-baseline.yml`
2. Repo-local `SECURITY.md` and `docs/security/threat-model.md` skeletons added across all 9 local repo snapshots.
3. SDK repo-local provenance workflow and provenance draft added:
   - `sdk/.github/workflows/sdk-release-provenance-local.yml`
   - `sdk/docs/security/release-provenance.md`
4. Machine-readable repo auditability registry added (9 repos + required baseline files + advanced expected workflows/docs):
   - `docs/governance/repo-auditability-registry.json`
5. Auditability baseline validator + rollout matrix generator added:
   - `scripts/validate-repo-auditability.py`
   - `docs/audits/aethel-mr-003-repo-auditability-rollout-matrix.md`
6. Umbrella CI guard added to keep the registry/matrix in sync:
   - `.github/workflows/repo-auditability-guard.yml`

What is already improved:
- `aethelred-tee-worker` now has local `nitro-sdk` warning-budget scripts and a pushed remediation branch with code-level hardening.
- Repo-local workflow versions were prepared but GitHub PAT lacked `workflow` scope for push.
- The rollout gap is now quantified per repo (`baseline`, `tracked`, `advanced`) in the generated matrix instead of being tracked only by notes.

Current measured rollout status (from local clones, generated matrix):
- All 9 repos now show baseline `4/4` present and `4/4` tracked locally.
- `aethelred-core` and `aethelred-cosmos-node` baseline + authority workflows are on workflow-bearing local branches prepared earlier.
- The other 7 repos now have dedicated baseline rollout branches prepared locally:
  - `codex/aethel-mr-003-auditability-baseline-20260224` in `aethelred-tee-worker`, `aethelred-contracts`, `aethelred-sdks`, `aethelred-developer-tools`, `aethelred-integrations`, `aethelred-dashboard`, `aethelred-rust-node`.
- Advanced workflow coverage remains uneven by repo (tracked in the rollout matrix) and is now explicitly measurable.

Remaining action (per repo):
1. Push the workflow-bearing baseline branches (all 9 repos) using a token with `workflow` scope.
2. Push advanced repo-specific workflows (SDK coverage/release readiness, nitro warning budgets, contract/integration pipelines) into the corresponding repos where the matrix shows gaps.
3. Publish or attach scan/test artifacts per release.

Blocker noted:
- PAT used for pushes lacked `workflow` scope for `.github/workflows/*` updates.

## AETHEL-MR-004 - Absolute local workstation paths in public docs
Status: Remediated Locally (needs push to affected repos)
Severity: High

What was fixed:
- Replaced `...` path references with `$AETHELRED_REPO_ROOT/...` in public markdown docs across SDK + developer-tools + integrations docs.

Validation result:
- `sdk` markdown absolute-path refs: `0`
- `docs/sdk` markdown absolute-path refs: `0`
- `aethelred-developer-tools` markdown absolute-path refs: `0`
- `aethelred-integrations-repo` markdown absolute-path refs: `0`

Representative fixed files:
- `sdk/README.md`
- `docs/sdk/official-sdks.md`
- `docs/sdk/developer-tools.md`
- `aethelred-developer-tools/cli/aethel/README.md`
- `aethelred-integrations-repo/apps/fastapi-verifier/README.md`

Recommended follow-up:
1. Add docs hygiene CI (`rg '/Users/'`) to all public repos.
2. Extend to Windows/macOS local path patterns (`C:\\`, `/home/`, `/var/folders/`).

## AETHEL-MR-005 - SDKs still source-first / pending public artifact publication
Status: Partially Remediated (machine-checked repo-local provenance controls now in place), Operationally Open (public registry publication + signed releases pending)
Severity: High (release/provenance)

What is already in place:
- SDK docs clearly state source-first status and pending registry publication.
- Release-readiness workflows and packaging checks were added in the workspace.
- Repo-local SDK provenance workflow + provenance policy draft added:
  - `sdk/.github/workflows/sdk-release-provenance-local.yml`
  - `sdk/docs/security/release-provenance.md`
- Repo-local machine-checked provenance controls added:
  - `sdk/docs/security/release-provenance-registry.json`
  - `sdk/scripts/validate_release_provenance.py`
  - `sdk/.github/workflows/sdk-release-provenance-guard.yml`
  - `sdk/docs/security/release-provenance-status.md`
  - `sdk/docs/security/release-provenance-status.json`
  - `sdk/docs/security/release-verification-guide.md`
- Repo-local SDK release-readiness workflow added (independent of umbrella workflow):
  - `sdk/.github/workflows/sdk-release-readiness.yml`

Evidence:
- `sdk/README.md:5`
- `docs/sdk/official-sdks.md:18`
- `sdk/docs/security/release-provenance-status.json`

Required action (one-by-one):
1. Publish canonical artifacts to PyPI / npm / crates.io / Go module path.
2. Tag signed releases and publish checksums/provenance (workflow support now generates provenance bundle structure + checksums locally/in CI).
3. Update docs from “pending” to exact install commands for registry artifacts.
4. Maintain a public version matrix and release verification guide (guide now exists; keep it synchronized with actual registry release flow).

## AETHEL-MR-006 - Central security workflow targets stale contract paths (`contracts/ethereum`)
Status: Remediated Locally (workspace root)
Severity: High

What was fixed:
- Updated security scan workflow to target `contracts` instead of nonexistent `contracts/ethereum`.

Fixed file:
- `.github/workflows/security-scans.yml`

Specific corrections:
- `working-directory: contracts`
- Slither `target: contracts`
- Slither config `contracts/slither.config.json`
- npm audit working directory `contracts`

Recommended follow-up:
1. Add explicit path existence preflight checks in the workflow.
2. Mirror/push the corrected workflow to the actual repo that owns this CI configuration.

## AETHEL-MR-007 - Threat models / SBOMs / published security artifacts not visible per repo
Status: Partially Remediated (repo-local security policy/threat-model + SBOM baseline CI added; published artifacts still open)
Severity: High

Why it still matters:
- Security CI existence is not a substitute for published, reviewable artifacts and threat assumptions.

What was implemented now:
1. Added `SECURITY.md` to all 9 local repo snapshots.
2. Added `docs/security/threat-model.md` draft skeleton to all 9 local repo snapshots.
3. Added repo-local SBOM-capable CI baseline (`.github/workflows/repo-security-baseline.yml`) using `anchore/sbom-action`.

Remaining action (per critical repo):
1. Complete the threat models with repo-specific trust boundaries and abuse paths.
2. Publish SBOM artifacts for releases and link them from release notes.
3. Publish scan outputs or summaries (govulncheck, cargo-audit, Slither, npm audit) with commit/tag linkage.
4. Replace placeholder/private disclosure text in `SECURITY.md` with an official contact/channel.

## AETHEL-MR-008 - Dashboard lacks explicit CSP
Status: Partially Remediated Locally
Severity: Medium

What was fixed:
- Added a `Content-Security-Policy` header to dashboard Next.js config.

Fixed file:
- `aethelred-frontend-repo/dashboard/next.config.js:46`

Current limitation (strict auditor note):
- CSP still includes `'unsafe-inline'` for compatibility. `unsafe-eval` has been removed, but this is still transitional and not fully hardened.

Required follow-up:
1. Migrate to nonce/hash-based CSP and remove `'unsafe-inline'`.
2. Audit script/style injection requirements and third-party scripts.
3. Consider `report-uri` / `report-to` for CSP telemetry.

## AETHEL-MR-009 - Uneven test maturity across repos
Status: Partially Remediated (repo-local test/security baseline CI added everywhere; implementation tests still weak in some repos)
Severity: Medium

Current snapshot:
- Stronger: `aethelred-core`, `aethelred-cosmos-node`, `aethelred-contracts`, `aethelred-sdks`
- Weak/none visible: `aethelred-developer-tools`, `aethelred-integrations`, `aethelred-rust-node`

What was implemented now:
1. Added repo-local baseline CI workflow (`repo-security-baseline.yml`) to all 9 local repo snapshots, including inventory + SBOM generation and opportunistic test smoke checks.
2. Added repo-local docs hygiene CI (`docs-hygiene.yml`) to all 9 local repo snapshots.

Remaining action (repo-specific):
1. Add enforced (non-opportunistic) unit/integration test jobs per repo.
2. Add coverage gates where applicable (especially `developer-tools`, `integrations`, and future `rust-node` implementation).
3. If `aethelred-rust-node` remains public, add a build/test crate or keep it explicitly research-only.

## AETHEL-MR-010 - `nitro-sdk` `full-sdk` warnings not at zero
Status: Remediated Locally (0 warnings)
Severity: Medium (engineering quality confidence)

What was fixed:
- Added missing doc comment for `FineRule` enum in `nitro-sdk`.

Fixed file:
- `services/tee-worker/nitro-sdk/src/compliance/regulation.rs:66`

Validation:
- `cargo check --features full-sdk` => `0` warnings (local)
- `bash services/tee-worker/scripts/check-nitro-sdk-warning-budget.sh .` => pass at budget `0`
- `attestation-evidence` regression test still passes

Follow-up:
1. Push updated warning budget scripts/workflows to `aethelred-tee-worker` with a token that has `workflow` scope.

## Summary by Closure Type

- Remediated locally now: `AETHEL-MR-004`, `AETHEL-MR-006`, `AETHEL-MR-010`
- Partially remediated locally (needs push/ratification/hardening): `AETHEL-MR-001`, `AETHEL-MR-002`, `AETHEL-MR-003`, `AETHEL-MR-005`, `AETHEL-MR-007`, `AETHEL-MR-008`, `AETHEL-MR-009`
