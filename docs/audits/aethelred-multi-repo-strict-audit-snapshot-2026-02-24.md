# Aethelred Multi-Repo Security Audit (Strict Auditor-Style Snapshot)

> Status update (post-snapshot remediation): `aethelred-rust-node` has since been converted into a buildable/testable Rust crate baseline in the local remediation clone (`Cargo.toml` + CI + passing offline tests). Treat `AETHEL-MR-002` below as snapshot evidence, not current status.

Date: 2026-02-24
Reviewer: Codex (simulated independent auditor-style review; not an official Trail of Bits / OpenZeppelin / Hecken / CertiK engagement)
Scope: Public repos listed by user + mapped local snapshots / fresh clones where available.

## Executive Summary

This review is intentionally strict. The protocol has made substantial engineering progress versus earlier scaffold-stage assessments, and several previously raised code-level issues are now clearly remediated. However, there are still material risks in release governance, repo auditability, and public-facing documentation hygiene.

Most important conclusion:

- The broad markdown audit in the attached ZIP is **partially stale** (many technical claims are no longer accurate).
- The project still has **serious auditability and release-process gaps** that a top-tier auditor would continue to flag.
- The highest remaining risks are **repo fragmentation / duplication**, **non-buildable conceptual repos being presented alongside production-track repos**, and **evidence/CI not being consistently co-located with the public repos under review**.

## Snapshot / Scope Provenance

Audited snapshots (local/fresh clone commit heads used in this review):

- `aethelred-core`: `0c75e1c` (fresh clone to `/tmp/aethelred-core-audit`)
- `aethelred-tee-worker`: `1037f36` (local repo `services/tee-worker`)
- `aethelred-contracts`: `9b2d19a1` (local repo `contracts`)
- `aethelred-cosmos-node`: `a000c52` (local repo `aethelred-cosmos-node`)
- `aethelred-rust-node`: `4888224` (fresh clone to `/tmp/aethelred-rust-node-audit`)
- `aethelred-sdks`: `17c2cba` (local repo `sdk`)
- `aethelred-developer-tools`: `31ceed1` (local repo `aethelred-developer-tools`)
- `aethelred-integrations`: `6c406f9` (local repo `aethelred-integrations-repo`)
- `aethelred-dashboard`: `0b4627f` (local repo `aethelred-frontend-repo`)

Limitations:

- This is a desk/code/config review, not a live deployment penetration test.
- Remote `origin/main` HEAD hashes were not re-fetched for all repos in-session due network restrictions; this report is based on the snapshots above.

## Findings (Ordered by Severity)

### Critical Findings

#### AETHEL-MR-001: Duplicate chain repositories with the same Go module path create patch-drift and release ambiguity
Severity: Critical
Impact: Security fixes can land in one chain repo and not the other, while both appear authoritative to partners/integrators.

Evidence:

- `/tmp/aethelred-core-audit/go.mod:1` declares `module github.com/aethelred/aethelred`
- `aethelred-cosmos-node/go.mod:1` declares the same module path `github.com/aethelred/aethelred`
- Both repos are full Cosmos-style Go modules with substantial `x/` code and tests.

Why this is severe:

- Two public repos representing the same module path significantly increases operational and audit confusion.
- Security advisories, patch provenance, and reproducible builds become ambiguous.

Recommendation:

- Define a single canonical chain repo immediately.
- Deprecate/archive the other or convert it to a mirror with automated sync and explicit bannering.
- Publish a repo authority policy and release provenance statement.

#### AETHEL-MR-002: `aethelred-rust-node` is a conceptual, non-buildable repo presented alongside implementation repos
Severity: Critical
Impact: Security claims may be inferred from a repo that cannot be built/tested, increasing diligence and misrepresentation risk.

Evidence:

- No `Cargo.toml` at repo root (`/tmp/aethelred-rust-node-audit`)
- Conceptual module exports and marketing/security claims appear in `/tmp/aethelred-rust-node-audit/mod.rs:1`

Why this is severe:

- Auditors and partners may interpret this repo as implementation-grade when it is not package/build/test ready.
- Security reviewability is fundamentally blocked without a build manifest and test harness.

Recommendation:

- Either archive/mark as research-only, or convert into a proper crate (`Cargo.toml`, CI, tests, docs, security scope statement).
- Add a top-level disclaimer if it remains conceptual.

#### AETHEL-MR-003: Public repo-level audit evidence is fragmented outside the repos under review
Severity: Critical
Impact: Third-party auditors reviewing the listed GitHub repos cannot reproduce security claims if CI/guards/evidence live only in a separate umbrella workspace.

Evidence:

- Repo-local `.github/workflows` counts are `0` for the reviewed repo snapshots (core, cosmos-node, tee-worker, contracts, sdk, developer-tools, integrations, dashboard, rust-node).
- In contrast, substantial security/test workflows exist only in the local workspace root (`.github/workflows/*`).

Why this is severe:

- Security posture becomes non-portable and non-verifiable from the public repo itself.
- External auditors, exchanges, and enterprise partners typically require repo-local CI evidence or published artifacts.

Recommendation:

- Move or mirror required CI/security workflows into each public repo.
- Publish per-repo audit evidence bundles (test, coverage, scan outputs, SBOMs).

### High Findings

#### AETHEL-MR-004: Absolute local workstation paths are still present in public docs across SDKs and tooling repos
Severity: High
Impact: Leaks developer environment details, reduces portability, and signals unreconciled internal documentation in public-facing materials.

Evidence:

- `sdk/README.md:18`
- `sdk/README.md:27`
- `sdk/README.md:34`
- `sdk/README.md:46`
- `sdk/README.md:57`
- `docs/sdk/official-sdks.md:22`
- `docs/sdk/official-sdks.md:40`
- `aethelred-developer-tools/cli/aethel/README.md:14`
- `aethelred-integrations-repo/apps/fastapi-verifier/README.md:21`
- `docs/sdk/developer-tools.md:9`

Recommendation:

- Replace absolute paths with repo-relative paths and copy-paste-safe commands.
- Add a docs hygiene CI check that blocks `/Users/` and similar local path patterns.

#### AETHEL-MR-005: SDK documentation still explicitly marks several packages as source-first / pending public publication
Severity: High (go-to-market / operational risk), Medium (security)
Impact: Installability and supply-chain provenance claims can be overstated if public registry releases are not yet authoritative.

Evidence:

- `sdk/README.md:5` (“source-first” and pending releases)
- `docs/sdk/official-sdks.md:18`
- `docs/sdk/official-sdks.md:19`

Why this matters for security:

- Enterprise consumers expect signed, versioned artifacts from official registries and provenance tied to release tags.

Recommendation:

- Publish canonical artifacts (PyPI, npm, crates.io, Go module path) before making broad “production-ready SDK” claims.
- Add release signatures/provenance and a public release verification guide.

#### AETHEL-MR-006: Central security scan workflow appears to target stale contract paths (`contracts/ethereum`)
Severity: High
Impact: Security CI may produce false confidence if scans run against nonexistent paths or fail silently in a non-blocking manner.

Evidence:

- `.github/workflows/security-scans.yml:21` sets `working-directory: contracts/ethereum`
- `.github/workflows/security-scans.yml:32`
- `.github/workflows/security-scans.yml:33`
- `.github/workflows/security-scans.yml:77`
- Actual config file exists at `contracts/slither.config.json` (not `contracts/ethereum/slither.config.json`)

Recommendation:

- Fix path targets and add a preflight step that asserts all scan target paths exist.
- Fail fast if any configured scan root is missing.

#### AETHEL-MR-007: Threat model / SBOM / published security artifacts are not visible in most public repos
Severity: High
Impact: External auditors and counterparties cannot validate trust boundaries, dependency risk posture, or incident assumptions from repo-local evidence.

Evidence:

- Repo-level scans showed `0` threat-model references for most repos (core, cosmos-node, tee-worker, rust-node, developer-tools, integrations, dashboard).
- No repo-local SBOM generation or published SBOM artifacts were visible in the individual repo snapshots.

Recommendation:

- Publish a threat model and architecture/security assumptions per critical repo.
- Generate and publish SBOMs (CycloneDX or SPDX) at release time.

### Medium Findings

#### AETHEL-MR-008: Dashboard sets baseline security headers but lacks an explicit Content Security Policy (CSP)
Severity: Medium (potentially High depending feature set and third-party scripts)
Impact: XSS blast radius is larger without CSP, even when other headers are present.

Evidence:

- `aethelred-frontend-repo/dashboard/next.config.js:24` defines security headers.
- `aethelred-frontend-repo/dashboard/next.config.js:29`-`:45` shows `X-Frame-Options`, `X-Content-Type-Options`, `X-XSS-Protection`, `Referrer-Policy` but no `Content-Security-Policy` / `frame-ancestors`.

Recommendation:

- Add a CSP (nonce- or hash-based where needed) and prefer `frame-ancestors` in CSP over legacy-only clickjacking controls.

#### AETHEL-MR-009: Test coverage maturity is uneven across repos (strong in chain/SDK/contracts, weak in tools/integrations/rust-node)
Severity: Medium
Impact: Security regressions are more likely in operational tooling and integration surfaces where automated coverage is sparse or absent.

Evidence (snapshot counts):

- Stronger: `aethelred-core` (~95 Go tests), `aethelred-cosmos-node` (~95 Go tests), `aethelred-contracts` (TS/spec tests present), `aethelred-sdks` (TS/Go/Python tests present)
- Weak/none visible: `aethelred-developer-tools` (0 tests), `aethelred-integrations` (0 tests), `aethelred-rust-node` (0 tests)

Recommendation:

- Prioritize tests for CLI parsing, devnet orchestration, deploy templates, and example app security defaults.
- Add repo-local CI to enforce minimum test execution on PRs.

#### AETHEL-MR-010: `nitro-sdk` quality gate is significantly improved, but `full-sdk` still emits one warning (docs lint)
Severity: Low security impact / Medium engineering quality impact
Impact: Low direct exploitability, but warning-free targets improve audit confidence and reduce signal loss.

Evidence:

- Current `cargo check --features full-sdk` result (local validation) parses to `1` warning.
- Warning location: `services/tee-worker/nitro-sdk/src/compliance/regulation.rs:67`

Recommendation:

- Document the remaining enum (`FineRule`) to bring `full-sdk` warning budget to `0`.
- Keep the new warning-budget CI gates enforced after repo-local workflow push.

## Findings From Earlier Broad Audit That Are Now Outdated / Materially Improved

The attached markdown audit (ZIP export) overstates several conditions relative to the current snapshot:

- “No tests visible” is no longer accurate for `aethelred-core`, `aethelred-cosmos-node`, `aethelred-contracts`, and `aethelred-sdks`.
- “No developer tools” / “no local testnet” is no longer accurate; these exist and have been expanded.
- “TEE attestation flow/evidence absent” is partially outdated; `nitro-sdk` now has runnable attestation evidence regressions and improved fail-closed behavior in related SDK layers.
- “No frontend protections visible” is partially outdated; the dashboard has baseline security headers (though CSP remains missing).

## Overall Assessment (Strict)

Current state is **significantly improved** and **no longer accurately described as pure scaffold across all repos**. However, from a top-tier external auditor perspective, the project would still be graded down for:

1. Repo authority ambiguity (`aethelred-core` vs `aethelred-cosmos-node`)
2. Conceptual/non-buildable repos presented next to implementation repos (`aethelred-rust-node`)
3. Public repo auditability gaps (CI/security evidence not co-located)
4. Documentation hygiene and release provenance gaps (absolute paths, source-first install instructions)

## Immediate Remediation Priorities (Auditor Re-test Focus)

1. Canonicalize the chain repo and deprecate/clearly scope the duplicate.
2. Convert `aethelred-rust-node` to a buildable/testable crate or mark it as research-only.
3. Push repo-local security/test CI workflows into each public repo (not only umbrella workspace).
4. Remove all absolute local paths from public docs and add a docs-hygiene CI check.
5. Fix stale scan paths in central security workflow and publish scan artifacts/SBOMs.
