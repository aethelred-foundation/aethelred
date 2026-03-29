# GitHub Rollout Resume Plan

Updated: 2026-03-13

## Purpose

This runbook captures the remaining GitHub rollout work that should be resumed
after `gh` access is restored.

## Local State Already Prepared

- All hard-coded `AethelredFoundation` references were updated to
  `aethelred-foundation`.
- The rollout exporter now preserves the canonical monorepo `.github/` tree.
- The rollout script now reuses an existing rollout branch instead of assuming
  a fresh branch push every time.
- The canonical required-check map was corrected to match real workflow gate
  names.
- Branch protection for `aethelred-foundation/aethelred:main` was applied once
  successfully during the earlier rollout session.

## Resume Prerequisites

1. Restore GitHub CLI auth:

   ```bash
   gh auth login -h github.com
   gh auth status
   ```

2. From the monorepo root, rerun the prepared resume script:

   ```bash
   bash scripts/resume-github-rollout.sh
   ```

3. If label writes still fail, keep `APPLY_LABELS=0`:

   ```bash
   APPLY_LABELS=0 bash scripts/resume-github-rollout.sh
   ```

## Safe Merge Order

Use `Squash and merge` or `Rebase and merge` because canonical branch
protection enforces linear history.

1. `.github`
2. `aethelred`
3. `contracts`
4. `aethelred-sdk-ts`
5. `aethelred-sdk-py`
6. `aethelred-sdk-go`
7. `aethelred-sdk-rs`
8. `aethelred-cli`
9. `vscode-aethelred`
10. `aethelred-docs`
11. `AIPs`
12. `cruzible`

## Manual Org Pinned Repos

Set these in the GitHub org profile UI:

1. `aethelred`
2. `contracts`
3. `AIPs`
4. `aethelred-sdk-ts`
5. `cruzible`
6. `aethelred-docs`

Rationale:

- `aethelred`: canonical source of truth
- `contracts`: high-trust audit surface
- `AIPs`: governance entry point
- `aethelred-sdk-ts`: most discoverable developer SDK
- `cruzible`: flagship application
- `aethelred-docs`: operator and developer onboarding

## Post-Merge Checks

1. Confirm every merged repo has the new org slug in README badges and links.
2. Reapply canonical branch protection if needed:

   ```bash
   bash scripts/setup_required_github_checks.sh aethelred-foundation/aethelred main
   ```

3. Spot-check:
   - org profile README banner renders
   - default issue templates resolve from `.github`
   - `repo-role.json` exports reference `aethelred-foundation`
   - package metadata links resolve on npm, PyPI, crates.io, and Go docs where applicable

## Follow-On Work

- Execute the dependency/vulnerability backlog in
  `docs/security/dependabot-remediation-backlog-2026-03-13.md`
- Re-run release/provenance spot checks after the rollout PRs merge
