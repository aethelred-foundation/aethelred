# Aethelred Foundation — Badge Policy

Date: 2026-03-30

## Purpose

Ensure every README badge across `aethelred-foundation` repos resolves correctly,
conveys trustworthy information, and does not break when workflows are renamed or
external services change.

## Allowed Badges

| Badge | Source | Rule |
|-------|--------|------|
| CI | GitHub native SVG | `github.com/<org>/<repo>/actions/workflows/<file>/badge.svg` |
| Security | GitHub native SVG | Same as CI, pointing to the security scan workflow |
| Status | Static Shields.io | `img.shields.io/badge/status-<phase>-<color>` |
| License | Static Shields.io | `img.shields.io/badge/license-Apache--2.0-blue` |
| Docs | Static Shields.io | `img.shields.io/badge/docs-<url>-orange` |
| AIPs | Static Shields.io | Only in `aethelred` root repo |

## Banned Badge Types

| Type | Reason |
|------|--------|
| Shields.io workflow-status proxy | Renders "repo or workflow not found" when org/repo/workflow names change |
| Discord member-count (`img.shields.io/discord/<slug>`) | Requires numeric guild ID; breaks with invite slugs; leaks community size |
| Codecov badge without live Codecov | Renders "unknown" or "invalid"; false signal |
| Any dynamic badge without a verified backend | Creates false-green or broken signals |

## Badge Format Rules

1. **CI/Security badges**: Always use GitHub's native SVG format:
   ```
   https://github.com/<org>/<repo>/actions/workflows/<file>/badge.svg?branch=main
   ```
   Never use `img.shields.io/github/actions/workflow/status/...`.

2. **Static badges**: Use Shields.io flat-square style:
   ```
   https://img.shields.io/badge/<label>-<message>-<color>?style=flat-square
   ```

3. **Discord**: Use a static badge only:
   ```
   https://img.shields.io/badge/Discord-community-5865F2?style=flat-square&logo=discord
   ```
   Do not use `img.shields.io/discord/<anything>`.

4. **Coverage**: Only add a coverage badge if:
   - `codecov.yml` or `.codecov.yml` exists in the repo root
   - Codecov is actively receiving uploads from CI
   - The badge URL uses the correct repo slug

## Enforcement

- The `readme-badge-guard.yml` workflow runs on every PR that modifies README files.
- It validates workflow file existence, bans Discord metric badges, and bans orphan Codecov badges.
- This workflow must be present in every `aethelred-foundation` repo.

## Adoption

1. `aethelred` — enforced (workflow added 2026-03-30)
2. `cruzible` — to be added when standalone repo README is updated
3. `noblepay` — to be added when standalone repo README is updated
4. `shiora` — to be added when standalone repo README is updated
5. `terraqura` — to be added when standalone repo README is updated
6. `zeroid` — to be added when standalone repo README is updated
