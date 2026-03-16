# Dependabot Remediation Backlog

Observed: 2026-03-13 during GitHub rollout pushes.

These counts came from GitHub's vulnerability banner during branch pushes and
should be revalidated after GitHub access is restored.

## Snapshot

| Repo | Critical | High | Moderate | Low | Total |
|---|---:|---:|---:|---:|---:|
| `aethelred` | 7 | 38 | 35 | 33 | 113 |
| `contracts` | 0 | 6 | 2 | 4 | 12 |
| `cruzible` | 0 | 13 | 11 | 11 | 35 |
| `aethelred-sdk-ts` | 0 | 3 | 1 | 0 | 4 |
| `aethelred-sdk-py` | 0 | 1 | 0 | 0 | 1 |
| `aethelred-sdk-go` | 1 | 1 | 2 | 0 | 4 |
| `aethelred-cli` | 0 | 0 | 1 | 0 | 1 |

Repos without a banner during rollout should still be rechecked in the GitHub
Security tab after auth is restored.

## Priority Order

### P0

1. `aethelred`
2. `aethelred-sdk-go`

Reason: current critical advisories were reported on these repos.

### P1

1. `cruzible`
2. `contracts`
3. `aethelred-sdk-ts`

Reason: highest concentration of high-severity advisories across public-facing
surfaces.

### P2

1. `aethelred-sdk-py`
2. `aethelred-cli`
3. remaining repos with no visible banner during rollout

## Local Triage Commands

Run these after auth is restored and before merging remediation PRs:

### Go

```bash
go mod tidy
govulncheck ./...
go list -m -u all
```

### Rust

```bash
cargo audit
cargo update
```

### Node / TypeScript

```bash
npm audit
npm outdated
```

### Python

```bash
python3 -m pip install pip-audit
pip-audit
```

## Repo-Specific Notes

### `aethelred`

- Review Go, Rust, and Node surfaces separately.
- Prioritize critical advisories affecting runtime, consensus, crypto, and CI
  release paths.
- Re-run:
  - `.github/workflows/security-scans.yml`
  - `.github/workflows/fuzzing-ci.yml`
  - `.github/workflows/e2e-tests.yml`

### `contracts`

- Focus first on JS/TS toolchain dependencies used by Hardhat/Foundry wrappers
  and CI.
- Validate ABI/typechain generation still matches after upgrades.

### `cruzible`

- Expect most findings to be npm ecosystem issues.
- Upgrade framework/runtime packages first, then wallet/web3 integrations.

### SDK / CLI Surfaces

- `aethelred-sdk-go`: clear the critical advisory first.
- `aethelred-sdk-ts`, `aethelred-cli`: refresh lockfiles and rerun package
  tests/builds.
- `aethelred-sdk-py`: re-audit publish/runtime deps after updates.

## Exit Criteria

1. No open critical advisories.
2. High advisories reduced to documented accepted risk or fixed.
3. Lockfiles and manifests updated in reviewed PRs.
4. CI green on affected repos.
5. Release notes mention dependency/security updates where relevant.
