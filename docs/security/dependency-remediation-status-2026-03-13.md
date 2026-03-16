# Dependency Remediation Status - 2026-03-13

This note captures the locally prepared dependency-remediation changesets that
are ready to push once GitHub access is restored, plus the repos that were
explicitly held back because they require deeper migration work.

## Ready To Push

### `sdk/go`

- Updated `github.com/stretchr/testify` from `v1.8.4` to `v1.11.1`.
- Removed unused direct requirements on `github.com/google/uuid` and
  `golang.org/x/crypto` after `go mod tidy`.
- Verified with:
  - `go mod tidy`
  - `go test ./...`

Files:

- `sdk/go/go.mod`
- `sdk/go/go.sum`

### `dApps/cruzible`

- Updated:
  - `next` to `15.5.12`
  - `eslint-config-next` to `15.5.12`
  - `@next/bundle-analyzer` to `15.5.12`
  - `@sentry/nextjs` to `8.55.0`
- Fixed a type mismatch by replacing `LiveDot color="emerald"` with
  `LiveDot color="green"` in the stablecoins page.
- Added the missing `next-sitemap.config.js` required by the existing
  `postbuild` step.
- Verified with:
  - `npm run build`
- Current audit count after update:
  - `8 total` (`3 high`, `1 moderate`, `4 low`)

Files:

- `dApps/cruzible/package.json`
- `dApps/cruzible/package-lock.json`
- `dApps/cruzible/src/pages/stablecoins/index.tsx`
- `dApps/cruzible/next-env.d.ts`
- `dApps/cruzible/next-sitemap.config.js`

### `dApps/cruzible/backend/api`

- Updated:
  - `@cosmjs/*` packages from `0.32.x` to `0.34.1`
  - `@typescript-eslint/*` to `7.18.0`
  - `vitest` and `@vitest/coverage-v8` to `3.2.4`
  - `redis-commander` to `0.9.0`
- Verified with:
  - `npm run build`
- Current audit count after update:
  - `6 total` (`2 high`, `1 moderate`, `3 low`)

Files:

- `dApps/cruzible/backend/api/package.json`
- `dApps/cruzible/backend/api/package-lock.json`

## Held Back

### Root `aethelred` Go module

Conservative dependency refresh testing was stopped because the repo currently
fails to compile in packages unrelated to the dependency bump. The observed
errors were missing generated types in:

- `x/ibc/types`
- `x/pouw/types`
- `x/verify/types`
- `x/seal/types`

This should be treated as a separate source-generation or checked-in-code
integrity issue before retrying root-module dependency upgrades.

### `contracts`

`contracts` was intentionally left out of the ready-to-push batch.

A bounded migration spike showed that updating OpenZeppelin to `5.6.1` is not a
drop-in change. The repo currently needs a broader compatibility pass involving
at least:

- removal or replacement of `ReentrancyGuardUpgradeable`
- migration of `UUPSUpgradeable` initialization usage
- compiler configuration updates for Solidity `0.8.24`

Because this cascaded beyond a simple dependency bump, the migration was kept in
the temp spike workspace instead of being applied to the main repo.
