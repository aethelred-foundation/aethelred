# dApps/ — Transitional Pointer Directory

> **TRANSITION NOTICE:** The canonical source for each flagship dApp is its standalone repository. This directory is retained as a lightweight pointer layer for backwards compatibility while `ecosystem/` becomes the structured source of ecosystem metadata and compatibility state.

## Canonical Sources

| dApp | Canonical Repo | This Mirror |
|------|---------------|-------------|
| Cruzible | [`aethelred-foundation/cruzible`](https://github.com/aethelred-foundation/cruzible) | `dApps/cruzible/` |
| ZeroID | [`aethelred-foundation/zeroid`](https://github.com/aethelred-foundation/zeroid) | `dApps/zeroid/` |
| NoblePay | [`aethelred-foundation/noblepay`](https://github.com/aethelred-foundation/noblepay) | `dApps/noblepay/` |
| TerraQura | [`aethelred-foundation/terraqura`](https://github.com/aethelred-foundation/terraqura) | `dApps/terraqura/` |
| Shiora | [`aethelred-foundation/shiora`](https://github.com/aethelred-foundation/shiora) | `dApps/shiora/` |

## Policy

1. **Do not start new feature work in these directories.** Use the standalone repos.
2. **Do not rely on these pointers as source of truth.** The canonical repos and `ecosystem/manifest.json` are authoritative.
3. **Prefer `ecosystem/apps/`** for structured protocol-owned references and compatibility metadata.

## Migration Path

See `ecosystem/README.md` and `docs/governance/repo-source-of-truth-matrix.md` for the full migration plan.
