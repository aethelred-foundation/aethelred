# Ecosystem Directory

This directory implements the **hub-and-spoke model** for managing Aethelred's dApp ecosystem within the protocol repo. The production applications are canonical in their standalone repositories, while this directory keeps the structured manifest, compatibility metadata, and developer-facing pointers needed by the protocol team.

## Directory Structure

```
ecosystem/
  manifest.json          # Single source of truth for all ecosystem repos
  README.md              # This file
  apps/
    cruzible/README.md   # Stub pointing to aethelred-foundation/cruzible
    zeroid/README.md     # Stub pointing to aethelred-foundation/zeroid
    noblepay/README.md   # Stub pointing to aethelred-foundation/noblepay
    terraqura/README.md  # Stub pointing to aethelred-foundation/terraqura
    shiora/README.md     # Stub pointing to aethelred-foundation/shiora
```

## How the Manifest Works

`ecosystem/manifest.json` is the machine-readable registry of every repository in the Aethelred ecosystem. It is organized into three tiers:

- **core** -- Protocol node, contracts, governance proposals, documentation
- **platform** -- SDKs (TypeScript, Python, Go, Rust), CLI, VS Code extension
- **dapps** -- Consumer-facing applications (Cruzible, ZeroID, NoblePay, TerraQura, Shiora)

Each dApp entry in the manifest includes:
- `repo` -- The canonical GitHub repository
- `pinned_sha` -- The exact commit tested for protocol compatibility
- `pinned_date` -- When the pin was last updated
- `homepage` -- The live deployment URL
- `status` -- Current deployment stage (e.g. `testnet-preview`)
- `package_manager` -- `npm` or `pnpm`
- `install_command` -- Exact install command used by compatibility CI
- `build_command` -- Exact build command used by compatibility CI

CI workflows and tooling read this manifest to drive automated compatibility checks.

## Compatibility Testing

The `.github/workflows/compatibility.yml` workflow runs weekly (Sundays at 06:00 UTC) and can be triggered manually. For each dApp in the manifest, it:

1. Checks out the protocol monorepo
2. Clones the dApp repo at its pinned SHA
3. Uses the package manager and commands declared in the manifest
4. Installs dependencies and runs the build
5. Reports pass/fail as a GitHub step summary

This workflow is intended to be authoritative. If a pinned dApp cannot install or build, the workflow should fail and the pinned SHA should be investigated before the protocol repo is declared compatible.

## Source of Truth

The authoritative mapping of which repository owns which component is maintained in:

[`docs/governance/repo-source-of-truth-matrix.md`](../docs/governance/repo-source-of-truth-matrix.md)

That document defines canonical ownership, contribution policies, and the rules governing when code may be mirrored versus referenced by stub.

The legacy `dApps/` directory remains as a lightweight pointer surface for backwards compatibility. The structured ecosystem metadata now lives under `ecosystem/`.
