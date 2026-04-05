# Repository Source-of-Truth Matrix

> **Policy adopted: 2026-04-05**
> Every artifact has exactly one canonical source of truth. The standalone repo is canonical for each product.

| Attribute | Value |
|-----------|-------|
| **Owner** | Ramesh Tamilselvan |
| **Version** | 1.0.0 |
| **Status** | Active |
| **Last Updated** | 2026-04-05 |

---

## Canonical Source Rule

- Protocol code -> `aethelred`
- Production contracts -> `contracts`
- Each SDK -> its own SDK repo
- Docs site -> `aethelred-docs`
- Each production dApp -> its own dApp repo
- Governance proposals -> `AIPs`
- Org policy -> `.github`

The protocol repo may **reference** other repos. It must not **mirror** full production source.

---

## Tier 1: Core Protocol Control Plane

| Repo | Canonical Role | Owner |
|------|---------------|-------|
| [`aethelred`](https://github.com/aethelred-foundation/aethelred) | Protocol core: node, consensus, modules, chain runtime, release provenance | Protocol Team |
| [`contracts`](https://github.com/aethelred-foundation/contracts) | Production smart contracts | Smart Contract Team |
| [`AIPs`](https://github.com/aethelred-foundation/AIPs) | Aethelred Improvement Proposals | Governance |
| [`.github`](https://github.com/aethelred-foundation/.github) | Org-level governance and defaults | Ops Team |
| [`aethelred-docs`](https://github.com/aethelred-foundation/aethelred-docs) | Documentation site | DevRel |

## Tier 2: Developer Platform

| Repo | Canonical Role | Owner |
|------|---------------|-------|
| [`aethelred-sdk-ts`](https://github.com/aethelred-foundation/aethelred-sdk-ts) | TypeScript SDK | SDK Team |
| [`aethelred-sdk-py`](https://github.com/aethelred-foundation/aethelred-sdk-py) | Python SDK | SDK Team |
| [`aethelred-sdk-go`](https://github.com/aethelred-foundation/aethelred-sdk-go) | Go SDK | SDK Team |
| [`aethelred-sdk-rs`](https://github.com/aethelred-foundation/aethelred-sdk-rs) | Rust SDK | SDK Team |
| [`aethelred-cli`](https://github.com/aethelred-foundation/aethelred-cli) | CLI tool | DevRel |
| [`vscode-aethelred`](https://github.com/aethelred-foundation/vscode-aethelred) | VS Code extension | DevRel |

## Tier 3: Flagship dApps

| Repo | Canonical Role | Owner | Homepage |
|------|---------------|-------|----------|
| [`cruzible`](https://github.com/aethelred-foundation/cruzible) | Explorer, staking, governance dashboard | Cruzible Team | cruzible.aethelred.io |
| [`zeroid`](https://github.com/aethelred-foundation/zeroid) | Self-sovereign identity with ZK proofs | ZeroID Team | zeroid.aethelred.io |
| [`noblepay`](https://github.com/aethelred-foundation/noblepay) | Enterprise cross-border payments | NoblePay Team | app.thenoble.one |
| [`terraqura`](https://github.com/aethelred-foundation/terraqura) | Carbon credit platform with Proof-of-Physics | TerraQura Team | app.terraqura.com |
| [`shiora`](https://github.com/aethelred-foundation/shiora) | Women's health AI with ZK privacy | Shiora Team | app.shiora.health |

---

## Protocol Repo Reference Surfaces

| Directory in `aethelred` | Status | Replacement |
|--------------------------|--------|-------------|
| `dApps/zeroid/` | **Legacy pointer stub** — canonical source is standalone repo | `ecosystem/apps/zeroid/` structured stub |
| `dApps/terraqura/` | **Legacy pointer stub** — canonical source is standalone repo | `ecosystem/apps/terraqura/` structured stub |
| `dApps/cruzible/` | **Legacy pointer stub** — canonical source is standalone repo | `ecosystem/apps/cruzible/` structured stub |
| `dApps/noblepay/` | **Legacy pointer stub** — canonical source is standalone repo | `ecosystem/apps/noblepay/` structured stub |
| `dApps/shiora/` | **Legacy pointer stub** — canonical source is standalone repo | `ecosystem/apps/shiora/` structured stub |
| `ecosystem/apps/*` | **Current structured reference layer** | canonical standalone repos listed in `ecosystem/manifest.json` |

---

## What Stays in `aethelred`

1. Protocol code (`go/`, `crates/`, `proto/`)
2. Release provenance (`docs/security/release-provenance.md`)
3. Ecosystem manifests (`ecosystem/manifest.json`)
4. Compatibility CI (`.github/workflows/compatibility.yml`)
5. Developer examples (`examples/`)
6. Testnet/devnet orchestration
7. Protocol-level documentation (`docs/`)

## What Leaves `aethelred` Over Time

1. Any reintroduced full app frontend/backend source trees
2. App lockfiles
3. App deployment configs
4. App-specific workflows
5. The legacy `dApps/` pointer layer once all consumers have moved to `ecosystem/`
