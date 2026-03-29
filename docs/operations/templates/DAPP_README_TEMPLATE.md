# {APP_NAME} — Standalone Repo README Template

Use this template when updating the README in each dedicated dApp repo.
Replace `{APP_NAME}`, `{app_slug}`, `{tagline}`, and `{ci_workflow_file}` with actual values.

---

```markdown
# {APP_NAME}

**{tagline}**

<p>
 <a href="https://github.com/aethelred-foundation/{app_slug}/actions/workflows/{ci_workflow_file}"><img src="https://github.com/aethelred-foundation/{app_slug}/actions/workflows/{ci_workflow_file}/badge.svg?branch=main" alt="CI"></a>
 <a href="https://github.com/aethelred-foundation/{app_slug}/actions/workflows/security-scans.yml"><img src="https://github.com/aethelred-foundation/{app_slug}/actions/workflows/security-scans.yml/badge.svg?branch=main" alt="Security"></a>
 <img src="https://img.shields.io/badge/status-testnet-0e8a16?style=flat-square" alt="Status: Testnet">
 <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square" alt="License"></a>
</p>

> Built on the [Aethelred](https://github.com/aethelred-foundation/aethelred) sovereign L1.

## Quick Start

... (app-specific content)

## Development

... (app-specific content)

## Security

Found a vulnerability? See [SECURITY.md](SECURITY.md).

## License

Apache-2.0
```

---

## Per-dApp Values

| dApp | `{APP_NAME}` | `{app_slug}` | `{tagline}` | `{ci_workflow_file}` |
|------|-------------|-------------|-----------|---------------------|
| Cruzible | Cruzible | cruzible | TEE-verified liquid staking vault for the Aethelred sovereign L1 | _map from actual repo_ |
| NoblePay | NoblePay | noblepay | Enterprise cross-border payments. TEE compliance. On-chain settlement. | _map from actual repo_ |
| Shiora | Shiora | shiora | Sovereign health data. Verifiable AI. Zero-knowledge privacy. | _map from actual repo_ |
| TerraQura | TerraQura | terraqura | Institutional-grade carbon credit platform with Proof-of-Physics verification | _map from actual repo_ |
| ZeroID | ZeroID | zeroid | Self-sovereign identity. Zero-knowledge proofs. TEE-verified credentials. | _map from actual repo_ |

**Important**: Map `{ci_workflow_file}` from the actual workflow files in each repo.
Do NOT guess `ci.yml` vs `ci-cd.yml` — check each repo's `.github/workflows/` directory first.
