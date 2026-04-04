# Production Controls Summary — For Regulatory Review

> **WARNING:** This is a scaffold. It requires completion and review by legal counsel.

| Attribute | Value |
|-----------|-------|
| **Owner** | [Assign — Head of Operations] |
| **Version** | 0.1.0 (Scaffold) |
| **Status** | Scaffold |
| **Last Updated** | 2026-04-03 |

---

## 1. Release Management

| Control | Description | Evidence |
|---------|-------------|----------|
| Gating plan | Multi-stage gates before mainnet promotion | `docs/operations/GATE_INVENTORY.md` |
| Current status | Mainnet BLOCKED until external audits complete | `docs/audits/STATUS.md` |
| Testnet operation | Testnet v1.0 active for validation | Branch: `release/testnet-v1.0` |
| Release provenance | Signed builds with supply-chain attestation | `docs/security/release-provenance.md` |

## 2. Validator Operations

| Control | Description | Evidence |
|---------|-------------|----------|
| Admission process | Operator review required before admission | `frontend/website/org/nodes.html` |
| Hardware requirements | Documented specifications | `docs/validator/HARDWARE_REQUIREMENTS.md` |
| Uptime target | 99.5% monthly (design target) | Network parameters |
| Monitoring | Validator monitoring and alerting | Validator runbook |

## 3. Disclosure Controls

| Control | Description | Evidence |
|---------|-------------|----------|
| Canonical source index | Maps authoritative docs per category | `docs/CANONICAL_SOURCE_INDEX.md` |
| Site claims register | Tracks all public claims | `legal/adgm-dlt-foundation/site-claims-register.md` |
| Prohibited phrases | Automated/manual checks for unsafe language | `docs/operations/prohibited-phrases/` |
| Benchmark governance | Performance claims require benchmark pack | Whitepaper policy |

## 4. Change Management

| Control | Description | Evidence |
|---------|-------------|----------|
| AIP process | Formal improvement proposal governance | `docs/AIPs/` (3 AIPs active) |
| Code review | Required for all changes | GitHub branch protection |
| CI/CD pipeline | Automated testing and scanning | `.github/workflows/` |
| Architecture Decision Records | Tracked decisions | `docs/governance/adr-*.md` |

## 5. Outstanding Items

- [ ] Production monitoring and alerting stack finalization
- [ ] Mainnet launch runbook
- [ ] Post-launch operational procedures
