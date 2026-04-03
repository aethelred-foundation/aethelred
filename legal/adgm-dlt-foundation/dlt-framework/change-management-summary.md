# Change Management Summary — For Regulatory Review

> **WARNING:** This is a scaffold. It requires completion and review by legal counsel.

| Attribute | Value |
|-----------|-------|
| **Owner** | [Assign — CTO] |
| **Version** | 0.1.0 (Scaffold) |
| **Status** | Scaffold |
| **Last Updated** | 2026-04-03 |

---

## 1. Protocol Change Process

### Aethelred Improvement Proposals (AIPs)

| Stage | Description | Governance |
|-------|-------------|------------|
| Draft | Author submits AIP with specification | Open to any contributor |
| Review | Technical council reviews for feasibility and security | Technical Council (7 members) |
| Vote | On-chain governance vote (post-mainnet) | Token holders (quorum: 4% supply, threshold: 51%) |
| Implementation | Engineering implementation with full test coverage | Core team + reviewed PRs |
| Testnet Validation | Deployed and validated on testnet | Validator operators |
| Mainnet Deployment | Promoted through gating process | Gate inventory sign-off |

### Active AIPs

| AIP | Title | Status |
|-----|-------|--------|
| AIP-0001 | [See `docs/AIPs/AIP-0001.md`] | [Check current status] |
| AIP-0002 | [See `docs/AIPs/AIP-0002.md`] | [Check current status] |
| AIP-0003 | [See `docs/AIPs/AIP-0003.md`] | [Check current status] |

## 2. Emergency Change Procedures

| Scenario | Procedure | Authority |
|----------|-----------|-----------|
| Critical security vulnerability | Immediate patch + disclosure per `SECURITY.md` | Security team + CTO |
| Network halt | Emergency validator coordination | Technical Council veto power |
| Smart contract exploit | Pause mechanism + incident response | Security runbook |
| Regulatory requirement | Expedited AIP or council action | Legal counsel + Council |

## 3. Code Change Controls

| Control | Description |
|---------|-------------|
| Branch protection | `main` branch requires review approval |
| CI/CD gates | All tests, security scans, and linting must pass |
| Audit requirements | Material changes to consensus/bridge require audit |
| Documentation | Architecture decisions recorded in ADRs |

## 4. Document Change Controls

| Control | Description |
|---------|-------------|
| Canonical documents | Changes require legal reviewer sign-off |
| Website content | Changes must not contradict canonical sources |
| Claims register | Must be updated with any new public claims |
| Approval log | All document version changes logged |

## 5. Outstanding Items

- [ ] Post-mainnet governance activation procedures
- [ ] Emergency upgrade runbook for mainnet
- [ ] Regulatory change response procedures
