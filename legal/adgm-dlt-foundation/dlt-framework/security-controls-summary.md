# Security Controls Summary — For Regulatory Review

> **WARNING:** This is a scaffold. It requires completion by the security team and review by legal counsel.

| Attribute | Value |
|-----------|-------|
| **Owner** | [Assign — Head of Security] |
| **Version** | 0.1.0 (Scaffold) |
| **Status** | Scaffold |
| **Last Updated** | 2026-04-03 |

---

## 1. Cryptographic Controls

| Control | Implementation | Evidence |
|---------|---------------|----------|
| Post-quantum signatures | ML-DSA-65 + ECDSA hybrid | `crates/` implementation |
| Post-quantum key encapsulation | ML-KEM-768 | `crates/` implementation |
| Hash functions | SHA-3 / Keccak-256 | Standard library |
| Randomness | VRF-based validator selection | `crates/consensus/` |

## 2. Execution Environment Controls

| Control | Implementation | Evidence |
|---------|---------------|----------|
| Trusted Execution | Intel SGX, AMD SEV-SNP, AWS Nitro, Azure CoCo | TEE attestation module |
| Attestation verification | On-chain remote attestation | `crates/` implementation |
| Key custody | FIPS-level HSM requirement for validators | Validator admission criteria |

## 3. Network Security Controls

| Control | Implementation | Evidence |
|---------|---------------|----------|
| Validator isolation | Private network segment, sentry topology | Network architecture docs |
| DDoS protection | Public sentry ingress layer | Validator runbook |
| Peer authentication | Authenticated peer connections | CometBFT configuration |

## 4. Smart Contract Security

| Control | Implementation | Evidence |
|---------|---------------|----------|
| Internal audit | 27 findings — all remediated | `docs/audits/STATUS.md` |
| External audit (v2) | 36 findings — all closed | `docs/audits/STATUS.md` |
| Consultant review | VRF critical finding — fixed and verified | `docs/audits/STATUS.md` |
| External audits (pending) | AUD-2026-001, AUD-2026-002 | **In progress** |
| Formal verification | Plan documented | `docs/security/FORMAL_VERIFICATION.md` |
| Fuzzing | Active (Go native + Rust cargo-fuzz) | CI pipeline |

## 5. Operational Security

| Control | Implementation | Evidence |
|---------|---------------|----------|
| CI/CD scanning | gosec, trivy, gitleaks, slither, cargo-audit | CI pipeline — all passing |
| Dependency scanning | Dependabot + manual review | `go.sum`, `Cargo.lock` |
| Secret detection | gitleaks in CI | CI pipeline |
| Release provenance | Supply chain attestation | `docs/security/release-provenance.md` |

## 6. Incident Response

| Control | Implementation | Evidence |
|---------|---------------|----------|
| Severity classification | Defined (P0-P4) | `docs/security/SECURITY_RUNBOOKS.md` |
| Response procedures | Documented per severity | `docs/security/SECURITY_RUNBOOKS.md` |
| Bug bounty | Active with SLA | `docs/security/BUG_BOUNTY_SLA.md` |
| Security contact | security@aethelred.org | `SECURITY.md` |

## 7. Outstanding Items

- [ ] External audits AUD-2026-001 and AUD-2026-002 completion
- [ ] Formal verification execution (plan exists, not yet started)
- [ ] Mainnet security gate clearance
