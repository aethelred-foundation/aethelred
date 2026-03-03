# Security Policy

## Reporting a Vulnerability

**Please do NOT report security vulnerabilities through public GitHub Issues.**

Email **security@aethelred.io** with:
- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- (Optional) Suggested fix

We will acknowledge within **24 hours** and provide a detailed response within **72 hours**.

## Severity Matrix & SLA

| Severity | Criteria | Response SLA | Fix SLA |
|---|---|---|---|
| **Critical** | Consensus halt, funds theft, double-spend | 24h | 7 days |
| **High** | TEE bypass, ZK proof forgery, governance attack | 48h | 14 days |
| **Medium** | DoS, data integrity issues | 72h | 30 days |
| **Low** | Info leak, non-exploitable misconfig | 7 days | 90 days |

## Bug Bounty Program

We maintain an active bug bounty program. Rewards are paid in AETHEL tokens.

| Severity | Reward Range |
|---|---|
| Critical | 50,000 – 500,000 AETHEL |
| High | 10,000 – 50,000 AETHEL |
| Medium | 1,000 – 10,000 AETHEL |
| Low | 100 – 1,000 AETHEL |

## Audit History

| Date | Auditor | Scope | Report |
|---|---|---|---|
| 2026-02-28 | Internal | Full codebase (27 findings resolved) | [Link](#) |

## Supported Versions

| Version | Supported |
|---|---|
| `main` | ✅ |
| `v0.x.x` | ✅ |

## Security Design Principles

- **Fail closed**: All security-critical paths default to reject/fail on unexpected state
- **No floating point in consensus**: All arithmetic uses `sdkmath.Int` (deterministic)
- **Signed vote extensions**: Ed25519 + BLS12-381 signatures required in production
- **TEE attestation binding**: Block height + chain ID bound into attestation `UserData`
- **PQC ready**: Dilithium3 post-quantum signatures available alongside Ed25519
- **Encrypted mempool**: Threshold encryption prevents front-running
