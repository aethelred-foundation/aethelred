# Security Policy

## Reporting a Vulnerability

Please do **not** report security vulnerabilities through public GitHub issues,
discussions, or pull requests.

Send reports to **security@aethelred.io** with:

- affected asset, branch, tag, endpoint, or image
- issue summary and impact
- reproducible steps or proof of concept
- exploit prerequisites and assumptions
- logs, traces, or transaction references where relevant
- suggested remediation, if available

If you need an encrypted channel, email first and request a secure handoff.

## Program Status

Aethelred currently operates a **private, invitation-only protocol bug bounty**
for the protocol and validator surface.

Current status:

- **Protocol bug bounty**: active, private by invitation
- **Public protocol bug bounty**: not yet open
- **dApps and ecosystem repos**: out of scope until separately announced

## Program Contacts

| Function | Contact |
|---|---|
| Official intake mailbox | `security@aethelred.io` |
| Interim triage owner | `Ramesh Tamilselvan <rameshtamilselvan@gmail.com>` |
| Interim reward approval owner | `Ramesh Tamilselvan <rameshtamilselvan@gmail.com>` |
| Interim disclosure approval owner | `Ramesh Tamilselvan <rameshtamilselvan@gmail.com>` |

The canonical program documents are:

- [docs/security/BUG_BOUNTY_PROGRAM.md](docs/security/BUG_BOUNTY_PROGRAM.md)
- [docs/security/BUG_BOUNTY_SEVERITY_MATRIX.md](docs/security/BUG_BOUNTY_SEVERITY_MATRIX.md)
- [docs/security/BUG_BOUNTY_SLA.md](docs/security/BUG_BOUNTY_SLA.md)
- [docs/security/BUG_BOUNTY_TRIAGE_PLAYBOOK.md](docs/security/BUG_BOUNTY_TRIAGE_PLAYBOOK.md)
- [docs/security/BUG_BOUNTY_ROLLOUT_PLAN.md](docs/security/BUG_BOUNTY_ROLLOUT_PLAN.md)

## Scope Summary

In scope for the current private program:

- protocol consensus safety and liveness
- validator, staking, slashing, and governance controls
- PoUW job integrity, randomness, and settlement correctness
- TEE attestation validation and enclave trust binding
- bridge and custody-critical paths when deployed or reachable in the current release
- protocol RPC, REST, gRPC, and validator-facing security flaws
- protocol SDK issues that create a real protocol exploit path
- validator image and release artifacts in the active supported release

Out of scope unless explicitly approved in writing:

- marketing sites, brochure pages, or general website content issues
- social engineering, phishing, spam, or physical attacks
- denial-of-service without a concrete protocol exploit path
- missing headers, generic best-practice findings, or clickjacking with no material impact
- third-party library CVEs without a demonstrated Aethelred exploit path
- vulnerabilities in dApps or ecosystem repos that have not been explicitly added to scope

## Supported Security Targets

| Surface | Status |
|---|---|
| `release/testnet-v1.0` | Supported |
| `main` | Supported |
| `ghcr.io/aethelred-foundation/aethelred/aethelredd:testnet-v1.0.1` | Supported |

## Response Standards

| Severity | Initial acknowledgement | Triage target | Update cadence |
|---|---:|---:|---:|
| Critical | 24 hours | 72 hours | every 24 hours |
| High | 24 hours | 5 business days | every 3 business days |
| Medium | 48 hours | 7 business days | weekly |
| Low | 5 business days | 10 business days | at milestones |

Detailed remediation and disclosure SLAs are maintained in
[docs/security/BUG_BOUNTY_SLA.md](docs/security/BUG_BOUNTY_SLA.md).

## Reward Policy

The current protocol bounty is denominated in **USD value**, not in AETHEL
tokens.

Default payout method:

- **USDC**

Fallback payout methods may be used where needed for legal, compliance, or
counterparty reasons.

Severity bands and payout ranges are defined in
[docs/security/BUG_BOUNTY_SEVERITY_MATRIX.md](docs/security/BUG_BOUNTY_SEVERITY_MATRIX.md).

## Safe Harbor

If you act in good faith, avoid privacy violations and destructive testing, and
follow this policy, Aethelred will not pursue action against compliant security
research performed within scope.

Researchers must:

- avoid accessing, modifying, or exfiltrating third-party data
- avoid degrading availability for real users, validators, or counterparties
- stop testing and report immediately once sensitive data or systemic access is obtained
- avoid persistence, backdoors, or post-exploitation activity beyond what is needed to prove impact

## Audit Evidence and Provenance

- Audit evidence index: [docs/audits/README.md](docs/audits/README.md)
- Audit status tracker: [docs/audits/STATUS.md](docs/audits/STATUS.md)
- Release provenance: [docs/security/release-provenance.md](docs/security/release-provenance.md)

## Security Design Principles

- **Fail closed**: security-critical paths reject on unexpected state
- **Deterministic consensus**: no floating point or nondeterministic arithmetic in consensus
- **Attestation binding**: enclave trust is bound to chain and workload context
- **Defense in depth**: compile-time, genesis-time, and runtime gates are all used
- **Operational traceability**: security-relevant changes require evidence and provenance
