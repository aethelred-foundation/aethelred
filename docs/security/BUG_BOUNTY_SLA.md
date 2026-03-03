# Aethelred Immunefi Bug Bounty SLA (Testnet -> Mainnet)

## Scope

This SLA governs submissions affecting:

- PoUW consensus and job assignment randomness
- TEE attestation verification and enclave integrity checks
- Slashing, insurance appeals, and emergency halt controls
- Stablecoin bridge contracts and CCTP relay paths

## Severity Tiers

### Critical - `$100,000`

Examples:

- TEE execution escape or attestation bypass that allows fraudulent compute acceptance
- Consensus halt or permanent liveness break caused by protocol-level exploit
- Bridge exploit enabling unauthorized mint/burn or loss of custody guarantees

Target response: acknowledge within 24 hours, mitigation plan within 72 hours, patch rollout initiated immediately.

### High - `$50,000`

Examples:

- MEV/randomness manipulation in PoUW assignment that biases high-value workloads
- Circuit-breaker or halt-governance bypass leading to unsafe unpause/halt control
- Slashing/appeal logic exploit causing unauthorized reimbursement or slash evasion

Target response: acknowledge within 24 hours, mitigation plan within 5 days.

### Medium - `$10,000`

Examples:

- Security-impacting validation gaps requiring elevated privileges
- Non-critical bridge/accounting mismatch risks with no direct theft path
- Denial-of-service vectors with practical recovery paths

Target response: acknowledge within 48 hours, mitigation plan within 7 days.

## Exclusions

- Findings requiring compromised validator/custodian root credentials
- Best-practice issues with no realistic exploitability
- Third-party provider outages without protocol exploit path

## Disclosure Workflow

1. Submit on Immunefi with PoC, affected component, blast radius, and reproducibility steps.
2. Security team triages and assigns severity/owner.
3. Patch + regression tests are required before closure.
4. Public disclosure only after fix deployment and explicit disclosure window approval.
