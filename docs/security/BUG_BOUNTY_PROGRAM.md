# Aethelred Protocol Bug Bounty Program

## Purpose

This program exists to give qualified security researchers a clear, fair, and
well-operated path to report protocol vulnerabilities before mainnet launch and
throughout the protocol lifecycle.

The Aethelred bug bounty is intentionally **protocol-first**:

- the protocol is the primary product
- validator and node safety are first-class targets
- ecosystem apps are added only after the protocol program is mature

## Current Program Phase

### Phase 1: Private Protocol Bounty

Status: **active by invitation**

Phase 1 covers the protocol surfaces needed for public testnet readiness and
mainnet hardening. It is suitable for invited researchers, audit partners, and
trusted operators.

Current operating assignments:

- intake mailbox: `security@aethelred.io`
- interim triage owner: `Ramesh Tamilselvan <rameshtamilselvan@gmail.com>`
- interim reward approval owner: `Ramesh Tamilselvan <rameshtamilselvan@gmail.com>`
- interim disclosure approval owner: `Ramesh Tamilselvan <rameshtamilselvan@gmail.com>`
- default payout rail: `USDC`

### Planned Future Phases

| Phase | Description | Status |
|---|---|---|
| Phase 2 | Public protocol bounty ahead of mainnet | Planned |
| Phase 3 | Selective ecosystem and dApp scope expansion | Planned |

The activation path for each phase is documented in
[BUG_BOUNTY_ROLLOUT_PLAN.md](BUG_BOUNTY_ROLLOUT_PLAN.md).

## Current In-Scope Assets

### Protocol repositories and branches

- `aethelred-foundation/aethelred`
- `main`
- `release/testnet-v1.0`

### Protocol asset classes

| Area | Examples |
|---|---|
| Consensus and validator safety | consensus halt, safety failure, vote extension exploitation, equivocation bypass |
| Economic integrity | unauthorized mint, slash evasion, reward manipulation, governance privilege escalation |
| PoUW integrity | assignment randomness bias, fraudulent job acceptance, settlement corruption |
| TEE and attestation | attestation bypass, enclave identity confusion, trust-binding flaws |
| RPC / REST / gRPC | unauthenticated privileged access, signing bypass, unsafe state mutation |
| Release and node artifacts | validator image, release packaging, genesis integrity, supply-affecting config flaws |
| Bridge and custody-critical paths | only where deployed, reachable, or represented in the current supported release |
| SDK-driven protocol exploits | flaws in official SDKs that create a real protocol exploit path |

## Current Out-of-Scope Assets

The following are out of scope for the current private protocol program unless
explicitly approved:

- dApp-specific issues in Cruzible, NoblePay, ZeroID, TerraQura, or Shiora
- brochure sites, investor decks, or marketing content
- social engineering or phishing
- generic clickjacking, headers, CSP, or best-practice findings without material impact
- rate-limit bypasses that do not create a protocol exploit path
- third-party dependency CVEs without a demonstrated exploit chain in Aethelred
- theoretical attacks with no plausible execution path

## Researcher Rules

To remain eligible:

- test only within the authorized scope
- minimize impact and preserve service availability
- do not access or retain user, operator, or counterparty data beyond what is
  necessary to prove the issue
- do not pivot into third-party systems
- do not publicly disclose the issue before Aethelred approves disclosure timing
- stop immediately if you obtain sensitive data, validator secrets, or systemic
  control that is not required to prove impact

## Submission Requirements

Valid submissions should contain:

- concise title
- affected asset, branch, tag, image, or endpoint
- prerequisites and attacker model
- exact reproduction steps
- impact narrative in business and technical terms
- proof of concept or transaction trace
- evidence that the issue is not a duplicate of a known public issue

High-quality submissions that reduce triage time may receive reward uplifts.

## Reward Philosophy

Rewards are based on:

- real exploitability
- demonstrated blast radius
- required attacker capabilities
- asset criticality
- quality of the report and reproduction
- whether the issue affects currently supported releases

Rewards are **not** based on chain token price or token distribution. The
program uses USD-value reward bands to keep the policy stable and easier to
operate from a legal and accounting standpoint.

Current payout method:

- default: `USDC`
- fallback: `USD wire` or another approved cash-equivalent path

See [BUG_BOUNTY_SEVERITY_MATRIX.md](BUG_BOUNTY_SEVERITY_MATRIX.md) for the
current payout framework.

## Duplicate and Known-Issue Policy

- the first valid report of a distinct vulnerability is normally eligible
- substantially better reports may receive partial discretionary rewards
- known internal issues, previously reported issues, and already mitigated
  conditions are generally not reward eligible

## Disclosure Policy

- coordinated disclosure is required
- no public disclosure before a fix or mitigation plan is agreed
- for critical issues, Aethelred may require delayed disclosure until network
  risk is acceptably reduced

The detailed lifecycle is documented in
[BUG_BOUNTY_SLA.md](BUG_BOUNTY_SLA.md) and
[BUG_BOUNTY_TRIAGE_PLAYBOOK.md](BUG_BOUNTY_TRIAGE_PLAYBOOK.md).

## Safe Harbor

Aethelred supports good-faith research performed within this policy.

Researchers acting in line with this program should expect:

- no request to publicly self-identify
- no retaliation for compliant good-faith research
- clear triage communication
- clear reward and disclosure decisions

## Launch Standard

This program should be treated as operational only when all of the following
exist and are staffed:

- published `SECURITY.md`
- active security mailbox
- designated triage owner
- severity matrix and reward bands
- fix and disclosure workflow
- payment approval path
- legal and compliance review path for rewards

## Initial Researcher Cohort

Recommended first cohort size:

- `8` invited researchers

Coverage mix:

- `2` protocol or consensus researchers
- `2` Rust or systems-security researchers
- `2` smart contract or bridge researchers
- `1` TEE, enclave, or attestation researcher
- `1` validator, networking, or operator-security researcher

Use the cohort template at
[BUG_BOUNTY_RESEARCHER_SHORTLIST_TEMPLATE.md](BUG_BOUNTY_RESEARCHER_SHORTLIST_TEMPLATE.md).
