# Aethelred Bug Bounty Rollout Plan

## Objective

Roll out the Aethelred bug bounty in phases that match actual protocol maturity.

## Phase 1: Private Protocol Bounty

Goal:

- strengthen protocol, validator, and release surfaces before public testnet and
  mainnet hardening are complete

Activation criteria:

- `SECURITY.md` published
- security mailbox monitored
- triage owner and engineering owners assigned
- severity matrix approved
- reward approval path agreed

Researcher cohort:

- invited protocol researchers
- prior audit partners
- trusted validator/security operators

Recommended first wave:

- `8` researchers
- chosen for protocol coverage, not prestige alone
- selected to cover consensus, Rust/systems, contracts/bridge, TEE, and validator ops

Scope:

- protocol only
- validator image and release artifacts
- supported testnet and supported release branches

## Phase 2: Public Protocol Bounty

Goal:

- widen review before or at mainnet readiness

Activation criteria:

- private program operating smoothly
- repeatable triage and payout handling
- mainnet-critical audit items materially closed
- public endpoints and incident response path stable

Scope:

- protocol remains the center
- select bridge and custody surfaces where deployed

## Phase 3: Selective Ecosystem Expansion

Goal:

- add ecosystem assets only after the protocol program is stable

Activation criteria:

- protocol program mature
- dApp repos have dedicated owners, runbooks, and response paths
- bounty scope for each app can be supported operationally

Scope:

- apps added individually, never all at once by default

## Do Not Do

- do not launch a public all-assets bounty first
- do not pay rewards in token units by default
- do not make dApps launch blockers for the protocol bounty
- do not open public bounty scope before the triage path is staffed
