# DAO Transition Architecture (2027)

## Document Metadata

| Attribute | Value |
|-----------|-------|
| Status | Draft migration architecture |
| Target Window | 2027 governance handoff |
| Scope | Stablecoin bridge emergency control transition |
| Current Contract | `InstitutionalStablecoinBridge.sol` |
| Governance Stack | OpenZeppelin `Governor` + `TimelockController` |

## Objective

Migrate emergency bridge control from institutional keyholders to token-weighted governance while preserving safety guarantees and auditability.

Specifically, transfer:

- `PAUSER_ROLE`
- `UNPAUSER_ROLE`

from the current institutional model to governance-controlled execution.

## Current State (2026 Baseline)

The existing bridge implementation uses OpenZeppelin `AccessControlUpgradeable` with:

- `PAUSER_ROLE` for pause and risk-control operations.
- `UNPAUSER_ROLE` plus joint-signature checks in `unpauseWithJointSignatures(...)`.
- Governance key rotation via `SovereignGovernanceTimelock.sol`.

Note: where prior planning artifacts refer to `SovereignAccessControl.sol`, this repository's active equivalent control surface is `InstitutionalStablecoinBridge.sol`.

Reference files:

- `contracts/ethereum/contracts/InstitutionalStablecoinBridge.sol`
- `contracts/ethereum/contracts/SovereignGovernanceTimelock.sol`

## Target State (2027)

Adopt a standard OpenZeppelin governance stack:

1. `AethelredGovernor` (`Governor`, `GovernorVotes`, `GovernorVotesQuorumFraction`, `GovernorTimelockControl`)
2. `BridgeGovTimelock` (`TimelockController`)
3. `AethelredToken` (`ERC20Votes`) as governance voting power source

Governance parameters for stablecoin bridge control:

- Voting delay: **28,800 blocks** (~2 days at 6s blocks)
- Voting period: **100,800 blocks** (~7 days at 6s blocks)
- Proposal threshold: **25,000,000 AETHEL** (0.25% of 10B supply)
- Quorum target (recommended): **4%** of voting supply

## Required Bridge Upgrade Before Role Transfer

Because current unpause logic requires institutional signatures, a bridge upgrade is required before DAO cutover:

- add governance-native unpause path callable by timelock (`governanceUnpause(actionId)`),
- add an explicit mode switch:
  - `INSTITUTIONAL_ONLY`
  - `HYBRID`
  - `DAO_ONLY`

In `DAO_ONLY`, `unpauseWithJointSignatures(...)` must be disabled.

## Role Transfer Runbook (Exact Process)

1. Deploy `BridgeGovTimelock` with minimum delay = 7 days.
2. Deploy `AethelredGovernor` wired to `AethelredToken` and `BridgeGovTimelock`.
3. Upgrade bridge to governance-ready version supporting unpause mode switch.
4. Through current timelock/admin controls, execute:
   - `grantRole(PAUSER_ROLE, BridgeGovTimelock)`
   - `grantRole(UNPAUSER_ROLE, BridgeGovTimelock)`
   - `configureGovernanceTimelock(BridgeGovTimelock, 7 days)`
5. Enter `HYBRID` mode for one governance epoch to validate operational behavior.
6. After successful validation, switch to `DAO_ONLY`.
7. Revoke institutional direct emergency roles:
   - `revokeRole(PAUSER_ROLE, <institutional_addresses>)`
   - `revokeRole(UNPAUSER_ROLE, <institutional_addresses>)`
8. Publish on-chain proof bundle (proposal IDs, tx hashes, role member snapshots).

## Community Unpause Flow (2027+)

1. Proposal submitted meeting threshold (`>= 25,000,000 AETHEL` delegated votes).
2. Proposal waits voting delay (`28,800` blocks).
3. Vote remains open for `100,800` blocks.
4. If proposal passes quorum and majority rules, governor queues timelock action.
5. After 7-day timelock, execution calls `governanceUnpause(actionId)` on bridge.

## Control Invariants

- No single signer can unpause in DAO mode.
- Any emergency unpause is delayed and publicly observable.
- Role handoff is reversible only via another governance proposal and timelock cycle.

## Acceptance Mapping

- Exact process for transferring `PAUSER_ROLE` and `UNPAUSER_ROLE` is defined.
- Voting delay, voting period, and proposal threshold are explicitly specified in AETHEL terms.
- Migration preserves safety through staged cutover (`HYBRID` then `DAO_ONLY`) and timelocked execution.
