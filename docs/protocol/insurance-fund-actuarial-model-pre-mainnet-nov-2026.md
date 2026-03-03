# x/insurance Payout Formula Whitepaper (Pre-Mainnet / Nov 2026)

## Document Metadata

| Attribute | Value |
|-----------|-------|
| Status | Draft for pre-mainnet publication |
| Due Date | November 2026 |
| Scope | Validator slash appeals + bridge indemnification limits |
| Primary Module | `x/insurance` |
| Related Components | `x/pouw`, `x/crisis`, `contracts/ethereum/contracts` bridge stack |

## Objective

Define a deterministic reimbursement model so institutional participants can calculate expected recovery after:

- false-positive fraud slashes (TEE or infrastructure anomalies), and
- approved bridge-loss indemnification events.

This model keeps the insurance pool solvent while providing transparent, auditable payouts.

## Baseline (Current Testnet Logic)

The current implementation already enforces:

- 14-day escrow hold before final forfeiture (`EscrowDurationDays = 14`).
- Appeal flow via `MsgSubmitAppeal`.
- 5-member randomized tribunal with 3-vote majority.

Reference files:

- `x/insurance/types/types.go`
- `x/insurance/keeper/keeper.go`

## Actuarial Variables

Let:

- `S` = slashed stake amount (AETHEL).
- `e` = evidence confidence score in `[0,1]` produced by tribunal policy.
- `PoolSnapshot_i` = insurance pool balance at incident `i` detection block.
- `IncidentCap_i = 0.10 * PoolSnapshot_i`.
- `Claimed_i` = total already-approved payouts for incident `i`.
- `RemainingCap_i = IncidentCap_i - Claimed_i`.

Fault classes:

- `F0` malicious or forged evidence.
- `F1` operator negligence / misconfiguration.
- `F2` mixed or uncertain non-malicious failure.
- `F3` verifiable cloud/provider failure (kernel panic, hypervisor failure, provider outage with attestation/log evidence).

## Slashing Refund Curve

Refund ratio `R(F,e)` is:

- `R(F0,e) = 0`
- `R(F1,e) = 0`
- `R(F2,e) = min(0.90, 0.55 + 0.35*e)`
- `R(F3,e) = min(0.95, 0.80 + 0.15*e)`

Validator payout:

`P_validator = min(S * R(F,e), RemainingCap_i)`

Interpretation:

- Confirmed non-malicious provider fault with high confidence (`F3`, `e=1`) reimburses **95%** of the slash.
- Malicious behavior remains **0%** reimbursement.
- Uncertain but non-malicious cases are partially reimbursed on a published curve.

## Bridge Hack Indemnification Cap

For any single bridge incident:

- Maximum indemnification is hard-capped at **10% of the pool snapshot**:
  - `TotalBridgePayout_i <= IncidentCap_i = 0.10 * PoolSnapshot_i`

If approved claims exceed `IncidentCap_i`:

- payouts are processed pro-rata:
  - `P_claim_j = IncidentCap_i * (Claim_j / SumApprovedClaims_i)`
- remaining losses require separate governance recapitalization.

This prevents full pool depletion from one incident.

## Accounting and Transparency Rules

For every payout event, store:

- `incident_id` (deterministic hash of root-cause evidence package),
- `pool_snapshot`,
- `refund_ratio`,
- `approved_amount`,
- `tribunal_verdict`.

Each payout must emit an event so monitoring systems can independently recompute cap usage.

## Parameterization for Mainnet

| Parameter | Value | Mutability |
|-----------|-------|------------|
| Escrow hold period | 14 days | Governance |
| Tribunal size | 5 | Governance |
| Tribunal majority | 3 | Governance |
| Max refund ratio | 95% | Governance (high quorum) |
| Per-incident cap | 10% of pool snapshot | Governance (high quorum) |

## Acceptance Mapping

- Mathematical refund curve defined, including a **95% reimbursement path** for verifiable non-malicious cloud failure.
- Bridge indemnification has an explicit **10% per-incident hard cap**.
- Payout logic is deterministic and auditable from on-chain events and recorded incident snapshots.
