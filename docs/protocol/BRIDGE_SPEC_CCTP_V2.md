# Aethelred Bridge Spec: Native USDC via Circle CCTP V2

## Security Objective

`x/bridge` must operate as an isolated wrapper over Circle CCTP V2 for USDC so that:

- no wrapped USDC representation is minted on Aethelred
- no liquidity-pool custody model exists for USDC bridging
- mint/burn authority remains in Circle CCTP domain validation flow

## USDC Path (No Wrapped Token Model)

1. Source-chain USDC is burned via Circle `TokenMessengerV2`.
2. Cross-domain attestation is validated through Circle infrastructure (`MessageTransmitterV2` + attestation relay path).
3. Destination-chain USDC is natively minted after successful message validation.

The architecture intentionally avoids any custom wrapped-USDC mint logic.

## `x/bridge` Scope Boundaries

For USDC, `x/bridge` only does:

- route requests into CCTP-compatible message flow
- track bridge state, limits, and observability metadata
- enforce protocol-level pause and risk controls

For USDC, `x/bridge` must not:

- implement alternate mint logic outside CCTP validation
- maintain AMM/LP liquidity pools for custody-based bridging
- create synthetic/wrapped USDC balances

## Audit Boundary

USDC bridge verification for July audit is limited to:

- strict dependency on `MessageTransmitterV2`-validated message execution
- absence of wrapped-token mint branches
- enforcement of emergency halt controls and relayer-bond guardrails

## Related Controls

- Security Council halt freezes `x/bridge` transfers immediately.
- Relayer bonding and slashing remain isolated from USDC mint path logic.
- Institutional stablecoin docs define additional sovereign-asset controls (USDU/DDSC) separately from native USDC CCTP flow.
