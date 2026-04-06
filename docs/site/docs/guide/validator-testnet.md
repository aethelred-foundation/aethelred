# Testnet Validator Onboarding

Aethelred public testnet validator onboarding is intentionally simpler than the planned mainnet program. This page gives operators the clean testnet path. If you are reviewing production requirements, use [Mainnet Validator Requirements](/guide/validators) instead.

## Use This Page If You Are

- joining `aethelred-testnet-1`
- validating infrastructure, ops, or signing flow before mainnet
- onboarding as an external testnet validator

## Canonical Operator References

- [Testnet Validator Runbook](https://github.com/aethelred-foundation/aethelred/blob/main/docs/TESTNET_VALIDATOR_RUNBOOK.md)
- [Validator Onboarding CLI Guide](https://github.com/aethelred-foundation/aethelred/blob/main/docs/guides/validator-onboarding-cli.md)
- [Network Configuration](/guide/network)

## Testnet Parameters

| Parameter | Value |
|---|---|
| Chain ID | `aethelred-testnet-1` |
| RPC | `https://rpc.testnet.aethelred.io` |
| REST API | `https://api.testnet.aethelred.io` |
| gRPC | `grpc.testnet.aethelred.io:9090` |
| Explorer | `https://explorer.testnet.aethelred.io` |
| Faucet | `https://faucet.testnet.aethelred.io` |
| Bond denom | `uaethel` |
| Minimum validator self-delegation | `1,000 tAETHEL` on testnet |

## Fast Onboarding Flow

1. Pull the published testnet node image.
2. Initialize node home with `aethelred-testnet-1`.
3. Download the release genesis and verify the published checksum.
4. Configure the published seeds and persistent peers.
5. Start the node and wait until sync completes.
6. Fund the operator address from the faucet.
7. Broadcast `tx staking create-validator`.
8. Confirm that the validator appears in the active set and keep telemetry enabled.

## Testnet vs Mainnet

| Topic | Testnet | Mainnet |
|---|---|---|
| Goal | onboarding and operational rehearsal | production consensus and compute |
| HSM required | No | Yes |
| TEE enforcement | relaxed for testing | enforced |
| Min self-stake | lower testnet threshold | governed production threshold |
| Simulated components | allowed where testnet policy permits | not allowed |

## Launch-Day Notes

- Treat the repository runbook as the final source for exact commands.
- If the published checksum, seeds, peers, or image tag change, use the runbook values rather than cached copies.
- If you are blocked on sync, funding, or validator activation, escalate through the validator channels listed in the runbook.

## Related Pages

- [Mainnet Validator Requirements](/guide/validators)
- [Connecting to Network](/guide/network)
- [TEE Attestation](/guide/tee-attestation)
