# Testnet Validator Onboarding CLI (April 1, 2026)

This runbook defines the deterministic onboarding flow for institutional validator operators on Aethelred Testnet V1.

## Scope

- Target operators: bank, enterprise, and regulated infrastructure partners.
- Security baseline: minimum 100,000 AETHEL stake, AWS Nitro PCR0 registration, and PoUW readiness verification.
- CLI binary in this repo: `aethelredd`.
- If your environment exposes `aethelred-cli`, use the same subcommands with that binary name.

## Prerequisites

1. AWS infrastructure provisioned with Nitro Enclaves enabled.
2. Node keypair created (`aethelredd keys add ...`).
3. Validator operator already created in staking (for example via `tx staking create-validator`).
4. Testnet balance funded from faucet.

## Required Commands

### 1) Stake for PoUW Eligibility

```bash
aethelredd tx pouw stake --amount 100000aethel --from <key-name> --chain-id <chain-id>
```

Notes:
- `aethel` and `uaeth` are accepted in `--amount`.
- Amount is normalized to `uaeth`.
- The command enforces the hard minimum of `100000aethel` (`100000000000uaeth`) before broadcast.
- If `--validator` is omitted, the command defaults to your own `valoper` address.

### 2) Register PCR0 Measurement

Two equivalent paths are available:

```bash
aethelredd tx pouw register-pcr0 <PCR0_HEX> --from <key-name> --chain-id <chain-id>
```

```bash
aethelredd tx attestation register-pcr0 <PCR0_HEX> --from <key-name> --chain-id <chain-id>
```

Notes:
- `PCR0_HEX` must be a 32-byte hash encoded as 64 hex characters.
- Registration binds the hash to the submitting validator identity.

### 3) Query PoUW/DKG Readiness

```bash
aethelredd query pouw status --validator <account-or-valoper-address> --chain-id <chain-id>
```

Output includes:
- Bonded stake and minimum-stake satisfaction.
- PCR0 registration status.
- Validator stats presence.
- Pending assignments and DKG-backed assignment observations.
- Final readiness signal: `ready_for_pouw`.

## Interpretation of `dkg_state`

- `blocked`: stake and/or PCR0 prerequisite not met.
- `eligible`: prerequisites met, waiting for DKG-backed assignment observation.
- `active`: DKG-backed assignment observed for this validator.

## Operational Checklist

1. `stake_requirement_met == true`
2. `pcr0_registered == true`
3. `validator_stats_found == true`
4. `ready_for_pouw == true`

If any item fails, follow the `notes` field from `query pouw status` and remediate before production-style test exercises.
