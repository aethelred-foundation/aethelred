# Deploying the seal-gated dApps on Aethelred

Five reference dApps each anchor a domain object to a **Digital Seal** minted by
the chain's own Proof-of-Useful-Work pipeline and verified by the ISeal
precompile (`0x0900`): ZeroID (a KYC credential), Cruzible (compliant liquid
staking), NoblePay (a cross-border corridor clearance), TerraQura (an MRV/carbon
anchor), and Shiora (a health-data attestation). Each ships a live-node
end-to-end script that is the running-node counterpart to the definitive
real-precompile proof in the chain repo (`internal/evmhost/<dapp>_test.go`).

Every script is a **two-phase operator playbook** — see below.

## Prerequisites (all dApps)

- An aethelredd EVM JSON-RPC reachable on **chain-id 7332**:
  `http://<validator-ip>:8545` (or `http://127.0.0.1:8545` when co-located).
- A **funded deployer key** (0x-hex). Fund the **0x address directly** —
  precisebank makes the Cosmos bank balance and the EVM balance the same account
  (`bank uaethel × 10¹² == EVM aaethel`), so `scripts/faucet.sh` or
  `aethelredd tx bank send <faucet> 0x<deployer> <amount>uaethel …` credits the
  EVM side. Do **not** import a genesis mnemonic into an EVM wallet: aethelredd
  derives keys at coin-type 118 and EVM wallets at coin-type 60, so the same
  mnemonic yields a different address.
- Node 18+ and `npm`. Foundry (`forge`) for ZeroID and Cruzible; Hardhat for
  TerraQura and Shiora (installed via `npm install`).
- **Gas is auto-sized** — every script follows the Aethelred fee convention
  (`estimate × 2` in viem, `gasMultiplier: 2` in Hardhat). Do not pass gas flags.
  Background: [evm-gas-and-fees.md](./evm-gas-and-fees.md).

## The two-phase pattern

1. **Gate closed.** The script deploys the contract, sets the CEAP policy, and
   proves the domain object is **not** valid with no seal — then prints the exact
   `aethelredd tx pouw …` command (including the contract's own
   `expectedPurpose()`) needed to mint the backing seal.
2. **Gate open.** Mint the seal (below), then re-run the same script with
   `JOB_ID=<job-id>` added. The object goes valid. Revoking the seal on-chain
   flips it back with no dApp transaction — the whole point of consensus
   anchoring.

Set `RPC_URL` (or `AETHELRED_TESTNET_RPC_URL` for TerraQura) to your node and a
funded key on every invocation.

## Per dApp

### 1. ZeroID — seal-anchored KYC credential · branch `feat/economic-flywheel`

```bash
cd zeroid && npm install && forge build
DEPLOYER_KEY=0x<funded> RPC_URL=http://<ip>:8545 \
  node scripts/devnet-seal-attestation-e2e.mjs
```
Optional: `REGISTRY_ADDRESS` (reuse a deployment), `SUBJECT`, `SCHEMA`, `JOB_ID`.

### 2. Cruzible — compliant liquid staking · branch `ramesh/production-grade-hardening`

```bash
cd cruzible && npm install
( cd backend/contracts-evm && forge build )   # artifacts are committed; rebuild if missing
DEPLOYER_KEY=0x<funded> RPC_URL=http://<ip>:8545 node scripts/devnet-deploy-e2e.mjs
DEPLOYER_KEY=0x<funded> RPC_URL=http://<ip>:8545 node scripts/devnet-seal-gate-e2e.mjs
```
`devnet-deploy-e2e.mjs` runs the full staking lifecycle and, if `DEPLOYER_KEY`
is unset, generates a key and waits while printing the 0x + bech32 address to
fund. `devnet-seal-gate-e2e.mjs` proves the seal-gated compliance path.

### 3. NoblePay — corridor clearance · branch `feat/seal-settlement-e2e`

No contract compile — the script deploys the reviewed vendored bytecode.

```bash
cd noblepay && npm install
DEPLOYER_KEY=0x<funded> RPC_URL=http://<ip>:8545 PAYEE=0x<counterparty> \
  node scripts/devnet-seal-settlement-e2e.mjs
```
Optional: `GATE_ADDRESS`, `PAYER` (default = deployer), `JOB_ID`.

### 4. TerraQura — MRV/carbon anchor · branch `fix/vercel-gitignore`

TerraQura is a **pnpm monorepo** (pnpm ≥9, Node ≥20) — `npm install` fails with
`EUNSUPPORTEDPROTOCOL "workspace:"`. Install with pnpm **from the repo root**,
build the shared workspace packages (the hardhat config imports
`@terraqura/network-manifest`, which builds to `dist/` via tsup), then run
hardhat from `apps/contracts`. The signer comes from `PRIVATE_KEY` (Hardhat feeds
it to the network's accounts); `AETHELRED_TESTNET_RPC_URL` points at the node.

```bash
corepack enable && corepack prepare pnpm@9.0.0 --activate   # or: npm i -g pnpm@9
cd terraqura
pnpm install                          # from the ROOT — resolves workspace:* deps
pnpm --filter "./packages/**" build   # builds network-manifest et al. (skips heavy apps)
cd apps/contracts
pnpm hardhat compile
PRIVATE_KEY=0x<funded> AETHELRED_TESTNET_RPC_URL=http://<ip>:8545 \
  pnpm hardhat run scripts/devnet-seal-proof-of-physics-e2e.ts --network aethelredTestnet
```
Optional: `REGISTRY_ADDRESS`, `DAC_UNIT`, `SENSOR_BATCH`, `JOB_ID`.

### 5. Shiora — health-data attestation · branch `feat/backbone-phi-encryption-audit`

```bash
cd shiora/contracts && npm install && npx hardhat compile
RPC_URL=http://<ip>:8545 DEPLOYER_KEY=0x<funded> \
  npx hardhat run scripts/devnet-seal-attestation-e2e.js --network aethelredDevnet
```
Optional: `REGISTRY_ADDRESS`, `SUBJECT`, `SCOPE`, `JOB_ID`.

> Key-variable names differ by toolchain: the viem scripts (ZeroID, Cruzible,
> NoblePay) and Shiora use `DEPLOYER_KEY`; TerraQura uses `PRIVATE_KEY`.

## Minting the backing seal (shared phase-2 step)

When a script prints its mint command, run it from a validator, using the exact
`--purpose` it printed (which the contract derives from `expectedPurpose()`):

```bash
aethelredd tx pouw register-model --model <name> --model-id <id> \
  --from validator --chain-id <chain-id> --keyring-backend test --yes
aethelredd tx pouw submit-job --model <name> --input <input> \
  --proof-type tee --purpose "<printed-purpose>" \
  --conf-backends <tee|fhe> --conf-residency <AE|EU> \
  --from validator --chain-id <chain-id> --keyring-backend test --yes
```

Wait for the validator quorum to mint the Digital Seal, take its `JOB_ID`, and
re-run the dApp script with `JOB_ID=<job-id>` to complete issuance. The CEAP
backend/residency you submit must satisfy the policy the script set (each script
prints its policy — e.g. ZeroID uses `fhe`/`EU`, NoblePay `tee`/`AE`).

## What each gate proves

| dApp      | Object            | Valid only when a seal is… |
| --------- | ----------------- | -------------------------- |
| ZeroID    | KYC credential    | ACTIVE, bound to this subject + schema, CEAP-satisfying |
| Cruzible  | Staking eligibility | ACTIVE, bound to this staker, CEAP-satisfying |
| NoblePay  | Corridor clearance | ACTIVE, bound to this ordered payer → payee, CEAP-satisfying |
| TerraQura | MRV/carbon anchor | ACTIVE, bound to this claim, CEAP-satisfying |
| Shiora    | Health attestation | ACTIVE, bound to this subject + scope, CEAP-satisfying |

In every case, revoking the seal on-chain invalidates the object instantly with
no dApp transaction — the enforcement lives in consensus, not in an oracle.
