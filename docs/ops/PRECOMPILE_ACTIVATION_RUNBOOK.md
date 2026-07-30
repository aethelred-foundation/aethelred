# Runbook — Activate Staking/Distribution Precompiles on the Public Testnet

**Purpose:** turn on the cosmos/evm staking (`0x0800`) and distribution
(`0x0801`) precompiles on the RUNNING public testnet so EVM contracts (the
Cruzible liquid-staking vault) can delegate pooled AETHEL and claim earned
rewards. This is the Gate-2 unblock in the Cruzible production-readiness plan.

**Mechanism:** the precompiles are compiled into the node binary
(PR #154, `feat/staking-distribution-precompiles`), but x/vm gates activation
on the `active_static_precompiles` **state param**. Registration in the binary
does nothing on its own; an on-chain gov `MsgUpdateParams` for the evm module
adds the two addresses to the param and activates them — **no chain restart,
no re-genesis.**

## Proven on a state-mirror devnet (2026-07-11)

A devnet running the **new** binary with the testnet's **old** 3-precompile
param set was used to rehearse the exact procedure:

1. **Before activation:** `Cruzible.delegateToValidator` REVERTS — the
   precompile is registered in the binary but not in the active param. This is
   the proof that upgrading validator binaries is a **safe rolling upgrade**:
   a node on the new binary behaves identically to one on the old binary until
   the param flips.
2. Ran `scripts/activate-precompiles-gov.sh` → proposal #1 submitted, voted,
   `PROPOSAL_STATUS_PASSED`, param updated to 5 precompiles.
3. **After activation, same running node (no restart):**
   `delegateToValidator(2 AETHEL)` SUCCEEDS — vault balance moved 5→3 AETHEL
   into x/staking, `totalDelegated = 2`. `claimStakingRewards` through
   `0x0801` claimed real earned yield.

## Consensus-safety sequencing (do NOT reorder)

1. **Upgrade every validator's binary FIRST** to the PR #154 release build.
   Do this as a rolling upgrade — one validator at a time — confirming block
   production continues after each. Because the param has not changed, a
   new-binary node produces byte-identical app hashes to an old-binary node,
   so the set can be mixed-version during the roll.
2. **Confirm the entire active set is on the new binary** before proceeding.
   A validator still on the old binary cannot register the precompile
   handlers; when the param later activates them, that node would compute a
   different app hash and **halt (apphash mismatch)**. This is the one hard
   ordering constraint.
3. **Then submit + pass the gov proposal.** The param change applies
   deterministically at the proposal's execution height on every (upgraded)
   node simultaneously — no fork.

## Required five-validator binary attestation

Do not infer the application binary from CometBFT `/status`: that endpoint
reports the CometBFT version, not the Aethelred application commit or binary
digest. Before submission, each of the five bonded validator operators must
return the following evidence from the service host:

```bash
# Record the real executable used by systemd. Replace the service name if the
# deployment does not use aethelredd.service.
systemctl show aethelredd.service --property=ExecStart --no-pager

# Run both commands against the absolute executable path shown above.
/absolute/path/to/aethelredd version --long
sha256sum /absolute/path/to/aethelredd
```

The release coordinator records validator moniker, executable path, full
`version --long` output, and SHA-256. Proceed only when all five operators
confirm the approved `4c9c258c5757d385e6259875625e63ac205aa5e8` release
artifact and the same checksum (or the same immutable container-image digest).
If checksums differ, stop and place every validator on one approved artifact
before changing the parameter.

## Execution

```bash
# On an operator box with a funded proposer key and the new binary:
BIN=aethelredd \
NODE=tcp://<validator-rpc>:26657 \
CHAIN_ID=aethelred-testnet-1 \
FROM=<proposer-key> \
HOME_DIR=<node-home> \
KEYRING=<backend> \
DEPOSIT=10000000uaethel \
VALIDATOR_SET_ATTESTED=1 \
  scripts/activate-precompiles-gov.sh
```

`VALIDATOR_SET_ATTESTED=1` is a deliberate operator acknowledgement, not an
automated discovery mechanism. The script refuses a public-testnet submission
without it. It also disables `--vote-all` on the public testnet.

The script is **read-safe and idempotent**: it first queries the current
params and exits early if `0x0800`/`0x0801` are already active. It also aborts
if a matching activation proposal is already in deposit or voting period, so
rerunning it cannot silently create a duplicate. It then builds a
`MsgUpdateParams` that takes the CURRENT evm params verbatim and appends the
two precompiles (sorted + de-duplicated, as `ValidatePrecompiles` requires),
submits the proposal, prints the proposal id, and returns control to the
operator.

The public testnet voting period was `172800s` (48 hours) when this runbook was
validated on 2026-07-28. The default command therefore does **not** block
waiting for execution. Do not interpret a still-open proposal as an activation
failure, and do not submit a second proposal.

**Voting.** On the public testnet each validator operator votes independently
— distribute the printed proposal id and have each run:

```bash
aethelredd tx gov vote <PID> yes --from <valkey> \
  --chain-id aethelred-testnet-1 --node tcp://<rpc>:26657 \
  --keyring-backend <backend> --fees 2000uaethel --gas 300000 --yes
```

For a single-operator devnet/rehearsal, pass `--vote-all` to cast YES from
every local validator key and wait for execution automatically. `--wait` is
also available when an operator deliberately wants the script to monitor a
proposal until terminal status; `WAIT_TIMEOUT_SECONDS=0` means no local
deadline.

Monitor the public-testnet proposal by its printed id:

```bash
aethelredd query gov proposal <PID> \
  --node tcp://<rpc>:26657 --output json
```

## Verification after `PROPOSAL_STATUS_PASSED`

```bash
# Safe post-passage verification: rerunning exits after confirming both are
# already active; it does not create another proposal.
BIN=aethelredd \
NODE=tcp://<validator-rpc>:26657 \
CHAIN_ID=aethelred-testnet-1 \
FROM=<proposer-key> \
HOME_DIR=<node-home> \
KEYRING=<backend> \
  scripts/activate-precompiles-gov.sh

# Param now lists all five precompiles:
aethelredd query evm params --node tcp://<rpc>:26657 --output json 2>&1 \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['params']['active_static_precompiles'])"

# Functional: a deployed Cruzible vault can now delegate (was reverting):
#   node cruzible/scripts/devnet-phase2-e2e.mjs   (RPC_URL/DEPLOYER_KEY/VALIDATOR)
```

## Rollback / abort

- **Before the proposal passes:** no state has changed — nothing to roll back.
  A rejected/expired proposal leaves the 3-precompile param intact.
- **After activation, to deactivate:** submit the inverse `MsgUpdateParams`
  restoring the 3-precompile list. Note that any funds already delegated by a
  vault remain in x/staking and unbond normally; only NEW delegate/claim calls
  would revert again. Deactivation is not an emergency lever — the precompiles
  are upstream cosmos/evm code, not custom.

## After activation — hand back to the Cruzible/Gate-3 track

Once live on the multi-validator testnet, the Gate-3 campaign (validator
fault injection, slashing drills, cross-VM atomicity, sustained load) runs
against the real precompiles, and `stakeWithSeal` seal-quorum E2E (wallet
gap W-3) becomes testable.
