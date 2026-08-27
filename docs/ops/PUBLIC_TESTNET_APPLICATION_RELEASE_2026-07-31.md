# Public Testnet Application Release — 2026-07-31

Release ID: `public-testnet-application-bundle-2026-07-31.3`

Status: approved public-testnet application baseline.

Canonical release tag:
`public-testnet-application-bundle-2026-07-31.3` in
`aethelred-foundation/aethelred`.

This release freezes the running Aethelred public testnet, Aethelred Wallet,
and the five application deployments at reviewed source commits. It does not
authorize a chain reset, re-genesis, validator restart, silent binary change,
or deployment from a moving branch tip.

The machine-readable companion is
[`public-testnet-application-release-2026-07-31.json`](./public-testnet-application-release-2026-07-31.json).
The copy-ready operator message is
[`PUBLIC_TESTNET_US_TEAM_HANDOFF_2026-07-31.md`](./PUBLIC_TESTNET_US_TEAM_HANDOFF_2026-07-31.md).

## 1. Operator rules

1. Keep the current network and validator data. Do not start the public
   testnet again.
2. Do not add an upgrade handler for this release. The validators are already
   running source revision
   `4c9c258c5757d385e6259875625e63ac205aa5e8`, and governance proposal `1`
   has already activated the required EVM parameters.
3. Fetch the named branch, then check out the exact 40-character commit in
   detached mode. Never deploy a branch tip.
4. Install and verify the frozen wallet before retesting any application
   wallet flow.
5. Preserve working contract addresses. Redeploy an application contract only
   where this document says the current ceremony is required, or where
   bytecode, manifest, ownership, or wiring verification fails.
6. Use the runtime specified for each repository. Node.js 25 is not an
   approved runtime for this release.
7. Any source, environment-contract, deployment-script, contract-address, or
   artifact change requires a new release ID and a new manifest.

This is a freeze of the branches the team is already using, not a request to
start over. If the current checkout, build, environment, and deployment
evidence already match this release, retain them and perform only the
component action listed below.

Use this checkout pattern for every source repository:

```bash
git fetch origin <release-branch>
git checkout --detach <release-sha>
test "$(git rev-parse HEAD)" = "<release-sha>"
test -z "$(git status --porcelain)"
```

## 2. Confirmed live chain state

Read-only verification at block `469283`, block time
`2026-08-05T07:42:56.530327282Z`, reconfirmed:

- chain ID `aethelred-testnet-1`;
- node `catching_up=false`;
- governance proposal `1` is `PROPOSAL_STATUS_PASSED`;
- final tally is `600000000000` yes and zero no, veto, or abstain;
- EVM chain ID is `7332` (`0x1ca4`), and block `450000` still has the pinned
  hash `0x1057a62d12eed50d8740fcf51be0cd784db9a4f8f98c9312eee8b8bc7e543ddc`;
- `active_static_precompiles` contains all five approved addresses:
  `0x0800`, `0x0801`, `0x0900`, `0x0901`, and `0x0902`.

No reviewed EVM JSON-RPC WSS URL is published in this release. CometBFT RPC
port `26657` is not an EVM WebSocket endpoint.

The exact verification references are:

- [`PRECOMPILE_ACTIVATION_RUNBOOK.md`](./PRECOMPILE_ACTIVATION_RUNBOOK.md)
- [`../../scripts/activate-precompiles-gov.sh`](../../scripts/activate-precompiles-gov.sh)

The proposal changed on-chain EVM parameters. It did not require an upgrade
handler, chain restart, or re-genesis.

All five validators reported:

```text
vcs.revision=4c9c258c5757d385e6259875625e63ac205aa5e8
vcs.modified=false
CGO_ENABLED=1
GOARCH=amd64
GOOS=linux
```

The reported executable SHA-256 differs by operating-system build environment:

```text
Ubuntu  633dc3df61a59de83a1ecbc14f1c957d97902e258f7036e57f58050092f1bbce
Debian  0fdc0920980cae58c4098175d44f4334ae0c35460da52815c04e4543ea4e13ab
```

That cross-distribution binary difference is expected for CGO builds. Keep the
per-host hashes in the operator evidence; the release identity is the clean
source revision above. Do not rebuild or restart a validator merely to make
the Ubuntu and Debian executable hashes equal.

## 3. Frozen source and deployment matrix

| Component | Repository and release branch                                                         | Frozen commit                              | Runtime                       | Deployment action                                                                                                                                                   |
| --------- | ------------------------------------------------------------------------------------- | ------------------------------------------ | ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Protocol  | `aethelred-foundation/aethelred`, `release/public-testnet-pqc`                        | `4c9c258c5757d385e6259875625e63ac205aa5e8` | Go `1.25.12`                  | No action. Keep the running chain.                                                                                                                                  |
| Wallet    | `aethelred-foundation/wallet`, `fix/wallet-popup-layout`                              | `9f1ba1358f3599ae1d0b084caec0efaee3250896` | Node `24.18.0`, pnpm `11.9.0` | Replace/reload the evaluation extension from the verified release artifact.                                                                                         |
| Cruzible  | `aethelred-foundation/cruzible`, `fix/us-testnet-wallet-staking`                      | `92671c4558d476a873caa7b33cc24f82c69676dd` | Node `>=20.0.0`, npm `10.9.4` | Keep the working contracts. Recreate the API only if it embeds an indexer, then run exactly one dedicated indexer until readiness recovers.                         |
| TerraQura | `aethelred-foundation/terraqura`, `ramesh/terraqura-pre-mainnet-remediation-20260414` | `af509d2f1629af98873de3f627896d483baed595` | Node `20.18.3`, pnpm `9.0.0`  | Use the repaired signer/RPC preflight, complete the five-proxy ceremony, then start the explicit direct-IP evaluation profile.                                      |
| ZeroID    | `aethelred-foundation/zeroid`, `release/zeroid-production-hardening`                  | `709beb25493b30093f5bd637824c0e1fcd2ed3ec` | Node `20.19.5`, npm `10.8.2`  | Keep the working `zeroid1` database and preserved old `zeroid` database. Rebuild the frontend with the exact API/RPC variables below; do not reset either database. |
| NoblePay  | `aethelred-foundation/noblepay`, `release/noblepay-production-readiness`              | `cf91c309252d3c5e69b52525975ceef98e6dc24e` | Node `24.18.0`, npm `11.16.0` | Verify and adopt both reported test tokens. Do not finalize the core bootstrap that bypassed the multisig check; start a new core ceremony only after a real governance multisig is deployed. |
| Shiora    | `aethelred-foundation/shiora`, `release/public-testnet-2026-07-31`                    | `2dd1255715a373beb691ab4bbcaecf787dcb8c09` | Node `20.x`, `npm ci`         | Keep the running deployment if its commit and environment match. Retest with the new wallet; do not redeploy the application or a verified attestation contract for this wallet defect. |

Expected service ports:

| Application | Frontend | Backend / API | Other                                |
| ----------- | -------: | ------------: | ------------------------------------ |
| Cruzible    |   `3000` |        `4001` | —                                    |
| Shiora      |   `3001` |  same process | —                                    |
| ZeroID      |   `3003` |        `4003` | —                                    |
| TerraQura   |   `3007` |        `4000` | —                                    |
| NoblePay    |   `3008` |        `4008` | optional gateway `4018`, edge `8080` |

## 4. Wallet artifact

Use the GitHub prerelease artifact, not a chat or CDN attachment:

```text
https://github.com/aethelred-foundation/wallet/releases/download/public-testnet-wallet-v0.9.0-20260805/aethelred-wallet-v0.9.0.zip
```

Required verification:

```text
file:    aethelred-wallet-v0.9.0.zip
size:    752337 bytes
sha256:  9635fd6473e4d2ce41a56d06736613f26b50624fe4eeba4cf5728d21c82670db
source:  9f1ba1358f3599ae1d0b084caec0efaee3250896
runtime: Node 24.18.0, pnpm 11.9.0
CI:      https://github.com/aethelred-foundation/wallet/actions/runs/30984536941
audit:   https://github.com/aethelred-foundation/wallet/actions/runs/30984537051
```

On Windows:

```powershell
Get-FileHash .\aethelred-wallet-v0.9.0.zip -Algorithm SHA256
```

If endpoint protection flags the archive, do not bypass or disable endpoint
protection. Build locally from the frozen source commit, compare the SHA-256,
and submit the hash to the security vendor for review. The release artifact is
a deterministic source build; a clean build and matching hash provide
provenance, not an instruction to ignore a security alert.

The wallet loads the page provider in the manifest-declared main world and
keeps the bridge in the isolated world. This removes the classic-script import
failure and strict-content-security-policy injection failure that prevented
ZeroID, Cruzible, and Shiora from detecting the extension. The popup navigation
and viewport layout fixes are included in the same artifact.

Revision `.3` also accepts the wallet's `safe` sign-in risk classification,
fails closed instead of crashing when an approval risk payload is malformed,
and opens the locked-wallet popup automatically for account requests on Chrome
127 and later. Unlocking does not silently resume the original dApp request:
after unlocking, return to the dApp and select **Connect** once more.

Disable or remove every older Aethelred Wallet copy before loading this one.
The reported browser configuration already grants the extension access on all
sites, so no build variable or new manual permission is required. Confirm that
the single enabled copy can access `http://93.127.132.52/*`, reload the
extension, and then reload every open dApp tab. Multiple enabled copies can
race provider injection and are not a valid test configuration.

References:

- `wallet/docs/testing/WALLET_PUBLIC_TESTNET_RETEST.md`
- `wallet/docs/engineering/WALLET_PRODUCTION_READINESS.md`

## 5. Application-specific instructions

### Cruzible

The US deployment has already completed stake and unstake successfully. Keep
the current Cruzible, StAETHEL, and WstAETHEL addresses. Do not redeploy the
contracts again unless the deployed manifest, bytecode, or wiring check fails.

After installing the frozen wallet, retest Aethelred Wallet connection,
stake, unstake, transaction confirmation, and receipt display. MetaMask and
Aethelred Wallet are both supported.

The current backend is not ready because its durable cursor reports
`requiresRebuild=true` and `INDEXER_GENERATION_UNCOMMITTED`. That is an
application-worker recovery condition, not a chain or contract failure.
Commit `92671c4558d476a873caa7b33cc24f82c69676dd` fixes the single-box topology:
the API is forced to `INDEXER_ENABLED=false` and exactly one dedicated indexer
is started by default. Resolve the Compose project that owns API port `4001`,
then follow **Recover an existing stuck rebuild without resetting data** in
the canonical runbook. Do not edit/delete the cursor, reset Prisma, remove the
PostgreSQL volume, redeploy contracts, or restart the chain. Readiness must
return 200 and the reconciliation discrepancy must clear before promotion.

References:

- `cruzible/docs/TESTNET_DEPLOYMENT.md`
- `cruzible/docs/TESTNET_TESTING_GUIDE.md`
- `cruzible/docs/ops/environment-reference.md`
- `cruzible/.env.testnet.example`
- `cruzible/backend/.env.example`

### TerraQura

If `contracts:preflight` reports `Source checkout contains modified or
untracked files`, do not weaken or bypass that release gate. Preserve the
current directory for evidence, record `git status --short`, and use a second,
clean checkout at the frozen commit. Keep the signer key, operator env, and
durable checkpoint at their existing external paths; a clean source checkout
does not restart the network or discard ceremony state. If any modified file
is application or contract source rather than local operator configuration,
stop and submit the diff for review before continuing.

Use the exact runtime before running any contract command:

```bash
nvm install
nvm use
test "$(node --version)" = "v20.18.3"
test "$(cat .node-version)" = "20.18.3"
corepack enable
corepack prepare "$(node -p 'require("./package.json").packageManager')" --activate
test "$(pnpm --version)" = "9.0.0"
HUSKY=0 pnpm install --frozen-lockfile
```

The deployment env must contain a path, not the private key value:

```dotenv
DEPLOYER_SIGNER_KEY_FILE=/secure/operator/terraqura-deployer.key
```

The referenced file contains exactly one `0x` followed by 64 hexadecimal
characters and has mode `0400` or `0600`. Source only the reviewed operator
env, clear any inherited legacy value, and run the read-only checks first:

```bash
unset PRIVATE_KEY
set -a
. /secure/operator/terraqura-contracts.env
set +a
env -u PRIVATE_KEY pnpm contracts:signer-key:check
env -u PRIVATE_KEY pnpm contracts:rpc:check
env -u PRIVATE_KEY pnpm contracts:preflight
```

Then run the reviewed ceremony:

```bash
export CONFIRM_TESTNET_DEPLOY=true
export CONFIRM_TESTNET_FINALIZE=false
env -u PRIVATE_KEY pnpm contracts:bootstrap
export CONFIRM_TESTNET_DEPLOY=false

export CONFIRM_TESTNET_DEPLOY=false
export CONFIRM_TESTNET_FINALIZE=true
env -u PRIVATE_KEY pnpm contracts:finalize
export CONFIRM_TESTNET_FINALIZE=false

env -u PRIVATE_KEY pnpm contracts:verify
```

For the current US host, install
`deploy/terraqura.public-testnet-evaluation.env.example` as the external
operator file `/secure/operator/terraqura-public-testnet-evaluation.env`, then
copy the finalized five proxy addresses into that external file. Do not edit
the tracked example. Use only `docker-compose.public-testnet-evaluation.yml`;
it is the reviewed production-runtime, direct-IP profile for web `3007`, API
`4000`, chain `7332`, and the pinned RPC anchor. The API signer must be staged
as the separate UID/GID `1001`, mode-`0400` copy described in the runbook. Do
not use the old database or previous deployment scripts by default.

References:

- `terraqura/docs/deployment/PUBLIC_TESTNET_DEPLOYMENT.md`
- `terraqura/deploy/terraqura.contracts.public-testnet.env.example`
- `terraqura/deploy/terraqura.public-testnet-evaluation.env.example`
- `terraqura/docker-compose.public-testnet-evaluation.yml`
- `terraqura/deploy/terraqura.api.production.env.example`
- `terraqura/deploy/terraqura.web.production.env.example`

### ZeroID

The backend is healthy at port `4003` using the new `zeroid1` database. Keep
that database and preserve the old `zeroid` database; do not create another
database, remove the volume, run `migrate reset`, or edit
`_prisma_migrations`.

Rebuild only the frontend at the frozen commit with the browser-reachable API
and RPC values so its CSP includes both HTTP endpoints:

```dotenv
NEXT_PUBLIC_CHAIN_ENV=testnet
NEXT_PUBLIC_AETHELRED_TESTNET_RPC_URL=http://54.165.44.130:8545
NEXT_PUBLIC_ZEROID_API_URL=http://93.127.132.52:4003
NEXT_PUBLIC_API_URL=http://93.127.132.52:4003
ZEROID_BACKEND_API_URL=http://127.0.0.1:4003
ZEROID_ALLOW_PLAINTEXT_HTTP=true
```

The final wallet artifact fixes provider discovery. Reload the extension and
the ZeroID tab before retesting wallet connection.

Reuse existing ZeroID contract addresses only when the deployment manifest,
chain ID, bytecode, ownership, and wiring verify against this release. If that
evidence does not exist, stop and follow the complete contract ceremony before
publishing new addresses.

References:

- `zeroid/deployments/PUBLIC_TESTNET_RUNBOOK.md`
- `zeroid/backend/README.md#safe-database-migration-and-p3005-recovery`
- `zeroid/.env.testnet.example`
- `zeroid/backend/.env.testnet.example`

### NoblePay

Do not restore or use `scripts/setup-test-token.mjs`. The operator reports that
both test tokens have now been deployed. Do not deploy either token again.
Treat these addresses as operator-reported until the current provisioning
ceremony verifies their chain, runtime, name, symbol, and six decimals:

```text
USDC  0xB8FbD0B8cCB3f148DA18C223a1cFD77A594a280a
USDT  0x9928cF89b7ea982ee2E06C26a9Fd00105C02850D
```

Set both addresses and their exact on-chain `name()` results in the
provisioning env:

```dotenv
EXISTING_USDC_TOKEN_ADDRESS=0xB8FbD0B8cCB3f148DA18C223a1cFD77A594a280a
EXISTING_USDC_TOKEN_NAME=<exact-name-returned-by-name()>
EXISTING_USDT_TOKEN_ADDRESS=0x9928cF89b7ea982ee2E06C26a9Fd00105C02850D
EXISTING_USDT_TOKEN_NAME=<exact-name-returned-by-name()>
RPC_URL=http://54.165.44.130:8545
ALLOW_INSECURE_TESTNET_RPC=acknowledge-evaluation-only-plaintext-rpc
AETHELRED_CHAIN_ID=7332
AETHELRED_NETWORK_ANCHOR_BLOCK=450000
AETHELRED_NETWORK_ANCHOR_HASH=0x1057a62d12eed50d8740fcf51be0cd784db9a4f8f98c9312eee8b8bc7e543ddc
```

The signer file is one raw `0x` + 64-hex key with mode `0400`; it is not an
env assignment. Run validation, then the keyless on-chain verification:

```bash
export RELEASE_SHA=cf91c309252d3c5e69b52525975ceef98e6dc24e
export TOKEN_CHECKPOINT=/etc/noblepay/testnet-token-checkpoint.json
export TOKEN_MANIFEST=/etc/noblepay/testnet-token-manifest."$RELEASE_SHA".json

node --env-file=/etc/noblepay/testnet-token-provisioning.env \
  scripts/provision-testnet-tokens.mjs \
  --validate-only \
  --checkpoint-file "$TOKEN_CHECKPOINT" \
  --manifest-file "$TOKEN_MANIFEST"

node --env-file=/etc/noblepay/testnet-token-provisioning.env \
  scripts/provision-testnet-tokens.mjs \
  --verify-only \
  --checkpoint-file "$TOKEN_CHECKPOINT" \
  --manifest-file "$TOKEN_MANIFEST"
```

After review, set
`CONFIRM_TESTNET_TOKEN_PROVISIONING=deploy-publicly-mintable-test-tokens` in the
operator env and run:

```bash
node --env-file=/etc/noblepay/testnet-token-provisioning.env \
  scripts/provision-testnet-tokens.mjs \
  --checkpoint-file "$TOKEN_CHECKPOINT" \
  --manifest-file "$TOKEN_MANIFEST"
```

Return the confirmation to `false`. With both existing-token inputs present,
the command verifies and adopts USDC and USDT without deploying another token,
and produces resumable checkpoint and manifest evidence. It does not register
tokens, mint, approve, or modify core contracts. Copy only
the emitted `SUPPORTED_TOKEN_ADDRESSES`, `USDC_TOKEN_ADDRESS`, and
`USDT_TOKEN_ADDRESS` values into the core env.

The repository intentionally does not deploy the governance multisig. It must
be provisioned through the approved external governance process, and its
address must have runtime code before it is used as `ADMIN_ADDRESS`. Never
disable the `final governance multisig` check.

The reported core bootstrap was run after that check was disabled and used an
individual address as `ADMIN_ADDRESS`. Preserve its checkpoint and transcript
as evidence, but do not call `acceptOwnership`, do not finalize it, and do not
publish or configure its contract addresses. The checkpoint digest binds the
invalid admin input, so it cannot be repaired by replacing the address in the
env. After a real multisig is deployed, return to the clean frozen source and
start a new core ceremony with a new checkpoint and manifest path. The two
verified token contracts may be retained; this recovery redeploys only the
NoblePay core contracts, not the tokens or the chain.

The repaired core ceremony accepts the explicitly acknowledged HTTP RPC for
this evaluation network. After the new bootstrap, the governance multisig must
execute the generated `acceptOwnership()` payload. Core finalize then remains
blocked until a real credential-free Ethereum JSON-RPC WSS endpoint and the
required TLS publication endpoints exist. CometBFT port `26657` is not an EVM
WebSocket substitute, and none of these blockers requires restarting
validators.

References:

- `noblepay/deploy/PUBLIC_TESTNET_OPERATOR_RUNBOOK.md`
- `noblepay/deploy/README.md`
- `noblepay/deploy/core-deployment.env.example`
- `noblepay/deploy/testnet-token-provisioning.env.example`

### Shiora

The wallet approval crash shown on Shiora was caused by the wallet's `safe`
risk-classification handling, not by Shiora site access or contract bytecode.
The browser evidence already shows all-sites access. If the running Shiora
checkout is `2dd1255715a373beb691ab4bbcaecf787dcb8c09` and its environment
matches this release, keep that process and the verified attestation contract;
install the new wallet and retest. No Shiora source or contract redeployment is
required for this defect.

If the running commit or environment does not match, complete the operator copy of
`.env.public-testnet.example`, including every required secret, database,
admin, and migration value. Apply these direct-IP overrides; they are not a
complete Shiora environment:

```dotenv
NODE_ENV=production
PORT=3001
SHIORA_PREFLIGHT_MODE=evaluation
SHIORA_PROFILE=pilot
SHIORA_ALLOWED_ORIGINS=http://93.127.132.52:3001
SHIORA_ENABLE_HSTS=false
SHIORA_ALLOW_INSECURE_WALLET_HEADER=false
SHIORA_TRUSTED_PROXY_COUNT=0
```

These values are limited to synthetic public-testnet evaluation. Production or
live-data use still requires an approved HTTPS origin and the production
security gates.

The release portals the wallet modal to the document body, so it is no longer
clipped by the navigation stacking context. The exact allowed origin also
prevents the prior cross-origin mutation rejection.

References:

- `shiora/docs/PUBLIC_TESTNET_RUNBOOK.md`
- `shiora/.env.public-testnet.example`
- `shiora/contracts/.env.public-testnet.example`

## 6. Retest order and stop conditions

Run the retest in this order:

1. Verify the chain and five active precompiles read-only.
2. Install the frozen wallet and verify its SHA-256.
3. Recover Cruzible's dedicated indexer and retest without changing contracts.
4. Complete TerraQura with Node `20.18.3` and its explicit evaluation profile.
5. Keep ZeroID on `zeroid1`, rebuild its frontend, and verify the existing
   contract manifest before deciding whether a contract ceremony is required.
6. Verify/adopt NoblePay's existing USDC and USDT without another token
   deployment. Preserve but do not finalize the EOA-admin core checkpoint;
   provision a governance multisig and run a new core ceremony, then stop at
   the documented WSS/TLS finalization gate.
7. Keep the matching Shiora deployment and retest both wallet choices; rebuild
   only if its commit or environment differs from this release.

Stop the affected application deployment and report evidence if:

- the checked-out commit differs from this release;
- the wallet ZIP hash differs;
- the chain ID, network anchor, or active precompile set differs;
- a deployed contract's bytecode, proxy implementation, owner, or wiring does
  not match its reviewed manifest;
- ZeroID's migration preflight exits `78`;
- either NoblePay token address cannot be verified;
- NoblePay `ADMIN_ADDRESS` is not a deployed governance multisig, ownership has
  not been accepted through it, or finalization lacks a real EVM WSS endpoint
  or required TLS public endpoints;
- a production-mode service requires an insecure-origin exception.

None of those application stop conditions requires resetting the public
testnet.
