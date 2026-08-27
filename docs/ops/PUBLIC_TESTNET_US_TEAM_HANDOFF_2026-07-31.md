# US Team Handoff — Public Testnet Release 2026-07-31

Copy and send the message below without changing its release IDs, branches,
commits, artifact hash, or deployment order.

---

Team,

Do not restart, reset, or recreate the public testnet. Do not add an upgrade
handler. The five validators are already on protocol source revision
`4c9c258c5757d385e6259875625e63ac205aa5e8`. Governance proposal `1` has
passed, and the live EVM parameters now contain `0x0800`, `0x0801`, `0x0900`,
`0x0901`, and `0x0902`.

We are freezing the application setup to release
`public-testnet-application-bundle-2026-07-31.3`. From this point, do not
deploy a branch tip. Fetch the branch and check out the exact commit in
detached mode:

```bash
git fetch origin <release-branch>
git checkout --detach <release-sha>
test "$(git rev-parse HEAD)" = "<release-sha>"
test -z "$(git status --porcelain)"
```

This is not a request to start the setup again. You are already on the release
branches. If your current checkout and deployment evidence match the frozen
commit, retain the deployment and perform only the action stated below.

Use these exact releases:

```text
Protocol
branch: release/public-testnet-pqc
commit: 4c9c258c5757d385e6259875625e63ac205aa5e8
action: no restart and no binary change

Wallet
branch: fix/wallet-popup-layout
commit: 9f1ba1358f3599ae1d0b084caec0efaee3250896
Node: 24.18.0
pnpm: 11.9.0

Cruzible
branch: fix/us-testnet-wallet-staking
commit: 92671c4558d476a873caa7b33cc24f82c69676dd
action: keep the working contract addresses; do not redeploy

TerraQura
branch: ramesh/terraqura-pre-mainnet-remediation-20260414
commit: af509d2f1629af98873de3f627896d483baed595
Node: 20.18.3
pnpm: 9.0.0

ZeroID
branch: release/zeroid-production-hardening
commit: 709beb25493b30093f5bd637824c0e1fcd2ed3ec
Node: 20.19.5
npm: 10.8.2

NoblePay
branch: release/noblepay-production-readiness
commit: cf91c309252d3c5e69b52525975ceef98e6dc24e
Node: 24.18.0
npm: 11.16.0

Shiora
branch: release/public-testnet-2026-07-31
commit: 2dd1255715a373beb691ab4bbcaecf787dcb8c09
Node: 20.x
install: npm ci
```

Install the wallet first. Use the GitHub artifact:

```text
https://github.com/aethelred-foundation/wallet/releases/download/public-testnet-wallet-v0.9.0-20260805/aethelred-wallet-v0.9.0.zip
SHA-256: 9635fd6473e4d2ce41a56d06736613f26b50624fe4eeba4cf5728d21c82670db
size: 752337 bytes
```

Verify the hash before loading the unpacked extension. If endpoint protection
still flags the ZIP, do not disable or bypass protection. Build it locally
from the exact wallet commit and submit the hash for security-vendor review.
Disable/remove older Aethelred Wallet copies and load only this release. The
reported browser already grants all-sites access, so no build variable or new
manual permission is needed; confirm access to `http://93.127.132.52/*`, then
reload the extension and every open dApp tab.

This wallet accepts Shiora's `safe` sign-in classification without crashing.
On Chrome 127 and later, an account request also opens the popup when the
wallet is locked. Unlock it, return to the dApp, and select **Connect** once
again; the original request is deliberately not resumed silently.

Proceed in this order.

### 1. Cruzible

Keep the current contract addresses. Deploy commit
`92671c4558d476a873caa7b33cc24f82c69676dd` for the application processes.
The current `requiresRebuild=true` / `INDEXER_GENERATION_UNCOMMITTED` state is
an indexer-worker recovery issue, not a reason to reset the database, redeploy
contracts, or restart the chain. Follow **Recover an existing stuck rebuild
without resetting data** in `docs/TESTNET_DEPLOYMENT.md` so the API has
`INDEXER_ENABLED=false` and exactly one dedicated indexer runs. Require
readiness 200 before retesting both wallets and stake/unstake.

```bash
docker ps --filter label=com.docker.compose.service=api \
  --format 'project={{.Label "com.docker.compose.project"}} container={{.Names}} ports={{.Ports}}'
docker ps --filter label=com.docker.compose.service=indexer \
  --format 'project={{.Label "com.docker.compose.project"}} container={{.Names}} status={{.Status}}'
export CRUZIBLE_COMPOSE_PROJECT='<exact project from the API row>'
docker compose -p "$CRUZIBLE_COMPOSE_PROJECT" config --quiet
docker compose -p "$CRUZIBLE_COMPOSE_PROJECT" ps -a
docker compose -p "$CRUZIBLE_COMPOSE_PROJECT" exec -T api \
  sh -c 'printf "API INDEXER_ENABLED=%s\n" "${INDEXER_ENABLED:-unset}"'
```

If that last command reports `true`, stop any separate worker and recreate
only the API before starting one worker:

```bash
docker compose -p "$CRUZIBLE_COMPOSE_PROJECT" stop indexer
docker compose -p "$CRUZIBLE_COMPOSE_PROJECT" up --build -d --no-deps \
  --force-recreate api
docker compose -p "$CRUZIBLE_COMPOSE_PROJECT" exec -T api \
  sh -c 'test "$INDEXER_ENABLED" = false'
docker compose -p "$CRUZIBLE_COMPOSE_PROJECT" up --build -d --no-deps indexer
```

If it reports `false`, leave the API running and run only the final `up ...
indexer` command above. Then monitor the existing cursor:

```bash
docker compose -p "$CRUZIBLE_COMPOSE_PROJECT" logs --tail 200 indexer
curl -sS -w '\nHTTP %{http_code}\n' \
  http://93.127.132.52:4001/health/ready
```

### 2. TerraQura

Do not bypass the clean-source gate. If preflight reports modified or untracked
files, preserve the current directory, record `git status --short`, and use a
second clean checkout at the frozen commit. Continue to use the existing
external signer key, operator env, and durable checkpoint. This is source
recovery only; it does not restart the chain or discard ceremony state. If the
dirty files include application or contract source, send the diff for review
before continuing.

Use exactly Node `20.18.3` and pnpm `9.0.0`. In
`/secure/operator/terraqura-contracts.env`, set `DEPLOYER_SIGNER_KEY_FILE` to an
absolute path—not to the key value. The referenced mode-0400/0600 file is
exactly one `0x` + 64-hex line. Install the custody-supplied file separately,
then run:

```bash
TERRAQURA_OPERATOR_USER="$(id -un)"
TERRAQURA_OPERATOR_GROUP="$(id -gn)"
sudo install -d -o "$TERRAQURA_OPERATOR_USER" \
  -g "$TERRAQURA_OPERATOR_GROUP" -m 0700 /secure/operator
sudo install -o "$TERRAQURA_OPERATOR_USER" \
  -g "$TERRAQURA_OPERATOR_GROUP" -m 0600 \
  deploy/terraqura.contracts.public-testnet.env.example \
  /secure/operator/terraqura-contracts.env
sudo install -o "$TERRAQURA_OPERATOR_USER" \
  -g "$TERRAQURA_OPERATOR_GROUP" -m 0400 \
  /path/from/custody/terraqura-deployer.key \
  /secure/operator/terraqura-deployer.key
```

Fill every required non-secret field in
`/secure/operator/terraqura-contracts.env`, set its signer variable to
`DEPLOYER_SIGNER_KEY_FILE=/secure/operator/terraqura-deployer.key`, and then
run:

```bash
unset PRIVATE_KEY
set -a
. /secure/operator/terraqura-contracts.env
set +a
env -u PRIVATE_KEY pnpm contracts:signer-key:check
env -u PRIVATE_KEY pnpm contracts:rpc:check
env -u PRIVATE_KEY pnpm contracts:preflight
```

Then use the bootstrap/finalize/verify sequence and confirmation interlocks
in `docs/deployment/PUBLIC_TESTNET_DEPLOYMENT.md`. After finalization, install
`deploy/terraqura.public-testnet-evaluation.env.example` as
`/secure/operator/terraqura-public-testnet-evaluation.env` and copy the five
finalized proxy addresses into that external file; do not edit the tracked
example. Use it with `docker-compose.public-testnet-evaluation.yml` for ports
`3007/4000`. Stage the API operator key as the separate UID/GID-1001,
mode-0400 copy documented there. Do not use old deployment scripts or an old
manifest.

### 3. ZeroID

The backend is already healthy on port `4003` using `zeroid1`. Keep `zeroid1`,
preserve the old `zeroid` database, and do not create or reset another
database. Rebuild only the frontend at the frozen commit with API
`http://93.127.132.52:4003`, RPC `http://54.165.44.130:8545`, and
`ZEROID_ALLOW_PLAINTEXT_HTTP=true`. Reload the final wallet extension and
browser tab.

```dotenv
NEXT_PUBLIC_CHAIN_ENV=testnet
NEXT_PUBLIC_AETHELRED_TESTNET_RPC_URL=http://54.165.44.130:8545
NEXT_PUBLIC_ZEROID_API_URL=http://93.127.132.52:4003
NEXT_PUBLIC_API_URL=http://93.127.132.52:4003
ZEROID_BACKEND_API_URL=http://127.0.0.1:4003
ZEROID_ALLOW_PLAINTEXT_HTTP=true
```

### 4. NoblePay

Do not restore `scripts/setup-test-token.mjs` and do not deploy another test
token. Configure both operator-reported addresses plus each exact on-chain
name, and use the following evaluation inputs in
`/etc/noblepay/testnet-token-provisioning.env`:

```dotenv
CHAIN_ENV=testnet
RPC_URL=http://54.165.44.130:8545
ALLOW_INSECURE_TESTNET_RPC=acknowledge-evaluation-only-plaintext-rpc
AETHELRED_CHAIN_ID=7332
AETHELRED_NETWORK_ANCHOR_BLOCK=450000
AETHELRED_NETWORK_ANCHOR_HASH=0x1057a62d12eed50d8740fcf51be0cd784db9a4f8f98c9312eee8b8bc7e543ddc
NOBLEPAY_SOURCE_COMMIT=cf91c309252d3c5e69b52525975ceef98e6dc24e
TOKEN_PROVISIONER_ADDRESS=0x<funded-testnet-provisioner>
TOKEN_PROVISIONER_KEY_FILE=/etc/noblepay/token-provisioner.key
EXISTING_USDC_TOKEN_ADDRESS=0xB8FbD0B8cCB3f148DA18C223a1cFD77A594a280a
EXISTING_USDC_TOKEN_NAME=<exact-output-of-on-chain-name()>
EXISTING_USDT_TOKEN_ADDRESS=0x9928cF89b7ea982ee2E06C26a9Fd00105C02850D
EXISTING_USDT_TOKEN_NAME=<exact-output-of-on-chain-name()>
CONFIRM_TESTNET_TOKEN_PROVISIONING=false
```

The signer file contains only one raw `0x` + 64-hex key and has mode
`0400`; it is not an env assignment. Obtain the exact on-chain name of each
token, enter both names in the env, and then run the two non-transaction
checks:

```bash
for TOKEN_ADDRESS in \
  0xB8FbD0B8cCB3f148DA18C223a1cFD77A594a280a \
  0x9928cF89b7ea982ee2E06C26a9Fd00105C02850D
do
  node --input-type=module -e \
    'import {createPublicClient,http,parseAbi} from "viem";const [rpc,address]=process.argv.slice(1);const client=createPublicClient({transport:http(rpc)});console.log(`${address} ${await client.readContract({address,abi:parseAbi(["function name() view returns (string)"]),functionName:"name"})}`);' \
    http://54.165.44.130:8545 \
    "$TOKEN_ADDRESS"
done

export RELEASE_SHA=cf91c309252d3c5e69b52525975ceef98e6dc24e
export TOKEN_CHECKPOINT=/etc/noblepay/testnet-token-checkpoint.json
export TOKEN_MANIFEST=/etc/noblepay/testnet-token-manifest."$RELEASE_SHA".json

node --env-file=/etc/noblepay/testnet-token-provisioning.env \
  scripts/provision-testnet-tokens.mjs --validate-only \
  --checkpoint-file "$TOKEN_CHECKPOINT" --manifest-file "$TOKEN_MANIFEST"
node --env-file=/etc/noblepay/testnet-token-provisioning.env \
  scripts/provision-testnet-tokens.mjs --verify-only \
  --checkpoint-file "$TOKEN_CHECKPOINT" --manifest-file "$TOKEN_MANIFEST"
```

After review, change only `CONFIRM_TESTNET_TOKEN_PROVISIONING` to
`deploy-publicly-mintable-test-tokens` and run:

```bash
node --env-file=/etc/noblepay/testnet-token-provisioning.env \
  scripts/provision-testnet-tokens.mjs \
  --checkpoint-file "$TOKEN_CHECKPOINT" --manifest-file "$TOKEN_MANIFEST"
```

Immediately return the confirmation to `false`. The ceremony adopts verified
USDC and USDT without another token deployment.

Stop the current core ceremony. The repository does not include a governance
multisig deployment script; the multisig must be provisioned through the
approved external governance process. The prior bootstrap disabled the
multisig-code check and used an individual address as `ADMIN_ADDRESS`, so do
not call `acceptOwnership`, do not run `--finalize`, and do not configure or
publish those core addresses. Preserve its checkpoint and transcript.

After a real governance multisig is deployed, use the clean frozen source and
start a new core ceremony with that contract as `ADMIN_ADDRESS` and with new
checkpoint and manifest paths. The verified USDC and USDT addresses can be
retained. Bootstrap may use the acknowledged anchored HTTP RPC. Have the
multisig execute the generated `acceptOwnership()` payload; finalization must
then wait for a real Ethereum JSON-RPC WSS endpoint and the required TLS
publication endpoints. CometBFT `26657` is not a substitute, and no validator
restart is required.

### 5. Shiora

The Shiora failure was a wallet approval-rendering defect, and the site-access
setting was already correct. If the running application is commit
`2dd1255715a373beb691ab4bbcaecf787dcb8c09` with the release environment, keep
it and its verified attestation contract. Install the new wallet and retest;
do not redeploy Shiora for this defect.

Only if the running commit or environment differs, complete an operator copy of
`.env.public-testnet.example`, including its required secrets, database, admin,
and migration values. For the current synthetic direct-IP evaluation, apply
these overrides; this block is not a complete environment:

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

Retest both Aethelred Wallet and MetaMask. The modal clipping and exact-origin
handling remain fixed in the pinned Shiora commit.

Expected ports are:

```text
Cruzible  frontend 3000, API 4001
Shiora    combined frontend/API 3001
ZeroID    frontend 3003, API 4003
TerraQura frontend 3007, API 4000
NoblePay  frontend 3008, API/WS 4008
```

For each component, reply with:

- the exact `git rev-parse HEAD`;
- `node --version` and package-manager version;
- the deployment-manifest path and verified contract addresses, or “no
  contract change”;
- the running service URLs;
- wallet-connect and primary-flow smoke-test results;
- transaction hashes for any newly broadcast contract ceremony.

Stop only the affected application if a commit, artifact hash, network anchor,
contract verification, migration preflight, or canonical token check fails.
Do not reset the network.

The authoritative release details and recovery instructions are in
`docs/ops/PUBLIC_TESTNET_APPLICATION_RELEASE_2026-07-31.md`.

---
