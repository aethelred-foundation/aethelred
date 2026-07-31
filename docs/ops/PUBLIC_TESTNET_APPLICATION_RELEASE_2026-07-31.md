# Public Testnet Application Release — 2026-07-31

Release ID: `public-testnet-application-bundle-2026-07-31.1`

Status: approved public-testnet application baseline.

Canonical release tag:
`public-testnet-application-bundle-2026-07-31.1` in
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

Read-only verification at block `388445`, block time
`2026-07-31T06:45:49.109924979Z`, confirmed:

- chain ID `aethelred-testnet-1`;
- node `catching_up=false`;
- governance proposal `1` is `PROPOSAL_STATUS_PASSED`;
- final tally is `600000000000` yes and zero no, veto, or abstain;
- `active_static_precompiles` contains all five approved addresses:
  `0x0800`, `0x0801`, `0x0900`, `0x0901`, and `0x0902`.

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

| Component | Repository and release branch | Frozen commit | Runtime | Deployment action |
| --- | --- | --- | --- | --- |
| Protocol | `aethelred-foundation/aethelred`, `release/public-testnet-pqc` | `4c9c258c5757d385e6259875625e63ac205aa5e8` | Go `1.25.12` | No action. Keep the running chain. |
| Wallet | `aethelred-foundation/wallet`, `fix/wallet-popup-layout` | `c33d4c05120ba98449aad8f9ac820df2ad701955` | Node `24.18.0`, pnpm `11.9.0` | Replace/reload the evaluation extension from the verified release artifact. |
| Cruzible | `aethelred-foundation/cruzible`, `fix/us-testnet-wallet-staking` | `7df3998ae1a09d149eec9f005b6cf4146851acb1` | Node `>=20.0.0`, npm `10.9.4` | Keep the working contract deployment. Rebuild/restart the application only if needed after the wallet update. |
| TerraQura | `aethelred-foundation/terraqura`, `ramesh/terraqura-pre-mainnet-remediation-20260414` | `0f84a3f0c820afed6bcf2af50dd1c258481d3fe4` | Node `20.18.3`, pnpm `9.0.0` | Complete the current two-phase contract ceremony; do not reuse removed scripts or an old manifest. |
| ZeroID | `aethelred-foundation/zeroid`, `release/zeroid-production-hardening` | `709beb25493b30093f5bd637824c0e1fcd2ed3ec` | Node `20.19.5`, npm `10.8.2` | Move the application to a fresh database in the existing PostgreSQL volume. Preserve verified contract addresses; run the contract ceremony only if no valid deployment manifest exists. |
| NoblePay | `aethelred-foundation/noblepay`, `release/noblepay-production-readiness` | `2f6d71ac1fe6d1f787534d7fe5234c3646aabab1` | Node `24.18.0`, npm `11.16.0` | Follow the current two-phase core ceremony. Provision test tokens only if the network operator confirms canonical test tokens do not exist. |
| Shiora | `aethelred-foundation/shiora`, `release/public-testnet-2026-07-31` | `2dd1255715a373beb691ab4bbcaecf787dcb8c09` | Node `20.x`, `npm ci` | Rebuild/restart the combined application with the evaluation origin settings. Do not redeploy a verified attestation contract. |

Expected service ports:

| Application | Frontend | Backend / API | Other |
| --- | ---: | ---: | --- |
| Cruzible | `3000` | `4001` | — |
| Shiora | `3001` | same process | — |
| ZeroID | `3003` | `4003` | — |
| TerraQura | `3007` | `4000` | — |
| NoblePay | `3008` | `4008` | optional gateway `4018`, edge `8080` |

## 4. Wallet artifact

Use the GitHub prerelease artifact, not a chat or CDN attachment:

```text
https://github.com/aethelred-foundation/wallet/releases/download/public-testnet-wallet-v0.9.0-20260731/aethelred-wallet-v0.9.0.zip
```

Required verification:

```text
file:    aethelred-wallet-v0.9.0.zip
size:    752236 bytes
sha256:  a7d4314b4b484c44de89404a5a539a593c06ea782851145772e8e141d2cad90e
source:  c33d4c05120ba98449aad8f9ac820df2ad701955
runtime: Node 24.18.0, pnpm 11.9.0
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

The wallet fix loads the page provider in the manifest-declared main world and
keeps the bridge in the isolated world. This removes the classic-script import
failure and strict-content-security-policy injection failure that prevented
ZeroID, Cruzible, and Shiora from detecting the extension. The popup navigation
and viewport layout fixes are included in the same artifact.

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

References:

- `cruzible/docs/TESTNET_DEPLOYMENT.md`
- `cruzible/docs/TESTNET_TESTING_GUIDE.md`
- `cruzible/docs/ops/environment-reference.md`
- `cruzible/.env.testnet.example`
- `cruzible/backend/.env.example`

### TerraQura

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

Run the reviewed ceremony:

```bash
pnpm contracts:preflight

export CONFIRM_TESTNET_DEPLOY=true
export CONFIRM_TESTNET_FINALIZE=false
pnpm contracts:bootstrap
export CONFIRM_TESTNET_DEPLOY=false

export CONFIRM_TESTNET_DEPLOY=false
export CONFIRM_TESTNET_FINALIZE=true
pnpm contracts:finalize
export CONFIRM_TESTNET_FINALIZE=false

pnpm contracts:verify
```

References:

- `terraqura/docs/deployment/PUBLIC_TESTNET_DEPLOYMENT.md`
- `terraqura/deploy/terraqura.contracts.public-testnet.env.example`
- `terraqura/deploy/terraqura.api.production.env.example`
- `terraqura/deploy/terraqura.web.production.env.example`

### ZeroID

The wallet-provider error is fixed by the wallet release; ZeroID already
supports the required provider surfaces.

For Prisma `P3005`, preserve the existing PostgreSQL volume and create a fresh
public-testnet database:

```bash
cd backend
docker compose stop api
docker compose up -d postgres
docker compose exec -T postgres sh -eu -c \
  'createdb --username "$POSTGRES_USER" --owner "$POSTGRES_USER" zeroid_testnet_20260731'
```

Update both `POSTGRES_DB` and the database component of `DATABASE_URL`, then:

```bash
docker compose up -d --build
docker compose logs --no-color migrate
docker compose ps
```

Do not remove the volume, drop the old database, run `migrate reset`, execute a
generated schema diff, or edit `_prisma_migrations`. The old database remains
available for a separately reviewed backup and baseline audit.

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

Do not restore or use `scripts/setup-test-token.mjs`. First ask the network
operator for the canonical public-testnet USDC and USDT addresses and verify
their chain ID, bytecode, decimals, and mint policy.

Only when the operator confirms that canonical test tokens do not exist, use:

```bash
node --env-file=/etc/noblepay/testnet-token-provisioning.env \
  scripts/provision-testnet-tokens.mjs \
  --validate-only \
  --checkpoint-file "$TOKEN_CHECKPOINT" \
  --manifest-file "$TOKEN_MANIFEST"
```

After review, the same command without `--validate-only` performs the
testnet-only ceremony. The script does not register tokens, mint, approve, or
modify core contracts. The resulting `SUPPORTED_TOKEN_ADDRESSES`,
`USDC_TOKEN_ADDRESS`, and `USDT_TOKEN_ADDRESS` values enter the normal
two-phase core deployment.

References:

- `noblepay/deploy/PUBLIC_TESTNET_OPERATOR_RUNBOOK.md`
- `noblepay/deploy/README.md`
- `noblepay/deploy/core-deployment.env.example`
- `noblepay/deploy/testnet-token-provisioning.env.example`

### Shiora

For the current direct-IP evaluation host, use:

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
3. Retest Cruzible without changing contracts.
4. Complete TerraQura with Node `20.18.3`.
5. Start ZeroID on the fresh database and verify the existing contract
   manifest before deciding whether a contract ceremony is required.
6. Complete NoblePay; do not provision duplicate test tokens.
7. Restart Shiora with the exact evaluation origin and retest both wallet
   choices.

Stop the affected application deployment and report evidence if:

- the checked-out commit differs from this release;
- the wallet ZIP hash differs;
- the chain ID, network anchor, or active precompile set differs;
- a deployed contract's bytecode, proxy implementation, owner, or wiring does
  not match its reviewed manifest;
- ZeroID's migration preflight exits `78`;
- a NoblePay canonical token address cannot be verified;
- a production-mode service requires an insecure-origin exception.

None of those application stop conditions requires resetting the public
testnet.
