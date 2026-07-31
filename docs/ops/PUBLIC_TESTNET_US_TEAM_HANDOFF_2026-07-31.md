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
`public-testnet-application-bundle-2026-07-31.1`. From this point, do not
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
commit: c33d4c05120ba98449aad8f9ac820df2ad701955
Node: 24.18.0
pnpm: 11.9.0

Cruzible
branch: fix/us-testnet-wallet-staking
commit: 7df3998ae1a09d149eec9f005b6cf4146851acb1
action: keep the working contract addresses; do not redeploy

TerraQura
branch: ramesh/terraqura-pre-mainnet-remediation-20260414
commit: 0f84a3f0c820afed6bcf2af50dd1c258481d3fe4
Node: 20.18.3
pnpm: 9.0.0

ZeroID
branch: release/zeroid-production-hardening
commit: 709beb25493b30093f5bd637824c0e1fcd2ed3ec
Node: 20.19.5
npm: 10.8.2

NoblePay
branch: release/noblepay-production-readiness
commit: 2f6d71ac1fe6d1f787534d7fe5234c3646aabab1
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
https://github.com/aethelred-foundation/wallet/releases/download/public-testnet-wallet-v0.9.0-20260731/aethelred-wallet-v0.9.0.zip
SHA-256: a7d4314b4b484c44de89404a5a539a593c06ea782851145772e8e141d2cad90e
size: 752236 bytes
```

Verify the hash before loading the unpacked extension. If endpoint protection
still flags the ZIP, do not disable or bypass protection. Build it locally
from the exact wallet commit and submit the hash for security-vendor review.

Then proceed in this order:

1. Cruzible: keep the current contracts. With the new wallet installed, retest
   Aethelred Wallet connection, stake, unstake, transaction confirmation, and
   receipts. Stake and unstake have already succeeded with MetaMask, so a
   contract redeploy is not approved unless bytecode or wiring verification
   fails.
2. TerraQura: switch from Node 25 to exactly Node `20.18.3`, install with the
   frozen lockfile, then run `pnpm contracts:preflight`,
   `pnpm contracts:bootstrap`, `pnpm contracts:finalize`, and
   `pnpm contracts:verify` using the confirmation variables and sequence in
   `docs/deployment/PUBLIC_TESTNET_DEPLOYMENT.md`. Do not reuse an old
   deployment manifest or removed script.
3. ZeroID: the wallet-provider issue is handled by the wallet release. For
   Prisma `P3005`, keep the existing PostgreSQL volume and old database, create
   a new database named `zeroid_testnet_20260731`, update `POSTGRES_DB` and
   `DATABASE_URL`, then start the one-shot `migrate` service and API. Do not
   drop the old database, remove the volume, run `migrate reset`, or edit
   `_prisma_migrations`. Reuse contract addresses only after the manifest,
   chain ID, bytecode, owner, and wiring verify.
4. NoblePay: follow
   `deploy/PUBLIC_TESTNET_OPERATOR_RUNBOOK.md`. Do not use or restore
   `scripts/setup-test-token.mjs`. First obtain and verify the canonical
   public-testnet USDC and USDT addresses. Run
   `scripts/provision-testnet-tokens.mjs` only if the network operator confirms
   that canonical test tokens do not exist.
5. Shiora: rebuild and restart the application at commit
   `2dd1255715a373beb691ab4bbcaecf787dcb8c09`. For the current synthetic
   direct-IP evaluation, set:

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

Do not redeploy a verified Shiora attestation contract. Retest both Aethelred
Wallet and MetaMask; the modal clipping and exact-origin handling are fixed in
this release.

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
