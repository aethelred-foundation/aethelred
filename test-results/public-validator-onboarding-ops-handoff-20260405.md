# Public Validator Onboarding Ops Handoff

Date: 2026-04-05
Scope: external operator readiness for `aethelred-testnet-1`

## Repo-Side Fixes Included

This branch standardizes the validator image source of truth to:

```text
ghcr.io/aethelred-foundation/aethelred/aethelredd
```

It also updates:

- release image publishing workflow
- Docker build workflow
- validator runbooks
- release candidate checklist
- Helm and Docker deployment defaults
- local and verification-stack compose files

## External Actions Still Required

### 1. Cut and publish the testnet image tag

The release workflow now supports:

- `testnet-v*.*.*`
- `mainnet-v*.*.*`
- `v*.*.*`

Required action:

1. Create the public testnet release tag from the frozen release branch:
   - `testnet-v1.0.0`
2. Confirm GitHub Actions publishes:
   - `ghcr.io/aethelred-foundation/aethelred/aethelredd:testnet-v1.0.0`
   - `ghcr.io/aethelred-foundation/aethelred/aethelredd:latest`

### 2. Make the GHCR package public

External validators must be able to run:

```bash
docker pull ghcr.io/aethelred-foundation/aethelred/aethelredd:testnet-v1.0.0
```

Required action:

1. Open the container package settings in GitHub Packages.
2. Set package visibility to `public`.
3. Re-test anonymous pull from a machine that is not authenticated to GHCR.

### 3. Publish public DNS

The following published hostnames must resolve publicly:

- `rpc.testnet.aethelred.io`
- `api.testnet.aethelred.io`
- `grpc.testnet.aethelred.io`
- `explorer.testnet.aethelred.io`
- `faucet.testnet.aethelred.io`
- `seed1.testnet.aethelred.io`
- `seed2.testnet.aethelred.io`
- `peer1.testnet.aethelred.io`
- `peer2.testnet.aethelred.io`
- `peer3.testnet.aethelred.io`

Required action:

1. Create or correct the DNS records in the external DNS provider.
2. Confirm public resolution from an unauthenticated machine.
3. Confirm the RPC, explorer, and faucet endpoints answer health or HTTP requests.

## Exit Criteria

Do not announce public validator onboarding until all three are true:

1. Anonymous `docker pull` for the published validator image succeeds.
2. Public DNS resolves for RPC, explorer, faucet, seeds, and peers.
3. The clean-room validator walkthrough passes from docs only.
