# Aethelred Docker Profiles

These files package the Aethelred node and the TEE/zkML HTTP adapters. They do
not generate validator material, a production genesis, a real enclave backend,
or a real proving backend.

The nonexistent Explorer Dockerfile and image-only Faucet have been removed.
Grafana was also removed because the repository has no datasource or dashboard
provisioning for it. Prometheus is retained only for the real CometBFT metrics
endpoint enabled on the node; the TEE and zkML adapters do not expose
`/metrics` and are intentionally not scraped.

## Production prerequisites

Before running `docker-compose.yml`:

1. Prepare a node home on the host. It must contain the intended
   `config/genesis.json`, `config/config.toml`, `config/app.toml`,
   `config/priv_validator_key.json`, node key, and matching validator state.
   The genesis must already contain the funded validator set. The directory
   must be writable by the container. Compose uses
   `bind.create_host_path: false`, so a typo cannot silently create an empty
   validator home.
2. Confirm that `AETHELRED_CHAIN_ID` exactly matches the chain ID in that
   genesis. Compose does not create or rewrite genesis.
3. Deploy real TEE and zkML backend services. Their base URLs are supplied as
   `AETHELRED_TEE_BACKEND_URL` and `AETHELRED_ZKML_BACKEND_URL`.
4. Terminate TLS in a local reverse proxy in front of
   `127.0.0.1:8545` (TEE) and `127.0.0.1:8546` (zkML). Configure public DNS and
   certificates for the three URLs consumed by the node:
   `AETHELRED_TEE_ENDPOINT`,
   `AETHELRED_ATTESTATION_VERIFIER_ENDPOINT`, and
   `AETHELRED_PROVER_ENDPOINT`.
5. Use public `https://` URLs. The node and adapters deliberately reject plain
   HTTP outside explicit localhost, Docker service names, private addresses,
   loopback addresses, link-local addresses, and cloud metadata destinations.
   Do not weaken that SSRF protection to make `http://tee-worker:8545` work.
6. Generate four independent strong bearer tokens: one inbound token for each
   public adapter and one outbound token for each real backend. The reverse
   proxy must preserve the node-to-adapter `Authorization` header. The adapters
   deliberately replace it with the corresponding backend token instead of
   forwarding caller credentials. Each real backend must expose an authenticated
   `GET /health` endpoint; adapter readiness fails when that probe is unreachable
   or non-2xx. Supply all secrets from the deployment secret manager; do not
   commit them to this directory. Environment-backed secrets remain visible
   through container inspection, so restrict Docker daemon access and rotate
   the tokens.

Example environment:

```bash
export AETHELRED_NODE_HOME=/srv/aethelred/validator
export AETHELRED_CHAIN_ID=aethelred-testnet-1
export AETHELRED_MONIKER=validator-uae-1

export AETHELRED_TEE_ENDPOINT=https://tee.example.net
export AETHELRED_ATTESTATION_VERIFIER_ENDPOINT=https://tee.example.net
export AETHELRED_PROVER_ENDPOINT=https://prover.example.net

export AETHELRED_TEE_BACKEND_URL=https://real-tee-backend.example.net
export AETHELRED_ZKML_BACKEND_URL=https://real-zkml-backend.example.net

export AETHELRED_TEE_API_TOKEN="$(openssl rand -hex 32)"
export AETHELRED_ZKML_API_TOKEN="$(openssl rand -hex 32)"
export AETHELRED_TEE_BACKEND_API_TOKEN="$(openssl rand -hex 32)"
export AETHELRED_ZKML_BACKEND_API_TOKEN="$(openssl rand -hex 32)"
```

Start only after all prerequisites are satisfied:

```bash
docker compose -f integrations/docker/docker-compose.yml config --quiet
docker compose -f integrations/docker/docker-compose.yml up -d --build
```

Production execution fails closed when either real backend URL or any of the
four API tokens is missing. The node is explicitly configured in `remote` TEE
mode and receives only the two adapter-facing tokens; backend credentials stay
inside their respective adapters.

## Development initialization

The development profile enables `nitro-simulated` in the node, mock TEE
execution, and simulated zkML proofs. It still does not turn an empty directory
into a chain that produces blocks.

Choose an absolute host directory, initialize the base files once, and then
install a valid development genesis/validator set before `up`:

```bash
export AETHELRED_DEV_NODE_HOME=/absolute/path/to/aethelred-dev-node
export AETHELRED_DEV_CHAIN_ID=aethelred-local
export AETHELRED_DEV_MONIKER=local-validator

mkdir -p "$AETHELRED_DEV_NODE_HOME"
docker compose -f integrations/docker/docker-compose.dev.yml run --rm \
  aethelred-node init "$AETHELRED_DEV_MONIKER" \
  --chain-id "$AETHELRED_DEV_CHAIN_ID" \
  --home /root/.aethelred
```

`aethelredd init` creates configuration and private-validator files, but its
initial genesis does not create a funded validator set. Replace or amend
`$AETHELRED_DEV_NODE_HOME/config/genesis.json` with the team-approved
development genesis and ensure its validator public keys match the mounted
private-validator material. Starting sooner may launch a process, but it will
not produce a usable chain.

Then start the profile:

```bash
docker compose -f integrations/docker/docker-compose.dev.yml up -d --build
```

The development-only default bearer values are intentionally predictable.
Override `AETHELRED_TEE_API_TOKEN` and `AETHELRED_ZKML_API_TOKEN` whenever the
host is shared.

## Network exposure

| Service | Host binding | Notes |
|---|---:|---|
| Node P2P | `0.0.0.0:26656` | Public peer traffic |
| Node RPC | `127.0.0.1:26657` | Local proxy or SSH tunnel only |
| Node REST and gRPC-Web | `127.0.0.1:1317` | Local proxy or SSH tunnel only |
| Node gRPC | `127.0.0.1:9090` | Local proxy or SSH tunnel only |
| TEE adapter | `127.0.0.1:8545` | Put behind TLS; bearer required remotely |
| zkML adapter | `127.0.0.1:8546` | Put behind TLS; bearer required remotely |
| Prometheus | `127.0.0.1:9092` | CometBFT node metrics only |

CometBFT metrics are enabled through
`AETHELREDD_INSTRUMENTATION_PROMETHEUS=true` and bound to
`0.0.0.0:26660` inside the Compose network. Confirm the target is `UP` at
`http://127.0.0.1:9092/targets`; do not treat the deployment as monitored if
that target is down.

## Smoke checks

```bash
curl -fsS http://127.0.0.1:26657/status
curl -fsS http://127.0.0.1:8545/health \
  -H "Authorization: Bearer ${AETHELRED_TEE_API_TOKEN}"
curl -fsS http://127.0.0.1:8546/health \
  -H "Authorization: Bearer ${AETHELRED_ZKML_API_TOKEN}"
curl -fsS http://127.0.0.1:9092/-/ready
```
