# Aethelred Devnet Launch Pack

**Classification:** Public devnet reference  
**Network:** `aethelred-devnet-1`  
**Audience:** validators, infrastructure operators, SDK developers, dApp developers, and internal release reviewers

This launch pack is the first-stop guide for teams joining Aethelred Devnet. It is designed for a clean-room onboarding experience: a validator or developer should be able to clone the repository, run the validation gates, start the local devnet stack, and understand exactly what is expected before touching hosted infrastructure.

Devnet is a rehearsal and integration network. It is not mainnet, does not use value-bearing tokens, and intentionally allows devnet-only simulated components where the verification policy permits them.

---

## First Impression Standard

Aethelred Devnet should feel like a professional network from the first command:

| Surface | Standard |
|---|---|
| Repository entrypoint | One clear command family: `make devnet-*` |
| Genesis artifact | Deterministic, validated, and guarded by CI-ready checks |
| Operator path | No guesswork around chain ID, endpoints, keys, or health checks |
| Developer path | SDK and RPC examples work from source without registry assumptions |
| Observability | Prometheus, Grafana, logs, and health checks are named and discoverable |
| Security posture | Mainnet keys are never reused; simulated paths are explicitly devnet-only |
| Handoff package | Genesis, checksums, image tags, endpoints, runbooks, and escalation channels are published together |

---

## Network Modes

| Mode | Purpose | Command |
|---|---|---|
| Lightweight local stack | Fast SDK, UI, and verifier integration with mock RPC | `make local-testnet-up` |
| Full local devnet | Multi-service devnet cluster with validators, compute, bridge, faucet, explorer, and observability | `make devnet-up` |
| Hosted devnet | Shared external onboarding environment for invited validators and developers | Published by the release coordinator |

Use the lightweight local stack for rapid development. Use the full local devnet before validator walkthroughs, demo days, and release candidate checks.

---

## Golden Path

### 1. Validate the Devnet Package

```bash
make devnet-validate
```

This runs:

- Devnet genesis guard: `scripts/validate-devnet-genesis.py`
- Compose security guard: `scripts/validate-compose-security.sh`
- Devnet topology guard: `scripts/validate-devnet-topology.py`
- Compose syntax validation when Docker Compose is available
- Documentation presence check for this launch pack

### 2. Start the Full Devnet

```bash
make devnet-up
```

For a clean rebuild:

```bash
make devnet-clean-start
```

### 3. Check Runtime Health

```bash
make devnet-doctor
make devnet-status
make devnet-endpoints
```

### 4. Stream Logs

```bash
make devnet-logs
```

### 5. Stop the Devnet

```bash
make devnet-down
```

---

## Local Endpoints

| Service | Endpoint |
|---|---|
| JSON-RPC | `http://localhost:8545` |
| WebSocket | `ws://localhost:8546` |
| GraphQL | `http://localhost:8547/graphql` |
| Faucet | `http://localhost:8080` |
| Explorer | `http://localhost:4000` |
| Prometheus | `http://localhost:9090` |
| Grafana | `http://localhost:3000` |

Use `make devnet-endpoints` as the canonical local endpoint source. The demo dashboard runs separately on `http://localhost:5173` so it does not collide with Grafana.

Hosted devnet endpoints must be published with the release package. Do not rely on stale endpoint values from cached docs or chat messages.

---

## Validator Onboarding Packet

Every validator invite should include the following artifacts in one message or release bundle:

| Artifact | Required Content |
|---|---|
| Chain identity | Chain ID, network name, genesis time, and release tag |
| Genesis | Canonical genesis file and SHA-256 checksum |
| Node image | Registry, immutable tag, and digest |
| Peering | Seeds, persistent peers, and expected P2P port |
| Wallet | Faucet URL, token denom, and minimum self-delegation |
| Monitoring | RPC health check, Prometheus target, Grafana dashboard, and log guidance |
| Security | Key custody rules, no mainnet key reuse, and double-sign prevention |
| Support | Validator channel, emergency channel, and response expectations |

Validator operators should complete the public testnet runbook flow before joining any shared hosted environment:

- [Testnet Validator Runbook](../TESTNET_VALIDATOR_RUNBOOK.md)
- [Validator Onboarding CLI](../guides/validator-onboarding-cli.md)
- [Validator Hardware Requirements](../validator/HARDWARE_REQUIREMENTS.md)

For local devnet only, setup scripts create deterministic keys so every developer can reproduce the same sandbox. These keys are public test fixtures and must never be reused for hosted devnet, testnet, mainnet, bridge, faucet, or validator operations.

Generate the local genesis checksum with:

```bash
shasum -a 256 tools/devnet/genesis.json
```

Before publishing a hosted devnet packet, replace all placeholder validator keys, hybrid keys, attestations, and TEE measurements, then run:

```bash
make devnet-release-genesis-check
```

For any hosted devnet cohort, render the Docker Compose profile with an immutable image tag and record the resulting image digests in the handoff packet:

```bash
AETHELRED_VERSION=<release-tag> docker compose \
  -f integrations/deploy/docker/docker-compose.yml \
  config
```

Do not publish a validator packet that relies on mutable image tags, placeholder bridge or faucet keys, or simulated attestation values.

---

## Developer Onboarding Packet

Every developer invite should include:

| Artifact | Required Content |
|---|---|
| RPC profile | RPC, REST, gRPC, WebSocket, and explorer endpoints |
| Faucet | Funding instructions and rate limits |
| SDKs | Source-path install instructions until registry publishing is complete |
| Examples | One seal verification example and one job submission example |
| Limits | Devnet request limits, payload limits, and expected reset cadence |
| Support | Developer channel, issue template, and escalation path |

Start here:

- [Developer Quickstart](../DEVELOPER_QUICKSTART.md)
- [SDK Guide](../SDK_GUIDE.md)
- [REST API](../api/rest.md)
- [OpenAPI Specification](../api/openapi/README.md)

---

## Release Readiness Gates

Before opening Devnet to external validators or developers, all items below must be true.

| Gate | Command or Evidence | Required Result |
|---|---|---|
| Genesis security floor | `make devnet-validate` | Pass |
| Compose security posture | `scripts/validate-compose-security.sh` | Pass |
| Local lightweight stack | `make local-testnet-up && make local-testnet-doctor` | All expected services healthy |
| Full devnet stack | `make devnet-up && make devnet-doctor` | All expected services healthy |
| SDK packageability | `make sdk-publish-dry-run` | Pass |
| Core protocol tests | `make test-unit` | Pass |
| Rust protocol tests | `make rust-test` | Pass for changed Rust surfaces |
| Contracts smoke | `make contracts-build && make contracts-test` | Pass for changed contract surfaces |
| Public runbook walkthrough | Clean-room operator follows docs only | Pass |
| Disclosure hygiene | No unpublished launch, valuation, counterparty, or performance claims | Pass |

If a gate fails, do not onboard external operators until the failure is fixed or explicitly waived in the release notes.

---

## Security Rules

- Do not reuse mainnet, testnet, or personal validator keys on devnet.
- Do not publish mnemonic phrases, validator private keys, or faucet keys.
- Do not run two validators with the same consensus key.
- Do not treat devnet faucet tokens as having monetary value.
- Do not use devnet simulated TEE or proof paths as production evidence.
- Do not announce performance numbers unless they are backed by the performance claims register.

The verification policy defines where simulated paths are allowed:

- [Verification Policy](../security/VERIFICATION_POLICY.md)
- [Gating Plan](../security/GATING_PLAN.md)

---

## Handoff Checklist

Use this checklist before every hosted devnet cohort.

- [ ] Release branch or tag selected.
- [ ] Genesis file checksum verified.
- [ ] Node image digest recorded.
- [ ] Faucet funded and rate limits configured.
- [ ] Seed and peer list verified from a clean environment.
- [ ] Explorer and RPC endpoints pass external health checks.
- [ ] Grafana dashboard shows block production, peer count, mempool, and faucet status.
- [ ] Validator invite packet reviewed.
- [ ] Developer invite packet reviewed.
- [ ] Incident owner and escalation channel assigned.
- [ ] Known limitations documented in release notes.

---

## Ownership

| Area | Owner |
|---|---|
| Devnet release package | Release Engineering |
| Genesis and chain parameters | Protocol Engineering |
| Validator onboarding | Infrastructure Operations |
| Developer onboarding | Developer Relations |
| Security gates | Security Engineering |
| Public claims and release wording | Protocol Foundation |

The repository remains the source of truth. If a public page, message, or document conflicts with this launch pack, update the stale reference before onboarding the next cohort.
