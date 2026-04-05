# Aethelred Testnet Validator Runbook (v1.1)

**Network:** `aethelred-testnet-1`
**Last Updated:** 2026-04-05
**Image Tag:** `aethelred/node:testnet-v1.0.0`
**Release Branch:** `release/testnet-v1.0`
**Primary Contact:** `validators@aethelred.io`
**Operator Channels:** Slack `#validators-testnet`, Slack `#validators-emergency`

This is the canonical operator runbook for onboarding a validator to the Aethelred public testnet. If you are building against the protocol rather than operating infrastructure, start with [DEVELOPER_QUICKSTART.md](./DEVELOPER_QUICKSTART.md). If you are reviewing the planned production posture, use [VALIDATOR_RUNBOOK.md](./VALIDATOR_RUNBOOK.md) and the public validators guide.

---

## Happy Path

1. Pull the published testnet image.
2. Initialize the node with `aethelred-testnet-1`.
3. Download the testnet genesis and verify the checksum.
4. Configure seeds and persistent peers.
5. Start the node and wait until `catching_up` is `false`.
6. Fund the operator wallet from the faucet.
7. Submit the `create-validator` transaction with the required self-delegation.
8. Confirm the validator appears in the active set and keep telemetry on.

If any step diverges from that flow, stop and use the troubleshooting section before broadcasting additional transactions.

## Quick Start

```bash
# 1. Pull the testnet image
docker pull aethelred/node:testnet-v1.0.0

# 2. Initialize node home
mkdir -p $HOME/.aethelred
docker run --rm -v $HOME/.aethelred:/root/.aethelred \
  aethelred/node:testnet-v1.0.0 init my-validator --chain-id aethelred-testnet-1

# 3. Download and verify genesis
curl -fsSL \
  https://raw.githubusercontent.com/aethelred-foundation/aethelred/release/testnet-v1.0/config/genesis/testnet-genesis.json \
  -o $HOME/.aethelred/config/genesis.json

echo "fa276d9f9f9c5d2c50e17c88fb820b8e8ac500b8acb0ae1c1b9e0637c080b3a6  $HOME/.aethelred/config/genesis.json" \
  | shasum -a 256 -c -
# Must print: OK

# 4. Configure seeds and peers
sed -i'' -e 's/^seeds = .*/seeds = "seed-1@seed1.testnet.aethelred.io:26656,seed-2@seed2.testnet.aethelred.io:26656"/' \
  $HOME/.aethelred/config/config.toml

sed -i'' -e 's/^persistent_peers = .*/persistent_peers = "peer-1@peer1.testnet.aethelred.io:26656,peer-2@peer2.testnet.aethelred.io:26656,peer-3@peer3.testnet.aethelred.io:26656"/' \
  $HOME/.aethelred/config/config.toml

# 5. Start the node and let it sync
docker run -d --name aethelred-testnet \
  --restart unless-stopped \
  -p 26656:26656 -p 26657:26657 -p 1317:1317 -p 9090:9090 \
  -v $HOME/.aethelred:/root/.aethelred \
  aethelred/node:testnet-v1.0.0 start

docker exec aethelred-testnet aethelredd status | jq '.sync_info.catching_up'
# Wait until: false

# 6. Request faucet funds
curl -X POST https://faucet.testnet.aethelred.io/api/faucet \
  -H 'Content-Type: application/json' \
  -d '{"address":"YOUR_AETHELRED_ADDRESS"}'

# 7. Create validator
docker exec aethelred-testnet aethelredd tx staking create-validator \
  --amount=1000000000uaethel \
  --pubkey=$(docker exec aethelred-testnet aethelredd tendermint show-validator) \
  --moniker="my-validator" \
  --chain-id=aethelred-testnet-1 \
  --commission-rate="0.10" \
  --commission-max-rate="0.20" \
  --commission-max-change-rate="0.01" \
  --min-self-delegation="1000000000" \
  --from=validator \
  --gas=auto \
  --gas-adjustment=1.5 \
  --yes
```

## Network Details

| Parameter | Value |
|-----------|-------|
| Chain ID | `aethelred-testnet-1` |
| Token | `tAETHEL` (test token, no monetary value) |
| Bond denom | `uaethel` |
| Block time | 6 seconds |
| Min validator stake | 1,000 tAETHEL |
| Unbonding period | 1 day |
| Active validator set | 50 |
| Min uptime | 80% |
| Downtime slash | 0.5% |
| Double-sign slash | 50% |
| Simulated verification | Allowed (`allow_simulated: true`) |

## Endpoints

| Service | URL |
|---------|-----|
| RPC | `https://rpc.testnet.aethelred.io` or local `http://localhost:26657` |
| REST API | `https://api.testnet.aethelred.io` or local `http://localhost:1317` |
| gRPC | `grpc.testnet.aethelred.io:9090` or local `localhost:9090` |
| Explorer | `https://explorer.testnet.aethelred.io` |
| Faucet | `https://faucet.testnet.aethelred.io` |

## Seed Nodes

```text
seed-1@seed1.testnet.aethelred.io:26656
seed-2@seed2.testnet.aethelred.io:26656
```

## Persistent Peers

```text
peer-1@peer1.testnet.aethelred.io:26656
peer-2@peer2.testnet.aethelred.io:26656
peer-3@peer3.testnet.aethelred.io:26656
```

## Genesis Verification

Every validator must verify the genesis file before starting:

```bash
shasum -a 256 $HOME/.aethelred/config/genesis.json
# Expected: fa276d9f9f9c5d2c50e17c88fb820b8e8ac500b8acb0ae1c1b9e0637c080b3a6
```

If the checksum does not match, do not start the node. Escalate in Slack `#validators-testnet`.

## Hardware Requirements (Testnet)

Testnet requirements are intentionally lighter than the planned mainnet profile:

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 4 cores | 8+ cores |
| RAM | 16 GB | 32 GB |
| Storage | 200 GB SSD | 500 GB NVMe |
| Network | 100 Mbps | 1 Gbps |
| HSM | Not required | Optional |

Software keys are acceptable on testnet. Mainnet custody and HSM requirements are tracked separately.

## Monitoring

### Check Node Status

```bash
# Sync status
docker exec aethelred-testnet aethelredd status | jq '.sync_info'

# Validator state
docker exec aethelred-testnet aethelredd query staking validator \
  $(docker exec aethelred-testnet aethelredd keys show validator -a --bech val)

# Logs
docker logs -f --tail 100 aethelred-testnet

# Connected peers
docker exec aethelred-testnet aethelredd query tendermint-validator-set
```

### Prometheus Metrics

If you want local Prometheus scraping, enable telemetry in `config.toml`:

```toml
[telemetry]
enabled = true
prometheus_listen_addr = "0.0.0.0:26660"
```

Then add:

```yaml
- job_name: 'aethelred-testnet'
  static_configs:
    - targets: ['localhost:26660']
```

## Unjailing After Downtime

If your validator is jailed for downtime:

```bash
# Check jail status
docker exec aethelred-testnet aethelredd query staking validator $VAL_ADDR | jq '.jailed'

# Unjail after the jail period expires (5 minutes on testnet)
docker exec aethelred-testnet aethelredd tx slashing unjail \
  --from validator \
  --chain-id aethelred-testnet-1 \
  --gas auto \
  --yes
```

## Upgrading

When a new testnet image is announced:

```bash
# 1. Stop current node
docker stop aethelred-testnet

# 2. Pull the new image
docker pull aethelred/node:testnet-v1.0.1

# 3. Remove old container (the data remains under $HOME/.aethelred)
docker rm aethelred-testnet

# 4. Start again with the new tag
docker run -d --name aethelred-testnet \
  --restart unless-stopped \
  -p 26656:26656 -p 26657:26657 -p 1317:1317 -p 9090:9090 \
  -v $HOME/.aethelred:/root/.aethelred \
  aethelred/node:testnet-v1.0.1 start
```

## Testnet vs Mainnet

| Topic | Testnet | Mainnet |
|-------|---------|---------|
| Tokens have value | No | Yes |
| HSM required | No | Yes |
| Sentry nodes required | No | Yes (2+) |
| Failover node required | No | Yes |
| Min stake | 1,000 tAETHEL | 100,000 AETHEL |
| Unbonding | 1 day | 21 days |
| Uptime requirement | 80% | 95% |
| Simulated proofs | Allowed | Forbidden |
| Compliance controls | Relaxed | Enforced |

## Troubleshooting

### Node Won't Sync

1. Verify the genesis checksum.
2. Check peer connectivity: `curl http://localhost:26657/net_info | jq '.result.n_peers'`
3. Confirm that port `26656` is reachable through your firewall.
4. As a last resort, reset state: `docker exec aethelred-testnet aethelredd tendermint unsafe-reset-all`

### Transaction Fails

1. Check balance: `docker exec aethelred-testnet aethelredd query bank balances $ADDR`
2. If balance is zero, fund from the faucet:
   `curl -X POST https://faucet.testnet.aethelred.io/api/faucet -d '{"address":"$ADDR"}'`
3. Re-run with `--gas auto --gas-adjustment 1.5`.

### Validator Not Signing

1. Check jail state: `aethelredd query staking validator $VAL_ADDR | jq '.jailed'`
2. Check active set membership: `aethelredd query tendermint-validator-set | grep $CONS_ADDR`
3. Check sync state: `aethelredd status | jq '.sync_info.catching_up'`

## Escalation Contacts

| Issue | Contact | Response Time |
|-------|---------|---------------|
| General questions | Slack `#validators-testnet` | Best effort |
| Node issues | `validators@aethelred.io` | < 4 hours |
| Security concerns | `security@aethelred.org` | < 1 hour |
| Urgent chain issues | Slack `#validators-emergency` | < 15 min |

## Document History

| Version | Date | Changes |
|---------|------|---------|
| 1.1 | 2026-04-05 | Clarified operator happy path, refreshed contacts, and aligned public testnet onboarding guidance |
| 1.0 | 2026-03-26 | Initial testnet runbook for `aethelred-testnet-1` |
