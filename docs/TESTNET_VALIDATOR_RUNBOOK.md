# Aethelred Testnet Validator Runbook (v1.0)

**Network:** `aethelred-testnet-1`
**Last Updated:** 2026-03-26
**Image Tag:** `aethelred/node:testnet-v1.0.0`
**Release Branch:** `release/testnet-v1.0`
**Contact:** validators@aethelred.org | Slack: `#validators-testnet`

---

## Quick Start

```bash
# 1. Pull the testnet image
docker pull aethelred/node:testnet-v1.0.0

# 2. Initialize node
docker run --rm -v $HOME/.aethelred:/root/.aethelred \
  aethelred/node:testnet-v1.0.0 init my-validator --chain-id aethelred-testnet-1

# 3. Download and verify genesis
curl -o $HOME/.aethelred/config/genesis.json \
  https://raw.githubusercontent.com/aethelred/aethelred/release/testnet-v1.0/config/genesis/testnet-genesis.json

echo "3d1444f8aad97614323b5ddefaf85f27caf5c65cd9465a9aa4b84de8e018c36d  $HOME/.aethelred/config/genesis.json" \
  | shasum -a 256 -c -
# Must print: OK

# 4. Configure seeds and peers
sed -i'' -e 's/^seeds = .*/seeds = "seed-1@seed1.testnet.aethelred.io:26656,seed-2@seed2.testnet.aethelred.io:26656"/' \
  $HOME/.aethelred/config/config.toml

sed -i'' -e 's/^persistent_peers = .*/persistent_peers = "peer-1@peer1.testnet.aethelred.io:26656,peer-2@peer2.testnet.aethelred.io:26656,peer-3@peer3.testnet.aethelred.io:26656"/' \
  $HOME/.aethelred/config/config.toml

# 5. Start the node (sync first)
docker run -d --name aethelred-testnet \
  --restart unless-stopped \
  -p 26656:26656 -p 26657:26657 -p 1317:1317 -p 9090:9090 \
  -v $HOME/.aethelred:/root/.aethelred \
  aethelred/node:testnet-v1.0.0 start

# 6. Wait for sync, then create validator
docker exec aethelred-testnet aethelredd status | jq '.sync_info.catching_up'
# Wait until: false

# 7. Get testnet tokens from faucet
curl -X POST https://faucet.testnet.aethelred.io/api/faucet \
  -H 'Content-Type: application/json' \
  -d '{"address":"YOUR_AETHELRED_ADDRESS"}'

# 8. Create validator
docker exec aethelred-testnet aethelredd tx staking create-validator \
  --amount=10000000000000000000000utaethelel \
  --pubkey=$(docker exec aethelred-testnet aethelredd tendermint show-validator) \
  --moniker="my-validator" \
  --chain-id=aethelred-testnet-1 \
  --commission-rate="0.10" \
  --commission-max-rate="0.20" \
  --commission-max-change-rate="0.01" \
  --min-self-delegation="1000000000000000000000" \
  --from=validator \
  --gas=auto \
  --gas-adjustment=1.5 \
  --yes
```

---

## Network Details

| Parameter | Value |
|-----------|-------|
| Chain ID | `aethelred-testnet-1` |
| Token | `tAETHEL` (no monetary value) |
| Bond denom | `utaethelel` |
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
| RPC | `https://rpc.testnet.aethelred.io` (or local `http://localhost:26657`) |
| REST API | `https://api.testnet.aethelred.io` (or local `http://localhost:1317`) |
| gRPC | `grpc.testnet.aethelred.io:9090` (or local `localhost:9090`) |
| Explorer | `https://explorer.testnet.aethelred.io` |
| Faucet | `https://faucet.testnet.aethelred.io` |

## Seed Nodes

```
seed-1@seed1.testnet.aethelred.io:26656
seed-2@seed2.testnet.aethelred.io:26656
```

## Persistent Peers

```
peer-1@peer1.testnet.aethelred.io:26656
peer-2@peer2.testnet.aethelred.io:26656
peer-3@peer3.testnet.aethelred.io:26656
```

---

## Genesis Verification

Every validator MUST verify the genesis file before starting:

```bash
shasum -a 256 $HOME/.aethelred/config/genesis.json
# Expected: 3d1444f8aad97614323b5ddefaf85f27caf5c65cd9465a9aa4b84de8e018c36d
```

If the checksum does not match, **do not start the node**. Contact `#validators-testnet` on Slack.

---

## Hardware Requirements (Testnet)

Testnet requirements are lower than mainnet:

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 4 cores | 8+ cores |
| RAM | 16 GB | 32 GB |
| Storage | 200 GB SSD | 500 GB NVMe |
| Network | 100 Mbps | 1 Gbps |
| HSM | Not required | Optional |

**Note:** HSM is not required for testnet. Software keys are acceptable.

---

## Monitoring

### Check Node Status

```bash
# Sync status
docker exec aethelred-testnet aethelredd status | jq '.sync_info'

# Validator signing
docker exec aethelred-testnet aethelredd query staking validator \
  $(docker exec aethelred-testnet aethelredd keys show validator -a --bech val)

# View logs
docker logs -f --tail 100 aethelred-testnet

# Check peers
docker exec aethelred-testnet aethelredd query tendermint-validator-set
```

### Prometheus Metrics

If you want to monitor with Prometheus, enable telemetry in `config.toml`:

```toml
[telemetry]
enabled = true
prometheus_listen_addr = "0.0.0.0:26660"
```

Then add to your Prometheus scrape config:

```yaml
- job_name: 'aethelred-testnet'
  static_configs:
    - targets: ['localhost:26660']
```

---

## Unjailing After Downtime

If your validator is jailed for downtime:

```bash
# Check jail status
docker exec aethelred-testnet aethelredd query staking validator $VAL_ADDR | jq '.jailed'

# Unjail (after jail period expires — 5 minutes on testnet)
docker exec aethelred-testnet aethelredd tx slashing unjail \
  --from validator --chain-id aethelred-testnet-1 --gas auto --yes
```

---

## Upgrading

When a new testnet image is released:

```bash
# 1. Stop current node
docker stop aethelred-testnet

# 2. Pull new image
docker pull aethelred/node:testnet-v1.0.1  # or whatever the new tag is

# 3. Remove old container (data persists in volume)
docker rm aethelred-testnet

# 4. Start with new image
docker run -d --name aethelred-testnet \
  --restart unless-stopped \
  -p 26656:26656 -p 26657:26657 -p 1317:1317 -p 9090:9090 \
  -v $HOME/.aethelred:/root/.aethelred \
  aethelred/node:testnet-v1.0.1 start
```

---

## Testnet vs Mainnet

| | Testnet | Mainnet |
|---|---------|---------|
| Tokens have value | No | Yes |
| HSM required | No | Yes |
| Sentry nodes required | No | Yes (2+) |
| Failover node required | No | Yes |
| Min stake | 1,000 tAETHEL | 100,000 AETHEL |
| Unbonding | 1 day | 21 days |
| Uptime requirement | 80% | 95% |
| Simulated proofs | Allowed | Forbidden |
| Compliance | Disabled | Enabled |

---

## Troubleshooting

### Node Won't Sync

1. Check you have the correct genesis: verify checksum
2. Check seed/peer connectivity: `curl http://localhost:26657/net_info | jq '.result.n_peers'`
3. Check firewall: port 26656 must be open for P2P
4. Try resetting: `docker exec aethelred-testnet aethelredd tendermint unsafe-reset-all` (loses state)

### Transaction Fails

1. Check balance: `docker exec aethelred-testnet aethelredd query bank balances $ADDR`
2. If zero, use faucet: `curl -X POST https://faucet.testnet.aethelred.io/api/faucet -d '{"address":"$ADDR"}'`
3. Check gas: add `--gas auto --gas-adjustment 1.5`

### Validator Not Signing

1. Check if jailed: `aethelredd query staking validator $VAL_ADDR | jq '.jailed'`
2. Check if in active set: `aethelredd query tendermint-validator-set | grep $CONS_ADDR`
3. Check connectivity: `aethelredd status | jq '.sync_info.catching_up'`

---

## Escalation Contacts

| Issue | Contact | Response Time |
|-------|---------|---------------|
| General questions | Slack `#validators-testnet` | Best effort |
| Node issues | validators@aethelred.org | < 4 hours |
| Security concerns | security@aethelred.org | < 1 hour |
| Urgent (chain halt) | Slack `#validators-emergency` | < 15 min |

---

## Document History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-03-26 | Initial testnet runbook for `aethelred-testnet-1` |
