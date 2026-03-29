# Aethelred Testnet Peer List

Chain ID: `aethelred-testnet-1`

## Seed Nodes

Add these to `seeds` in `~/.aethelred/config/config.toml`.

### US-East (Virginia)

```
seed-us-east-1: <node-id-us-east-1>@us-east-1.testnet.aethelred.io:26656
seed-us-east-2: <node-id-us-east-2>@us-east-2.testnet.aethelred.io:26656
seed-us-east-3: <node-id-us-east-3>@us-east-3.testnet.aethelred.io:26656
```

### EU-West (Frankfurt)

```
seed-eu-west-1: <node-id-eu-west-1>@eu-west-1.testnet.aethelred.io:26656
seed-eu-west-2: <node-id-eu-west-2>@eu-west-2.testnet.aethelred.io:26656
```

### AP-Southeast (Singapore)

```
seed-ap-southeast-1: <node-id-ap-southeast-1>@ap-southeast-1.testnet.aethelred.io:26656
seed-ap-southeast-2: <node-id-ap-southeast-2>@ap-southeast-2.testnet.aethelred.io:26656
```

### Combined Seeds String

Copy this directly into `config.toml`:

```toml
seeds = "<node-id-us-east-1>@us-east-1.testnet.aethelred.io:26656,<node-id-us-east-2>@us-east-2.testnet.aethelred.io:26656,<node-id-us-east-3>@us-east-3.testnet.aethelred.io:26656,<node-id-eu-west-1>@eu-west-1.testnet.aethelred.io:26656,<node-id-eu-west-2>@eu-west-2.testnet.aethelred.io:26656,<node-id-ap-southeast-1>@ap-southeast-1.testnet.aethelred.io:26656,<node-id-ap-southeast-2>@ap-southeast-2.testnet.aethelred.io:26656"
```

## RPC Endpoints

| Region | RPC URL | Status |
|--------|---------|--------|
| US-East | `https://rpc-us.testnet.aethelred.io:443` | Pending launch |
| EU-West | `https://rpc-eu.testnet.aethelred.io:443` | Pending launch |
| AP-Southeast | `https://rpc-ap.testnet.aethelred.io:443` | Pending launch |

### gRPC Endpoints

| Region | gRPC URL |
|--------|----------|
| US-East | `grpc-us.testnet.aethelred.io:9090` |
| EU-West | `grpc-eu.testnet.aethelred.io:9090` |
| AP-Southeast | `grpc-ap.testnet.aethelred.io:9090` |

### REST (LCD) Endpoints

| Region | REST URL |
|--------|----------|
| US-East | `https://lcd-us.testnet.aethelred.io:443` |
| EU-West | `https://lcd-eu.testnet.aethelred.io:443` |
| AP-Southeast | `https://lcd-ap.testnet.aethelred.io:443` |

## Adding Persistent Peers

Operators joining the testnet should add persistent peers to their `config.toml`:

```toml
persistent_peers = "<node-id>@<ip>:26656"
```

### How to find your node ID

```bash
aethelredd tendermint show-node-id
```

This returns the node ID that other operators will use to peer with you.

### Recommended config.toml settings for testnet

```toml
[p2p]
max_num_inbound_peers = 40
max_num_outbound_peers = 10
addr_book_strict = false
allow_duplicate_ip = true

[mempool]
max_txs_bytes = 1073741824
max_tx_bytes = 1048576

[consensus]
timeout_propose = "3s"
timeout_prevote = "1s"
timeout_precommit = "1s"
timeout_commit = "6s"
```

## Operator Checklist

1. Initialize node: `aethelredd init <moniker> --chain-id aethelred-testnet-1`
2. Replace `genesis.json` with the canonical testnet genesis file
3. Set `seeds` in `config.toml` using the combined seeds string above
4. Optionally add `persistent_peers` for direct peering with known validators
5. Configure firewall to allow inbound TCP on port 26656 (P2P)
6. Start the node: `aethelredd start`
7. Verify sync status: `aethelredd status | jq .sync_info`

## Submitting Your Peer Information

To add your node to the peer list, provide:

- Node ID (from `aethelredd tendermint show-node-id`)
- Public IP address and P2P port
- Region / data center location
- Moniker

Submit via the testnet coordination channel.
