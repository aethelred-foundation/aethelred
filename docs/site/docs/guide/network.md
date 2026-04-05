# Connecting to Network

Aethelred operates multiple networks for different stages of development and deployment. This page covers how to configure your SDK to connect to each network, manage RPC endpoints, and handle failover.

## Available Networks

| Network | Chain ID | Purpose | RPC Endpoint |
|---|---|---|---|
| **Mainnet** | `aethelred-mainnet-1` | Production | `https://rpc.mainnet.aethelred.io` |
| **Testnet** | `aethelred-testnet-1` | Pre-production testing | `https://rpc.testnet.aethelred.io` |
| **Devnet** | `aethelred-devnet` | Development and experimentation | `https://rpc.devnet.aethelred.io` |
| **Local** | `aethelred-local` | Local single-node development | `http://localhost:26657` |

### Additional Endpoints

| Protocol | Port | Description |
|---|---|---|
| JSON-RPC | 26657 | Tendermint RPC (queries, broadcast) |
| gRPC | 9090 | Cosmos SDK gRPC (queries, simulate) |
| REST (LCD) | 1317 | Legacy REST API |
| WebSocket | 26657/websocket | Real-time event subscription |

## Connecting

### Go

```go
import aethelred "github.com/aethelred/sdk-go"

// Simple connection
client, err := aethelred.NewClient(
    aethelred.WithEndpoint("https://rpc.testnet.aethelred.io"),
)

// With full configuration
client, err := aethelred.NewClient(
    aethelred.WithEndpoint("https://rpc.mainnet.aethelred.io"),
    aethelred.WithGRPCEndpoint("grpc.mainnet.aethelred.io:9090"),
    aethelred.WithChainID("aethelred-mainnet-1"),
    aethelred.WithTimeout(15 * time.Second),
    aethelred.WithKeyring(keyring),
    aethelred.WithRetryPolicy(aethelred.RetryPolicy{
        MaxRetries:   3,
        InitialDelay: 100 * time.Millisecond,
        MaxDelay:     5 * time.Second,
    }),
)
```

### Rust

```rust
use aethelred::client::{Client, ClientConfig};

let client = Client::new(ClientConfig {
    rpc_endpoint: "https://rpc.testnet.aethelred.io".into(),
    grpc_endpoint: Some("grpc.testnet.aethelred.io:9090".into()),
    chain_id: "aethelred-testnet-1".into(),
    timeout: Duration::from_secs(15),
    ..Default::default()
}).await?;
```

### TypeScript

```typescript
import { Client } from '@aethelred/sdk';

const client = await Client.connect({
  rpcEndpoint: 'https://rpc.testnet.aethelred.io',
  chainId: 'aethelred-testnet-1',
  timeout: 15_000,
});
```

### Python

```python
import aethelred

client = aethelred.Client(
    rpc_endpoint="https://rpc.testnet.aethelred.io",
    chain_id="aethelred-testnet-1",
)
```

## Environment Variables

All SDKs respect the following environment variables as defaults:

| Variable | Description | Example |
|---|---|---|
| `AETHELRED_RPC_URL` | Primary RPC endpoint | `https://rpc.mainnet.aethelred.io` |
| `AETHELRED_GRPC_URL` | gRPC endpoint | `grpc.mainnet.aethelred.io:9090` |
| `AETHELRED_CHAIN_ID` | Chain identifier | `aethelred-mainnet-1` |
| `AETHELRED_KEYRING_BACKEND` | Keyring backend | `file`, `os`, `test` |
| `AETHELRED_KEYRING_DIR` | Keyring directory | `~/.aethelred/keyring` |
| `AETHELRED_GAS_PRICES` | Default gas prices | `0.025uaeth` |

## Multi-Endpoint Failover

For production deployments, configure multiple endpoints for automatic failover:

```go
client, err := aethelred.NewClient(
    aethelred.WithEndpoints([]string{
        "https://rpc1.mainnet.aethelred.io",
        "https://rpc2.mainnet.aethelred.io",
        "https://rpc3.mainnet.aethelred.io",
    }),
    aethelred.WithLoadBalancing(aethelred.RoundRobin),
    aethelred.WithHealthCheckInterval(30 * time.Second),
)
```

## Querying Network Status

```go
status, err := client.Status(ctx)
fmt.Printf("Network:       %s\n", status.NodeInfo.Network)
fmt.Printf("Latest block:  %d\n", status.SyncInfo.LatestBlockHeight)
fmt.Printf("Latest time:   %s\n", status.SyncInfo.LatestBlockTime)
fmt.Printf("Catching up:   %v\n", status.SyncInfo.CatchingUp)
fmt.Printf("Voting power:  %d\n", status.ValidatorInfo.VotingPower)
```

## Local Development

Start a local single-node network for development:

```bash
# Using Docker
docker run -p 26657:26657 -p 9090:9090 -p 1317:1317 \
  aethelred/node:latest init-and-start

# Using the CLI
aethelred node init --chain-id aethelred-local
aethelred node start
```

The local node comes pre-funded with test accounts:

```bash
aethelred keys list --keyring-backend test
# NAME     ADDRESS
# alice    aeth1qypqxpq9qcrsszg2pvxq6rs0zqg3yyc5lzv7u
# bob      aeth1z7tu6csdge3nkdq9ljsxkhzm54ynclr4w8z0d
```

## WebSocket Subscriptions

Subscribe to real-time events:

```go
sub, err := client.Subscribe(ctx, "tm.event='NewBlock'")
for event := range sub.Events() {
    block := event.Data.(types.EventDataNewBlock)
    fmt.Printf("New block: %d\n", block.Block.Height)
}
```

## Related Pages

- [Installation](/guide/installation) -- install SDKs before connecting
- [CLI Configuration](/cli/configuration) -- configure network via CLI
- [Submitting Jobs](/guide/jobs) -- send compute jobs to the network
- [Validators](/guide/validators) -- run a validator node
