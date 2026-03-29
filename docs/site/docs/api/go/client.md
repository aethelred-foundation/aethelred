# Client API

## Package `client`

The `client` package provides the main Aethelred SDK client for blockchain interaction, including network selection, seal operations, job submission, and node queries.

```go
import "github.com/aethelred/sdk-go/client"
```

---

### Network Constants

| Network   | Chain ID                | RPC Endpoint                          |
|-----------|-------------------------|---------------------------------------|
| `Mainnet` | `aethelred-1`           | `https://rpc.mainnet.aethelred.org`   |
| `Testnet` | `aethelred-testnet-1`   | `https://rpc.testnet.aethelred.org`   |
| `Devnet`  | `aethelred-devnet-1`    | `https://rpc.devnet.aethelred.org`    |
| `Local`   | `aethelred-local`       | `http://127.0.0.1:26657`             |

---

### Constructor

#### `NewClient(network Network, opts ...Option) (*Client, error)`

Creates a new client connected to the specified network with functional options.

```go
c, err := client.NewClient(client.Testnet,
    client.WithAPIKey("aeth_key_abc123"),
    client.WithTimeout(15 * time.Second),
)
if err != nil {
    log.Fatal(err)
}
```

| Parameter | Type        | Description                       |
|-----------|-------------|-----------------------------------|
| `network` | `Network`   | Target network (`Mainnet`, etc.)  |
| `opts`    | `...Option` | Functional configuration options  |

---

### Options

#### `WithAPIKey(apiKey string) Option`

Sets the `X-API-Key` header on all outbound requests.

#### `WithTimeout(timeout time.Duration) Option`

Sets the HTTP client timeout. Default is `30s`.

#### `WithRPCURL(url string) Option`

Overrides the default RPC URL for the selected network.

#### `WithHTTPClient(httpClient *http.Client) Option`

Injects a fully configured `*http.Client`, bypassing internal transport setup.

#### `WithConnectionPool(pool ConnectionPoolConfig) Option`

Configures HTTP connection pooling parameters.

```go
c, _ := client.NewClient(client.Mainnet,
    client.WithConnectionPool(client.ConnectionPoolConfig{
        MaxIdleConns:        100,
        MaxIdleConnsPerHost: 10,
        IdleConnTimeout:     90 * time.Second,
    }),
)
```

#### `WithTransport(transport Transport) Option`

Sets a custom pluggable transport (e.g., gRPC-backed).

#### `WithGRPCTransport(transport Transport) Option`

Alias for `WithTransport` for semantic clarity when using gRPC.

---

### Client Methods

#### `(*Client) Get(ctx context.Context, path string, result interface{}) error`

Performs a GET request against the node RPC. Deserializes JSON into `result`.

#### `(*Client) Post(ctx context.Context, path string, body, result interface{}) error`

Performs a POST request. Marshals `body` to JSON and deserializes the response.

#### `(*Client) GetNodeInfo(ctx context.Context) (*types.NodeInfo, error)`

Returns metadata about the connected node (moniker, network, version).

```go
info, err := c.GetNodeInfo(context.Background())
fmt.Println(info.Moniker, info.Version)
```

#### `(*Client) HealthCheck(ctx context.Context) bool`

Returns `true` if the node responds to a node-info query without error.

#### `(*Client) RPCURL() string`

Returns the resolved RPC URL.

#### `(*Client) ChainID() string`

Returns the resolved chain ID.

---

### Sub-modules

The client exposes domain-specific modules as struct fields:

| Field          | Type                  | Description                        |
|----------------|-----------------------|------------------------------------|
| `Jobs`         | `*jobs.Module`        | Submit and query compute jobs      |
| `Seals`        | `*seals.Module`       | Create, verify, and revoke seals   |
| `Models`       | `*models.Module`      | Register and query models          |
| `Validators`   | `*validators.Module`  | Query validator stats              |
| `Verification` | `*verification.Module`| Verify proofs and attestations     |

#### Seal operations example

```go
resp, err := c.Seals.Create(ctx, seals.CreateRequest{
    JobID: "job-abc-123",
})
fmt.Println("Seal ID:", resp.SealID)

result, _ := c.Seals.Verify(ctx, resp.SealID)
fmt.Println("Valid:", result.Valid)
```

---

### Types

#### `Config`

```go
type Config struct {
    Network         Network
    RPCURL          string
    ChainID         string
    APIKey          string
    Timeout         time.Duration
    MaxRetries      int
    HTTPClient      *http.Client
    ConnectionPool  *ConnectionPoolConfig
    CustomTransport Transport
}
```

#### `Transport` interface

```go
type Transport interface {
    Do(ctx context.Context, req *TransportRequest) (*TransportResponse, error)
}
```

---

### Related packages

- [runtime](/api/go/runtime) -- Device management and memory pools
- [tensor](/api/go/tensor) -- Tensor operations for model I/O
- [crypto](/api/go/crypto) -- Hashing and key management
