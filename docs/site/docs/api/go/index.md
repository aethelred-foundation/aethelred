# Go SDK API Reference

## Package `aethelred`

The top-level package provides SDK initialization, device access, and blockchain client creation.

### Functions

#### `GetRuntime() *runtime.Runtime`

Returns the singleton runtime instance. Thread-safe via `sync.Once`.

```go
rt := aethelred.GetRuntime()
rt.Initialize()
defer rt.Shutdown()
```

#### `CPU() *runtime.Device`

Returns the default CPU device.

#### `GPU(index int) *runtime.Device`

Returns a GPU accelerator device by index. Returns an unavailable device stub if no GPU is detected at the given index.

#### `HasPhysicalGPU() bool`

Reports whether GPU hardware is visible on this host.

#### `HasNativeGPUBackend() bool`

Reports whether this build includes native GPU dispatch (requires `aethelred_gpu_native` build tag).

---

### `Client`

#### `NewClient(network Network, configs ...ClientConfig) (*Client, error)`

Creates a new blockchain client connected to the specified network.

| Network | Endpoint |
|---------|----------|
| `Mainnet` | `https://rpc.aethelred.io` |
| `Testnet` | `https://testnet-rpc.aethelred.io` |
| `Devnet` | `https://devnet-rpc.aethelred.io` |
| `Local` | `http://localhost:26657` |

#### `(*Client) CreateSeal(output *tensor.Tensor) (*Seal, error)`

Creates a digital seal for a tensor output, hashing and submitting to the blockchain.

#### `(*Client) VerifySeal(sealID string) (bool, error)`

Verifies a digital seal on-chain.

#### `(*Client) SubmitJob(modelID, inputHash string) (*ComputeJob, error)`

Submits an AI compute job to the network.

---

### Types

#### `Seal`

```go
type Seal struct {
    ID             string
    ModelHash      string
    InputHash      string
    OutputHash     string
    Timestamp      time.Time
    BlockHeight    int64
    ValidatorSet   []string
    TEEAttestation *TEEAttestation
    ZKProof        *ZKProof
}
```

#### `SDKComputeCapabilities`

```go
type SDKComputeCapabilities struct {
    HasPhysicalGPU      bool
    HasNativeGPUBackend bool
    AllowsSimulatedGPU  bool
}
```

---

## Sub-packages

- [runtime](/api/go/runtime) - Device management, memory pools, profiling
- [tensor](/api/go/tensor) - Tensor operations with lazy evaluation
- [nn](/api/go/nn) - Neural network modules (PyTorch-compatible)
- [optim](/api/go/crypto) - Optimizers and learning rate schedulers
- [distributed](/api/go/distributed) - DDP, ZeRO, model parallelism
