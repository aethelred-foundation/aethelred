# Installation

This page covers installing the Aethelred SDKs, the CLI tool, and verifying your setup. For CLI-specific installation details, see [CLI Installation](/cli/installation).

## System Requirements

| Requirement | Minimum | Recommended |
|---|---|---|
| OS | Linux (x86_64, aarch64), macOS 13+ | Ubuntu 22.04 LTS |
| RAM | 4 GB | 16 GB (32 GB for training workloads) |
| Disk | 2 GB free | 20 GB (includes model cache) |
| TEE (optional) | -- | Intel SGX2 / AMD SEV-SNP / AWS Nitro |
| GPU (optional) | -- | CUDA 12.0+ or ROCm 5.7+ |

## Go SDK

Requires Go 1.21 or later.

```bash
go get github.com/aethelred/sdk-go@latest
```

Verify:

```go
package main

import (
    "fmt"
    aethelred "github.com/aethelred/sdk-go"
)

func main() {
    fmt.Println("Aethelred Go SDK version:", aethelred.Version())
}
```

```bash
go run main.go
# Aethelred Go SDK version: 2.0.0
```

## Rust SDK

Requires Rust 1.75+ (2024 edition recommended).

Add to your `Cargo.toml`:

```toml
[dependencies]
aethelred = "2.0"
aethelred-crypto = "2.0"       # post-quantum primitives
aethelred-attestation = "2.0"  # TEE attestation
aethelred-sovereign = "2.0"    # sovereign data containers
aethelred-zktensor = "2.0"     # zkML tensor operations
```

Verify:

```rust
fn main() {
    println!("Aethelred Rust SDK v{}", aethelred::VERSION);
}
```

### Feature Flags

```toml
[dependencies]
aethelred = { version = "2.0", features = ["sgx", "sev-snp", "cuda"] }
```

| Feature | Description |
|---|---|
| `sgx` | Enable Intel SGX DCAP attestation |
| `sev-snp` | Enable AMD SEV-SNP attestation |
| `nitro` | Enable AWS Nitro Enclave attestation |
| `cuda` | Enable NVIDIA CUDA tensor backend |
| `rocm` | Enable AMD ROCm tensor backend |

## TypeScript SDK

Requires Node.js 18+ or any modern browser with WASM support.

```bash
npm install @aethelred/sdk
# or
yarn add @aethelred/sdk
# or
pnpm add @aethelred/sdk
```

Verify:

```typescript
import { Aethelred } from '@aethelred/sdk';

console.log('Aethelred TS SDK version:', Aethelred.version);
```

### Browser Usage

The TypeScript SDK ships with a WASM module for tensor operations. Most bundlers (Vite, webpack 5+) handle WASM imports automatically. If you need manual initialization:

```typescript
import { initWasm } from '@aethelred/sdk/wasm';

await initWasm();
```

## Python SDK

Requires Python 3.10+.

```bash
pip install aethelred
```

For GPU support:

```bash
pip install aethelred[cuda]   # NVIDIA
pip install aethelred[rocm]   # AMD
```

Verify:

```python
import aethelred
print(f"Aethelred Python SDK v{aethelred.__version__}")
print(f"CUDA available: {aethelred.cuda.is_available()}")
```

## Post-Installation Verification

Run the built-in diagnostic across any SDK:

```bash
# Using the CLI (recommended)
aethelred doctor

# Expected output:
# ✓ SDK version: 2.0.0
# ✓ Post-quantum crypto: Dilithium3 + Kyber768
# ✓ TEE support: SGX DCAP detected
# ✓ Network: testnet reachable (ping 42ms)
# ✓ GPU: CUDA 12.2 (NVIDIA A100)
```

## Configuring Network Access

After installation, point your SDK at a network. See [Connecting to Network](/guide/network) for full details.

```bash
# Quick: set via environment variable
export AETHELRED_RPC_URL=https://rpc.testnet.aethelred.io

# Or via CLI config
aethelred config set rpc-url https://rpc.testnet.aethelred.io
```

## Troubleshooting

| Problem | Solution |
|---|---|
| `libsgx_urts.so not found` | Install the Intel SGX PSW: `sudo apt install libsgx-urts` |
| `CUDA driver version mismatch` | Ensure your NVIDIA driver matches CUDA 12.x |
| `connection refused` on RPC | Check firewall rules; default RPC port is `26657` |
| Python `ImportError` on Apple Silicon | Use `pip install aethelred --no-binary :all:` to build from source |

## Next Steps

- [Quick Start](/guide/getting-started) -- your first transaction
- [Architecture](/guide/architecture) -- understand how the pieces fit
- [CLI Configuration](/cli/configuration) -- customize your environment
