# Getting Started

## Prerequisites

- **Go 1.22+** for the Go SDK
- **Rust 1.75+** for the Rust SDK and CLI
- **Node.js 20+** for the TypeScript SDK
- **Python 3.10+** for the Python SDK

## Installation

### Go SDK

```bash
go get github.com/aethelred/sdk-go@v2.0.0
```

### Rust SDK

```toml
# Cargo.toml
[dependencies]
aethelred-sdk = "1.0"
```

### TypeScript SDK

```bash
npm install @aethelred/sdk
```

### Python SDK

```bash
pip install aethelred
```

### CLI

```bash
cargo install aethelred-cli
```

## Quick Start (Go)

```go
package main

import (
    "fmt"
    aethelred "github.com/aethelred/sdk-go"
    "github.com/aethelred/sdk-go/pkg/tensor"
)

func main() {
    // Initialize runtime
    runtime := aethelred.GetRuntime()
    runtime.Initialize()
    defer runtime.Shutdown()

    // Create a tensor on CPU
    x, _ := tensor.Randn([]int{32, 784}, tensor.Float32, aethelred.CPU())

    // Connect to Aethelred testnet
    client, _ := aethelred.NewClient(aethelred.Testnet)
    defer client.Close()

    // Create a digital seal for verified output
    seal, _ := client.CreateSeal(x)
    fmt.Printf("Seal ID: %s\n", seal.ID)
}
```

## Quick Start (Rust)

```rust
use aethelred_sdk::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a sovereign data container
    let data = Sovereign::new(patient_record)
        .require_jurisdiction(Jurisdiction::UAE)
        .require_hardware(Hardware::IntelSGX)
        .build()?;

    // Generate hybrid post-quantum signature
    let keypair = HybridKeypair::generate()?;
    let signature = keypair.sign(data.hash())?;

    // Create digital seal
    let client = AethelredClient::connect("https://testnet-rpc.aethelred.io")?;
    let seal = client.create_seal(&data, &signature)?;
    
    println!("Seal: {}", seal.id());
    Ok(())
}
```

## Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                    Application Layer                     │
├──────────┬──────────┬──────────────┬────────────────────┤
│  Go SDK  │ Rust SDK │TypeScript SDK│   Python SDK       │
├──────────┴──────────┴──────────────┴────────────────────┤
│              Aethelred Core Libraries                    │
│  ┌──────────┬───────────┬──────────────┬──────────────┐ │
│  │  Crypto  │   TEE     │   zkML       │  Sovereign   │ │
│  │ ECDSA +  │ SGX/SEV/  │ Groth16/     │ Jurisdiction │ │
│  │Dilithium │ Nitro     │ PLONK/STARK  │ Enforcement  │ │
│  └──────────┴───────────┴──────────────┴──────────────┘ │
├─────────────────────────────────────────────────────────┤
│              Aethelred Blockchain Network                │
│  ┌──────────┬───────────┬──────────────┬──────────────┐ │
│  │Validators│ Consensus │ Digital Seals│Model Registry│ │
│  │ Staking  │ BFT+PoV   │ Verification │ Governance   │ │
│  └──────────┴───────────┴──────────────┴──────────────┘ │
└─────────────────────────────────────────────────────────┘
```

## Next Steps

- [Core Concepts: Digital Seals](/guide/digital-seals)
- [Core Concepts: TEE Attestation](/guide/tee-attestation)
- [Runtime & Devices](/guide/runtime)
- [Post-Quantum Cryptography](/cryptography/overview)
