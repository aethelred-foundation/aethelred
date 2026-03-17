# Rust SDK Overview

The Aethelred Rust SDK provides zero-cost abstractions for blockchain interaction, post-quantum cryptography, TEE attestation, sovereign data containers, and zero-knowledge tensor operations. It is the reference implementation for Aethelred's core protocol.

## Crates

| Crate | Description | Docs |
|---|---|---|
| `aethelred` | Core client, types, and configuration | This page |
| `aethelred-sovereign` | Sovereign data containers with compile-time jurisdiction enforcement | [sovereign](/api/rust/sovereign) |
| `aethelred-attestation` | TEE attestation (SGX DCAP, SEV-SNP, Nitro) | [attestation](/api/rust/attestation) |
| `aethelred-crypto` | Post-quantum cryptography (Dilithium3, Kyber768) | [crypto](/api/rust/crypto) |
| `aethelred-zktensor` | Zero-knowledge tensor operations and proof generation | [zktensor](/api/rust/zktensor) |
| `aethelred-client` | Blockchain RPC/gRPC client | [client](/api/rust/client) |

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
aethelred = "2.0"
```

Or include specific crates:

```toml
[dependencies]
aethelred-client = "2.0"
aethelred-crypto = "2.0"
aethelred-sovereign = "2.0"
aethelred-attestation = "2.0"
aethelred-zktensor = "2.0"
```

## Feature Flags

| Feature | Description | Default |
|---|---|---|
| `full` | Enable all features | No |
| `client` | Blockchain client | Yes |
| `crypto` | Cryptographic primitives | Yes |
| `sovereign` | Sovereign data containers | No |
| `attestation` | TEE attestation | No |
| `zktensor` | zkML proof generation | No |
| `sgx` | Intel SGX DCAP support | No |
| `sev-snp` | AMD SEV-SNP support | No |
| `nitro` | AWS Nitro Enclave support | No |
| `cuda` | NVIDIA GPU tensor backend | No |
| `rocm` | AMD GPU tensor backend | No |

## Quick Start

```rust
use aethelred::prelude::*;

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new(ClientConfig {
        rpc_endpoint: "https://rpc.testnet.aethelred.io".into(),
        chain_id: "aethelred-testnet-3".into(),
        ..Default::default()
    }).await?;

    let status = client.status().await?;
    println!("Network: {}", status.node_info.network);
    println!("Height:  {}", status.sync_info.latest_block_height);

    let keypair = crypto::generate_keypair()?;
    println!("Address: {}", keypair.address());

    Ok(())
}
```

## Error Handling

All fallible operations return `Result<T, aethelred::Error>` with structured variants:

```rust
match client.submit_job(request).await {
    Ok(job) => println!("Job ID: {}", job.id),
    Err(Error::InsufficientFunds { required, available }) => {
        eprintln!("Need {} uaeth, have {}", required, available);
    }
    Err(Error::Network(e)) => eprintln!("Network error: {}", e),
    Err(e) => eprintln!("Unexpected: {}", e),
}
```

## Async Runtime

The Rust SDK is async-first and requires a Tokio runtime.

## Minimum Supported Rust Version

Rust 1.75+ (2024 edition). Some `aethelred-sovereign` features require nightly for const generics extensions, gated behind the `nightly` feature flag.

## Related Pages

- [Rust Client API](/api/rust/client) -- blockchain interaction
- [Rust Sovereign API](/api/rust/sovereign) -- data sovereignty
- [Rust Attestation API](/api/rust/attestation) -- TEE attestation
- [Rust Cryptography API](/api/rust/crypto) -- post-quantum crypto
- [Rust zkTensor API](/api/rust/zktensor) -- zero-knowledge tensors
- [Installation Guide](/guide/installation) -- setup instructions
