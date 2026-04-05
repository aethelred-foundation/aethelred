# Architecture

Aethelred is organized into four principal layers: the **Client Layer**, the **Compute Layer**, the **Attestation & Proof Layer**, and the **Consensus Layer**. Each layer is accessible through the multi-language SDKs and is designed to operate independently while composing into a unified protocol.

## Layer Diagram

```
┌──────────────────────────────────────────────────────────┐
│                    Application Layer                      │
│   (Go / Rust / TypeScript / Python SDKs, CLI, dApps)     │
├──────────────────────────────────────────────────────────┤
│                     Client Layer                          │
│   RPC transport ─ Transaction builder ─ Query engine      │
│   Wallet management ─ Hybrid ECDSA+ML-DSA-65 (Dilithium3) signing    │
├──────────────────────────────────────────────────────────┤
│                    Compute Layer                           │
│   Runtime ─ Device mgmt ─ Tensor engine ─ NN modules     │
│   Distributed training ─ Quantization ─ Model registry   │
├──────────────────────────────────────────────────────────┤
│              Attestation & Proof Layer                     │
│   TEE quotes (SGX/SEV/Nitro) ─ zkML circuits             │
│   Digital Seals ─ Sovereign data containers               │
├──────────────────────────────────────────────────────────┤
│                   Consensus Layer                          │
│   BFT finality ─ PoUW block production ─ State machine   │
│   Validator set management ─ Slashing ─ Rewards           │
└──────────────────────────────────────────────────────────┘
```

## Client Layer

The Client Layer provides the interface between user applications and the Aethelred network. It handles:

- **Transaction construction** -- build, sign, and broadcast transactions using hybrid ECDSA + ML-DSA-65 (Dilithium3) signatures
- **Query engine** -- read on-chain state (accounts, jobs, seals, models) via RPC or gRPC
- **Key management** -- generate, store, and rotate post-quantum key pairs (see [Key Management](/cryptography/key-management))
- **Connection pooling** -- automatic failover across multiple RPC endpoints

```go
// Go example: creating a client
client, err := aethelred.NewClient(
    aethelred.WithEndpoint("https://rpc.mainnet.aethelred.io"),
    aethelred.WithKeyring(keyring),
    aethelred.WithTimeout(10 * time.Second),
)
```

See [Connecting to Network](/guide/network) for detailed configuration.

## Compute Layer

The Compute Layer is a local execution environment embedded in every SDK. It manages hardware resources and executes tensor operations, neural network training, and inference. Key components:

### Runtime

The [Runtime](/guide/runtime) initializes device contexts (CPU, CUDA GPU, ROCm GPU), allocates memory pools, and schedules operations. It supports:

- Lazy and eager evaluation modes
- Automatic mixed-precision (AMP)
- Memory-mapped model loading for large checkpoints

### Tensor Engine

The [Tensor Engine](/guide/tensors) provides NumPy/PyTorch-compatible multi-dimensional array operations with support for `float16`, `bfloat16`, `float32`, `float64`, `int8`, `int32`, and `int64` data types.

### Neural Network Modules

The [NN module system](/guide/neural-networks) mirrors PyTorch's `nn.Module` pattern. All standard layers (Linear, Conv2d, LayerNorm, MultiHeadAttention, etc.) are available across SDKs.

### Distributed Training

[Distributed training](/guide/distributed) supports DDP (data-parallel), ZeRO stages 1-3, tensor parallelism, and pipeline parallelism over TCP/IP or RDMA fabrics.

## Attestation & Proof Layer

This layer provides the cryptographic trust anchors that differentiate Aethelred from general-purpose blockchains.

### TEE Attestation

[TEE Attestation](/guide/tee-attestation) generates and verifies hardware attestation quotes proving that a specific binary ran inside a genuine enclave:

| TEE Platform | Quote Format | Verification Method |
|---|---|---|
| Intel SGX | DCAP (ECDSA-based) | On-chain DCAP verification contract |
| AMD SEV-SNP | Versioned attestation report | On-chain report parser + AMD root cert |
| AWS Nitro | COSE_Sign1 document | On-chain Nitro attestation verifier |

### zkML Proofs

[zkML Proofs](/guide/zkml-proofs) allow a prover to demonstrate that a specific neural network produced a specific output for a given input, without revealing model weights or input data. Aethelred supports three proof backends:

- **Groth16** -- smallest proof size (~200 bytes), trusted setup required
- **PLONK** -- universal setup, moderate proof size (~500 bytes)
- **STARK** -- no trusted setup, largest proof size (~50 KB), post-quantum secure

### Digital Seals

[Digital Seals](/guide/digital-seals) combine a model hash, a TEE attestation quote, and a zkML proof into a single on-chain object. They serve as immutable certificates of AI provenance.

### Sovereign Data

[Sovereign Data containers](/guide/sovereign-data) enforce jurisdictional and compliance constraints at the type-system level, ensuring data never crosses unauthorized boundaries.

## Consensus Layer

Aethelred uses a hybrid **BFT + Proof-of-Useful-Work (PoUW)** consensus mechanism:

1. **Block proposal** -- the proposer selects pending transactions and compute jobs
2. **PoUW execution** -- validators execute assigned AI jobs inside TEE enclaves
3. **Attestation aggregation** -- TEE quotes and zkML proofs are collected
4. **BFT finality** -- a supermajority (2/3+) of validators sign the block; finality is achieved in a single round

### Block Structure

```
Block {
    Header {
        height:          uint64
        timestamp:       RFC3339
        proposer:        Address (ML-DSA-65 (Dilithium3) public key hash)
        parent_hash:     SHA3-256
        state_root:      Merkle root
        attestation_root: Merkle root of TEE quotes
    }
    Transactions []Tx
    ComputeResults []JobResult
    Attestations []TEEQuote
    Proofs []ZKProof
}
```

### Validator Economics

Validators stake AETHEL tokens and earn rewards proportional to the useful work they contribute. See [Validators](/guide/validators) for staking requirements, reward calculation, and slashing conditions.

## Data Flow: End-to-End Job Execution

```
1. User submits compute job via SDK
2. Client signs tx with hybrid ECDSA+ML-DSA-65 (Dilithium3)
3. Transaction enters mempool
4. Proposer includes job in next block
5. Validators execute job inside TEE enclaves
6. Each validator produces:
   - Job result (inference output)
   - TEE attestation quote
   - zkML proof of correct execution
7. BFT round finalizes block with results
8. Digital Seal is minted on-chain
9. User queries result via SDK
```

## Next Steps

- [Digital Seals](/guide/digital-seals) -- deep dive into provenance certificates
- [TEE Attestation](/guide/tee-attestation) -- hardware trust anchors
- [zkML Proofs](/guide/zkml-proofs) -- zero-knowledge model verification
- [Cryptography Overview](/cryptography/overview) -- post-quantum primitives
