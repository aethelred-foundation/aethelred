# zkTensor Module

## `aethelred_sdk::verification` and `aethelred_core::types::seal`

The zkTensor module provides zero-knowledge machine learning (zkML) proof generation, circuit compilation, and on-chain verification. It enables public verifiability of AI inference results without revealing model weights or input data.

See also: [Attestation Module](/api/rust/attestation) | [Client Module](/api/rust/client) | [Crypto Module](/api/rust/crypto)

---

### Proof Systems

Aethelred supports three zkML proof backends. The proof system is specified per-job via the `ProofType` enum.

#### `ProofType`

```rust
pub enum ProofType {
    ProofTypeUnspecified,
    ProofTypeTee,
    ProofTypeZkml,
    ProofTypeHybrid,
    ProofTypeOptimistic,
}
```

| Variant | Verification | Latency | Use case |
|---------|-------------|---------|----------|
| `ProofTypeTee` | Hardware attestation | ~100ms | Real-time inference |
| `ProofTypeZkml` | ZK proof on-chain | ~10--60s | Trustless verification |
| `ProofTypeHybrid` | TEE + ZK | ~10--60s | Maximum assurance |
| `ProofTypeOptimistic` | Challenge window | ~minutes | Cost-optimized batch |

---

### ZK Proof Structures

#### `ZKMLProof`

Stored on-chain inside a `DigitalSeal` when the job uses `ProofTypeZkml` or `ProofTypeHybrid`.

```rust
pub struct ZKMLProof {
    pub proof_system: String,       // "groth16", "plonk", or "stark"
    pub proof: String,              // Base64-encoded proof bytes
    pub public_inputs: Vec<String>, // Public circuit inputs
    pub verifying_key_hash: Hash,   // SHA-256 of the verifying key
}
```

| Field | Description |
|-------|-------------|
| `proof_system` | Identifier for the backend (`"groth16"`, `"plonk"`, `"stark"`) |
| `proof` | The serialized proof (base64) |
| `public_inputs` | Values visible to the verifier (e.g., output hash, model hash) |
| `verifying_key_hash` | Binds the proof to a specific compiled circuit |

---

### Seal Evidence (zkML)

When a seal carries zero-knowledge proof evidence, it uses the `SealEvidence::ZkmlOnly` or `SealEvidence::Hybrid` variant from the core crate.

```rust
pub enum SealEvidence {
    ZkmlOnly {
        proof: Vec<u8>,
        verifying_key_hash: Hash256,
        public_inputs: Vec<u8>,
    },
    Hybrid {
        attestations: Vec<TeeAttestation>,
        zkml_proof: Vec<u8>,
        verifying_key_hash: Hash256,
        min_attestations: u32,
    },
    // ...
}
```

---

### On-Chain Verification

#### `VerifyZKProofRequest`

Submit a proof for on-chain verification via `client.verification().verify_zk_proof(request)`.

```rust
pub struct VerifyZKProofRequest {
    pub proof: String,
    pub public_inputs: Vec<String>,
    pub verifying_key_hash: String,
    pub proof_system: Option<String>,
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `proof` | Yes | Base64-encoded proof bytes |
| `public_inputs` | Yes | Ordered public inputs matching the circuit |
| `verifying_key_hash` | Yes | SHA-256 hex of the verifying key |
| `proof_system` | No | Override auto-detection (`"groth16"`, `"plonk"`, `"stark"`) |

#### `VerifyZKProofResponse`

```rust
pub struct VerifyZKProofResponse {
    pub valid: bool,
    pub verification_time_ms: u64,
    pub error: Option<String>,
}
```

---

### Proof-Backed Job Submission

When submitting a compute job that requires zkML verification, set `proof_type` on the `SubmitJobRequest`:

```rust
use aethelred_sdk::jobs::{SubmitJobRequest};
use aethelred_sdk::core::types::ProofType;

let request = SubmitJobRequest {
    model_hash: model_hash.clone(),
    input_hash: input_hash.clone(),
    proof_type: Some(ProofType::ProofTypeZkml),
    priority: Some(5),
    max_gas: None,
    timeout_blocks: Some(100),
};

let resp = client.jobs().submit(request).await?;
```

The validator assigned to the job will generate a ZK proof during compute. The resulting `DigitalSeal` will contain the proof in its `zkml_proof` field.

---

### Verification Workflow

```text
  Client                   Validator                 Chain
    |                         |                        |
    |-- SubmitJob(zkml) ----->|                        |
    |                         |-- Compute in TEE ----->|
    |                         |-- Generate ZK proof -->|
    |                         |-- Create seal -------->|
    |                         |                        |
    |<--- seal_id ------------|                        |
    |                                                  |
    |-- verify_zk_proof(seal.proof) ------------------>|
    |<--- VerifyZKProofResponse -----------------------|
```

---

### Example: Full zkML Verification Flow

```rust
use aethelred_sdk::{AethelredClient, Network};
use aethelred_sdk::jobs::SubmitJobRequest;
use aethelred_sdk::verification::VerifyZKProofRequest;
use aethelred_sdk::core::types::ProofType;
use std::time::Duration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let client = AethelredClient::new(Network::Testnet).await?;

    // 1. Submit job with zkML proof requirement
    let job = client.jobs().submit(SubmitJobRequest {
        model_hash: "sha256:abc123".into(),
        input_hash: "sha256:def456".into(),
        proof_type: Some(ProofType::ProofTypeZkml),
        priority: Some(10),
        max_gas: None,
        timeout_blocks: None,
    }).await?;

    // 2. Wait for completion
    let completed = client.jobs()
        .wait_for_completion(&job.job_id, Duration::from_secs(5), Duration::from_secs(300))
        .await?;

    // 3. Retrieve the seal
    let seal = client.seals().get(&completed.id).await?;

    // 4. Independently verify the ZK proof
    if let Some(ref zkml) = seal.zkml_proof {
        let result = client.verification().verify_zk_proof(VerifyZKProofRequest {
            proof: zkml.proof.clone(),
            public_inputs: zkml.public_inputs.clone(),
            verifying_key_hash: zkml.verifying_key_hash.clone(),
            proof_system: Some(zkml.proof_system.clone()),
        }).await?;

        println!("Proof valid: {} (verified in {}ms)", result.valid, result.verification_time_ms);
    }

    Ok(())
}
```

---

### Supported Proof Backends

| Backend | Curve | Proof Size | Verify Time | Trusted Setup |
|---------|-------|------------|-------------|---------------|
| Groth16 | BN254 | ~200 B | ~5 ms | Yes (circuit-specific) |
| PLONK | BN254 | ~500 B | ~10 ms | Universal (one-time) |
| STARK | - | ~50 KB | ~50 ms | No (transparent) |
