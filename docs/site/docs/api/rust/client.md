# Client Module

## `aethelred_sdk::core`

The Client module provides `AethelredClient`, the primary entry point for interacting with the Aethelred blockchain. It manages HTTP connections, module routing, and the async Tokio runtime.

See also: [Rust SDK Overview](/api/rust/) | [Crypto Module](/api/rust/crypto) | [Attestation Module](/api/rust/attestation)

---

### `AethelredClient`

Main client for all blockchain operations. Holds sub-modules for jobs, seals, models, validators, and verification.

```rust
use aethelred_sdk::{AethelredClient, Network};

let client = AethelredClient::new(Network::Testnet).await?;
```

#### Constructors

| Method | Signature | Description |
|--------|-----------|-------------|
| `new` | `async fn new(network: Network) -> Result<Self>` | Connect with default config for the given network |
| `with_config` | `async fn with_config(config: Config) -> Result<Self>` | Connect with custom configuration |
| `mainnet` | `async fn mainnet() -> Result<Self>` | Shorthand for `new(Network::Mainnet)` |
| `testnet` | `async fn testnet() -> Result<Self>` | Shorthand for `new(Network::Testnet)` |
| `local` | `async fn local() -> Result<Self>` | Shorthand for `new(Network::Local)` |

#### Module Accessors

| Method | Returns | Description |
|--------|---------|-------------|
| `jobs()` | `&JobsModule` | Compute job submission, polling, cancellation |
| `seals()` | `&SealsModule` | Digital seal CRUD and verification |
| `models()` | `&ModelsModule` | On-chain model registry |
| `validators()` | `&ValidatorsModule` | Validator stats and capabilities |
| `verification()` | `&VerificationModule` | TEE and zkML proof verification |

#### Node Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `get_node_info` | `async fn get_node_info(&self) -> Result<NodeInfo>` | Query Tendermint node info |
| `health_check` | `async fn health_check(&self) -> bool` | Returns `true` if the node is reachable |
| `rpc_url` | `fn rpc_url(&self) -> &str` | Effective RPC endpoint URL |
| `chain_id` | `fn chain_id(&self) -> &str` | Effective chain ID string |

---

### Network

```rust
pub enum Network {
    Mainnet,
    Testnet,
    Devnet,
    Local,
}
```

| Variant | RPC URL | Chain ID |
|---------|---------|----------|
| `Mainnet` | `https://rpc.mainnet.aethelred.org` | `aethelred-1` |
| `Testnet` | `https://rpc.testnet.aethelred.org` | `aethelred-testnet-1` |
| `Devnet` | `https://rpc.devnet.aethelred.org` | `aethelred-devnet-1` |
| `Local` | `http://127.0.0.1:26657` | `aethelred-local` |

---

### Config

Builder-pattern configuration for custom client setups.

```rust
use aethelred_sdk::Config;
use std::time::Duration;

let config = Config::testnet()
    .with_api_key("aeth_key_abc123")
    .with_timeout(Duration::from_secs(60));

let client = AethelredClient::with_config(config).await?;
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `network` | `Network` | `Mainnet` | Target network |
| `rpc_url` | `Option<String>` | `None` | Override the network's default RPC URL |
| `chain_id` | `Option<String>` | `None` | Override the network's default chain ID |
| `api_key` | `Option<String>` | `None` | API key sent as `X-API-Key` header |
| `timeout` | `Duration` | 30s | HTTP request timeout |
| `max_retries` | `u32` | 3 | Maximum retry attempts |
| `log_requests` | `bool` | `false` | Log outgoing HTTP requests |

---

### Jobs Module

#### `SubmitJobRequest`

```rust
pub struct SubmitJobRequest {
    pub model_hash: String,
    pub input_hash: String,
    pub proof_type: Option<ProofType>,
    pub priority: Option<u32>,
    pub max_gas: Option<String>,
    pub timeout_blocks: Option<u32>,
}
```

#### Key Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `submit` | `async fn submit(&self, req: SubmitJobRequest) -> Result<SubmitJobResponse>` | Submit a compute job |
| `get` | `async fn get(&self, job_id: &str) -> Result<ComputeJob>` | Fetch job by ID |
| `list` | `async fn list(&self, pagination: Option<PageRequest>) -> Result<Vec<ComputeJob>>` | List jobs |
| `cancel` | `async fn cancel(&self, job_id: &str) -> Result<()>` | Cancel a pending job |
| `wait_for_completion` | `async fn wait_for_completion(&self, job_id: &str, poll_interval: Duration, timeout: Duration) -> Result<ComputeJob>` | Poll until terminal status |

---

### Seals Module

#### Key Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `create` | `async fn create(&self, req: CreateSealRequest) -> Result<CreateSealResponse>` | Create a digital seal for a completed job |
| `get` | `async fn get(&self, seal_id: &str) -> Result<DigitalSeal>` | Fetch seal by ID |
| `list` | `async fn list(&self, pagination: Option<PageRequest>) -> Result<Vec<DigitalSeal>>` | List seals |
| `verify` | `async fn verify(&self, seal_id: &str) -> Result<VerifySealResponse>` | Verify seal integrity on-chain |
| `revoke` | `async fn revoke(&self, seal_id: &str, reason: &str) -> Result<()>` | Revoke an active seal |

#### `DigitalSeal`

```rust
pub struct DigitalSeal {
    pub id: String,
    pub job_id: String,
    pub model_hash: Hash,
    pub input_commitment: Hash,
    pub output_commitment: Hash,
    pub status: SealStatus,
    pub requester: Address,
    pub validators: Vec<ValidatorAttestation>,
    pub tee_attestation: Option<TEEAttestation>,
    pub zkml_proof: Option<ZKMLProof>,
    pub regulatory_info: Option<RegulatoryInfo>,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}
```

---

### Async Runtime

The SDK requires a Tokio async runtime. All network-bound methods are `async` and return `Result<T, AethelredError>`.

```rust
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let client = AethelredClient::new(Network::Testnet).await?;

    let info = client.get_node_info().await?;
    println!("Connected to {} ({})", info.moniker, info.network);

    Ok(())
}
```

For non-async contexts, use `tokio::runtime::Runtime::block_on`:

```rust
let rt = tokio::runtime::Runtime::new()?;
let client = rt.block_on(AethelredClient::new(Network::Testnet))?;
let healthy = rt.block_on(async { client.health_check().await });
```

---

### Example: End-to-End Job Workflow

```rust
use aethelred_sdk::{AethelredClient, Network};
use aethelred_sdk::jobs::SubmitJobRequest;
use aethelred_sdk::seals::CreateSealRequest;
use std::time::Duration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let client = AethelredClient::new(Network::Testnet).await?;

    // Submit job
    let job = client.jobs().submit(SubmitJobRequest {
        model_hash: "sha256:abc123".into(),
        input_hash: "sha256:def456".into(),
        proof_type: None,
        priority: Some(5),
        max_gas: None,
        timeout_blocks: None,
    }).await?;

    // Wait for completion
    let completed = client.jobs()
        .wait_for_completion(&job.job_id, Duration::from_secs(2), Duration::from_secs(120))
        .await?;

    // Create seal
    let seal = client.seals().create(CreateSealRequest {
        job_id: completed.id.clone(),
        regulatory_info: None,
        expires_in_blocks: Some(100_000),
    }).await?;

    // Verify seal
    let result = client.seals().verify(&seal.seal_id).await?;
    println!("Seal {} valid: {}", seal.seal_id, result.valid);

    Ok(())
}
```
