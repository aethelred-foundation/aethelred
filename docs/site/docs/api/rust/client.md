# Rust Client API

The `aethelred-client` crate provides the async blockchain client for interacting with Aethelred nodes via RPC and gRPC.

## Import

```rust
use aethelred_client::{Client, ClientConfig, TxBuilder, BroadcastMode};
```

## Client

### Client::new

```rust
pub async fn new(config: ClientConfig) -> Result<Client>
```

### ClientConfig

```rust
pub struct ClientConfig {
    pub rpc_endpoint: String,
    pub grpc_endpoint: Option<String>,
    pub chain_id: String,
    pub timeout: Duration,
    pub retry_policy: RetryPolicy,
    pub keyring: Option<Keyring>,
}
```

### Multi-Endpoint Failover

```rust
let client = Client::with_failover(vec![
    "https://rpc1.mainnet.aethelred.io".into(),
    "https://rpc2.mainnet.aethelred.io".into(),
], ClientConfig {
    chain_id: "aethelred-1".into(),
    ..Default::default()
}).await?;
```

## Queries

```rust
pub async fn status(&self) -> Result<StatusResponse>;
pub async fn query_account(&self, address: &str) -> Result<Account>;
pub async fn query_block(&self, height: u64) -> Result<Block>;
pub async fn query_tx(&self, hash: &[u8; 32]) -> Result<TxResponse>;
```

## Transactions

### TxBuilder

```rust
let tx = client.tx_builder()
    .add_message(MsgSend {
        from_address: sender.clone(),
        to_address: recipient.clone(),
        amount: vec![Coin::new(1_000_000, "uaeth")],
    })
    .set_gas_limit(200_000)
    .set_fee(vec![Coin::new(5_000, "uaeth")])
    .set_memo("payment")
    .sign(&signer_name)
    .await?;

let resp = client.broadcast_tx(&tx, BroadcastMode::Sync).await?;
```

### BroadcastMode

```rust
pub enum BroadcastMode {
    Sync,   // wait for mempool acceptance
    Async,  // return immediately
}
```

### wait_for_tx

```rust
pub async fn wait_for_tx(&self, hash: &[u8; 32], timeout: Duration) -> Result<TxResponse>
```

## Digital Seals

```rust
pub async fn create_seal(&self, req: SealRequest) -> Result<Seal>;
pub async fn verify_seal(&self, seal_id: &[u8; 32]) -> Result<SealVerifyResult>;
pub async fn query_seals(&self, query: SealQuery) -> Result<Vec<Seal>>;
```

## Compute Jobs

```rust
pub async fn submit_job(&self, req: JobRequest) -> Result<Job>;
pub async fn job_status(&self, job_id: &[u8; 32]) -> Result<JobStatus>;
pub async fn job_result(&self, job_id: &[u8; 32]) -> Result<JobResult>;
pub async fn cancel_job(&self, job_id: &[u8; 32]) -> Result<()>;
```

## Model Registry

```rust
pub async fn publish_model(&self, req: ModelPublishRequest) -> Result<ModelVersion>;
pub async fn search_models(&self, query: ModelQuery) -> Result<Vec<ModelInfo>>;
pub async fn download_model(&self, name: &str, version: &str, dest: &Path) -> Result<PathBuf>;
```

## Subscriptions

```rust
pub async fn subscribe(&self, query: &str) -> Result<Subscription>
```

```rust
let mut sub = client.subscribe("tm.event='NewBlock'").await?;
while let Some(event) = sub.next().await {
    println!("Block: {}", event.height);
}
```

## Response Types

```rust
pub struct TxResponse {
    pub tx_hash: [u8; 32],
    pub height: u64,
    pub code: u32,
    pub gas_used: u64,
    pub gas_wanted: u64,
    pub log: String,
    pub events: Vec<Event>,
}

pub struct Account {
    pub address: String,
    pub balance: u128,
    pub sequence: u64,
    pub account_number: u64,
}
```

## Related Pages

- [Connecting to Network](/guide/network) -- network configuration
- [Rust SDK Overview](/api/rust/) -- crate overview
- [Rust Cryptography API](/api/rust/crypto) -- key management for signing
- [Submitting Jobs](/guide/jobs) -- job lifecycle guide
