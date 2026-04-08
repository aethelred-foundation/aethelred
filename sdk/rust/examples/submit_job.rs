//! Submit a compute job to the Aethelred network.
//!
//! Usage: cargo run --example submit_job

use aethelred_sdk::{AethelredClient, Config, Result};
use std::env;

#[tokio::main]
async fn main() -> Result<()> {
    // Configure client -- reads API key from environment for security.
    let config = Config::testnet()
        .with_api_key(&env::var("AETHELRED_API_KEY").unwrap_or_default());

    let client = AethelredClient::with_config(config).await?;

    // Health check
    let healthy = client.health_check().await;
    println!("Node healthy: {}", healthy);

    // Get node info
    let info = client.get_node_info().await?;
    println!("Chain ID: {}", info.network);
    println!("Node version: {}", info.version);
    println!("Moniker: {}", info.moniker);

    // Submit a job
    // (In production, use real model and input hashes)
    println!("\nSubmitting compute job...");
    // let response = client.jobs().submit(SubmitJobRequest {
    //     model_hash: "sha256:abc123...".into(),
    //     input_hash: "sha256:def456...".into(),
    //     proof_type: None, // defaults to ProofTypeHybrid
    //     priority: Some(5),
    //     max_gas: None,
    //     timeout_blocks: Some(100),
    // }).await?;
    // println!("Job ID: {}", response.job_id);
    // println!("Tx hash: {}", response.tx_hash);
    // println!("Estimated blocks: {}", response.estimated_blocks);

    println!("(Uncomment submit call with real hashes to submit)");

    Ok(())
}
