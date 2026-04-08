//! Verify a Digital Seal on the Aethelred network.
//!
//! Demonstrates listing seals, fetching a specific seal, and verifying its
//! integrity through the verification module.
//!
//! Usage: cargo run --example verify_seal

use aethelred_sdk::{AethelredClient, Config, Result};
use std::env;

#[tokio::main]
async fn main() -> Result<()> {
    // Configure client
    let config = Config::testnet()
        .with_api_key(&env::var("AETHELRED_API_KEY").unwrap_or_default());

    let client = AethelredClient::with_config(config).await?;

    println!("Connected to: {}", client.rpc_url());
    println!("Chain ID: {}", client.chain_id());

    // Step 1: List existing seals
    println!("\n--- Listing Digital Seals ---");
    let seals = client.seals().list(None).await?;
    println!("Found {} seal(s)", seals.len());

    for seal in &seals {
        println!(
            "  Seal {} | Status: {:?} | Job: {}",
            seal.id, seal.status, seal.job_id,
        );
    }

    // Step 2: Fetch a specific seal (using the first one if available)
    if let Some(first) = seals.first() {
        println!("\n--- Fetching Seal {} ---", first.id);
        let seal = client.seals().get(&first.id).await?;
        println!("  Model hash:  {}", seal.model_hash);
        println!("  Input commitment:  {}", seal.input_commitment);
        println!("  Output commitment: {}", seal.output_commitment);
        println!("  Validators: {}", seal.validators.len());

        if let Some(ref tee) = seal.tee_attestation {
            println!("  TEE platform: {:?}", tee.platform);
            println!("  Enclave hash: {}", tee.enclave_hash);
        }
        if let Some(ref zk) = seal.zkml_proof {
            println!("  zkML proof system: {}", zk.proof_system);
        }

        // Step 3: Verify the seal
        println!("\n--- Verifying Seal ---");
        let result = client.seals().verify(&first.id).await?;
        println!("  Valid: {}", result.valid);
        for (check, passed) in &result.verification_details {
            println!("  {}: {}", check, if *passed { "PASS" } else { "FAIL" });
        }
        if !result.errors.is_empty() {
            println!("  Errors:");
            for err in &result.errors {
                println!("    - {}", err);
            }
        }
    } else {
        println!("\nNo seals found. Submit a job first to create one.");
    }

    Ok(())
}
