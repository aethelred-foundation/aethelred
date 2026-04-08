//! Enterprise Hybrid Compute Job -- The Recommended Path (Rust SDK)
//!
//! Demonstrates the full enterprise lifecycle:
//!   1. Configure enterprise client
//!   2. Submit a hybrid job (TEE + zkML -- the default)
//!   3. Poll for completion
//!   4. Fetch the evidence bundle (Digital Seal)
//!   5. Verify the audit trail
//!
//! Usage: cargo run --example enterprise_hybrid

use aethelred_sdk::{AethelredClient, Config, Result};
use aethelred_sdk::jobs::SubmitJobRequest;
use std::env;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<()> {
    println!("{}", "=".repeat(60));
    println!("  Enterprise Hybrid Verification -- Rust SDK");
    println!("{}", "=".repeat(60));
    println!();

    // -- Step 1: Configure enterprise client ----------------------
    let config = Config::testnet()
        .with_api_key(&env::var("AETHELRED_API_KEY").unwrap_or_default())
        .with_timeout(Duration::from_secs(120));

    let client = AethelredClient::with_config(config).await?;
    println!("[1/5] Client configured (testnet)");
    println!("      RPC:      {}", client.rpc_url());
    println!("      Chain ID: {}", client.chain_id());

    // -- Step 2: Submit a hybrid job (the default) ----------------
    //
    // proof_type is omitted -- the SDK fills in ProofTypeHybrid.
    let response = client.jobs().submit(SubmitJobRequest {
        model_hash: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into(),
        input_hash: "sha256:7d793037a0760186574b0282f2f435e7cee9c11619c6e091b3bc44b34c3e8c14".into(),
        proof_type: None, // defaults to HYBRID (TEE attestation + zkML proof)
        priority: Some(5),
        max_gas: None,
        timeout_blocks: Some(100),
    }).await?;
    println!("[2/5] Submitted enterprise hybrid job");
    println!("      Job ID:  {}", response.job_id);
    println!("      Tx hash: {}", response.tx_hash);
    println!("      proof_type = HYBRID (TEE attestation + zkML proof)");

    // -- Step 3: Poll for completion ------------------------------
    println!("[3/5] Polling for completion (timeout 120 s)...");
    let job = client.jobs().wait_for_completion(
        &response.job_id,
        Duration::from_secs(2),
        Duration::from_secs(120),
    ).await?;
    println!("      Job status: {:?}", job.status);

    // -- Step 4: Fetch evidence bundle ----------------------------
    //
    // The completed job's metadata contains the seal ID linking to
    // the on-chain Digital Seal with TEE attestation + zkML proof.
    if let Some(seal_id) = job.metadata.get("seal_id") {
        let seal = client.seals().get(seal_id).await?;
        println!("[4/5] Evidence bundle retrieved");
        println!("      Seal ID:     {}", seal.id);
        println!("      Validators:  {}", seal.validators.len());
        if seal.tee_attestation.is_some() {
            println!("      TEE:         present");
        }
        if seal.zkml_proof.is_some() {
            println!("      zkML proof:  present");
        }

        // -- Step 5: Verify audit trail ---------------------------
        let result = client.seals().verify(&seal.id).await?;
        println!("[5/5] Audit trail verified: {}", result.valid);
        for (check, passed) in &result.verification_details {
            println!("      {}: {}", check, if *passed { "PASS" } else { "FAIL" });
        }
    } else {
        println!("[4/5] No seal_id in job metadata (job may still be processing)");
        println!("[5/5] Skipped -- no seal to verify");
    }

    println!();
    println!("{}", "=".repeat(60));
    println!("  Enterprise hybrid flow complete.");
    println!();
    println!("  Why HYBRID is the enterprise default:");
    println!("    - TEE gives fast hardware attestation (~1 s)");
    println!("    - zkML adds a mathematical proof (~30 s)");
    println!("    - Together they satisfy SOC 2 / HIPAA / GDPR audits");
    println!("    - The Digital Seal anchors both proofs on-chain");
    println!("{}", "=".repeat(60));

    Ok(())
}
