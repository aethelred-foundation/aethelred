//! # WASM Module for Browser Support
//!
//! This module provides WebAssembly bindings for the Aethelred SDK,
//! enabling browser-based applications to interact with the blockchain.
//!
//! ## Features
//!
//! - Client initialization and configuration
//! - Job submission and querying
//! - Seal verification
//! - Cryptographic operations (hashing, signing)
//! - Transaction building and signing
//!
//! ## Usage in JavaScript
//!
//! ```javascript
//! import init, { AethelredWasm, Network } from 'aethelred-sdk-wasm';
//!
//! async function main() {
//!     await init();
//!
//!     const client = new AethelredWasm(Network.Testnet);
//!
//!     // Submit a job
//!     const jobId = await client.submitJob({
//!         modelHash: "abc123...",
//!         inputHash: "def456...",
//!         proofType: "TEE",
//!         purpose: "Credit score inference"
//!     });
//!
//!     // Query job status
//!     const status = await client.getJobStatus(jobId);
//!     console.log("Job status:", status);
//!
//!     // Verify a seal
//!     const verification = await client.verifySeal("seal_123");
//!     console.log("Seal valid:", verification.valid);
//! }
//! ```
//!
//! ## Building for WASM
//!
//! ```bash
//! # Install wasm-pack
//! cargo install wasm-pack
//!
//! # Build for browser
//! wasm-pack build --target web --features wasm
//!
//! # Build for Node.js
//! wasm-pack build --target nodejs --features wasm
//! ```

#![cfg(target_arch = "wasm32")]

use js_sys::{Promise, Uint8Array};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use web_sys::console;

// ============================================================================
// Error Handling
// ============================================================================

/// WASM-compatible error type
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct WasmError {
    code: String,
    message: String,
}

#[wasm_bindgen]
impl WasmError {
    /// Get the error code
    #[wasm_bindgen(getter)]
    pub fn code(&self) -> String {
        self.code.clone()
    }

    /// Get the error message
    #[wasm_bindgen(getter)]
    pub fn message(&self) -> String {
        self.message.clone()
    }
}

impl From<String> for WasmError {
    fn from(msg: String) -> Self {
        WasmError {
            code: "INTERNAL_ERROR".to_string(),
            message: msg,
        }
    }
}

// ============================================================================
// Network Configuration
// ============================================================================

/// Network selection for WASM client
#[wasm_bindgen]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WasmNetwork {
    /// Mainnet network
    Mainnet,
    /// Testnet network
    Testnet,
    /// Local development network
    Local,
}

impl WasmNetwork {
    fn endpoint(&self) -> &'static str {
        match self {
            WasmNetwork::Mainnet => "https://api.aethelred.org/v1",
            WasmNetwork::Testnet => "https://testnet-api.aethelred.org/v1",
            WasmNetwork::Local => "http://127.0.0.1:26657",
        }
    }
}

// ============================================================================
// Data Types
// ============================================================================

/// Proof type for verification
#[wasm_bindgen]
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum WasmProofType {
    /// TEE-based proof
    TEE,
    /// Zero-knowledge ML proof
    ZKML,
    /// Hybrid (TEE + ZKML)
    Hybrid,
}

/// Job status
#[wasm_bindgen]
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum WasmJobStatus {
    /// Job is pending
    Pending,
    /// Job is being processed
    Processing,
    /// Job completed successfully
    Completed,
    /// Job failed
    Failed,
    /// Job expired
    Expired,
}

/// Job submission request
#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen]
pub struct SubmitJobRequest {
    model_hash: String,
    input_hash: String,
    proof_type: WasmProofType,
    purpose: String,
    priority: Option<u8>,
}

#[wasm_bindgen]
impl SubmitJobRequest {
    /// Create a new job submission request
    #[wasm_bindgen(constructor)]
    pub fn new(
        model_hash: String,
        input_hash: String,
        proof_type: WasmProofType,
        purpose: String,
    ) -> Self {
        SubmitJobRequest {
            model_hash,
            input_hash,
            proof_type,
            purpose,
            priority: None,
        }
    }

    /// Set job priority (0-10)
    #[wasm_bindgen]
    pub fn with_priority(mut self, priority: u8) -> Self {
        self.priority = Some(priority.min(10));
        self
    }
}

/// Job submission response
#[wasm_bindgen]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitJobResponse {
    job_id: String,
    tx_hash: String,
    status: WasmJobStatus,
}

#[wasm_bindgen]
impl SubmitJobResponse {
    /// Get the job ID
    #[wasm_bindgen(getter)]
    pub fn job_id(&self) -> String {
        self.job_id.clone()
    }

    /// Get the transaction hash
    #[wasm_bindgen(getter)]
    pub fn tx_hash(&self) -> String {
        self.tx_hash.clone()
    }

    /// Get the job status
    #[wasm_bindgen(getter)]
    pub fn status(&self) -> WasmJobStatus {
        self.status
    }
}

/// Job details
#[wasm_bindgen]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmJob {
    id: String,
    model_hash: String,
    input_hash: String,
    output_hash: Option<String>,
    proof_type: WasmProofType,
    status: WasmJobStatus,
    purpose: String,
    seal_id: Option<String>,
    created_at: String,
}

#[wasm_bindgen]
impl WasmJob {
    #[wasm_bindgen(getter)]
    pub fn id(&self) -> String {
        self.id.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn model_hash(&self) -> String {
        self.model_hash.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn input_hash(&self) -> String {
        self.input_hash.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn output_hash(&self) -> Option<String> {
        self.output_hash.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn proof_type(&self) -> WasmProofType {
        self.proof_type
    }

    #[wasm_bindgen(getter)]
    pub fn status(&self) -> WasmJobStatus {
        self.status
    }

    #[wasm_bindgen(getter)]
    pub fn purpose(&self) -> String {
        self.purpose.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn seal_id(&self) -> Option<String> {
        self.seal_id.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn created_at(&self) -> String {
        self.created_at.clone()
    }
}

/// Seal verification result
#[wasm_bindgen]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealVerificationResult {
    valid: bool,
    seal_id: String,
    proof_valid: bool,
    signatures_valid: bool,
    not_revoked: bool,
    not_expired: bool,
    error: Option<String>,
}

#[wasm_bindgen]
impl SealVerificationResult {
    #[wasm_bindgen(getter)]
    pub fn valid(&self) -> bool {
        self.valid
    }

    #[wasm_bindgen(getter)]
    pub fn seal_id(&self) -> String {
        self.seal_id.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn proof_valid(&self) -> bool {
        self.proof_valid
    }

    #[wasm_bindgen(getter)]
    pub fn signatures_valid(&self) -> bool {
        self.signatures_valid
    }

    #[wasm_bindgen(getter)]
    pub fn not_revoked(&self) -> bool {
        self.not_revoked
    }

    #[wasm_bindgen(getter)]
    pub fn not_expired(&self) -> bool {
        self.not_expired
    }

    #[wasm_bindgen(getter)]
    pub fn error(&self) -> Option<String> {
        self.error.clone()
    }
}

// ============================================================================
// Cryptographic Utilities
// ============================================================================

/// WASM-compatible cryptographic utilities
#[wasm_bindgen]
pub struct WasmCrypto;

#[wasm_bindgen]
impl WasmCrypto {
    /// Compute SHA-256 hash
    #[wasm_bindgen]
    pub fn sha256(data: &[u8]) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }

    /// Compute SHA-256 hash and return as hex string
    #[wasm_bindgen]
    pub fn sha256_hex(data: &[u8]) -> String {
        let hash = Self::sha256(data);
        hex::encode(hash)
    }

    /// Convert bytes to hex string
    #[wasm_bindgen]
    pub fn to_hex(data: &[u8]) -> String {
        hex::encode(data)
    }

    /// Convert hex string to bytes
    #[wasm_bindgen]
    pub fn from_hex(hex_str: &str) -> Result<Vec<u8>, JsValue> {
        hex::decode(hex_str).map_err(|e| JsValue::from_str(&format!("Invalid hex: {}", e)))
    }

    /// Generate random bytes
    #[wasm_bindgen]
    pub fn random_bytes(length: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; length];
        getrandom::getrandom(&mut bytes).expect("Failed to generate random bytes");
        bytes
    }

    /// Verify a signature (placeholder - requires full crypto implementation)
    #[wasm_bindgen]
    pub fn verify_signature(_message: &[u8], _signature: &[u8], _public_key: &[u8]) -> bool {
        // TODO: Implement signature verification
        // This requires bringing in a signature library compatible with WASM
        console::warn_1(&"Signature verification not yet implemented in WASM".into());
        false
    }
}

// ============================================================================
// Main Client
// ============================================================================

/// Main WASM client for Aethelred
#[wasm_bindgen]
pub struct AethelredWasm {
    network: WasmNetwork,
    endpoint: String,
}

#[wasm_bindgen]
impl AethelredWasm {
    /// Create a new WASM client
    #[wasm_bindgen(constructor)]
    pub fn new(network: WasmNetwork) -> Self {
        console::log_1(&format!("Initializing Aethelred WASM SDK for {:?}", network).into());
        AethelredWasm {
            network,
            endpoint: network.endpoint().to_string(),
        }
    }

    /// Create a client with a custom endpoint
    #[wasm_bindgen]
    pub fn with_endpoint(endpoint: String) -> Self {
        console::log_1(
            &format!(
                "Initializing Aethelred WASM SDK with endpoint: {}",
                endpoint
            )
            .into(),
        );
        AethelredWasm {
            network: WasmNetwork::Local,
            endpoint,
        }
    }

    /// Get the current network
    #[wasm_bindgen(getter)]
    pub fn network(&self) -> WasmNetwork {
        self.network
    }

    /// Get the API endpoint
    #[wasm_bindgen(getter)]
    pub fn endpoint(&self) -> String {
        self.endpoint.clone()
    }

    /// Submit a compute job
    #[wasm_bindgen]
    pub async fn submit_job(
        &self,
        request: SubmitJobRequest,
    ) -> Result<SubmitJobResponse, JsValue> {
        let url = format!("{}/jobs", self.endpoint);

        let body = serde_json::json!({
            "model_hash": request.model_hash,
            "input_hash": request.input_hash,
            "proof_type": format!("{:?}", request.proof_type).to_uppercase(),
            "purpose": request.purpose,
            "priority": request.priority.unwrap_or(0),
        });

        let response = self.fetch_json(&url, "POST", Some(body)).await?;

        serde_json::from_value(response)
            .map_err(|e| JsValue::from_str(&format!("Failed to parse response: {}", e)))
    }

    /// Get job by ID
    #[wasm_bindgen]
    pub async fn get_job(&self, job_id: &str) -> Result<WasmJob, JsValue> {
        let url = format!("{}/jobs/{}", self.endpoint, job_id);
        let response = self.fetch_json(&url, "GET", None).await?;

        serde_json::from_value(response)
            .map_err(|e| JsValue::from_str(&format!("Failed to parse job: {}", e)))
    }

    /// Get job status
    #[wasm_bindgen]
    pub async fn get_job_status(&self, job_id: &str) -> Result<WasmJobStatus, JsValue> {
        let job = self.get_job(job_id).await?;
        Ok(job.status)
    }

    /// Verify a seal
    #[wasm_bindgen]
    pub async fn verify_seal(&self, seal_id: &str) -> Result<SealVerificationResult, JsValue> {
        let url = format!("{}/seals/{}/verify", self.endpoint, seal_id);
        let response = self.fetch_json(&url, "POST", None).await?;

        serde_json::from_value(response)
            .map_err(|e| JsValue::from_str(&format!("Failed to parse verification result: {}", e)))
    }

    /// Get chain status
    #[wasm_bindgen]
    pub async fn get_chain_status(&self) -> Result<JsValue, JsValue> {
        let url = format!("{}/chain/status", self.endpoint);
        let response = self.fetch_json(&url, "GET", None).await?;

        Ok(serde_wasm_bindgen::to_value(&response)?)
    }

    /// Get current block height
    #[wasm_bindgen]
    pub async fn get_block_height(&self) -> Result<u64, JsValue> {
        let status = self.get_chain_status().await?;
        let height: u64 = js_sys::Reflect::get(&status, &"latest_block_height".into())?
            .as_f64()
            .ok_or_else(|| JsValue::from_str("Invalid block height"))?
            as u64;
        Ok(height)
    }

    // Internal fetch helper
    async fn fetch_json(
        &self,
        url: &str,
        method: &str,
        body: Option<serde_json::Value>,
    ) -> Result<serde_json::Value, JsValue> {
        use wasm_bindgen_futures::JsFuture;
        use web_sys::{Request, RequestInit, RequestMode, Response};

        let mut opts = RequestInit::new();
        opts.method(method);
        opts.mode(RequestMode::Cors);

        if let Some(body) = body {
            let body_str = serde_json::to_string(&body)
                .map_err(|e| JsValue::from_str(&format!("Failed to serialize body: {}", e)))?;
            opts.body(Some(&JsValue::from_str(&body_str)));
        }

        let request = Request::new_with_str_and_init(url, &opts)?;
        request.headers().set("Content-Type", "application/json")?;

        let window = web_sys::window().ok_or_else(|| JsValue::from_str("No window"))?;
        let response_value = JsFuture::from(window.fetch_with_request(&request)).await?;
        let response: Response = response_value.dyn_into()?;

        if !response.ok() {
            return Err(JsValue::from_str(&format!(
                "HTTP error: {} {}",
                response.status(),
                response.status_text()
            )));
        }

        let json = JsFuture::from(response.json()?).await?;
        serde_wasm_bindgen::from_value(json)
            .map_err(|e| JsValue::from_str(&format!("Failed to parse JSON: {}", e)))
    }
}

// ============================================================================
// Offline Transaction Builder
// ============================================================================

/// Offline transaction builder for signing transactions without network access
#[wasm_bindgen]
pub struct OfflineTransactionBuilder {
    chain_id: String,
    account_number: u64,
    sequence: u64,
}

#[wasm_bindgen]
impl OfflineTransactionBuilder {
    /// Create a new offline transaction builder
    #[wasm_bindgen(constructor)]
    pub fn new(chain_id: String, account_number: u64, sequence: u64) -> Self {
        OfflineTransactionBuilder {
            chain_id,
            account_number,
            sequence,
        }
    }

    /// Build a submit job transaction
    #[wasm_bindgen]
    pub fn build_submit_job_tx(
        &self,
        sender: &str,
        model_hash: &str,
        input_hash: &str,
        proof_type: WasmProofType,
        purpose: &str,
        fee_amount: &str,
    ) -> Result<Vec<u8>, JsValue> {
        // Build the transaction body
        let tx_body = serde_json::json!({
            "messages": [{
                "@type": "/aethelred.pouw.v1.MsgSubmitJob",
                "sender": sender,
                "model_hash": model_hash,
                "input_hash": input_hash,
                "proof_type": format!("{:?}", proof_type).to_uppercase(),
                "purpose": purpose,
            }],
            "memo": "",
            "timeout_height": "0",
            "extension_options": [],
            "non_critical_extension_options": []
        });

        let auth_info = serde_json::json!({
            "signer_infos": [{
                "public_key": null, // Will be filled by signer
                "mode_info": {
                    "single": {
                        "mode": "SIGN_MODE_DIRECT"
                    }
                },
                "sequence": self.sequence.to_string()
            }],
            "fee": {
                "amount": [{
                    "denom": "uaethel",
                    "amount": fee_amount
                }],
                "gas_limit": "200000",
                "payer": "",
                "granter": ""
            }
        });

        let sign_doc = serde_json::json!({
            "body_bytes": "", // Would be protobuf encoded
            "auth_info_bytes": "", // Would be protobuf encoded
            "chain_id": self.chain_id,
            "account_number": self.account_number.to_string()
        });

        // For a real implementation, this would use protobuf encoding
        // Here we return a JSON representation for demonstration
        let tx = serde_json::json!({
            "body": tx_body,
            "auth_info": auth_info,
            "sign_doc": sign_doc,
        });

        serde_json::to_vec(&tx)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize tx: {}", e)))
    }

    /// Get the bytes to sign for a transaction
    #[wasm_bindgen]
    pub fn get_sign_bytes(&self, tx_bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
        // In a real implementation, this would extract and format the sign bytes
        // For now, we hash the transaction bytes
        Ok(WasmCrypto::sha256(tx_bytes))
    }

    /// Attach a signature to a transaction
    #[wasm_bindgen]
    pub fn attach_signature(
        &self,
        tx_bytes: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> Result<Vec<u8>, JsValue> {
        // Parse the transaction
        let mut tx: serde_json::Value = serde_json::from_slice(tx_bytes)
            .map_err(|e| JsValue::from_str(&format!("Failed to parse tx: {}", e)))?;

        // Attach signature (simplified - real impl uses protobuf)
        tx["signatures"] = serde_json::json!([hex::encode(signature)]);
        tx["auth_info"]["signer_infos"][0]["public_key"] = serde_json::json!({
            "@type": "/cosmos.crypto.secp256k1.PubKey",
            "key": base64::encode(public_key)
        });

        serde_json::to_vec(&tx)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize signed tx: {}", e)))
    }

    /// Increment sequence for next transaction
    #[wasm_bindgen]
    pub fn increment_sequence(&mut self) {
        self.sequence += 1;
    }
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize the WASM module (call this first)
#[wasm_bindgen(start)]
pub fn wasm_init() {
    // Set up panic hook for better error messages
    console_error_panic_hook::set_once();

    console::log_1(&"Aethelred WASM SDK initialized".into());
}

/// Get SDK version
#[wasm_bindgen]
pub fn get_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Check if running in browser environment
#[wasm_bindgen]
pub fn is_browser() -> bool {
    web_sys::window().is_some()
}

// ============================================================================
// Exports for use in other modules
// ============================================================================

pub use base64;
pub use hex;
pub use sha2;
