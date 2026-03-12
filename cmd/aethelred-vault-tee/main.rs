//! Crucible TEE Worker Binary
//!
//! Stateless HTTP service for TEE-verified vault operations:
//!   - Validator selection with diversity scoring
//!   - MEV-protected transaction ordering
//!   - Cryptographic reward calculation with Merkle proofs
//!
//! # Usage
//!
//! ```sh
//! # Mock mode (development)
//! CRUCIBLE_TEE_PLATFORM=mock aethelred-vault-tee
//!
//! # Real platform (production)
//! CRUCIBLE_TEE_PLATFORM=sgx \
//!   CRUCIBLE_OPERATOR_KEY_HEX=<64 hex chars> \
//!   CRUCIBLE_ATTESTATION_RELAY_URL=https://relay.example.com/attest \
//!   CRUCIBLE_ENCLAVE_HASH_HEX=<64 hex chars> \
//!   CRUCIBLE_SIGNER_HASH_HEX=<64 hex chars> \
//!   aethelred-vault-tee
//! ```
//!
//! # Environment Variables
//!
//! ## Core
//!
//! | Variable | Description | Default |
//! |----------|-------------|---------|
//! | `CRUCIBLE_LISTEN_ADDR` | HTTP listen address | `127.0.0.1:8547` |
//! | `CRUCIBLE_TEE_PLATFORM` | TEE platform: `sgx`, `nitro`, `sev`, `mock` | `mock` |
//! | `CRUCIBLE_ALLOW_SIMULATED` | Enable simulated attestations | `true` |
//! | `CRUCIBLE_AUTH_TOKEN` | Bearer token for API auth (required in prod) | None |
//! | `CRUCIBLE_RATE_LIMIT_RPS` | Max requests per second | `50` |
//! | `CRUCIBLE_INSECURE_NO_AUTH` | Bypass auth check (dev only, NOT for prod) | `false` |
//! | `CRUCIBLE_INSECURE_LOCAL_VENDOR_KEY` | Allow local vendor key on real platforms (requires `mock-tee` build + loopback, dev only) | `false` |
//! | `RUST_LOG` | Log level filter | `info` |
//!
//! ## Identity & Attestation
//!
//! | Variable | Description | Default |
//! |----------|-------------|---------|
//! | `CRUCIBLE_OPERATOR_KEY_HEX` | secp256k1 operator signing key (64 hex chars) | Random (dev only) |
//! | `CRUCIBLE_ATTESTATION_RELAY_URL` | Production attestation relay URL | None |
//! | `CRUCIBLE_VENDOR_KEY_HEX` | P-256 local vendor key for dev/test (64 hex chars) | None |
//! | `CRUCIBLE_ENCLAVE_HASH_HEX` | Enclave measurement / MRENCLAVE (64 hex chars) | Placeholder (mock only) |
//! | `CRUCIBLE_SIGNER_HASH_HEX` | Signer measurement / MRSIGNER (64 hex chars) | Placeholder (mock only) |
//!
//! ## Limits
//!
//! | Variable | Description | Default |
//! |----------|-------------|---------|
//! | `CRUCIBLE_MAX_VALIDATORS` | Maximum validators per selection | `200` |
//! | `CRUCIBLE_MAX_STAKERS` | Maximum stakers per reward calculation | `100000` |
//! | `CRUCIBLE_MAX_COMMITMENTS` | Maximum commitments/reveals per MEV ordering | `10000` |
//!
//! # Security Notes
//!
//! - **`CRUCIBLE_OPERATOR_KEY_HEX`**: In production, this MUST be set to a
//!   stable key generated inside the TEE. Without it, the operator identity
//!   rotates on every restart and attestations from previous runs become invalid.
//!
//! - **`CRUCIBLE_ATTESTATION_RELAY_URL`** vs **`CRUCIBLE_VENDOR_KEY_HEX`**:
//!   The relay URL is the **required** production path — hardware evidence is
//!   verified by an independent service. `CRUCIBLE_VENDOR_KEY_HEX` is
//!   **rejected** for real platforms (SGX/Nitro/SEV) unless **all** of:
//!   1. The binary was built with `--features mock-tee` (compile-time gate).
//!   2. `CRUCIBLE_LISTEN_ADDR` is a loopback address (runtime gate).
//!   3. `CRUCIBLE_INSECURE_LOCAL_VENDOR_KEY=true` (runtime flag).
//!
//!   Production images must never enable `mock-tee`, so the local vendor
//!   path is removed at compile time. In dev builds, both loopback binding
//!   and the explicit flag are required — a non-loopback deployment will
//!   hard-error even with the flag set.
//!
//! - **`CRUCIBLE_ENCLAVE_HASH_HEX`** / **`CRUCIBLE_SIGNER_HASH_HEX`**:
//!   Required for real platforms. These must match the values registered on-chain
//!   via `setEnclaveConfig()`. Mismatches cause attestation failures.

use std::env;

use aethelred_vault::attestation::TEEPlatform;
use aethelred_vault::server::{start_server, VaultServiceConfig};

/// Read an optional env var, returning `None` if unset or empty.
fn opt_env(name: &str) -> Option<String> {
    env::var(name).ok().filter(|v| !v.is_empty())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .json()
        .init();

    // ── Core config ──────────────────────────────────────────────────────

    let listen_addr = env::var("CRUCIBLE_LISTEN_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8547".to_string());

    let platform = match env::var("CRUCIBLE_TEE_PLATFORM")
        .unwrap_or_else(|_| "mock".to_string())
        .to_lowercase()
        .as_str()
    {
        "sgx" | "intel-sgx" => TEEPlatform::IntelSGX,
        "nitro" | "aws-nitro" => TEEPlatform::AWSNitro,
        "sev" | "amd-sev" => TEEPlatform::AMDSEV,
        "mock" => TEEPlatform::Mock,
        other => {
            return Err(format!(
                "unknown TEE platform '{}'. Supported: sgx, nitro, sev, mock", other
            ).into());
        }
    };

    let allow_simulated = env::var("CRUCIBLE_ALLOW_SIMULATED")
        .unwrap_or_else(|_| "true".to_string())
        .parse::<bool>()
        .unwrap_or(true);

    // ── Identity & attestation ───────────────────────────────────────────

    let operator_key_hex = opt_env("CRUCIBLE_OPERATOR_KEY_HEX");
    let attestation_relay_url = opt_env("CRUCIBLE_ATTESTATION_RELAY_URL");
    let vendor_attestation_key_hex = opt_env("CRUCIBLE_VENDOR_KEY_HEX");
    let enclave_hash_hex = opt_env("CRUCIBLE_ENCLAVE_HASH_HEX");
    let signer_hash_hex = opt_env("CRUCIBLE_SIGNER_HASH_HEX");
    let application_hash_hex = opt_env("CRUCIBLE_APPLICATION_HASH_HEX");

    // ── Limits ───────────────────────────────────────────────────────────

    let max_validators: usize = env::var("CRUCIBLE_MAX_VALIDATORS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(200);

    let max_stakers: usize = env::var("CRUCIBLE_MAX_STAKERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(100_000);

    let max_commitments: usize = env::var("CRUCIBLE_MAX_COMMITMENTS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10_000);

    // ── Auth & rate limit ──────────────────────────────────────────────────

    let auth_token = opt_env("CRUCIBLE_AUTH_TOKEN");

    // Explicit opt-in to bypass the fail-closed auth check.
    // Only useful for local dev with real hardware on loopback.
    let insecure_no_auth = env::var("CRUCIBLE_INSECURE_NO_AUTH")
        .unwrap_or_else(|_| "false".to_string())
        .parse::<bool>()
        .unwrap_or(false);

    // Explicit opt-in to use a local vendor key on real platforms.
    // By default, real platforms require attestation_relay_url.
    let insecure_local_vendor_key = env::var("CRUCIBLE_INSECURE_LOCAL_VENDOR_KEY")
        .unwrap_or_else(|_| "false".to_string())
        .parse::<bool>()
        .unwrap_or(false);

    let rate_limit_rps: u32 = env::var("CRUCIBLE_RATE_LIMIT_RPS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(50);

    // ── Build config ─────────────────────────────────────────────────────

    let config = VaultServiceConfig {
        listen_addr,
        tee_platform: platform,
        allow_simulated,
        max_validators,
        max_stakers,
        max_commitments,
        operator_key_hex,
        vendor_attestation_key_hex,
        attestation_relay_url,
        enclave_hash_hex,
        signer_hash_hex,
        application_hash_hex,
        auth_token,
        rate_limit_rps,
        insecure_no_auth,
        insecure_local_vendor_key,
    };

    // ── Startup log ──────────────────────────────────────────────────────

    tracing::info!(
        platform = %config.tee_platform,
        simulated = config.allow_simulated,
        addr = %config.listen_addr,
        auth_enabled = config.auth_token.is_some(),
        rate_limit_rps = config.rate_limit_rps,
        operator_key = config.operator_key_hex.is_some(),
        relay_url = config.attestation_relay_url.is_some(),
        vendor_key = config.vendor_attestation_key_hex.is_some(),
        enclave_hash = config.enclave_hash_hex.is_some(),
        signer_hash = config.signer_hash_hex.is_some(),
        application_hash = config.application_hash_hex.is_some(),
        max_validators = config.max_validators,
        max_stakers = config.max_stakers,
        max_commitments = config.max_commitments,
        "Starting Crucible TEE service"
    );

    start_server(config).await?;

    Ok(())
}
