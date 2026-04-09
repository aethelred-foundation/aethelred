//! Integration tests for the aethelred-bridge crate.
//!
//! The bridge relayer requires live RPC connections to Ethereum and Aethelred
//! nodes, so these tests focus on configuration, type construction, and error
//! handling that can be exercised without network access.

use aethelred_bridge::{BridgeConfig, BridgeError};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

#[test]
fn test_bridge_config_default() {
    let config = BridgeConfig::default();
    assert!(config.metrics_enabled);
    assert!(config.metrics_port > 0);
    assert!(!config.log_level.is_empty());
}

#[test]
fn test_bridge_config_storage_path() {
    let config = BridgeConfig::default();
    assert!(!config.storage_path.as_os_str().is_empty());
}

#[test]
fn test_bridge_config_ethereum_section() {
    let config = BridgeConfig::default();
    assert!(!config.ethereum.rpc_url.is_empty());
}

#[test]
fn test_bridge_config_aethelred_section() {
    let config = BridgeConfig::default();
    assert!(!config.aethelred.rpc_url.is_empty());
}

// ---------------------------------------------------------------------------
// Error Construction
// ---------------------------------------------------------------------------

#[test]
fn test_bridge_error_config() {
    let err = BridgeError::Config("bad setting".into());
    assert!(err.to_string().contains("bad setting"));
}

#[test]
fn test_bridge_error_ethereum() {
    let err = BridgeError::Ethereum("timeout".into());
    assert!(err.to_string().contains("timeout"));
}

#[test]
fn test_bridge_error_aethelred() {
    let err = BridgeError::Aethelred("connection refused".into());
    assert!(err.to_string().contains("connection refused"));
}

#[test]
fn test_bridge_error_storage() {
    let err = BridgeError::Storage("disk full".into());
    assert!(err.to_string().contains("disk full"));
}

#[test]
fn test_bridge_error_consensus() {
    let err = BridgeError::Consensus("quorum not reached".into());
    assert!(err.to_string().contains("quorum not reached"));
}

#[test]
fn test_bridge_error_signing() {
    let err = BridgeError::Signing("key not found".into());
    assert!(err.to_string().contains("key not found"));
}

// ---------------------------------------------------------------------------
// Type accessibility
// ---------------------------------------------------------------------------

#[test]
fn test_bridge_types_accessible() {
    // Verify types from the types module are re-exported.
    let _ = std::mem::size_of::<aethelred_bridge::EthAddress>();
    let _ = std::mem::size_of::<aethelred_bridge::AethelredAddress>();
    let _ = std::mem::size_of::<aethelred_bridge::TokenAmount>();
}
