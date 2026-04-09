//! Integration tests for the Aethelred Rust SDK.
//!
//! Tests cover configuration, type serialization, error handling,
//! and SDK metadata. Network-dependent client tests use mocked servers.

use aethelred_sdk::core::config::{Config, Network};
use aethelred_sdk::core::error::AethelredError;
use aethelred_sdk::core::types::*;
use aethelred_sdk::{get_sdk_info, VERSION};
use std::time::Duration;

// ---------------------------------------------------------------------------
// SDK Metadata
// ---------------------------------------------------------------------------

#[test]
fn test_sdk_version_is_non_empty() {
    assert!(!VERSION.is_empty(), "VERSION must not be empty");
}

#[test]
fn test_sdk_info_populated() {
    let info = get_sdk_info();
    assert_eq!(info.name, "aethelred-sdk");
    assert!(!info.features.core.is_empty());
    assert!(!info.features.blockchain.is_empty());
    assert!(!info.supported_devices.is_empty());
}

// ---------------------------------------------------------------------------
// Network & Config
// ---------------------------------------------------------------------------

#[test]
fn test_network_rpc_urls() {
    assert_eq!(Network::Mainnet.rpc_url(), "https://rpc.mainnet.aethelred.io");
    assert_eq!(Network::Testnet.rpc_url(), "https://rpc.testnet.aethelred.io");
    assert_eq!(Network::Devnet.rpc_url(), "https://rpc.devnet.aethelred.io");
    assert_eq!(Network::Local.rpc_url(), "http://127.0.0.1:26657");
    assert_eq!(Network::Mock.rpc_url(), "http://127.0.0.1:26657");
}

#[test]
fn test_network_chain_ids() {
    assert_eq!(Network::Mainnet.chain_id(), "aethelred-mainnet-1");
    assert_eq!(Network::Testnet.chain_id(), "aethelred-testnet-1");
    assert_eq!(Network::Devnet.chain_id(), "aethelred-devnet-1");
    assert_eq!(Network::Local.chain_id(), "aethelred-local");
    assert_eq!(Network::Mock.chain_id(), "aethelred-mock-1");
}

#[test]
fn test_config_default() {
    let cfg = Config::default();
    assert_eq!(cfg.network, Network::Mainnet);
    assert_eq!(cfg.timeout, Duration::from_secs(30));
    assert_eq!(cfg.max_retries, 3);
    assert!(cfg.api_key.is_none());
    assert!(cfg.rpc_url.is_none());
}

#[test]
fn test_config_builder_methods() {
    let cfg = Config::testnet()
        .with_api_key("test-key-123")
        .with_timeout(Duration::from_secs(5));

    assert_eq!(cfg.network, Network::Testnet);
    assert_eq!(cfg.api_key.as_deref(), Some("test-key-123"));
    assert_eq!(cfg.timeout, Duration::from_secs(5));
}

#[test]
fn test_config_get_rpc_url_fallback() {
    let cfg = Config::new(Network::Local);
    assert_eq!(cfg.get_rpc_url(), "http://127.0.0.1:26657");
}

#[test]
fn test_config_get_rpc_url_override() {
    let mut cfg = Config::new(Network::Local);
    cfg.rpc_url = Some("http://custom:9999".to_string());
    assert_eq!(cfg.get_rpc_url(), "http://custom:9999");
}

#[test]
fn test_config_get_chain_id_fallback() {
    let cfg = Config::new(Network::Testnet);
    assert_eq!(cfg.get_chain_id(), "aethelred-testnet-1");
}

#[test]
fn test_config_mock() {
    let cfg = Config::mock();
    assert_eq!(cfg.network, Network::Mock);
    assert_eq!(cfg.get_chain_id(), "aethelred-mock-1");
}

// ---------------------------------------------------------------------------
// Type Serialization Roundtrips
// ---------------------------------------------------------------------------

#[test]
fn test_job_status_serde_roundtrip() {
    let statuses = vec![
        JobStatus::JobStatusPending,
        JobStatus::JobStatusCompleted,
        JobStatus::JobStatusFailed,
        JobStatus::JobStatusCancelled,
    ];
    for status in statuses {
        let json = serde_json::to_string(&status).expect("serialize");
        let decoded: JobStatus = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(status, decoded);
    }
}

#[test]
fn test_seal_status_serde_roundtrip() {
    let statuses = vec![
        SealStatus::SealStatusActive,
        SealStatus::SealStatusRevoked,
        SealStatus::SealStatusExpired,
    ];
    for status in statuses {
        let json = serde_json::to_string(&status).expect("serialize");
        let decoded: SealStatus = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(status, decoded);
    }
}

#[test]
fn test_proof_type_serde_roundtrip() {
    let types = vec![
        ProofType::ProofTypeTee,
        ProofType::ProofTypeZkml,
        ProofType::ProofTypeHybrid,
        ProofType::ProofTypeOptimistic,
    ];
    for pt in types {
        let json = serde_json::to_string(&pt).expect("serialize");
        let decoded: ProofType = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(pt, decoded);
    }
}

#[test]
fn test_tee_platform_serde_roundtrip() {
    let platforms = vec![
        TEEPlatform::TeePlatformIntelSgx,
        TEEPlatform::TeePlatformAmdSev,
        TEEPlatform::TeePlatformAwsNitro,
    ];
    for p in platforms {
        let json = serde_json::to_string(&p).expect("serialize");
        let decoded: TEEPlatform = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(p, decoded);
    }
}

#[test]
fn test_compute_job_serde_roundtrip() {
    let job = ComputeJob {
        id: "job-1".into(),
        creator: "aethelred1creator".into(),
        model_hash: "0xmodel".into(),
        input_hash: "0xinput".into(),
        output_hash: None,
        status: JobStatus::JobStatusPending,
        proof_type: ProofType::ProofTypeHybrid,
        priority: 1,
        max_gas: "100000".into(),
        timeout_blocks: 100,
        created_at: chrono::Utc::now(),
        completed_at: None,
        validator_address: None,
        metadata: std::collections::HashMap::new(),
    };

    let json = serde_json::to_string(&job).expect("serialize");
    let decoded: ComputeJob = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(decoded.id, "job-1");
    assert_eq!(decoded.status, JobStatus::JobStatusPending);
    assert_eq!(decoded.proof_type, ProofType::ProofTypeHybrid);
}

#[test]
fn test_digital_seal_serde_roundtrip() {
    let seal = DigitalSeal {
        id: "seal-1".into(),
        job_id: "job-1".into(),
        model_hash: "0xmodel".into(),
        input_commitment: "0xinput".into(),
        output_commitment: "0xoutput".into(),
        model_commitment: "0xmodelcommit".into(),
        status: SealStatus::SealStatusActive,
        requester: "aethelred1req".into(),
        validators: vec![],
        tee_attestation: None,
        zkml_proof: None,
        regulatory_info: None,
        created_at: chrono::Utc::now(),
        expires_at: None,
        revoked_at: None,
        revocation_reason: None,
    };

    let json = serde_json::to_string(&seal).expect("serialize");
    let decoded: DigitalSeal = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(decoded.id, "seal-1");
    assert_eq!(decoded.status, SealStatus::SealStatusActive);
}

#[test]
fn test_page_request_defaults() {
    let pr = PageRequest::default();
    assert!(pr.key.is_none());
    assert!(pr.offset.is_none());
    assert!(pr.limit.is_none());
}

// ---------------------------------------------------------------------------
// Error Display
// ---------------------------------------------------------------------------

#[test]
fn test_error_display_messages() {
    let err = AethelredError::Connection("refused".into());
    assert!(err.to_string().contains("refused"));

    let err = AethelredError::RateLimit {
        retry_after: Some(30),
    };
    assert!(err.to_string().contains("30"));

    let err = AethelredError::NotFound("seal-xyz".into());
    assert!(err.to_string().contains("seal-xyz"));

    let err = AethelredError::Http {
        status: 503,
        message: "service unavailable".into(),
    };
    assert!(err.to_string().contains("503"));

    let err = AethelredError::Validation {
        message: "bad input".into(),
        field: Some("model_hash".into()),
    };
    assert!(err.to_string().contains("bad input"));
}

// ---------------------------------------------------------------------------
// Utility Category
// ---------------------------------------------------------------------------

#[test]
fn test_utility_category_variants() {
    let categories = vec![
        UtilityCategory::UtilityCategoryMedical,
        UtilityCategory::UtilityCategoryScientific,
        UtilityCategory::UtilityCategoryFinancial,
        UtilityCategory::UtilityCategoryLegal,
        UtilityCategory::UtilityCategoryEducational,
        UtilityCategory::UtilityCategoryEnvironmental,
        UtilityCategory::UtilityCategoryGeneral,
    ];
    assert_eq!(categories.len(), 7);
}
