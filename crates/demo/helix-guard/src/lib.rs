//! # Project Helix-Guard: Sovereign Genomics Collaboration Platform
//!
//! Enterprise-grade demonstration of blind drug discovery between M42 Health
//! (UAE) and global pharmaceutical partners using Aethelred's sovereign
//! AI verification infrastructure.
//!
//! ## Overview
//!
//! Project Helix-Guard showcases Aethelred's capability to enable secure
//! genomics collaboration while preserving data sovereignty. The demo demonstrates:
//!
//! - **M42 Health** (Abu Dhabi) holds 100,000+ Emirati genomes
//! - **AstraZeneca** (UK) wants to test drug candidates against UAE genetic markers
//! - Neither party can share their raw data (sovereignty + IP protection)
//! - Aethelred enables verification without exposing underlying data
//!
//! ## The Blind Drug Discovery Protocol
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
//! │                         THE BLIND DRUG DISCOVERY PROTOCOL                                        │
//! ├─────────────────────────────────────────────────────────────────────────────────────────────────┤
//! │                                                                                                  │
//! │   ┌─────────────────────────────┐         ┌─────────────────────────────┐                       │
//! │   │      M42 SOVEREIGN VAULT    │         │     PHARMA IP VAULT         │                       │
//! │   │      (Abu Dhabi, UAE)       │         │     (London/Boston)         │                       │
//! │   │                             │         │                             │                       │
//! │   │  ┌───────────────────────┐  │         │  ┌───────────────────────┐  │                       │
//! │   │  │ Emirati Genome Program│  │         │  │ Drug Molecule Formula │  │                       │
//! │   │  │ 100,000+ genomes      │  │         │  │ Proprietary compounds │  │                       │
//! │   │  └───────────────────────┘  │         │  └───────────────────────┘  │                       │
//! │   │            │                │         │            │                │                       │
//! │   │            │ POINTER ONLY   │         │            │ ENCRYPTED      │                       │
//! │   │            ▼                │         │            ▼                │                       │
//! │   └────────────┼────────────────┘         └────────────┼────────────────┘                       │
//! │                │                                       │                                        │
//! │                └───────────────────┬───────────────────┘                                        │
//! │                                    │                                                            │
//! │                                    ▼                                                            │
//! │   ┌─────────────────────────────────────────────────────────────────────────────────────────┐  │
//! │   │                        AETHELRED TEE ENCLAVE (NVIDIA H100)                               │  │
//! │   │                                                                                          │  │
//! │   │   ┌────────────────────────────────────────────────────────────────────────────────────┐│  │
//! │   │   │                              Med42 LLM Inference                                    ││  │
//! │   │   │                                                                                    ││  │
//! │   │   │   • Load genome markers (RAM only, never disk)                                    ││  │
//! │   │   │   • Decrypt drug formula (TEE-sealed keys)                                        ││  │
//! │   │   │   • Run pharmacogenomic analysis                                                  ││  │
//! │   │   │   • Generate efficacy prediction                                                  ││  │
//! │   │   │   • Wipe all sensitive data from memory                                           ││  │
//! │   │   │                                                                                    ││  │
//! │   │   └────────────────────────────────────────────────────────────────────────────────────┘│  │
//! │   │                                    │                                                     │  │
//! │   │                                    ▼                                                     │  │
//! │   │   ┌────────────────────────────────────────────────────────────────────────────────────┐│  │
//! │   │   │                         Cryptographic Output                                       ││  │
//! │   │   │                                                                                    ││  │
//! │   │   │   OUTPUT:                                                                         ││  │
//! │   │   │   • Efficacy Score: 87% ± 3%                                                      ││  │
//! │   │   │   • Confidence Level: HIGH                                                        ││  │
//! │   │   │   • TEE Attestation: 0x7f3a...                                                    ││  │
//! │   │   │   • zkML Proof: [Optional cryptographic proof]                                    ││  │
//! │   │   │                                                                                    ││  │
//! │   │   │   ⚠️ NO RAW DATA EXPOSED: Only aggregate results and proofs                       ││  │
//! │   │   │                                                                                    ││  │
//! │   │   └────────────────────────────────────────────────────────────────────────────────────┘│  │
//! │   │                                                                                          │  │
//! │   └─────────────────────────────────────────────────────────────────────────────────────────┘  │
//! │                                    │                                                            │
//! │                                    ▼                                                            │
//! │   ┌─────────────────────────────────────────────────────────────────────────────────────────┐  │
//! │   │                         AETHELRED SETTLEMENT CHAIN                                       │  │
//! │   │                                                                                          │  │
//! │   │   • Verify TEE attestation                                                              │  │
//! │   │   • Verify zkML proof (optional)                                                        │  │
//! │   │   • Process royalty payment (500 AETHEL → M42 Treasury)                                 │  │
//! │   │   • Create immutable audit trail                                                        │  │
//! │   │                                                                                          │  │
//! │   └─────────────────────────────────────────────────────────────────────────────────────────┘  │
//! │                                                                                                  │
//! └─────────────────────────────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Key Insight
//!
//! > "M42's genome data stayed in Abu Dhabi. AstraZeneca's drug formulas stayed encrypted.
//! > Aethelred only moved the TRUTH, not the DATA."
//!
//! ## Modules
//!
//! - [`types`] - Sovereign genomics type definitions
//! - [`error`] - Comprehensive error handling
//! - [`enclave`] - TEE enclave computation engine
//! - [`discovery`] - Blind drug discovery protocol
//! - [`royalty`] - Royalty calculation and settlement
//! - [`demo`] - Demo orchestration and M42 dashboard
//!
//! ## Example Usage
//!
//! ```rust,ignore
//! use helix_guard::{HelixGuardDemo, DemoConfig};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Initialize demo with default configuration
//!     let config = DemoConfig::default();
//!     let demo = HelixGuardDemo::new(config);
//!
//!     // Execute the full demo workflow
//!     let output = demo.run().await?;
//!
//!     // Access results
//!     println!("Status: {:?}", output.status);
//!     println!("Total Royalty: {} AETHEL", output.total_royalty_aethel);
//!     println!("Sovereignty Verified: {}", output.sovereignty_verified);
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Compliance Standards
//!
//! | Jurisdiction | Standards |
//! |--------------|-----------|
//! | UAE | UAE Department of Health, UAE Data Residency Law |
//! | UK | MHRA, UK GDPR |
//! | Cross-Border | HIPAA (reference), GxP Compliance |
//!
//! ## Security Features
//!
//! - **TEE Protection** - All sensitive data processed in hardware enclaves
//! - **Post-Quantum Ready** - Encryption supports Kyber768 hybrid
//! - **Zero-Knowledge Proofs** - Optional zkML proofs for additional verification
//! - **Immutable Audit Trail** - Full regulatory compliance evidence
//! - **Data Sovereignty** - Genome data NEVER leaves UAE jurisdiction
//!
//! ## Version History
//!
//! - **1.0.0** - Initial release with M42-AstraZeneca demo scenario

#![doc(html_logo_url = "https://aethelred.io/logo.png")]
#![doc(html_favicon_url = "https://aethelred.io/favicon.ico")]
#![warn(missing_docs)]
#![warn(rustdoc::missing_crate_level_docs)]

// =============================================================================
// MODULE DECLARATIONS
// =============================================================================

pub mod types;
pub mod error;
pub mod enclave;
pub mod discovery;
pub mod royalty;
pub mod demo;

// =============================================================================
// PUBLIC RE-EXPORTS
// =============================================================================

// Core types
pub use types::{
    // Type aliases
    Hash,
    Signature,
    ProofBytes,
    Did,
    TokenAmount,

    // Genomics types
    GenomeCohort,
    GenomeDataReference,
    GeneticMarkerType,
    DataQualityMetrics,

    // Data custodian & sovereignty
    DataCustodian,
    SovereigntyConstraints,
    DataResidency,
    ProcessingRestriction,
    ExportControls,
    RegulatoryBody,

    // Pharmaceutical partner
    PharmaPartner,
    PartnerTier,
    TherapeuticArea,

    // Drug candidate
    DrugCandidate,
    EncryptedPayload,
    EncryptionAlgorithm,
    KeyInfo,
    KeyType,
    GeneticMarkerQuery,
    MarkerQueryType,
    DevelopmentPhase,

    // TEE & computation
    TeeType,
    AttestationMethod,
    BlindComputeJob,
    ComputeJobType,
    JobStatus,
    ModelConfig,
    ModelType,
    GpuRequirement,
    TeeRequirements,
    ServiceLevelAgreement,
    PrivacyLevel,
    OutputVisibility,
    AuditLevel,

    // Results
    EfficacyResult,
    ConfidenceInterval,
    ConfidenceLevel,
    PopulationCoverage,
    Finding,
    FindingCategory,
    SignificanceLevel,
    ClinicalRelevance,

    // Attestation & proof
    TeeAttestation,
    PlatformInfo,
    ZkmlProof,
    ZkProofSystem,

    // Payment
    RoyaltyPayment,
    PaymentStatus,

    // Common types
    Jurisdiction,
    ComplianceStandard,
    Certification,
    UseCase,
    AccessPolicy,
    ContactInfo,
    AuditEntry,
    AuditAction,
};

// Error types
pub use error::{
    HelixGuardError,
    HelixGuardResult,
};

// Enclave engine
pub use enclave::{
    EnclaveEngine,
    EnclaveConfig,
    EnclaveInstance,
    EnclaveStatus,
    EnclaveMetrics,
    DEFAULT_ENCLAVE_MEMORY_GB,
    ATTESTATION_VALIDITY_HOURS,
    MAX_INFERENCE_TIME_SECS,
};

// Discovery protocol
pub use discovery::{
    BlindDiscoveryProtocol,
    DiscoveryConfig,
    DiscoverySession,
    SessionStatus,
    SessionApprovals,
    SessionTimeline,
    DiscoveryMetrics,
    DiscoveryAuditEntry,
    DiscoveryAuditAction,
    DiscoverySessionBuilder,
    MAX_CONCURRENT_SESSIONS,
    DEFAULT_SESSION_TIMEOUT_HOURS,
    MAX_JOB_RETRIES,
};

// Royalty engine
pub use royalty::{
    RoyaltyEngine,
    RoyaltyConfig,
    EscrowBalance,
    EscrowStatus,
    ReleaseCondition,
    TreasuryAccount,
    PartnerAccount,
    VolumeDiscountTier,
    SettlementTransaction,
    SettlementTxType,
    TransactionStatus,
    RoyaltyMetrics,
    RoyaltyCalculationParams,
    RoyaltyCalculation,
    UsageMultiplier,
    BASE_ROYALTY_USD,
    AETHEL_USD_RATE,
    AETHEL_DECIMALS,
    MIN_ROYALTY_AETHEL,
};

// Demo orchestration
pub use demo::{
    HelixGuardDemo,
    DemoConfig,
    DemoState,
    DemoStep,
    DemoStatus,
    DemoEvent,
    DemoEventType,
    DemoOutput,
    StepTiming,
    EfficacyResultSummary,
    DiscoveryMetricsSummary,
    EnclaveMetricsSummary,
    RoyaltyMetricsSummary,
    new_demo,
    new_demo_with_config,
    print_banner,
    DEMO_PROJECT_NAME,
    DEMO_SCENARIO,
    PRIMARY_CUSTODIAN,
    PRIMARY_PARTNER,
    DEMO_VALUE_USD,
};

// =============================================================================
// CRATE CONSTANTS
// =============================================================================

/// Crate version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Project code name
pub const PROJECT_NAME: &str = "Helix-Guard";

/// Demo scenario name
pub const SCENARIO_NAME: &str = "The Blind Drug Discovery Protocol";

/// Primary organizations in demo
pub const DEMO_ORGS: [&str; 2] = ["M42 Health (UAE)", "AstraZeneca (UK)"];

/// Genome program size
pub const GENOME_PROGRAM_SIZE: u32 = 100_000;

/// Supported jurisdictions in this demo
pub const SUPPORTED_JURISDICTIONS: [Jurisdiction; 2] = [
    Jurisdiction::Uae,
    Jurisdiction::UnitedKingdom,
];

// =============================================================================
// CONVENIENCE FUNCTIONS
// =============================================================================

/// Get version information string
///
/// # Returns
///
/// Formatted version string including project name and version
pub fn version_info() -> String {
    format!("Project {} v{}", PROJECT_NAME, VERSION)
}

// =============================================================================
// PRELUDE MODULE
// =============================================================================

/// Convenient imports for common usage
///
/// # Example
///
/// ```rust,ignore
/// use helix_guard::prelude::*;
///
/// let demo = HelixGuardDemo::new(DemoConfig::default());
/// let output = demo.run().await?;
/// ```
pub mod prelude {
    pub use super::{
        // Demo
        HelixGuardDemo,
        DemoConfig,
        DemoOutput,
        DemoStatus,

        // Discovery
        BlindDiscoveryProtocol,
        DiscoveryConfig,
        DiscoverySession,

        // Types
        GenomeCohort,
        DataCustodian,
        PharmaPartner,
        DrugCandidate,
        EfficacyResult,
        TeeAttestation,

        // Engines
        EnclaveEngine,
        RoyaltyEngine,

        // Results
        HelixGuardResult,
        HelixGuardError,

        // Convenience
        new_demo,
        print_banner,
        version_info,
    };
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_info() {
        let info = version_info();
        assert!(info.contains(PROJECT_NAME));
        assert!(info.contains(VERSION));
    }

    #[test]
    fn test_supported_jurisdictions() {
        assert_eq!(SUPPORTED_JURISDICTIONS.len(), 2);
        assert!(SUPPORTED_JURISDICTIONS.contains(&Jurisdiction::Uae));
        assert!(SUPPORTED_JURISDICTIONS.contains(&Jurisdiction::UnitedKingdom));
    }

    #[test]
    fn test_demo_orgs() {
        assert_eq!(DEMO_ORGS.len(), 2);
        assert!(DEMO_ORGS[0].contains("M42"));
        assert!(DEMO_ORGS[1].contains("AstraZeneca"));
    }

    #[test]
    fn test_genome_program_size() {
        assert_eq!(GENOME_PROGRAM_SIZE, 100_000);
    }

    #[test]
    fn test_new_demo_creates_instance() {
        let demo = new_demo();
        assert!(demo.config().verbose);
    }

    #[test]
    fn test_new_demo_with_custom_config() {
        let config = DemoConfig {
            verbose: false,
            simulate_delays: false,
            ..Default::default()
        };
        let demo = new_demo_with_config(config);
        assert!(!demo.config().verbose);
    }

    #[tokio::test]
    async fn test_full_demo_execution() {
        let config = DemoConfig {
            verbose: false,
            simulate_delays: false,
            show_visualizations: false,
            drug_candidate_count: 2,
            ..Default::default()
        };
        let demo = HelixGuardDemo::new(config);

        let result = demo.run().await;
        assert!(result.is_ok());

        let output = result.unwrap();
        assert_eq!(output.status, DemoStatus::Completed);
        assert!(output.sovereignty_verified);
        assert!(output.no_data_leaks);
    }
}
