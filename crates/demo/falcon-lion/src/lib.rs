//! # Project Falcon-Lion: Cross-Border Trade Finance Demo
//!
//! Enterprise-grade demonstration of Zero-Knowledge Letter of Credit verification
//! between FAB (First Abu Dhabi Bank, UAE) and DBS (Development Bank of Singapore).
//!
//! ## Overview
//!
//! Project Falcon-Lion showcases Aethelred's capability to enable secure cross-border
//! trade finance transactions while preserving data sovereignty. The demo demonstrates
//! a $5M solar panel trade where:
//!
//! - **UAE Solar Manufacturer** (FAB Client) exports to Singapore
//! - **Singapore Construction Firm** (DBS Client) imports from UAE
//! - Neither bank can share private financial records due to data sovereignty laws
//! - Aethelred enables verification without exposing underlying data
//!
//! ## Data Sovereignty Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────────┐
//! │                    AETHELRED DATA SOVEREIGNTY MODEL                          │
//! ├─────────────────────────────────────────────────────────────────────────────┤
//! │                                                                              │
//! │   ┌─────────────────────┐              ┌─────────────────────┐              │
//! │   │   UAE TEE ENCLAVE   │              │ SINGAPORE TEE ENCLAVE│             │
//! │   │                     │              │                      │             │
//! │   │  ┌───────────────┐  │              │  ┌───────────────┐   │             │
//! │   │  │ FAB Private   │  │              │  │ DBS Private   │   │             │
//! │   │  │ Financial Data│  │              │  │ Financial Data│   │             │
//! │   │  └───────────────┘  │              │  └───────────────┘   │             │
//! │   │         │           │              │         │            │             │
//! │   │         ▼           │              │         ▼            │             │
//! │   │  ┌───────────────┐  │              │  ┌───────────────┐   │             │
//! │   │  │ AI Risk Model │  │              │  │ AI Risk Model │   │             │
//! │   │  │ (Local Exec)  │  │              │  │ (Local Exec)  │   │             │
//! │   │  └───────────────┘  │              │  └───────────────┘   │             │
//! │   │         │           │              │         │            │             │
//! │   │         ▼           │              │         ▼            │             │
//! │   │  ┌───────────────┐  │              │  ┌───────────────┐   │             │
//! │   │  │ ZK Proof Only │──┼──────────────┼──│ ZK Proof Only │   │             │
//! │   │  └───────────────┘  │              │  └───────────────┘   │             │
//! │   │                     │              │                      │             │
//! │   └─────────────────────┘              └──────────────────────┘             │
//! │                │                                   │                         │
//! │                └─────────────┬─────────────────────┘                         │
//! │                              ▼                                               │
//! │               ┌─────────────────────────────┐                                │
//! │               │   AETHELRED SETTLEMENT CHAIN │                               │
//! │               │                              │                               │
//! │               │  • Verifies proofs only      │                               │
//! │               │  • Never sees raw data       │                               │
//! │               │  • Mints Verifiable LC       │                               │
//! │               │  • Creates audit trail       │                               │
//! │               └─────────────────────────────┘                                │
//! │                                                                              │
//! └─────────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Key Insight
//!
//! > "FAB's data stayed in the UAE node. DBS's data stayed in the Singapore node.
//! > Aethelred only moved the TRUTH, not the DATA."
//!
//! ## Modules
//!
//! - [`types`] - Core trade finance type definitions
//! - [`error`] - Comprehensive error handling
//! - [`compliance`] - Multi-jurisdiction compliance engine
//! - [`settlement`] - Cross-border settlement with ZK LC minting
//! - [`demo`] - Demo orchestration and visualization
//!
//! ## Example Usage
//!
//! ```rust,ignore
//! use falcon_lion::{FalconLionDemo, DemoConfig};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Initialize demo with default configuration
//!     let config = DemoConfig::default();
//!     let demo = FalconLionDemo::new(config);
//!
//!     // Execute the full demo workflow
//!     let output = demo.run().await?;
//!
//!     // Access results
//!     println!("Trade Deal: {}", output.trade_deal.id);
//!     println!("Letter of Credit: {}", output.letter_of_credit.id);
//!     println!("Settlement Hash: {}", output.settlement_hash);
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Compliance Standards
//!
//! | Jurisdiction | Standards |
//! |--------------|-----------|
//! | UAE | UAE Central Bank Regulations, UAE Data Protection Law |
//! | Singapore | MAS Notice 655, Singapore PDPA |
//! | Cross-Border | FATF Guidelines, Basel III, UCP 600 |
//!
//! ## Trade Finance Workflow
//!
//! 1. **Deal Creation** - Trade parameters established between parties
//! 2. **FAB Verification** - UAE-side compliance in TEE enclave
//! 3. **DBS Verification** - Singapore-side compliance in TEE enclave
//! 4. **Proof Settlement** - ZK proofs settled on Aethelred chain
//! 5. **LC Minting** - Verifiable Letter of Credit issued on-chain
//!
//! ## Security Features
//!
//! - **TEE Protection** - All sensitive data processed in hardware enclaves
//! - **Post-Quantum Signatures** - Dilithium3 for future-proof security
//! - **Zero-Knowledge Proofs** - Verify without revealing underlying data
//! - **Immutable Audit Trail** - Full regulatory compliance evidence
//!
//! ## Version History
//!
//! - **1.0.0** - Initial release with FAB-DBS demo scenario

#![doc(html_logo_url = "https://aethelred.io/logo.png")]
#![doc(html_favicon_url = "https://aethelred.io/favicon.ico")]
#![allow(missing_docs)]
#![warn(rustdoc::missing_crate_level_docs)]

// =============================================================================
// MODULE DECLARATIONS
// =============================================================================

pub mod types;
pub mod error;
pub mod compliance;
pub mod settlement;
pub mod demo;

// =============================================================================
// PUBLIC RE-EXPORTS
// =============================================================================

// Core types
pub use types::{
    // Jurisdictions and compliance
    Jurisdiction,
    ComplianceStandard,

    // Financial primitives
    Currency,
    MonetaryAmount,
    CurrencyAmount,

    // Bank identifiers
    BankIdentifier,

    // Trade participants
    TradeParticipant,
    Address,
    ContactInfo,
    RiskRating,
    SanctionsStatus,
    SanctionsResult,
    SanctionsList,

    // Letter of Credit
    LetterOfCredit,
    LetterOfCreditType,
    LcStatus,
    LcAvailability,
    RequiredDocument,
    DocumentType,
    LcAmendment,

    // Trade deals
    TradeDeal,
    DealStatus,
    BlockchainStatus,
    BankGuarantee,
    GuaranteeType,
    GuaranteeStatus,
    Incoterms,

    // Verification
    VerificationProof,
    ProofType,
    VerificationMethod,
    ProofResultSummary,
    RiskLevel,

    // Audit
    AuditEntry,
    AuditAction,

    // AI Jobs
    TradeVerificationJob,
    TradeJobType,
    JobStatus,
    JobSla,
    PrivacyLevel,

    // Type aliases
    Hash,
    ProofBytes,
};

// Error types
pub use error::{
    FalconLionError,
    FalconLionResult,
};

// Compliance engine
pub use compliance::{
    ComplianceEngine,
    CompliancePolicy,
    VerificationSession,
    VerificationResult,
    ComplianceCheck,
    ComplianceCheckType,
    CheckStatus,
    SessionStatus,
    Finding,
    FindingSeverity,
    ConsentRequirements,
    AuditRequirements,
    ComplianceMetrics,
};

// Settlement engine
pub use settlement::{
    SettlementEngine,
    NetworkConfig,
    VerifiableLetterOfCredit,
    OnChainLcStatus,
    SettlementTransaction,
    SettlementTxType,
    TxStatus,
    SettlementEvent,
    SettlementEventType,
    SettlementMetrics,
    ContractAddress,
    TxHash,
    BlockNumber,
};

// Demo orchestration
pub use demo::{
    FalconLionDemo,
    DemoConfig,
    DemoMode,
    DemoState,
    DemoOutput,
    DemoStep,
    DemoStatus,
    DemoEvent,
    DemoEventType,
    DemoMetrics,
    StepTiming,
};

// =============================================================================
// CRATE CONSTANTS
// =============================================================================

/// Crate version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Project code name
pub const PROJECT_NAME: &str = "Falcon-Lion";

/// Demo scenario name
pub const DEMO_SCENARIO: &str = "Zero-Knowledge Letter of Credit";

/// Primary banks in demo
pub const DEMO_BANKS: [&str; 2] = ["FAB (First Abu Dhabi Bank)", "DBS (Development Bank of Singapore)"];

/// Trade value in demo (USD)
pub const DEMO_TRADE_VALUE: u64 = 5_000_000;

/// Supported jurisdictions in this demo
pub const SUPPORTED_JURISDICTIONS: [Jurisdiction; 2] = [
    Jurisdiction::Uae,
    Jurisdiction::Singapore,
];

// =============================================================================
// CONVENIENCE FUNCTIONS
// =============================================================================

/// Create a new demo instance with default configuration
///
/// # Example
///
/// ```rust,ignore
/// use falcon_lion::new_demo;
///
/// let demo = new_demo();
/// let output = demo.run().await?;
/// ```
pub fn new_demo() -> FalconLionDemo {
    FalconLionDemo::new(DemoConfig::default())
}

/// Create a new demo instance with custom configuration
///
/// # Arguments
///
/// * `config` - Custom demo configuration
///
/// # Example
///
/// ```rust,ignore
/// use falcon_lion::{new_demo_with_config, DemoConfig};
///
/// let config = DemoConfig {
///     verbose: true,
///     simulate_delays: false,
///     ..Default::default()
/// };
/// let demo = new_demo_with_config(config);
/// ```
pub fn new_demo_with_config(config: DemoConfig) -> FalconLionDemo {
    FalconLionDemo::new(config)
}

/// Get version information string
///
/// # Returns
///
/// Formatted version string including project name and version
pub fn version_info() -> String {
    format!("Project {} v{}", PROJECT_NAME, VERSION)
}

/// Print the project banner
///
/// Displays ASCII art banner with project information
pub fn print_banner() {
    println!(r#"
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   ███████╗ █████╗ ██╗      ██████╗ ██████╗ ███╗   ██╗                       ║
║   ██╔════╝██╔══██╗██║     ██╔════╝██╔═══██╗████╗  ██║                       ║
║   █████╗  ███████║██║     ██║     ██║   ██║██╔██╗ ██║                       ║
║   ██╔══╝  ██╔══██║██║     ██║     ██║   ██║██║╚██╗██║                       ║
║   ██║     ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║                       ║
║   ╚═╝     ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝                       ║
║                                                                              ║
║   ██╗     ██╗ ██████╗ ███╗   ██╗                                            ║
║   ██║     ██║██╔═══██╗████╗  ██║                                            ║
║   ██║     ██║██║   ██║██╔██╗ ██║                                            ║
║   ██║     ██║██║   ██║██║╚██╗██║                                            ║
║   ███████╗██║╚██████╔╝██║ ╚████║                                            ║
║   ╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═══╝                                            ║
║                                                                              ║
║   Zero-Knowledge Letter of Credit Demo                                       ║
║   FAB (UAE) ←→ DBS (Singapore)                                              ║
║                                                                              ║
║   Powered by Aethelred: Where Data Stays, Truth Travels                      ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
"#);
}

// =============================================================================
// PRELUDE MODULE
// =============================================================================

/// Convenient imports for common usage
///
/// # Example
///
/// ```rust,ignore
/// use falcon_lion::prelude::*;
///
/// let demo = FalconLionDemo::new(DemoConfig::default());
/// let output = demo.run().await?;
/// ```
pub mod prelude {
    pub use super::{
        // Demo
        FalconLionDemo,
        DemoConfig,
        DemoOutput,

        // Types
        Jurisdiction,
        Currency,
        MonetaryAmount,
        BankIdentifier,
        TradeParticipant,
        LetterOfCredit,
        TradeDeal,
        VerificationProof,

        // Engines
        ComplianceEngine,
        SettlementEngine,

        // Results
        FalconLionResult,
        FalconLionError,

        // Convenience
        new_demo,
        print_banner,
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
        assert!(SUPPORTED_JURISDICTIONS.contains(&Jurisdiction::Singapore));
    }

    #[test]
    fn test_demo_banks() {
        assert_eq!(DEMO_BANKS.len(), 2);
        assert!(DEMO_BANKS[0].contains("FAB"));
        assert!(DEMO_BANKS[1].contains("DBS"));
    }

    #[test]
    fn test_demo_trade_value() {
        assert_eq!(DEMO_TRADE_VALUE, 5_000_000);
    }

    #[test]
    fn test_new_demo_creates_instance() {
        let demo = new_demo();
        // Demo should be created with default config
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
            ..Default::default()
        };
        let demo = FalconLionDemo::new(config);

        // Run the full demo
        let result = demo.run().await;
        assert!(result.is_ok());

        let output = result.unwrap();

        // Verify demo completed
        assert_eq!(output.status, DemoStatus::Completed);

        // Verify LC was minted
        assert!(output.lc_reference.is_some());
        assert!(output.lc_id.is_some());

        // Verify settlement
        assert!(output.settlement_tx_hash.is_some());

        // Verify no sensitive data was exposed
        assert!(!output.metrics.sensitive_data_exposed);
    }
}
