//! # Project Falcon-Lion: Enterprise Trade Finance Types
//!
//! Comprehensive type definitions for cross-border trade finance operations
//! between FAB (First Abu Dhabi Bank) and DBS (Development Bank of Singapore).
//!
//! ## Architecture Overview
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────────────────────┐
//! │                    PROJECT FALCON-LION: TRADE FINANCE TYPES                              │
//! ├─────────────────────────────────────────────────────────────────────────────────────────┤
//! │                                                                                          │
//! │  ┌───────────────────────────────────────────────────────────────────────────────────┐  │
//! │  │                         TRADE PARTICIPANTS                                         │  │
//! │  │                                                                                    │  │
//! │  │   ┌─────────────────┐         ┌─────────────────┐         ┌─────────────────┐    │  │
//! │  │   │    EXPORTER     │         │   TRADE DEAL    │         │    IMPORTER     │    │  │
//! │  │   │  (UAE Solar Co) │◄───────►│  (Letter of     │◄───────►│ (SG Construct.) │    │  │
//! │  │   │                 │         │   Credit)       │         │                 │    │  │
//! │  │   └────────┬────────┘         └────────┬────────┘         └────────┬────────┘    │  │
//! │  │            │                           │                           │             │  │
//! │  │            ▼                           ▼                           ▼             │  │
//! │  │   ┌─────────────────┐         ┌─────────────────┐         ┌─────────────────┐    │  │
//! │  │   │   FAB BANK      │         │   AETHELRED     │         │   DBS BANK      │    │  │
//! │  │   │  (Advising)     │────────►│   SETTLEMENT    │◄────────│  (Issuing)      │    │  │
//! │  │   │                 │         │                 │         │                 │    │  │
//! │  │   └─────────────────┘         └─────────────────┘         └─────────────────┘    │  │
//! │  │                                                                                    │  │
//! │  └───────────────────────────────────────────────────────────────────────────────────┘  │
//! │                                                                                          │
//! │  ┌───────────────────────────────────────────────────────────────────────────────────┐  │
//! │  │                         FINANCIAL INSTRUMENTS                                      │  │
//! │  │                                                                                    │  │
//! │  │   LetterOfCredit ─────► StandbyLC / CommercialLC / RevolvingLC                   │  │
//! │  │   BankGuarantee ──────► PerformanceGuarantee / BidBond / AdvancePayment          │  │
//! │  │   TradeProof ─────────► SanctionsCheck / CreditScore / DocumentVerification      │  │
//! │  │                                                                                    │  │
//! │  └───────────────────────────────────────────────────────────────────────────────────┘  │
//! │                                                                                          │
//! └─────────────────────────────────────────────────────────────────────────────────────────┘
//! ```

use std::fmt;

use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// =============================================================================
// TYPE ALIASES
// =============================================================================

/// 32-byte hash for cryptographic identifiers
pub type Hash = [u8; 32];

/// Proof bytes (variable length cryptographic proof)
pub type ProofBytes = Vec<u8>;

/// Token amount in smallest unit (18 decimals)
pub type TokenAmount = u128;

/// Currency amount with high precision
pub type CurrencyAmount = Decimal;

// =============================================================================
// JURISDICTION & COMPLIANCE
// =============================================================================

/// Regulatory jurisdiction
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Jurisdiction {
    /// United Arab Emirates
    #[serde(rename = "UAE")]
    Uae,
    /// Singapore
    #[serde(rename = "SG")]
    Singapore,
    /// European Union (GDPR)
    #[serde(rename = "EU")]
    EuropeanUnion,
    /// United States
    #[serde(rename = "US")]
    UnitedStates,
    /// United Kingdom
    #[serde(rename = "UK")]
    UnitedKingdom,
    /// Hong Kong
    #[serde(rename = "HK")]
    HongKong,
    /// Switzerland
    #[serde(rename = "CH")]
    Switzerland,
    /// Japan
    #[serde(rename = "JP")]
    Japan,
}

impl Jurisdiction {
    /// Get the ISO 3166-1 alpha-2 country code
    pub fn country_code(&self) -> &'static str {
        match self {
            Self::Uae => "AE",
            Self::Singapore => "SG",
            Self::EuropeanUnion => "EU",
            Self::UnitedStates => "US",
            Self::UnitedKingdom => "GB",
            Self::HongKong => "HK",
            Self::Switzerland => "CH",
            Self::Japan => "JP",
        }
    }

    /// Get primary regulatory body
    pub fn regulatory_body(&self) -> &'static str {
        match self {
            Self::Uae => "UAE Central Bank / CBUAE",
            Self::Singapore => "Monetary Authority of Singapore / MAS",
            Self::EuropeanUnion => "European Banking Authority / EBA",
            Self::UnitedStates => "Federal Reserve / OCC",
            Self::UnitedKingdom => "Financial Conduct Authority / FCA",
            Self::HongKong => "Hong Kong Monetary Authority / HKMA",
            Self::Switzerland => "Swiss Financial Market Supervisory Authority / FINMA",
            Self::Japan => "Financial Services Agency / FSA",
        }
    }

    /// Get Aethelred node region identifier
    pub fn node_region(&self) -> &'static str {
        match self {
            Self::Uae => "uae-north-1",
            Self::Singapore => "sg-south-1",
            Self::EuropeanUnion => "eu-central-1",
            Self::UnitedStates => "us-east-1",
            Self::UnitedKingdom => "uk-west-1",
            Self::HongKong => "hk-east-1",
            Self::Switzerland => "ch-central-1",
            Self::Japan => "jp-east-1",
        }
    }
}

impl fmt::Display for Jurisdiction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Uae => write!(f, "United Arab Emirates"),
            Self::Singapore => write!(f, "Singapore"),
            Self::EuropeanUnion => write!(f, "European Union"),
            Self::UnitedStates => write!(f, "United States"),
            Self::UnitedKingdom => write!(f, "United Kingdom"),
            Self::HongKong => write!(f, "Hong Kong"),
            Self::Switzerland => write!(f, "Switzerland"),
            Self::Japan => write!(f, "Japan"),
        }
    }
}

/// Compliance standard required for data processing
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ComplianceStandard {
    /// UAE Central Bank regulations
    UaeCentralBank,
    /// UAE Data Protection Law (Federal Decree-Law No. 45 of 2021)
    UaeDataLaw,
    /// MAS Notice 655 - Technology Risk Management
    MasSingapore,
    /// Singapore Personal Data Protection Act
    SingaporePdpa,
    /// EU General Data Protection Regulation
    EuGdpr,
    /// US Bank Secrecy Act / AML
    UsBsaAml,
    /// Basel III Capital Requirements
    BaselIii,
    /// SWIFT Customer Security Programme
    SwiftCsp,
    /// ISO 27001 Information Security
    Iso27001,
    /// SOC 2 Type II
    Soc2TypeIi,
    /// PCI-DSS for payment data
    PciDss,
}

impl ComplianceStandard {
    /// Get standards required for a jurisdiction
    pub fn for_jurisdiction(jurisdiction: Jurisdiction) -> Vec<Self> {
        match jurisdiction {
            Jurisdiction::Uae => vec![
                Self::UaeCentralBank,
                Self::UaeDataLaw,
                Self::BaselIii,
                Self::SwiftCsp,
            ],
            Jurisdiction::Singapore => vec![
                Self::MasSingapore,
                Self::SingaporePdpa,
                Self::BaselIii,
                Self::SwiftCsp,
            ],
            Jurisdiction::EuropeanUnion => vec![
                Self::EuGdpr,
                Self::BaselIii,
                Self::SwiftCsp,
                Self::PciDss,
            ],
            Jurisdiction::UnitedStates => vec![
                Self::UsBsaAml,
                Self::BaselIii,
                Self::SwiftCsp,
                Self::Soc2TypeIi,
            ],
            _ => vec![Self::BaselIii, Self::SwiftCsp],
        }
    }

    /// Get display name
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::UaeCentralBank => "UAE Central Bank Regulations",
            Self::UaeDataLaw => "UAE Federal Data Protection Law",
            Self::MasSingapore => "MAS Technology Risk Management",
            Self::SingaporePdpa => "Singapore PDPA",
            Self::EuGdpr => "EU GDPR",
            Self::UsBsaAml => "US BSA/AML",
            Self::BaselIii => "Basel III",
            Self::SwiftCsp => "SWIFT CSP",
            Self::Iso27001 => "ISO 27001",
            Self::Soc2TypeIi => "SOC 2 Type II",
            Self::PciDss => "PCI-DSS",
        }
    }
}

// =============================================================================
// CURRENCY & FINANCIAL
// =============================================================================

/// ISO 4217 currency codes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Currency {
    /// United Arab Emirates Dirham
    Aed,
    /// Singapore Dollar
    Sgd,
    /// United States Dollar
    Usd,
    /// Euro
    Eur,
    /// British Pound Sterling
    Gbp,
    /// Swiss Franc
    Chf,
    /// Japanese Yen
    Jpy,
    /// Chinese Yuan Renminbi
    Cny,
    /// Hong Kong Dollar
    Hkd,
    /// AETHEL Token
    Aethel,
}

impl Currency {
    /// Get ISO 4217 numeric code
    pub fn numeric_code(&self) -> u16 {
        match self {
            Self::Aed => 784,
            Self::Sgd => 702,
            Self::Usd => 840,
            Self::Eur => 978,
            Self::Gbp => 826,
            Self::Chf => 756,
            Self::Jpy => 392,
            Self::Cny => 156,
            Self::Hkd => 344,
            Self::Aethel => 999, // Custom code
        }
    }

    /// Get decimal places for this currency
    pub fn decimal_places(&self) -> u8 {
        match self {
            Self::Jpy => 0, // Yen has no decimal places
            Self::Aethel => 18, // 18 decimals like ETH
            _ => 2, // Most currencies have 2 decimal places
        }
    }

    /// Get currency symbol
    pub fn symbol(&self) -> &'static str {
        match self {
            Self::Aed => "د.إ",
            Self::Sgd => "S$",
            Self::Usd => "$",
            Self::Eur => "€",
            Self::Gbp => "£",
            Self::Chf => "CHF",
            Self::Jpy => "¥",
            Self::Cny => "¥",
            Self::Hkd => "HK$",
            Self::Aethel => "AETH",
        }
    }
}

impl fmt::Display for Currency {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Aed => write!(f, "AED"),
            Self::Sgd => write!(f, "SGD"),
            Self::Usd => write!(f, "USD"),
            Self::Eur => write!(f, "EUR"),
            Self::Gbp => write!(f, "GBP"),
            Self::Chf => write!(f, "CHF"),
            Self::Jpy => write!(f, "JPY"),
            Self::Cny => write!(f, "CNY"),
            Self::Hkd => write!(f, "HKD"),
            Self::Aethel => write!(f, "AETHEL"),
        }
    }
}

/// Monetary amount with currency
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonetaryAmount {
    /// Amount value
    pub amount: CurrencyAmount,
    /// Currency code
    pub currency: Currency,
}

impl MonetaryAmount {
    /// Create new monetary amount
    pub fn new(amount: CurrencyAmount, currency: Currency) -> Self {
        Self { amount, currency }
    }

    /// Create from USD
    pub fn usd(amount: impl Into<Decimal>) -> Self {
        Self::new(amount.into(), Currency::Usd)
    }

    /// Create from AED
    pub fn aed(amount: impl Into<Decimal>) -> Self {
        Self::new(amount.into(), Currency::Aed)
    }

    /// Create from SGD
    pub fn sgd(amount: impl Into<Decimal>) -> Self {
        Self::new(amount.into(), Currency::Sgd)
    }

    /// Format with currency symbol
    pub fn formatted(&self) -> String {
        format!("{} {:.2}", self.currency.symbol(), self.amount)
    }
}

impl fmt::Display for MonetaryAmount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:.2} {}", self.amount, self.currency)
    }
}

// =============================================================================
// BANK & PARTICIPANT IDENTIFIERS
// =============================================================================

/// Bank identification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BankIdentifier {
    /// SWIFT/BIC code (8 or 11 characters)
    pub swift_code: String,
    /// Legal Entity Identifier (LEI) - 20 characters
    pub lei: Option<String>,
    /// Bank name
    pub name: String,
    /// Headquarters jurisdiction
    pub jurisdiction: Jurisdiction,
    /// Aethelred node ID
    pub node_id: String,
}

impl BankIdentifier {
    /// First Abu Dhabi Bank
    pub fn fab() -> Self {
        Self {
            swift_code: "NBABORWEXXX".to_string(), // FAB International
            lei: Some("549300UQMM86VQQNP093".to_string()),
            name: "First Abu Dhabi Bank".to_string(),
            jurisdiction: Jurisdiction::Uae,
            node_id: "fab-uae-primary".to_string(),
        }
    }

    /// DBS Bank Singapore
    pub fn dbs() -> Self {
        Self {
            swift_code: "DBSSSGSGXXX".to_string(),
            lei: Some("789QEUWQP9GMPVL44N49".to_string()),
            name: "DBS Bank Ltd".to_string(),
            jurisdiction: Jurisdiction::Singapore,
            node_id: "dbs-sg-primary".to_string(),
        }
    }

    /// Validate SWIFT code format
    pub fn is_valid_swift(&self) -> bool {
        let len = self.swift_code.len();
        (len == 8 || len == 11) && self.swift_code.chars().all(|c| c.is_alphanumeric())
    }
}

/// Trade participant (company/entity)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TradeParticipant {
    /// Unique identifier
    pub id: Uuid,
    /// Legal name
    pub legal_name: String,
    /// Trading name (if different)
    pub trading_name: Option<String>,
    /// Company registration number
    pub registration_number: String,
    /// Tax ID / VAT number
    pub tax_id: Option<String>,
    /// LEI (Legal Entity Identifier)
    pub lei: Option<String>,
    /// Jurisdiction of incorporation
    pub jurisdiction: Jurisdiction,
    /// Primary bank relationship
    pub bank: BankIdentifier,
    /// Industry classification (ISIC Rev.4)
    pub industry_code: String,
    /// Address
    pub address: Address,
    /// Contact information
    pub contact: ContactInfo,
    /// Risk rating (internal bank rating)
    pub risk_rating: Option<RiskRating>,
    /// Sanctions screening status
    pub sanctions_status: SanctionsStatus,
    /// KYC completion date
    pub kyc_verified_at: Option<DateTime<Utc>>,
}

/// Physical address
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Address {
    pub street_line_1: String,
    pub street_line_2: Option<String>,
    pub city: String,
    pub state_province: Option<String>,
    pub postal_code: String,
    pub country_code: String,
}

/// Contact information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactInfo {
    pub primary_name: String,
    pub primary_email: String,
    pub primary_phone: String,
    pub finance_email: Option<String>,
}

/// Internal risk rating
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RiskRating {
    /// Lowest risk - Investment grade
    Aaa,
    Aa,
    A,
    /// Medium risk
    Bbb,
    Bb,
    B,
    /// High risk - Speculative grade
    Ccc,
    Cc,
    C,
    /// Default
    D,
}

impl RiskRating {
    /// Numeric score (100 = best, 0 = worst)
    pub fn score(&self) -> u8 {
        match self {
            Self::Aaa => 100,
            Self::Aa => 95,
            Self::A => 85,
            Self::Bbb => 75,
            Self::Bb => 60,
            Self::B => 45,
            Self::Ccc => 30,
            Self::Cc => 15,
            Self::C => 5,
            Self::D => 0,
        }
    }

    /// Check if investment grade
    pub fn is_investment_grade(&self) -> bool {
        matches!(self, Self::Aaa | Self::Aa | Self::A | Self::Bbb)
    }
}

/// Sanctions screening status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SanctionsStatus {
    /// Overall status
    pub status: SanctionsResult,
    /// Last screening date
    pub screened_at: DateTime<Utc>,
    /// Lists checked
    pub lists_checked: Vec<SanctionsList>,
    /// Any potential matches requiring review
    pub potential_matches: u32,
    /// Screening provider
    pub provider: String,
}

/// Sanctions screening result
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SanctionsResult {
    /// Clear - no matches
    Clear,
    /// Potential match requiring review
    PotentialMatch,
    /// Confirmed match - blocked
    Match,
    /// Screening pending
    Pending,
}

/// Sanctions lists checked
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SanctionsList {
    /// UN Security Council
    UnSc,
    /// US OFAC SDN
    UsOfacSdn,
    /// EU Consolidated List
    EuConsolidated,
    /// UK HM Treasury
    UkHmTreasury,
    /// UAE Local Terrorist List
    UaeLocalList,
    /// Singapore MAS List
    SgMasList,
}

// =============================================================================
// LETTER OF CREDIT TYPES
// =============================================================================

/// Letter of Credit type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LetterOfCreditType {
    /// Irrevocable Documentary LC
    IrrevocableDocumentary,
    /// Standby Letter of Credit (SBLC)
    Standby,
    /// Revocable LC (rare)
    Revocable,
    /// Transferable LC
    Transferable,
    /// Back-to-Back LC
    BackToBack,
    /// Revolving LC
    Revolving,
    /// Red Clause LC (advance payment)
    RedClause,
    /// Green Clause LC (storage financing)
    GreenClause,
}

impl LetterOfCreditType {
    /// Get UCP 600 article reference
    pub fn ucp_reference(&self) -> &'static str {
        match self {
            Self::IrrevocableDocumentary => "UCP 600 Article 2",
            Self::Standby => "ISP98 / UCP 600",
            Self::Revocable => "UCP 600 Article 3",
            Self::Transferable => "UCP 600 Article 38",
            Self::BackToBack => "UCP 600 (Master/Secondary)",
            Self::Revolving => "UCP 600 Article 6",
            Self::RedClause => "UCP 600 + Custom Clause",
            Self::GreenClause => "UCP 600 + Custom Clause",
        }
    }
}

/// Letter of Credit status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LcStatus {
    /// Draft - not yet issued
    Draft,
    /// Pending approval
    PendingApproval,
    /// Issued - active
    Issued,
    /// Documents presented
    DocumentsPresented,
    /// Documents accepted
    DocumentsAccepted,
    /// Discrepancy found
    Discrepancy,
    /// Payment due
    PaymentDue,
    /// Paid - completed
    Paid,
    /// Expired without draw
    Expired,
    /// Cancelled
    Cancelled,
    /// Amended
    Amended,
}

/// Complete Letter of Credit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LetterOfCredit {
    /// Unique LC reference number
    pub reference: String,
    /// Blockchain hash of the LC
    pub blockchain_hash: Option<Hash>,
    /// LC Type
    pub lc_type: LetterOfCreditType,
    /// Current status
    pub status: LcStatus,

    // === PARTIES ===
    /// Applicant (buyer/importer)
    pub applicant: TradeParticipant,
    /// Beneficiary (seller/exporter)
    pub beneficiary: TradeParticipant,
    /// Issuing bank
    pub issuing_bank: BankIdentifier,
    /// Advising bank
    pub advising_bank: BankIdentifier,
    /// Confirming bank (if confirmed)
    pub confirming_bank: Option<BankIdentifier>,
    /// Nominated bank for payment
    pub nominated_bank: Option<BankIdentifier>,

    // === FINANCIAL TERMS ===
    /// LC amount
    pub amount: MonetaryAmount,
    /// Tolerance percentage (+/-)
    pub tolerance_percent: Option<Decimal>,
    /// Availability type
    pub availability: LcAvailability,

    // === DATES ===
    /// Issue date
    pub issue_date: DateTime<Utc>,
    /// Expiry date
    pub expiry_date: DateTime<Utc>,
    /// Latest shipment date
    pub latest_shipment_date: DateTime<Utc>,
    /// Document presentation period (days after shipment)
    pub presentation_period_days: u8,

    // === SHIPMENT ===
    /// Port of loading
    pub port_of_loading: String,
    /// Port of discharge
    pub port_of_discharge: String,
    /// Goods description
    pub goods_description: String,
    /// Incoterms (e.g., "CIF", "FOB")
    pub incoterms: Incoterms,
    /// Partial shipments allowed
    pub partial_shipments_allowed: bool,
    /// Transhipment allowed
    pub transhipment_allowed: bool,

    // === DOCUMENTS REQUIRED ===
    /// Required documents
    pub required_documents: Vec<RequiredDocument>,

    // === AETHELRED SPECIFIC ===
    /// Verification proofs attached
    pub verification_proofs: Vec<VerificationProof>,
    /// Smart contract address (if minted on-chain)
    pub smart_contract_address: Option<String>,
    /// Cross-border settlement TX hash
    pub settlement_tx_hash: Option<String>,

    // === METADATA ===
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    /// Last updated
    pub updated_at: DateTime<Utc>,
    /// Amendment history
    pub amendments: Vec<LcAmendment>,
}

/// LC availability/payment method
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LcAvailability {
    /// Sight payment (immediate)
    Sight,
    /// Deferred payment (X days from shipment/presentation)
    DeferredPayment { days: u16 },
    /// Acceptance (bank accepts draft, pays at maturity)
    Acceptance { days: u16 },
    /// Negotiation
    Negotiation,
    /// Mixed payment
    MixedPayment,
}

/// Incoterms 2020
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Incoterms {
    /// Ex Works
    Exw,
    /// Free Carrier
    Fca,
    /// Carriage Paid To
    Cpt,
    /// Carriage and Insurance Paid To
    Cip,
    /// Delivered at Place
    Dap,
    /// Delivered at Place Unloaded
    Dpu,
    /// Delivered Duty Paid
    Ddp,
    /// Free Alongside Ship
    Fas,
    /// Free on Board
    Fob,
    /// Cost and Freight
    Cfr,
    /// Cost, Insurance and Freight
    Cif,
}

impl fmt::Display for Incoterms {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exw => write!(f, "EXW"),
            Self::Fca => write!(f, "FCA"),
            Self::Cpt => write!(f, "CPT"),
            Self::Cip => write!(f, "CIP"),
            Self::Dap => write!(f, "DAP"),
            Self::Dpu => write!(f, "DPU"),
            Self::Ddp => write!(f, "DDP"),
            Self::Fas => write!(f, "FAS"),
            Self::Fob => write!(f, "FOB"),
            Self::Cfr => write!(f, "CFR"),
            Self::Cif => write!(f, "CIF"),
        }
    }
}

/// Required document specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequiredDocument {
    /// Document type
    pub document_type: DocumentType,
    /// Number of originals required
    pub originals_required: u8,
    /// Number of copies required
    pub copies_required: u8,
    /// Specific requirements/clauses
    pub special_requirements: Vec<String>,
    /// Must be presented within days of shipment
    pub presentation_deadline_days: Option<u8>,
}

/// Trade document types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DocumentType {
    /// Commercial Invoice
    CommercialInvoice,
    /// Packing List
    PackingList,
    /// Bill of Lading (marine)
    BillOfLading,
    /// Airway Bill
    AirwayBill,
    /// Certificate of Origin
    CertificateOfOrigin,
    /// Insurance Certificate/Policy
    InsuranceCertificate,
    /// Inspection Certificate
    InspectionCertificate,
    /// Phytosanitary Certificate
    PhytosanitaryCertificate,
    /// Weight Certificate
    WeightCertificate,
    /// Quality Certificate
    QualityCertificate,
    /// Beneficiary Certificate
    BeneficiaryCertificate,
    /// Draft/Bill of Exchange
    BillOfExchange,
}

/// LC Amendment record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LcAmendment {
    /// Amendment number
    pub number: u16,
    /// Amendment date
    pub date: DateTime<Utc>,
    /// Description of changes
    pub changes: Vec<String>,
    /// Accepted by beneficiary
    pub beneficiary_accepted: bool,
    /// Amendment fee
    pub fee: Option<MonetaryAmount>,
}

// =============================================================================
// VERIFICATION & PROOFS
// =============================================================================

/// Verification proof from Aethelred
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationProof {
    /// Proof ID
    pub id: Uuid,
    /// Proof type
    pub proof_type: ProofType,
    /// Cryptographic proof bytes
    pub proof_bytes: ProofBytes,
    /// Proof hash (for quick verification)
    pub proof_hash: Hash,
    /// Generation timestamp
    pub generated_at: DateTime<Utc>,
    /// Expiry (proofs have limited validity)
    pub expires_at: DateTime<Utc>,
    /// Node that generated the proof
    pub generating_node: String,
    /// Jurisdiction where data was processed
    pub data_jurisdiction: Jurisdiction,
    /// Compliance standards met
    pub compliance_met: Vec<ComplianceStandard>,
    /// Verification method used
    pub verification_method: VerificationMethod,
    /// Result summary (non-sensitive)
    pub result_summary: ProofResultSummary,
}

/// Types of verification proofs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProofType {
    /// AML/Sanctions screening passed
    SanctionsCheck,
    /// Credit scoring completed
    CreditScore,
    /// Document authenticity verified
    DocumentVerification,
    /// Identity verification (KYC)
    IdentityVerification,
    /// Trade data validation
    TradeDataValidation,
    /// Financial statement analysis
    FinancialAnalysis,
    /// Risk assessment
    RiskAssessment,
}

/// Verification method used
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VerificationMethod {
    /// Trusted Execution Environment
    TeeEnclave,
    /// Zero-Knowledge Proof
    ZeroKnowledge,
    /// Hybrid (TEE + ZK)
    Hybrid,
    /// AI/ML model verification
    AiProof,
    /// Multi-party computation
    Mpc,
}

/// Non-sensitive summary of proof result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofResultSummary {
    /// Overall pass/fail
    pub passed: bool,
    /// Confidence score (0-100)
    pub confidence_score: u8,
    /// Risk level
    pub risk_level: RiskLevel,
    /// Summary text (no sensitive data)
    pub summary_text: String,
    /// Flags/warnings
    pub flags: Vec<String>,
}

/// Risk level classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

// =============================================================================
// TRADE DEAL
// =============================================================================

/// Complete trade deal encompassing all parties and instruments
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TradeDeal {
    /// Deal ID
    pub id: Uuid,
    /// Deal reference (human readable)
    pub reference: String,
    /// Deal status
    pub status: DealStatus,

    // === PARTIES ===
    /// Exporter (seller)
    pub exporter: TradeParticipant,
    /// Importer (buyer)
    pub importer: TradeParticipant,
    /// Exporter's bank
    pub exporter_bank: BankIdentifier,
    /// Importer's bank
    pub importer_bank: BankIdentifier,

    // === COMMERCIAL TERMS ===
    /// Goods/services description
    pub goods_description: String,
    /// Quantity
    pub quantity: String,
    /// Unit price
    pub unit_price: MonetaryAmount,
    /// Total value
    pub total_value: MonetaryAmount,
    /// Incoterms
    pub incoterms: Incoterms,

    // === FINANCING ===
    /// Letter of Credit (if applicable)
    pub letter_of_credit: Option<LetterOfCredit>,
    /// Bank guarantees
    pub guarantees: Vec<BankGuarantee>,

    // === VERIFICATION ===
    /// Exporter verification proofs
    pub exporter_proofs: Vec<VerificationProof>,
    /// Importer verification proofs
    pub importer_proofs: Vec<VerificationProof>,
    /// Cross-verification proof (final settlement proof)
    pub settlement_proof: Option<VerificationProof>,

    // === BLOCKCHAIN ===
    /// On-chain settlement status
    pub blockchain_status: BlockchainStatus,
    /// Settlement transaction hash
    pub settlement_tx_hash: Option<String>,
    /// Smart contract address
    pub smart_contract_address: Option<String>,
    /// Gas/fees paid
    pub settlement_fees: Option<MonetaryAmount>,

    // === TIMELINE ===
    /// Deal creation
    pub created_at: DateTime<Utc>,
    /// Last update
    pub updated_at: DateTime<Utc>,
    /// Expected completion
    pub expected_completion: DateTime<Utc>,
    /// Actual completion
    pub completed_at: Option<DateTime<Utc>>,

    // === AUDIT ===
    /// Audit trail
    pub audit_trail: Vec<AuditEntry>,
}

/// Deal status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DealStatus {
    /// Initial draft
    Draft,
    /// Exporter verification in progress
    ExporterVerificationPending,
    /// Exporter verified
    ExporterVerified,
    /// Importer verification in progress
    ImporterVerificationPending,
    /// Importer verified
    ImporterVerified,
    /// Both parties verified - ready for LC
    ReadyForLc,
    /// LC issued
    LcIssued,
    /// Shipment in progress
    ShipmentInProgress,
    /// Documents presented
    DocumentsPresented,
    /// Settlement in progress
    SettlementPending,
    /// Completed successfully
    Completed,
    /// Cancelled
    Cancelled,
    /// Dispute
    Dispute,
}

/// Blockchain settlement status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockchainStatus {
    /// Is the deal recorded on-chain
    pub on_chain: bool,
    /// Network (mainnet/testnet)
    pub network: String,
    /// Contract version
    pub contract_version: String,
    /// Block height of last update
    pub last_block_height: Option<u64>,
    /// Confirmations
    pub confirmations: u32,
    /// Finalized
    pub finalized: bool,
}

/// Bank guarantee
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BankGuarantee {
    /// Guarantee reference
    pub reference: String,
    /// Guarantee type
    pub guarantee_type: GuaranteeType,
    /// Amount
    pub amount: MonetaryAmount,
    /// Issuing bank
    pub issuing_bank: BankIdentifier,
    /// Beneficiary
    pub beneficiary: TradeParticipant,
    /// Issue date
    pub issue_date: DateTime<Utc>,
    /// Expiry date
    pub expiry_date: DateTime<Utc>,
    /// Status
    pub status: GuaranteeStatus,
}

/// Types of bank guarantees
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GuaranteeType {
    /// Performance guarantee
    Performance,
    /// Bid bond
    BidBond,
    /// Advance payment guarantee
    AdvancePayment,
    /// Retention guarantee
    Retention,
    /// Payment guarantee
    Payment,
    /// Warranty guarantee
    Warranty,
}

/// Guarantee status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GuaranteeStatus {
    Draft,
    Issued,
    Extended,
    ClaimMade,
    ClaimPaid,
    Expired,
    Cancelled,
    Released,
}

/// Audit trail entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Entry ID
    pub id: Uuid,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Action type
    pub action: AuditAction,
    /// Actor (who performed the action)
    pub actor: String,
    /// Actor's jurisdiction
    pub actor_jurisdiction: Jurisdiction,
    /// Description
    pub description: String,
    /// Associated data hash (for integrity)
    pub data_hash: Option<Hash>,
    /// IP address (hashed for privacy)
    pub ip_hash: Option<Hash>,
}

/// Audit action types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AuditAction {
    Created,
    Updated,
    Viewed,
    Downloaded,
    Verified,
    Approved,
    Rejected,
    Submitted,
    Signed,
    Settled,
}

// =============================================================================
// AI JOB TYPES (AETHELRED SPECIFIC)
// =============================================================================

/// AI job for trade finance verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TradeVerificationJob {
    /// Job ID
    pub id: Uuid,
    /// Job type
    pub job_type: TradeJobType,
    /// Status
    pub status: JobStatus,
    /// Model ID used
    pub model_id: String,
    /// Input data hash (data never leaves jurisdiction)
    pub input_hash: Hash,
    /// Processing jurisdiction
    pub jurisdiction: Jurisdiction,
    /// Compliance requirements
    pub compliance_requirements: Vec<ComplianceStandard>,
    /// Service Level Agreement
    pub sla: JobSla,
    /// Submitted at
    pub submitted_at: DateTime<Utc>,
    /// Started processing at
    pub started_at: Option<DateTime<Utc>>,
    /// Completed at
    pub completed_at: Option<DateTime<Utc>>,
    /// Result (proof hash only)
    pub result_proof_hash: Option<Hash>,
    /// Processing node
    pub processing_node: Option<String>,
}

/// Types of trade verification jobs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TradeJobType {
    /// AML/Sanctions screening
    AmlSanctionsCheck,
    /// Credit score calculation
    CreditScoring,
    /// Financial statement analysis
    FinancialAnalysis,
    /// Document verification (OCR + fraud detection)
    DocumentVerification,
    /// Trade data validation
    TradeDataValidation,
    /// Risk assessment
    RiskAssessment,
    /// Identity verification
    IdentityVerification,
}

/// Job status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum JobStatus {
    Queued,
    Processing,
    Completed,
    Failed,
    Cancelled,
    TimedOut,
}

/// Service Level Agreement for job
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobSla {
    /// Maximum processing time (seconds)
    pub max_processing_time_secs: u32,
    /// Privacy level
    pub privacy_level: PrivacyLevel,
    /// Required verification method
    pub verification_method: VerificationMethod,
    /// Minimum confidence threshold
    pub min_confidence: u8,
}

/// Privacy level for processing
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PrivacyLevel {
    /// Standard processing
    Standard,
    /// TEE enclave only
    TeeEnclave,
    /// Zero-knowledge (no data visibility)
    ZeroKnowledge,
    /// Multi-party computation
    Mpc,
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use rust_decimal_macros::dec;

    #[test]
    fn test_jurisdiction_regions() {
        assert_eq!(Jurisdiction::Uae.node_region(), "uae-north-1");
        assert_eq!(Jurisdiction::Singapore.node_region(), "sg-south-1");
    }

    #[test]
    fn test_compliance_for_jurisdiction() {
        let uae_standards = ComplianceStandard::for_jurisdiction(Jurisdiction::Uae);
        assert!(uae_standards.contains(&ComplianceStandard::UaeCentralBank));
        assert!(uae_standards.contains(&ComplianceStandard::UaeDataLaw));

        let sg_standards = ComplianceStandard::for_jurisdiction(Jurisdiction::Singapore);
        assert!(sg_standards.contains(&ComplianceStandard::MasSingapore));
        assert!(sg_standards.contains(&ComplianceStandard::SingaporePdpa));
    }

    #[test]
    fn test_monetary_amount() {
        let amount = MonetaryAmount::usd(dec!(5_000_000));
        assert_eq!(amount.currency, Currency::Usd);
        assert_eq!(amount.formatted(), "$ 5,000,000.00");
    }

    #[test]
    fn test_bank_identifiers() {
        let fab = BankIdentifier::fab();
        assert!(fab.is_valid_swift());
        assert_eq!(fab.jurisdiction, Jurisdiction::Uae);

        let dbs = BankIdentifier::dbs();
        assert!(dbs.is_valid_swift());
        assert_eq!(dbs.jurisdiction, Jurisdiction::Singapore);
    }

    #[test]
    fn test_risk_rating() {
        assert!(RiskRating::Aaa.is_investment_grade());
        assert!(RiskRating::Bbb.is_investment_grade());
        assert!(!RiskRating::Bb.is_investment_grade());
        assert!(!RiskRating::Ccc.is_investment_grade());
    }

    #[test]
    fn test_incoterms_display() {
        assert_eq!(format!("{}", Incoterms::Cif), "CIF");
        assert_eq!(format!("{}", Incoterms::Fob), "FOB");
    }
}
