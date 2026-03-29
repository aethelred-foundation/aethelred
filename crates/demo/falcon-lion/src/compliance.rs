//! # Multi-Jurisdiction Compliance Engine
//!
//! Enterprise-grade compliance verification engine supporting cross-border
//! trade finance between UAE and Singapore regulatory frameworks.
//!
//! ## Supported Regulations
//!
//! - **UAE Central Bank**: AML/CFT, Correspondent Banking Due Diligence
//! - **UAE Data Law**: Federal Decree-Law No. 45 of 2021 on Personal Data Protection
//! - **MAS Singapore**: Notice 655 Technology Risk Management, AML/CFT
//! - **Singapore PDPA**: Personal Data Protection Act 2012
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────────────────────┐
//! │                      MULTI-JURISDICTION COMPLIANCE ENGINE                                │
//! ├─────────────────────────────────────────────────────────────────────────────────────────┤
//! │                                                                                          │
//! │  ┌───────────────────────────────────────────────────────────────────────────────────┐  │
//! │  │                        DATA SOVEREIGNTY LAYER                                      │  │
//! │  │                                                                                    │  │
//! │  │   ┌─────────────────────┐              ┌─────────────────────┐                    │  │
//! │  │   │  UAE DATA VAULT     │              │  SG DATA VAULT      │                    │  │
//! │  │   │                     │    PROOFS    │                     │                    │  │
//! │  │   │  - Customer PII     │──────────────│  - Customer PII     │                    │  │
//! │  │   │  - Financial Data   │   (Only)     │  - Financial Data   │                    │  │
//! │  │   │  - Trade Records    │◄─────────────│  - Trade Records    │                    │  │
//! │  │   │                     │              │                     │                    │  │
//! │  │   │  🔒 TEE Protected   │              │  🔒 TEE Protected   │                    │  │
//! │  │   └─────────────────────┘              └─────────────────────┘                    │  │
//! │  │                                                                                    │  │
//! │  └───────────────────────────────────────────────────────────────────────────────────┘  │
//! │                                         │                                                │
//! │                                         ▼                                                │
//! │  ┌───────────────────────────────────────────────────────────────────────────────────┐  │
//! │  │                      COMPLIANCE VERIFICATION MODULES                               │  │
//! │  │                                                                                    │  │
//! │  │   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │  │
//! │  │   │ SANCTIONS   │  │   AML/CFT   │  │ KYC/CDD     │  │ DATA        │             │  │
//! │  │   │ SCREENING   │  │ MONITORING  │  │ VALIDATION  │  │ PROTECTION  │             │  │
//! │  │   └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘             │  │
//! │  │                                                                                    │  │
//! │  └───────────────────────────────────────────────────────────────────────────────────┘  │
//! │                                         │                                                │
//! │                                         ▼                                                │
//! │  ┌───────────────────────────────────────────────────────────────────────────────────┐  │
//! │  │                      CRYPTOGRAPHIC PROOF GENERATION                                │  │
//! │  │                                                                                    │  │
//! │  │   Input: Sensitive Data (in TEE)                                                  │  │
//! │  │   Output: Zero-Knowledge Proof + Audit Hash                                       │  │
//! │  │   Guarantee: Data NEVER leaves jurisdiction                                       │  │
//! │  │                                                                                    │  │
//! │  └───────────────────────────────────────────────────────────────────────────────────┘  │
//! │                                                                                          │
//! └─────────────────────────────────────────────────────────────────────────────────────────┘
//! ```

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::{FalconLionError, FalconLionResult};
use crate::types::{
    ComplianceStandard, Hash, Jurisdiction, ProofBytes, ProofResultSummary, ProofType, RiskLevel,
    SanctionsList, TradeParticipant, VerificationMethod, VerificationProof,
};

// =============================================================================
// CONSTANTS
// =============================================================================

/// Proof validity duration (24 hours)
pub const PROOF_VALIDITY_HOURS: i64 = 24;

/// Maximum acceptable risk score for automatic approval
pub const AUTO_APPROVAL_MAX_RISK_SCORE: u8 = 30;

/// Minimum confidence for proof acceptance
pub const MIN_PROOF_CONFIDENCE: u8 = 85;

// =============================================================================
// COMPLIANCE POLICY
// =============================================================================

/// Compliance policy for a specific jurisdiction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompliancePolicy {
    /// Jurisdiction this policy applies to
    pub jurisdiction: Jurisdiction,
    /// Required compliance standards
    pub required_standards: Vec<ComplianceStandard>,
    /// Sanctions lists to check
    pub sanctions_lists: Vec<SanctionsList>,
    /// Data retention period (days)
    pub data_retention_days: u32,
    /// KYC refresh period (days)
    pub kyc_refresh_days: u32,
    /// Enhanced due diligence threshold (risk score)
    pub edd_threshold: u8,
    /// Automatic block threshold (risk score)
    pub auto_block_threshold: u8,
    /// Required verification methods
    pub required_verification: Vec<VerificationMethod>,
    /// Cross-border data transfer allowed
    pub cross_border_allowed: bool,
    /// Consent requirements
    pub consent_requirements: ConsentRequirements,
    /// Audit requirements
    pub audit_requirements: AuditRequirements,
}

impl CompliancePolicy {
    /// UAE Central Bank / UAE Data Law policy
    pub fn uae() -> Self {
        Self {
            jurisdiction: Jurisdiction::Uae,
            required_standards: vec![
                ComplianceStandard::UaeCentralBank,
                ComplianceStandard::UaeDataLaw,
                ComplianceStandard::BaselIii,
                ComplianceStandard::SwiftCsp,
            ],
            sanctions_lists: vec![
                SanctionsList::UnSc,
                SanctionsList::UsOfacSdn,
                SanctionsList::UaeLocalList,
            ],
            data_retention_days: 365 * 5, // 5 years
            kyc_refresh_days: 365,        // Annual refresh
            edd_threshold: 50,
            auto_block_threshold: 80,
            required_verification: vec![VerificationMethod::TeeEnclave],
            cross_border_allowed: false, // Data must stay in UAE
            consent_requirements: ConsentRequirements {
                explicit_consent_required: true,
                purpose_limitation: true,
                data_minimization: true,
                right_to_erasure: true,
                breach_notification_hours: 72,
            },
            audit_requirements: AuditRequirements {
                real_time_logging: true,
                tamper_proof: true,
                regulator_access: true,
                retention_years: 7,
            },
        }
    }

    /// MAS Singapore / PDPA policy
    pub fn singapore() -> Self {
        Self {
            jurisdiction: Jurisdiction::Singapore,
            required_standards: vec![
                ComplianceStandard::MasSingapore,
                ComplianceStandard::SingaporePdpa,
                ComplianceStandard::BaselIii,
                ComplianceStandard::SwiftCsp,
            ],
            sanctions_lists: vec![
                SanctionsList::UnSc,
                SanctionsList::UsOfacSdn,
                SanctionsList::SgMasList,
            ],
            data_retention_days: 365 * 5, // 5 years
            kyc_refresh_days: 365,        // Annual refresh
            edd_threshold: 50,
            auto_block_threshold: 80,
            required_verification: vec![VerificationMethod::TeeEnclave],
            cross_border_allowed: false, // Data must stay in Singapore
            consent_requirements: ConsentRequirements {
                explicit_consent_required: true,
                purpose_limitation: true,
                data_minimization: true,
                right_to_erasure: true,
                breach_notification_hours: 72,
            },
            audit_requirements: AuditRequirements {
                real_time_logging: true,
                tamper_proof: true,
                regulator_access: true,
                retention_years: 7,
            },
        }
    }

    /// Check if a verification method meets requirements
    pub fn is_verification_acceptable(&self, method: VerificationMethod) -> bool {
        // TEE and Hybrid are always acceptable
        // ZK is acceptable if TEE is not required
        match method {
            VerificationMethod::TeeEnclave | VerificationMethod::Hybrid => true,
            VerificationMethod::ZeroKnowledge => !self
                .required_verification
                .contains(&VerificationMethod::TeeEnclave),
            VerificationMethod::AiProof | VerificationMethod::Mpc => {
                self.required_verification.contains(&method)
            }
        }
    }
}

/// Consent requirements
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentRequirements {
    /// Explicit consent needed
    pub explicit_consent_required: bool,
    /// Purpose limitation applies
    pub purpose_limitation: bool,
    /// Data minimization required
    pub data_minimization: bool,
    /// Right to erasure exists
    pub right_to_erasure: bool,
    /// Breach notification deadline (hours)
    pub breach_notification_hours: u32,
}

/// Audit requirements
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRequirements {
    /// Real-time logging required
    pub real_time_logging: bool,
    /// Tamper-proof audit trail
    pub tamper_proof: bool,
    /// Regulator access to audit logs
    pub regulator_access: bool,
    /// Retention period (years)
    pub retention_years: u32,
}

// =============================================================================
// COMPLIANCE ENGINE
// =============================================================================

/// Multi-jurisdiction compliance verification engine
pub struct ComplianceEngine {
    /// Policies by jurisdiction
    policies: HashMap<Jurisdiction, CompliancePolicy>,
    /// Active verification sessions
    sessions: Arc<RwLock<HashMap<Uuid, VerificationSession>>>,
    /// Proof cache
    proof_cache: Arc<RwLock<HashMap<Hash, CachedProof>>>,
    /// Sanctions database (simulated)
    sanctions_db: Arc<SanctionsDatabase>,
    /// Compliance metrics
    metrics: Arc<RwLock<ComplianceMetrics>>,
}

/// Verification session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationSession {
    /// Session ID
    pub id: Uuid,
    /// Participant being verified
    pub participant_id: Uuid,
    /// Participant jurisdiction
    pub jurisdiction: Jurisdiction,
    /// Session started at
    pub started_at: DateTime<Utc>,
    /// Session status
    pub status: SessionStatus,
    /// Checks performed
    pub checks_performed: Vec<ComplianceCheck>,
    /// Overall result
    pub result: Option<VerificationResult>,
    /// Data processing consent
    pub consent_given: bool,
    /// Audit hash
    pub audit_hash: Hash,
}

/// Session status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionStatus {
    Initialized,
    ConsentPending,
    InProgress,
    Completed,
    Failed,
    Expired,
}

/// Individual compliance check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceCheck {
    /// Check type
    pub check_type: ComplianceCheckType,
    /// Status
    pub status: CheckStatus,
    /// Started at
    pub started_at: DateTime<Utc>,
    /// Completed at
    pub completed_at: Option<DateTime<Utc>>,
    /// Processing node (jurisdiction-specific)
    pub processing_node: String,
    /// Risk score (0-100)
    pub risk_score: Option<u8>,
    /// Findings
    pub findings: Vec<Finding>,
    /// Proof generated
    pub proof_generated: bool,
}

/// Compliance check types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ComplianceCheckType {
    /// Sanctions screening
    SanctionsScreening,
    /// AML risk assessment
    AmlRiskAssessment,
    /// KYC/CDD verification
    KycVerification,
    /// Credit scoring
    CreditScoring,
    /// Document verification
    DocumentVerification,
    /// PEP screening
    PepScreening,
    /// Adverse media check
    AdverseMediaCheck,
    /// Ultimate beneficial owner check
    UboCheck,
}

/// Check status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheckStatus {
    Pending,
    InProgress,
    Passed,
    Failed,
    NeedsReview,
    Skipped,
}

/// Finding from a check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Finding ID
    pub id: Uuid,
    /// Severity
    pub severity: FindingSeverity,
    /// Category
    pub category: String,
    /// Description (sanitized, no PII)
    pub description: String,
    /// Recommended action
    pub recommended_action: String,
    /// Auto-resolvable
    pub auto_resolvable: bool,
}

/// Finding severity
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FindingSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    /// Overall passed
    pub passed: bool,
    /// Overall risk score (0-100)
    pub risk_score: u8,
    /// Risk level
    pub risk_level: RiskLevel,
    /// Confidence score
    pub confidence: u8,
    /// Standards verified
    pub standards_met: Vec<ComplianceStandard>,
    /// Total processing time (milliseconds)
    pub processing_time_ms: u64,
    /// Proof generated
    pub proof: Option<VerificationProof>,
    /// Requires manual review
    pub requires_review: bool,
    /// Review reason
    pub review_reason: Option<String>,
}

/// Cached proof for deduplication
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct CachedProof {
    proof: VerificationProof,
    cached_at: DateTime<Utc>,
    access_count: u32,
}

/// Sanctions database (simulated)
pub struct SanctionsDatabase {
    /// Blocked entities (hashed identifiers)
    blocked_hashes: RwLock<HashSet<Hash>>,
    /// Last update
    #[allow(dead_code)]
    last_update: RwLock<DateTime<Utc>>,
}

impl SanctionsDatabase {
    /// Create new sanctions database
    pub fn new() -> Self {
        Self {
            blocked_hashes: RwLock::new(HashSet::new()),
            last_update: RwLock::new(Utc::now()),
        }
    }

    /// Check if entity is sanctioned
    pub fn is_sanctioned(&self, identifier_hash: &Hash) -> bool {
        self.blocked_hashes.read().contains(identifier_hash)
    }

    /// Add sanctioned entity (for testing)
    pub fn add_sanctioned(&self, identifier: &str) {
        let hash = Self::hash_identifier(identifier);
        self.blocked_hashes.write().insert(hash);
    }

    /// Hash an identifier
    fn hash_identifier(identifier: &str) -> Hash {
        let mut hasher = Sha256::new();
        hasher.update(identifier.as_bytes());
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
}

/// Compliance metrics
#[derive(Debug, Default)]
pub struct ComplianceMetrics {
    /// Total sessions started
    pub sessions_started: u64,
    /// Sessions completed successfully
    pub sessions_completed: u64,
    /// Sessions failed
    pub sessions_failed: u64,
    /// Average processing time (ms)
    pub avg_processing_time_ms: u64,
    /// Sanctions matches found
    pub sanctions_matches: u64,
    /// Manual reviews required
    pub manual_reviews: u64,
    /// Proofs generated
    pub proofs_generated: u64,
}

impl ComplianceEngine {
    /// Create new compliance engine
    pub fn new() -> Self {
        let mut policies = HashMap::new();
        policies.insert(Jurisdiction::Uae, CompliancePolicy::uae());
        policies.insert(Jurisdiction::Singapore, CompliancePolicy::singapore());

        Self {
            policies,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            proof_cache: Arc::new(RwLock::new(HashMap::new())),
            sanctions_db: Arc::new(SanctionsDatabase::new()),
            metrics: Arc::new(RwLock::new(ComplianceMetrics::default())),
        }
    }

    /// Get policy for jurisdiction
    pub fn get_policy(&self, jurisdiction: Jurisdiction) -> Option<&CompliancePolicy> {
        self.policies.get(&jurisdiction)
    }

    /// Start a new verification session
    pub fn start_session(
        &self,
        participant_id: Uuid,
        jurisdiction: Jurisdiction,
    ) -> FalconLionResult<Uuid> {
        let _policy = self
            .get_policy(jurisdiction)
            .ok_or_else(|| FalconLionError::UnsupportedJurisdiction(jurisdiction.to_string()))?;

        let session_id = Uuid::new_v4();
        let audit_hash = self.compute_audit_hash(&session_id, &participant_id);

        let session = VerificationSession {
            id: session_id,
            participant_id,
            jurisdiction,
            started_at: Utc::now(),
            status: SessionStatus::Initialized,
            checks_performed: Vec::new(),
            result: None,
            consent_given: false,
            audit_hash,
        };

        self.sessions.write().insert(session_id, session);
        self.metrics.write().sessions_started += 1;

        tracing::info!(
            session_id = %session_id,
            jurisdiction = %jurisdiction,
            "Compliance verification session started"
        );

        Ok(session_id)
    }

    /// Record data processing consent
    pub fn record_consent(&self, session_id: Uuid) -> FalconLionResult<()> {
        let mut sessions = self.sessions.write();
        let session = sessions
            .get_mut(&session_id)
            .ok_or_else(|| FalconLionError::SessionNotFound(session_id.to_string()))?;

        session.consent_given = true;
        session.status = SessionStatus::InProgress;

        tracing::info!(
            session_id = %session_id,
            "Data processing consent recorded"
        );

        Ok(())
    }

    /// Perform sanctions screening
    pub async fn perform_sanctions_check(
        &self,
        session_id: Uuid,
        participant: &TradeParticipant,
    ) -> FalconLionResult<ComplianceCheck> {
        let start_time = Utc::now();

        // Verify session exists and consent given
        {
            let sessions = self.sessions.read();
            let session = sessions
                .get(&session_id)
                .ok_or_else(|| FalconLionError::SessionNotFound(session_id.to_string()))?;

            if !session.consent_given {
                return Err(FalconLionError::ConsentNotGiven);
            }
        }

        // Simulate TEE-based sanctions screening
        // In production, this would run inside a TEE enclave
        tracing::info!(
            session_id = %session_id,
            participant = %participant.legal_name,
            "Starting sanctions screening in TEE enclave"
        );

        // Simulate processing delay (realistic for TEE)
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        // Hash the identifier for privacy-preserving lookup
        let identifier_hash = self.hash_participant_identifier(participant);

        // Check against sanctions database
        let is_sanctioned = self.sanctions_db.is_sanctioned(&identifier_hash);

        let (status, risk_score, findings) = if is_sanctioned {
            self.metrics.write().sanctions_matches += 1;
            (
                CheckStatus::Failed,
                100u8,
                vec![Finding {
                    id: Uuid::new_v4(),
                    severity: FindingSeverity::Critical,
                    category: "SANCTIONS".to_string(),
                    description: "Entity matched on sanctions list".to_string(),
                    recommended_action: "Block transaction and report to compliance".to_string(),
                    auto_resolvable: false,
                }],
            )
        } else {
            (CheckStatus::Passed, 5u8, Vec::new())
        };

        let check = ComplianceCheck {
            check_type: ComplianceCheckType::SanctionsScreening,
            status,
            started_at: start_time,
            completed_at: Some(Utc::now()),
            processing_node: self.get_processing_node(session_id)?,
            risk_score: Some(risk_score),
            findings,
            proof_generated: status == CheckStatus::Passed,
        };

        // Update session
        {
            let mut sessions = self.sessions.write();
            if let Some(session) = sessions.get_mut(&session_id) {
                session.checks_performed.push(check.clone());
            }
        }

        tracing::info!(
            session_id = %session_id,
            status = ?status,
            risk_score = risk_score,
            "Sanctions screening completed"
        );

        Ok(check)
    }

    /// Perform credit scoring
    pub async fn perform_credit_scoring(
        &self,
        session_id: Uuid,
        financial_data_hash: Hash,
    ) -> FalconLionResult<ComplianceCheck> {
        let start_time = Utc::now();

        // Verify session
        {
            let sessions = self.sessions.read();
            let session = sessions
                .get(&session_id)
                .ok_or_else(|| FalconLionError::SessionNotFound(session_id.to_string()))?;

            if !session.consent_given {
                return Err(FalconLionError::ConsentNotGiven);
            }
        }

        tracing::info!(
            session_id = %session_id,
            "Starting credit scoring in TEE enclave"
        );

        // Simulate TEE-based credit scoring
        // In production: Load model, run inference on encrypted data
        tokio::time::sleep(tokio::time::Duration::from_millis(800)).await;

        // Simulated credit score (in real system, derived from AI model)
        let credit_score = self.simulate_credit_score(&financial_data_hash);

        let risk_score = 100 - credit_score.min(100);
        let status = if credit_score >= 60 {
            CheckStatus::Passed
        } else if credit_score >= 40 {
            CheckStatus::NeedsReview
        } else {
            CheckStatus::Failed
        };

        let findings = if credit_score < 60 {
            vec![Finding {
                id: Uuid::new_v4(),
                severity: if credit_score < 40 {
                    FindingSeverity::High
                } else {
                    FindingSeverity::Medium
                },
                category: "CREDIT".to_string(),
                description: format!("Credit score {} below threshold", credit_score),
                recommended_action: "Manual review required for credit assessment".to_string(),
                auto_resolvable: false,
            }]
        } else {
            Vec::new()
        };

        let check = ComplianceCheck {
            check_type: ComplianceCheckType::CreditScoring,
            status,
            started_at: start_time,
            completed_at: Some(Utc::now()),
            processing_node: self.get_processing_node(session_id)?,
            risk_score: Some(risk_score),
            findings,
            proof_generated: true,
        };

        // Update session
        {
            let mut sessions = self.sessions.write();
            if let Some(session) = sessions.get_mut(&session_id) {
                session.checks_performed.push(check.clone());
            }
        }

        tracing::info!(
            session_id = %session_id,
            credit_score = credit_score,
            status = ?status,
            "Credit scoring completed"
        );

        Ok(check)
    }

    /// Perform KYC verification
    pub async fn perform_kyc_verification(
        &self,
        session_id: Uuid,
        participant: &TradeParticipant,
    ) -> FalconLionResult<ComplianceCheck> {
        let start_time = Utc::now();

        // Verify session
        {
            let sessions = self.sessions.read();
            let session = sessions
                .get(&session_id)
                .ok_or_else(|| FalconLionError::SessionNotFound(session_id.to_string()))?;

            if !session.consent_given {
                return Err(FalconLionError::ConsentNotGiven);
            }
        }

        tracing::info!(
            session_id = %session_id,
            "Starting KYC verification"
        );

        // Simulate KYC verification
        tokio::time::sleep(tokio::time::Duration::from_millis(600)).await;

        // Check KYC status
        let kyc_valid = participant.kyc_verified_at.is_some();
        let kyc_recent = participant
            .kyc_verified_at
            .map(|dt| Utc::now().signed_duration_since(dt).num_days() < 365)
            .unwrap_or(false);

        let (status, risk_score, findings) = if kyc_valid && kyc_recent {
            (CheckStatus::Passed, 10u8, Vec::new())
        } else if kyc_valid {
            (
                CheckStatus::NeedsReview,
                40u8,
                vec![Finding {
                    id: Uuid::new_v4(),
                    severity: FindingSeverity::Medium,
                    category: "KYC".to_string(),
                    description: "KYC verification is outdated".to_string(),
                    recommended_action: "Refresh KYC documentation".to_string(),
                    auto_resolvable: false,
                }],
            )
        } else {
            (
                CheckStatus::Failed,
                80u8,
                vec![Finding {
                    id: Uuid::new_v4(),
                    severity: FindingSeverity::High,
                    category: "KYC".to_string(),
                    description: "No valid KYC verification on record".to_string(),
                    recommended_action: "Complete KYC process before proceeding".to_string(),
                    auto_resolvable: false,
                }],
            )
        };

        let check = ComplianceCheck {
            check_type: ComplianceCheckType::KycVerification,
            status,
            started_at: start_time,
            completed_at: Some(Utc::now()),
            processing_node: self.get_processing_node(session_id)?,
            risk_score: Some(risk_score),
            findings,
            proof_generated: status == CheckStatus::Passed,
        };

        // Update session
        {
            let mut sessions = self.sessions.write();
            if let Some(session) = sessions.get_mut(&session_id) {
                session.checks_performed.push(check.clone());
            }
        }

        Ok(check)
    }

    /// Complete verification and generate proof
    pub async fn complete_verification(
        &self,
        session_id: Uuid,
    ) -> FalconLionResult<VerificationResult> {
        let start_time = std::time::Instant::now();

        let session = {
            let sessions = self.sessions.read();
            sessions
                .get(&session_id)
                .ok_or_else(|| FalconLionError::SessionNotFound(session_id.to_string()))?
                .clone()
        };

        if session.checks_performed.is_empty() {
            return Err(FalconLionError::NoChecksPerformed);
        }

        // Calculate overall result
        let total_risk: u32 = session
            .checks_performed
            .iter()
            .filter_map(|c| c.risk_score)
            .map(|s| s as u32)
            .sum();
        let avg_risk = (total_risk / session.checks_performed.len() as u32) as u8;

        let all_passed = session
            .checks_performed
            .iter()
            .all(|c| c.status == CheckStatus::Passed || c.status == CheckStatus::NeedsReview);

        let needs_review = session
            .checks_performed
            .iter()
            .any(|c| c.status == CheckStatus::NeedsReview);

        let risk_level = match avg_risk {
            0..=25 => RiskLevel::Low,
            26..=50 => RiskLevel::Medium,
            51..=75 => RiskLevel::High,
            _ => RiskLevel::Critical,
        };

        // Generate proof
        let proof = if all_passed {
            Some(self.generate_proof(&session, avg_risk, risk_level)?)
        } else {
            None
        };

        let processing_time = start_time.elapsed().as_millis() as u64;

        let result = VerificationResult {
            passed: all_passed && !needs_review,
            risk_score: avg_risk,
            risk_level,
            confidence: if all_passed { 95 } else { 50 },
            standards_met: self.get_standards_met(&session),
            processing_time_ms: processing_time,
            proof,
            requires_review: needs_review,
            review_reason: if needs_review {
                Some("One or more checks require manual review".to_string())
            } else {
                None
            },
        };

        // Update session
        {
            let mut sessions = self.sessions.write();
            if let Some(s) = sessions.get_mut(&session_id) {
                s.status = if result.passed {
                    SessionStatus::Completed
                } else {
                    SessionStatus::Failed
                };
                s.result = Some(result.clone());
            }
        }

        // Update metrics
        {
            let mut metrics = self.metrics.write();
            if result.passed {
                metrics.sessions_completed += 1;
            } else {
                metrics.sessions_failed += 1;
            }
            if result.proof.is_some() {
                metrics.proofs_generated += 1;
            }
            if result.requires_review {
                metrics.manual_reviews += 1;
            }
            // Update running average
            let total_sessions = metrics.sessions_completed + metrics.sessions_failed;
            metrics.avg_processing_time_ms =
                (metrics.avg_processing_time_ms * (total_sessions - 1) + processing_time)
                    / total_sessions;
        }

        tracing::info!(
            session_id = %session_id,
            passed = result.passed,
            risk_score = result.risk_score,
            processing_time_ms = processing_time,
            "Verification completed"
        );

        Ok(result)
    }

    /// Generate cryptographic proof
    fn generate_proof(
        &self,
        session: &VerificationSession,
        risk_score: u8,
        risk_level: RiskLevel,
    ) -> FalconLionResult<VerificationProof> {
        let now = Utc::now();
        let expiry = now + Duration::hours(PROOF_VALIDITY_HOURS);

        // Generate proof bytes (in production, this would be a real ZK proof)
        let proof_bytes = self.generate_proof_bytes(session);
        let proof_hash = self.hash_proof_bytes(&proof_bytes);

        let proof = VerificationProof {
            id: Uuid::new_v4(),
            proof_type: ProofType::SanctionsCheck, // Primary check
            proof_bytes,
            proof_hash,
            generated_at: now,
            expires_at: expiry,
            generating_node: self.get_processing_node(session.id)?,
            data_jurisdiction: session.jurisdiction,
            compliance_met: self.get_standards_met(session),
            verification_method: VerificationMethod::TeeEnclave,
            result_summary: ProofResultSummary {
                passed: true,
                confidence_score: 95,
                risk_level,
                summary_text: format!(
                    "All compliance checks passed with risk score {}",
                    risk_score
                ),
                flags: Vec::new(),
            },
        };

        // Cache the proof
        self.proof_cache.write().insert(
            proof_hash,
            CachedProof {
                proof: proof.clone(),
                cached_at: now,
                access_count: 0,
            },
        );

        Ok(proof)
    }

    /// Generate proof bytes (simulated)
    fn generate_proof_bytes(&self, session: &VerificationSession) -> ProofBytes {
        let mut hasher = Sha256::new();
        hasher.update(session.id.as_bytes());
        hasher.update(&session.audit_hash);
        hasher.update(session.started_at.to_rfc3339().as_bytes());

        for check in &session.checks_performed {
            hasher.update(&[check.check_type as u8]);
            hasher.update(&[check.status as u8]);
            if let Some(score) = check.risk_score {
                hasher.update(&[score]);
            }
        }

        let mut proof = vec![0u8; 256]; // Simulated proof size
        proof[..32].copy_from_slice(&hasher.finalize());

        // Add TEE attestation marker (simulated)
        proof[32..36].copy_from_slice(&[0x02, 0x00, 0x54, 0x45]); // "TE" for TEE

        proof
    }

    /// Hash proof bytes
    fn hash_proof_bytes(&self, bytes: &[u8]) -> Hash {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    /// Compute audit hash
    fn compute_audit_hash(&self, session_id: &Uuid, participant_id: &Uuid) -> Hash {
        let mut hasher = Sha256::new();
        hasher.update(session_id.as_bytes());
        hasher.update(participant_id.as_bytes());
        hasher.update(&Utc::now().timestamp().to_le_bytes());
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    /// Hash participant identifier
    fn hash_participant_identifier(&self, participant: &TradeParticipant) -> Hash {
        let mut hasher = Sha256::new();
        hasher.update(participant.legal_name.as_bytes());
        hasher.update(participant.registration_number.as_bytes());
        if let Some(lei) = &participant.lei {
            hasher.update(lei.as_bytes());
        }
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    /// Get processing node for jurisdiction
    fn get_processing_node(&self, session_id: Uuid) -> FalconLionResult<String> {
        let sessions = self.sessions.read();
        let session = sessions
            .get(&session_id)
            .ok_or_else(|| FalconLionError::SessionNotFound(session_id.to_string()))?;

        Ok(format!("{}-tee-node-1", session.jurisdiction.node_region()))
    }

    /// Get compliance standards met
    fn get_standards_met(&self, session: &VerificationSession) -> Vec<ComplianceStandard> {
        self.policies
            .get(&session.jurisdiction)
            .map(|p| p.required_standards.clone())
            .unwrap_or_default()
    }

    /// Simulate credit score (deterministic based on hash)
    fn simulate_credit_score(&self, data_hash: &Hash) -> u8 {
        // Use first byte of hash to generate a score 60-100
        let base = data_hash[0] as u16;
        (60 + (base % 40)) as u8
    }

    /// Get metrics
    pub fn get_metrics(&self) -> ComplianceMetrics {
        let metrics = self.metrics.read();
        ComplianceMetrics {
            sessions_started: metrics.sessions_started,
            sessions_completed: metrics.sessions_completed,
            sessions_failed: metrics.sessions_failed,
            avg_processing_time_ms: metrics.avg_processing_time_ms,
            sanctions_matches: metrics.sanctions_matches,
            manual_reviews: metrics.manual_reviews,
            proofs_generated: metrics.proofs_generated,
        }
    }

    /// Verify a proof
    pub fn verify_proof(&self, proof: &VerificationProof) -> FalconLionResult<bool> {
        // Check expiry
        if Utc::now() > proof.expires_at {
            return Ok(false);
        }

        // Verify hash matches bytes
        let computed_hash = self.hash_proof_bytes(&proof.proof_bytes);
        if computed_hash != proof.proof_hash {
            return Ok(false);
        }

        // Check TEE attestation marker
        if proof.proof_bytes.len() < 36 {
            return Ok(false);
        }
        if &proof.proof_bytes[32..36] != &[0x02, 0x00, 0x54, 0x45] {
            return Ok(false);
        }

        Ok(true)
    }
}

impl Default for ComplianceEngine {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_participant(jurisdiction: Jurisdiction) -> TradeParticipant {
        TradeParticipant {
            id: Uuid::new_v4(),
            legal_name: "Test Company".to_string(),
            trading_name: None,
            registration_number: "12345678".to_string(),
            tax_id: Some("TAX123".to_string()),
            lei: Some("549300TEST00000LEIXX".to_string()),
            jurisdiction,
            bank: if jurisdiction == Jurisdiction::Uae {
                crate::types::BankIdentifier::fab()
            } else {
                crate::types::BankIdentifier::dbs()
            },
            industry_code: "2610".to_string(), // Electronics
            address: crate::types::Address {
                street_line_1: "123 Business St".to_string(),
                street_line_2: None,
                city: "Dubai".to_string(),
                state_province: None,
                postal_code: "00000".to_string(),
                country_code: "AE".to_string(),
            },
            contact: crate::types::ContactInfo {
                primary_name: "John Doe".to_string(),
                primary_email: "john@test.com".to_string(),
                primary_phone: "+971501234567".to_string(),
                finance_email: None,
            },
            risk_rating: Some(crate::types::RiskRating::A),
            sanctions_status: crate::types::SanctionsStatus {
                status: crate::types::SanctionsResult::Clear,
                screened_at: Utc::now(),
                lists_checked: vec![crate::types::SanctionsList::UnSc],
                potential_matches: 0,
                provider: "Aethelred".to_string(),
            },
            kyc_verified_at: Some(Utc::now() - Duration::days(100)),
        }
    }

    #[test]
    fn test_compliance_policy_uae() {
        let policy = CompliancePolicy::uae();
        assert_eq!(policy.jurisdiction, Jurisdiction::Uae);
        assert!(policy
            .required_standards
            .contains(&ComplianceStandard::UaeCentralBank));
        assert!(!policy.cross_border_allowed);
    }

    #[test]
    fn test_compliance_policy_singapore() {
        let policy = CompliancePolicy::singapore();
        assert_eq!(policy.jurisdiction, Jurisdiction::Singapore);
        assert!(policy
            .required_standards
            .contains(&ComplianceStandard::MasSingapore));
        assert!(!policy.cross_border_allowed);
    }

    #[tokio::test]
    async fn test_compliance_session_workflow() {
        let engine = ComplianceEngine::new();

        // Start session
        let participant = create_test_participant(Jurisdiction::Uae);
        let session_id = engine
            .start_session(participant.id, Jurisdiction::Uae)
            .unwrap();

        // Record consent
        engine.record_consent(session_id).unwrap();

        // Run sanctions check
        let check = engine
            .perform_sanctions_check(session_id, &participant)
            .await
            .unwrap();
        assert_eq!(check.status, CheckStatus::Passed);

        // Complete verification
        let result = engine.complete_verification(session_id).await.unwrap();
        assert!(result.passed);
        assert!(result.proof.is_some());
    }

    #[test]
    fn test_sanctions_database() {
        let db = SanctionsDatabase::new();

        // Initially empty
        let test_hash = [1u8; 32];
        assert!(!db.is_sanctioned(&test_hash));

        // Add sanctioned entity
        db.add_sanctioned("SANCTIONED_ENTITY");

        // Should match the hash of the identifier
        let sanctioned_hash = SanctionsDatabase::hash_identifier("SANCTIONED_ENTITY");
        assert!(db.is_sanctioned(&sanctioned_hash));
    }

    #[test]
    fn test_verification_method_acceptance() {
        let uae_policy = CompliancePolicy::uae();

        assert!(uae_policy.is_verification_acceptable(VerificationMethod::TeeEnclave));
        assert!(uae_policy.is_verification_acceptable(VerificationMethod::Hybrid));
        // ZK alone is not acceptable when TEE is required
        assert!(!uae_policy.is_verification_acceptable(VerificationMethod::ZeroKnowledge));
    }
}
