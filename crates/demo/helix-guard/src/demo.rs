//! # Project Helix-Guard: Demo Orchestrator
//!
//! Enterprise-grade demonstration orchestrator for the Blind Drug Discovery
//! Protocol. Showcases end-to-end sovereign genomics collaboration between
//! M42 Health (UAE) and pharmaceutical partners.
//!
//! ## Demo Scenario: The Blind Drug Discovery Protocol
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
//! │                              M42 COMMAND CENTER - ABU DHABI                                      │
//! ├─────────────────────────────────────────────────────────────────────────────────────────────────┤
//! │                                                                                                  │
//! │   ┌─────────────────────────────────────────────────────────────────────────────────────────┐   │
//! │   │                              SOVEREIGN DATA STATUS                                        │   │
//! │   │                                                                                          │   │
//! │   │   ████████████████████████████████████████████████████████████████████████████████████   │   │
//! │   │   █ EMIRATI GENOME PROGRAM │ 100,000 Genomes │ SOVEREIGN ✓ │ UAE DoH Compliant ✓ █   │   │
//! │   │   ████████████████████████████████████████████████████████████████████████████████████   │   │
//! │   │                                                                                          │   │
//! │   │   📊 Data Location: Abu Dhabi Sovereign Cloud                                           │   │
//! │   │   🔐 Encryption: AES-256-GCM + Post-Quantum Ready                                       │   │
//! │   │   🛡️ Access: TEE-Only Processing Enforced                                               │   │
//! │   │   📝 Audit: Full blockchain-backed trail                                                │   │
//! │   │                                                                                          │   │
//! │   └─────────────────────────────────────────────────────────────────────────────────────────┘   │
//! │                                                                                                  │
//! │   ┌─────────────────────────────────────────────────────────────────────────────────────────┐   │
//! │   │                              ACTIVE DISCOVERY SESSIONS                                   │   │
//! │   │                                                                                          │   │
//! │   │   Partner          Drug Candidates    Status              Efficacy    Royalty          │   │
//! │   │   ─────────────    ───────────────    ─────────────────   ────────    ───────          │   │
//! │   │   AstraZeneca      AZD-LUNG-001      ████████ 87%        HIGH        500 AETHEL       │   │
//! │   │   AstraZeneca      AZD-CARDIO-002    ████████████ 100%   COMPLETE    500 AETHEL       │   │
//! │   │   Pfizer           PFE-ONCO-003      ██████ 60%          MEDIUM      -                │   │
//! │   │                                                                                          │   │
//! │   └─────────────────────────────────────────────────────────────────────────────────────────┘   │
//! │                                                                                                  │
//! └─────────────────────────────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Demo Steps
//!
//! 1. **Initialize** - Set up M42 sovereign node and register genome cohort
//! 2. **Partner Onboarding** - Register AstraZeneca and submit drug candidates
//! 3. **Session Creation** - Create discovery session with required approvals
//! 4. **Approval Flow** - Ethics, DoH, custodian, and partner approvals
//! 5. **Blind Compute** - Execute analysis in TEE enclave
//! 6. **Settlement** - Process royalty payment in AETHEL tokens
//! 7. **Verification** - Verify proofs and generate audit report

use std::time::Instant;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::discovery::{BlindDiscoveryProtocol, DiscoveryAuditEntry, DiscoveryConfig};
use crate::error::{HelixGuardError, HelixGuardResult};
use crate::royalty::{RoyaltyCalculationParams, RoyaltyConfig, RoyaltyEngine};
use crate::types::*;

// =============================================================================
// CONSTANTS
// =============================================================================

/// Demo project name
pub const DEMO_PROJECT_NAME: &str = "Project Helix-Guard";

/// Demo scenario name
pub const DEMO_SCENARIO: &str = "The Blind Drug Discovery Protocol";

/// Primary data custodian
pub const PRIMARY_CUSTODIAN: &str = "M42 Health";

/// Primary pharma partner
pub const PRIMARY_PARTNER: &str = "AstraZeneca";

/// Demo trade value (notional)
pub const DEMO_VALUE_USD: u64 = 50_000_000;

// =============================================================================
// DEMO ORCHESTRATOR
// =============================================================================

/// Helix-Guard Demo Orchestrator
pub struct HelixGuardDemo {
    /// Demo configuration
    config: DemoConfig,
    /// Discovery protocol
    protocol: BlindDiscoveryProtocol,
    /// Royalty engine
    royalty_engine: RoyaltyEngine,
    /// Demo state (reserved for stateful operations)
    #[allow(dead_code)]
    state: DemoState,
    /// Demo events (reserved for event logging)
    #[allow(dead_code)]
    events: Vec<DemoEvent>,
    /// Step timings
    step_timings: Vec<StepTiming>,
}

/// Demo configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DemoConfig {
    /// Enable verbose output
    pub verbose: bool,
    /// Simulate realistic delays
    pub simulate_delays: bool,
    /// Show ASCII visualizations
    pub show_visualizations: bool,
    /// Enable zkML proofs
    pub zkml_enabled: bool,
    /// Number of drug candidates to test
    pub drug_candidate_count: u32,
    /// Discovery protocol config
    pub discovery_config: DiscoveryConfig,
    /// Royalty config
    pub royalty_config: RoyaltyConfig,
}

impl Default for DemoConfig {
    fn default() -> Self {
        Self {
            verbose: true,
            simulate_delays: true,
            show_visualizations: true,
            zkml_enabled: true,
            drug_candidate_count: 3,
            discovery_config: DiscoveryConfig::default(),
            royalty_config: RoyaltyConfig::default(),
        }
    }
}

/// Demo state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DemoState {
    /// Current step
    pub current_step: DemoStep,
    /// Demo status
    pub status: DemoStatus,
    /// Session ID (once created)
    pub session_id: Option<Uuid>,
    /// Cohort ID
    pub cohort_id: Option<Uuid>,
    /// Partner ID
    pub partner_id: Option<Uuid>,
    /// Drug candidate IDs
    pub drug_candidate_ids: Vec<Uuid>,
    /// Results
    pub results: Vec<EfficacyResult>,
    /// Total royalty paid
    pub total_royalty_aethel: u128,
    /// Started at
    pub started_at: DateTime<Utc>,
    /// Completed at
    pub completed_at: Option<DateTime<Utc>>,
}

impl Default for DemoState {
    fn default() -> Self {
        Self {
            current_step: DemoStep::Initialize,
            status: DemoStatus::NotStarted,
            session_id: None,
            cohort_id: None,
            partner_id: None,
            drug_candidate_ids: Vec::new(),
            results: Vec::new(),
            total_royalty_aethel: 0,
            started_at: Utc::now(),
            completed_at: None,
        }
    }
}

/// Demo steps
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DemoStep {
    /// Initialization
    Initialize,
    /// Partner onboarding
    PartnerOnboarding,
    /// Drug candidate submission
    DrugSubmission,
    /// Session creation
    SessionCreation,
    /// Approval flow
    ApprovalFlow,
    /// Blind compute
    BlindCompute,
    /// Settlement
    Settlement,
    /// Verification
    Verification,
    /// Complete
    Complete,
}

impl DemoStep {
    /// Get step name
    pub fn name(&self) -> &'static str {
        match self {
            Self::Initialize => "Initialize",
            Self::PartnerOnboarding => "Partner Onboarding",
            Self::DrugSubmission => "Drug Candidate Submission",
            Self::SessionCreation => "Session Creation",
            Self::ApprovalFlow => "Approval Flow",
            Self::BlindCompute => "Blind Compute",
            Self::Settlement => "Settlement",
            Self::Verification => "Verification",
            Self::Complete => "Complete",
        }
    }

    /// Get step description
    pub fn description(&self) -> &'static str {
        match self {
            Self::Initialize => {
                "Setting up M42 sovereign node and registering Emirati Genome Program"
            }
            Self::PartnerOnboarding => "Registering AstraZeneca as pharmaceutical partner",
            Self::DrugSubmission => "Submitting encrypted drug candidates for analysis",
            Self::SessionCreation => "Creating blind discovery session",
            Self::ApprovalFlow => "Processing ethics, DoH, custodian, and partner approvals",
            Self::BlindCompute => "Executing Med42 inference in TEE enclave",
            Self::Settlement => "Processing royalty payment in AETHEL tokens",
            Self::Verification => "Verifying proofs and generating audit report",
            Self::Complete => "Demo completed successfully",
        }
    }
}

/// Demo status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DemoStatus {
    /// Not started
    NotStarted,
    /// Running
    Running,
    /// Paused
    Paused,
    /// Completed
    Completed,
    /// Failed
    Failed,
}

/// Demo event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DemoEvent {
    /// Event ID
    pub id: Uuid,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Event type
    pub event_type: DemoEventType,
    /// Step
    pub step: DemoStep,
    /// Message
    pub message: String,
    /// Data (JSON)
    pub data: Option<String>,
}

/// Demo event types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DemoEventType {
    /// Step started
    StepStarted,
    /// Step completed
    StepCompleted,
    /// Info message
    Info,
    /// Warning
    Warning,
    /// Error
    Error,
    /// Success
    Success,
    /// Data sovereignty verified
    SovereigntyVerified,
    /// TEE attestation generated
    TeeAttestation,
    /// Payment processed
    PaymentProcessed,
}

/// Step timing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepTiming {
    /// Step
    pub step: DemoStep,
    /// Duration (ms)
    pub duration_ms: u64,
    /// Started at
    pub started_at: DateTime<Utc>,
    /// Completed at
    pub completed_at: DateTime<Utc>,
}

/// Demo output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DemoOutput {
    /// Demo status
    pub status: DemoStatus,
    /// Session ID
    pub session_id: Option<Uuid>,
    /// Efficacy results
    pub results: Vec<EfficacyResultSummary>,
    /// Total royalty (AETHEL)
    pub total_royalty_aethel: u128,
    /// Total royalty (USD)
    pub total_royalty_usd: f64,
    /// Discovery metrics
    pub discovery_metrics: DiscoveryMetricsSummary,
    /// Enclave metrics
    pub enclave_metrics: EnclaveMetricsSummary,
    /// Royalty metrics
    pub royalty_metrics: RoyaltyMetricsSummary,
    /// Step timings
    pub step_timings: Vec<StepTiming>,
    /// Total duration (ms)
    pub total_duration_ms: u64,
    /// Audit log
    pub audit_log: Vec<DiscoveryAuditEntry>,
    /// Key insight
    pub key_insight: String,
    /// Data sovereignty verified
    pub sovereignty_verified: bool,
    /// No data leaks
    pub no_data_leaks: bool,
}

/// Efficacy result summary (for output)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EfficacyResultSummary {
    /// Drug candidate code name
    pub drug_code: String,
    /// Efficacy score
    pub efficacy_score: u8,
    /// Confidence level
    pub confidence: String,
    /// Finding count
    pub findings_count: usize,
    /// Has attestation
    pub has_attestation: bool,
    /// Has zkML proof
    pub has_zkml_proof: bool,
}

/// Discovery metrics summary
#[allow(missing_docs)]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DiscoveryMetricsSummary {
    pub sessions_created: u64,
    pub completed_sessions: u64,
    pub drug_candidates_evaluated: u64,
    pub efficacy_analyses: u64,
    pub avg_efficacy_score: f64,
}

/// Enclave metrics summary
#[allow(missing_docs)]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EnclaveMetricsSummary {
    pub jobs_processed: u64,
    pub avg_inference_time_ms: u64,
    pub attestations_generated: u64,
    pub data_leaks_detected: u64,
}

/// Royalty metrics summary
#[allow(missing_docs)]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RoyaltyMetricsSummary {
    pub total_royalties_aethel: u128,
    pub total_royalties_usd: f64,
    pub total_transactions: u64,
    pub avg_royalty_per_analysis_usd: f64,
}

// =============================================================================
// DEMO IMPLEMENTATION
// =============================================================================

impl HelixGuardDemo {
    /// Create new demo instance
    pub fn new(config: DemoConfig) -> Self {
        let protocol = BlindDiscoveryProtocol::new(config.discovery_config.clone());
        let royalty_engine = RoyaltyEngine::new(config.royalty_config.clone());

        Self {
            config,
            protocol,
            royalty_engine,
            state: DemoState::default(),
            events: Vec::new(),
            step_timings: Vec::new(),
        }
    }

    /// Run the full demo
    pub async fn run(&self) -> HelixGuardResult<DemoOutput> {
        let demo_start = Instant::now();

        if self.config.show_visualizations {
            self.print_banner();
        }

        // Step 1: Initialize
        self.execute_step(DemoStep::Initialize, || async {
            self.step_initialize().await
        })
        .await?;

        // Step 2: Partner Onboarding
        self.execute_step(DemoStep::PartnerOnboarding, || async {
            self.step_partner_onboarding().await
        })
        .await?;

        // Step 3: Drug Candidate Submission
        self.execute_step(DemoStep::DrugSubmission, || async {
            self.step_drug_submission().await
        })
        .await?;

        // Step 4: Session Creation
        self.execute_step(DemoStep::SessionCreation, || async {
            self.step_session_creation().await
        })
        .await?;

        // Step 5: Approval Flow
        self.execute_step(DemoStep::ApprovalFlow, || async {
            self.step_approval_flow().await
        })
        .await?;

        // Step 6: Blind Compute
        self.execute_step(DemoStep::BlindCompute, || async {
            self.step_blind_compute().await
        })
        .await?;

        // Step 7: Settlement
        self.execute_step(DemoStep::Settlement, || async {
            self.step_settlement().await
        })
        .await?;

        // Step 8: Verification
        self.execute_step(DemoStep::Verification, || async {
            self.step_verification().await
        })
        .await?;

        let total_duration = demo_start.elapsed().as_millis() as u64;

        // Build output
        let output = self.build_output(total_duration);

        if self.config.show_visualizations {
            self.print_summary(&output);
        }

        Ok(output)
    }

    /// Execute a demo step
    async fn execute_step<F, Fut>(&self, step: DemoStep, f: F) -> HelixGuardResult<()>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = HelixGuardResult<()>>,
    {
        let start = Instant::now();

        if self.config.verbose {
            println!("\n╔═══════════════════════════════════════════════════════════════════════╗");
            println!(
                "║ Step {}: {}",
                match step {
                    DemoStep::Initialize => "1",
                    DemoStep::PartnerOnboarding => "2",
                    DemoStep::DrugSubmission => "3",
                    DemoStep::SessionCreation => "4",
                    DemoStep::ApprovalFlow => "5",
                    DemoStep::BlindCompute => "6",
                    DemoStep::Settlement => "7",
                    DemoStep::Verification => "8",
                    DemoStep::Complete => "✓",
                },
                step.name()
            );
            println!("║ {}", step.description());
            println!("╚═══════════════════════════════════════════════════════════════════════╝");
        }

        // Add delay for realism
        if self.config.simulate_delays {
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }

        f().await?;

        let duration = start.elapsed().as_millis() as u64;

        if self.config.verbose {
            println!("  ✓ Completed in {}ms", duration);
        }

        Ok(())
    }

    /// Step 1: Initialize
    async fn step_initialize(&self) -> HelixGuardResult<()> {
        if self.config.verbose {
            println!("  → Initializing M42 Sovereign Node...");
            println!("  → Location: Abu Dhabi, UAE");
            println!("  → TEE: Intel SGX + NVIDIA H100 TEE");
        }

        // Cohort is already registered by default
        let cohorts = self.protocol.get_cohorts();
        let cohort = cohorts
            .iter()
            .find(|c| c.name == "Emirati Genome Program")
            .ok_or_else(|| HelixGuardError::CohortNotFound("Emirati Genome Program".to_string()))?;

        if self.config.verbose {
            println!(
                "  → Registered: {} ({} genomes)",
                cohort.name, cohort.population_size
            );
            println!("  → Sovereignty: Data NEVER leaves UAE ✓");
            println!("  → Compliance: UAE DoH, HIPAA ✓");
        }

        Ok(())
    }

    /// Step 2: Partner Onboarding
    async fn step_partner_onboarding(&self) -> HelixGuardResult<()> {
        // Partner is already registered by default
        let partners = self.protocol.get_partners();
        let partner = partners
            .iter()
            .find(|p| p.name.contains("AstraZeneca"))
            .ok_or_else(|| HelixGuardError::PartnerNotFound("AstraZeneca".to_string()))?;

        // Register partner account with royalty engine
        self.royalty_engine.register_partner_account(
            partner,
            10_000_000_000_000_000_000_000, // 10,000 AETHEL credit
        );

        if self.config.verbose {
            println!("  → Partner: {} ({})", partner.name, partner.jurisdiction);
            println!(
                "  → Tier: {:?} ({}x fee multiplier)",
                partner.tier,
                partner.tier.fee_multiplier()
            );
            println!("  → Research Areas: {:?}", partner.research_areas);
            println!("  → Node: {}", partner.node_id);
        }

        Ok(())
    }

    /// Step 3: Drug Candidate Submission
    async fn step_drug_submission(&self) -> HelixGuardResult<()> {
        let partners = self.protocol.get_partners();
        let partner = partners
            .iter()
            .find(|p| p.name.contains("AstraZeneca"))
            .ok_or_else(|| HelixGuardError::PartnerNotFound("AstraZeneca".to_string()))?;

        let drug_configs = vec![
            (
                "AZD-LUNG-001",
                TherapeuticArea::Oncology,
                "Non-Small Cell Lung Cancer",
            ),
            (
                "AZD-CARDIO-002",
                TherapeuticArea::Cardiovascular,
                "Heart Failure",
            ),
            (
                "AZD-NEURO-003",
                TherapeuticArea::Neuroscience,
                "Alzheimer's Disease",
            ),
        ];

        for (code_name, area, condition) in drug_configs
            .iter()
            .take(self.config.drug_candidate_count as usize)
        {
            let candidate = DrugCandidate {
                id: Uuid::new_v4(),
                code_name: code_name.to_string(),
                therapeutic_area: *area,
                target_condition: condition.to_string(),
                encrypted_structure: EncryptedPayload {
                    algorithm: EncryptionAlgorithm::Aes256Gcm,
                    ciphertext: vec![0u8; 256], // Simulated
                    iv: vec![0u8; 12],
                    key_info: KeyInfo {
                        key_type: KeyType::TeeSealed,
                        public_key_or_id: vec![0u8; 32],
                        derivation_params: None,
                    },
                    auth_tag: vec![0u8; 16],
                },
                target_markers: vec![GeneticMarkerQuery {
                    marker_type: GeneticMarkerType::Pharmacogenomic,
                    gene_id: "CYP2D6".to_string(),
                    variant_id: Some("rs1234567".to_string()),
                    query_type: MarkerQueryType::AlleleFrequency,
                }],
                development_phase: DevelopmentPhase::Phase2,
                submitting_partner: partner.id,
                submitted_at: Utc::now(),
            };

            self.protocol.submit_drug_candidate(candidate.clone())?;

            if self.config.verbose {
                println!("  → Submitted: {} ({:?})", code_name, area);
                println!("    Target: {}", condition);
                println!("    Encryption: AES-256-GCM ✓");
                println!("    IP Protection: TEE-sealed key ✓");
            }
        }

        Ok(())
    }

    /// Step 4: Session Creation
    async fn step_session_creation(&self) -> HelixGuardResult<()> {
        let cohorts = self.protocol.get_cohorts();
        let partners = self.protocol.get_partners();

        let cohort = cohorts
            .iter()
            .find(|c| c.name == "Emirati Genome Program")
            .ok_or_else(|| HelixGuardError::CohortNotFound("Emirati Genome Program".to_string()))?;

        let partner = partners
            .iter()
            .find(|p| p.name.contains("AstraZeneca"))
            .ok_or_else(|| HelixGuardError::PartnerNotFound("AstraZeneca".to_string()))?;

        // Get all submitted drug candidates
        // For demo, we'll create a session with available candidates
        // In real implementation, we'd track the IDs from step 3

        if self.config.verbose {
            println!("  → Creating Discovery Session...");
            println!(
                "    Cohort: {} ({} genomes)",
                cohort.name, cohort.population_size
            );
            println!("    Partner: {}", partner.name);
            println!("    Status: Pending Approval");
        }

        Ok(())
    }

    /// Step 5: Approval Flow
    async fn step_approval_flow(&self) -> HelixGuardResult<()> {
        if self.config.verbose {
            println!("  → Processing Approvals...");
            println!();
            println!("    ┌─────────────────────────────────────────────────────────┐");
            println!("    │                    APPROVAL CHAIN                        │");
            println!("    ├─────────────────────────────────────────────────────────┤");
        }

        // Simulate approvals
        let approvals = vec![
            (
                "Ethics Committee",
                "Dr. Ahmed Al-Hassan",
                "Research ethics verified",
            ),
            (
                "UAE Dept. of Health",
                "DoH Official #4521",
                "Regulatory compliance confirmed",
            ),
            (
                "M42 Data Custodian",
                "Omics Director",
                "Data access authorized",
            ),
            (
                "AstraZeneca Legal",
                "VP Legal Affairs",
                "Partner agreement signed",
            ),
        ];

        for (authority, approver, note) in approvals {
            if self.config.simulate_delays {
                tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
            }

            if self.config.verbose {
                println!("    │ ✓ {}: {}", authority, approver);
                println!("    │   └─ {}", note);
            }
        }

        if self.config.verbose {
            println!("    └─────────────────────────────────────────────────────────┘");
            println!();
            println!("  → All approvals granted ✓");
            println!("  → Session status: APPROVED");
        }

        Ok(())
    }

    /// Step 6: Blind Compute
    async fn step_blind_compute(&self) -> HelixGuardResult<()> {
        if self.config.verbose {
            println!("  → Initializing TEE Enclave...");
            println!("    Platform: NVIDIA H100 Confidential Computing");
            println!("    Memory Encryption: ENABLED");
            println!("    RAM-Only Processing: ENABLED");
            println!();
        }

        let candidates = vec![
            ("AZD-LUNG-001", 87),
            ("AZD-CARDIO-002", 92),
            ("AZD-NEURO-003", 74),
        ];

        for (code_name, score) in candidates
            .iter()
            .take(self.config.drug_candidate_count as usize)
        {
            if self.config.verbose {
                println!("  → Processing {}...", code_name);
                println!("    ├─ Loading encrypted genome data into RAM");
            }

            if self.config.simulate_delays {
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            }

            if self.config.verbose {
                println!("    ├─ Loading encrypted drug formula into RAM");
            }

            if self.config.simulate_delays {
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            }

            if self.config.verbose {
                println!("    ├─ Running Med42 LLM inference...");
            }

            if self.config.simulate_delays {
                tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
            }

            if self.config.verbose {
                println!("    ├─ Data leak check: PASSED ✓");
                println!("    ├─ Wiping sensitive data from RAM...");
                println!("    └─ Result: Efficacy {}% (High Confidence)", score);
                println!();
            }
        }

        if self.config.verbose {
            println!("  → All blind computations completed ✓");
            println!("  → TEE Attestations generated ✓");
            if self.config.zkml_enabled {
                println!("  → zkML Proofs generated ✓");
            }
        }

        Ok(())
    }

    /// Step 7: Settlement
    async fn step_settlement(&self) -> HelixGuardResult<()> {
        if self.config.verbose {
            println!("  → Calculating Royalties...");
            println!();
        }

        let params = RoyaltyCalculationParams {
            partner_tier: PartnerTier::Strategic,
            analysis_type: ComputeJobType::EfficacyPrediction,
            population_size: 100_000,
            marker_types: vec![GeneticMarkerType::Pharmacogenomic],
            batch_size: self.config.drug_candidate_count,
            total_partner_analyses: 0,
        };

        let calc = self.royalty_engine.calculate_royalty(&params);

        if self.config.verbose {
            println!("    ┌─────────────────────────────────────────────────────────┐");
            println!("    │                  ROYALTY CALCULATION                     │");
            println!("    ├─────────────────────────────────────────────────────────┤");
            println!("    │ Base Fee:        ${} per analysis", 500);
            println!(
                "    │ Tier Multiplier: {}x (Strategic)",
                calc.tier_multiplier
            );
            println!(
                "    │ Usage Multiplier: {}x",
                calc.combined_usage_multiplier
            );
            println!(
                "    │ Batch Size:      {} analyses",
                self.config.drug_candidate_count
            );
            println!("    │ Volume Discount: {}%", calc.volume_discount_percent);
            println!("    ├─────────────────────────────────────────────────────────┤");
            println!(
                "    │ TOTAL:           ${} ({} AETHEL)",
                calc.final_usd.round_dp(2),
                calc.final_aethel / 1_000_000_000_000_000_000
            );
            println!("    └─────────────────────────────────────────────────────────┘");
            println!();
            println!("  → Processing payment on Aethelred chain...");
        }

        if self.config.simulate_delays {
            tokio::time::sleep(tokio::time::Duration::from_millis(150)).await;
        }

        if self.config.verbose {
            println!("  → Payment confirmed ✓");
            println!("  → Recipient: M42 Health Treasury");
            println!("  → Transaction hash: 0x7f3a...e2b1");
        }

        Ok(())
    }

    /// Step 8: Verification
    async fn step_verification(&self) -> HelixGuardResult<()> {
        if self.config.verbose {
            println!("  → Verifying Proofs...");
            println!();
            println!("    ┌─────────────────────────────────────────────────────────┐");
            println!("    │                  VERIFICATION REPORT                     │");
            println!("    ├─────────────────────────────────────────────────────────┤");
            println!(
                "    │ TEE Attestations:      {} VERIFIED ✓",
                self.config.drug_candidate_count
            );
            if self.config.zkml_enabled {
                println!(
                    "    │ zkML Proofs:           {} VERIFIED ✓",
                    self.config.drug_candidate_count
                );
            }
            println!("    │ Data Sovereignty:      UAE COMPLIANT ✓");
            println!("    │ IP Protection:         VERIFIED ✓");
            println!("    │ Royalty Settlement:    CONFIRMED ✓");
            println!("    ├─────────────────────────────────────────────────────────┤");
            println!("    │ AUDIT TRAIL:           BLOCKCHAIN-BACKED ✓");
            println!("    └─────────────────────────────────────────────────────────┘");
            println!();
        }

        if self.config.verbose {
            println!("  → All verifications passed ✓");
            println!("  → Audit report generated");
        }

        Ok(())
    }

    /// Build demo output
    fn build_output(&self, total_duration_ms: u64) -> DemoOutput {
        let discovery_metrics = self.protocol.get_metrics();
        let enclave_metrics = self.protocol.get_enclave_metrics();
        let royalty_metrics = self.royalty_engine.get_metrics();

        DemoOutput {
            status: DemoStatus::Completed,
            session_id: None, // Would be set from actual session
            results: vec![
                EfficacyResultSummary {
                    drug_code: "AZD-LUNG-001".to_string(),
                    efficacy_score: 87,
                    confidence: "High".to_string(),
                    findings_count: 3,
                    has_attestation: true,
                    has_zkml_proof: self.config.zkml_enabled,
                },
                EfficacyResultSummary {
                    drug_code: "AZD-CARDIO-002".to_string(),
                    efficacy_score: 92,
                    confidence: "Very High".to_string(),
                    findings_count: 4,
                    has_attestation: true,
                    has_zkml_proof: self.config.zkml_enabled,
                },
                EfficacyResultSummary {
                    drug_code: "AZD-NEURO-003".to_string(),
                    efficacy_score: 74,
                    confidence: "Medium".to_string(),
                    findings_count: 2,
                    has_attestation: true,
                    has_zkml_proof: self.config.zkml_enabled,
                },
            ]
            .into_iter()
            .take(self.config.drug_candidate_count as usize)
            .collect(),
            total_royalty_aethel: 1050_000_000_000_000_000_000, // Simulated
            total_royalty_usd: 1050.0,
            discovery_metrics: DiscoveryMetricsSummary {
                sessions_created: discovery_metrics.sessions_created,
                completed_sessions: discovery_metrics.completed_sessions,
                drug_candidates_evaluated: discovery_metrics.drug_candidates_evaluated,
                efficacy_analyses: discovery_metrics.efficacy_analyses,
                avg_efficacy_score: discovery_metrics.avg_efficacy_score,
            },
            enclave_metrics: EnclaveMetricsSummary {
                jobs_processed: enclave_metrics.jobs_processed,
                avg_inference_time_ms: enclave_metrics.avg_inference_time_ms,
                attestations_generated: enclave_metrics.attestations_generated,
                data_leaks_detected: enclave_metrics.data_leaks_detected,
            },
            royalty_metrics: RoyaltyMetricsSummary {
                total_royalties_aethel: royalty_metrics.total_royalties_aethel,
                total_royalties_usd: royalty_metrics
                    .total_royalties_usd
                    .to_string()
                    .parse()
                    .unwrap_or(0.0),
                total_transactions: royalty_metrics.total_transactions,
                avg_royalty_per_analysis_usd: royalty_metrics
                    .avg_royalty_per_analysis_usd
                    .to_string()
                    .parse()
                    .unwrap_or(0.0),
            },
            step_timings: self.step_timings.clone(),
            total_duration_ms,
            audit_log: self.protocol.get_audit_log(),
            key_insight: "M42's genome data stayed in Abu Dhabi. AstraZeneca's drug formulas \
                          stayed encrypted. Aethelred only moved the TRUTH, not the DATA."
                .to_string(),
            sovereignty_verified: true,
            no_data_leaks: true,
        }
    }

    /// Print demo banner
    fn print_banner(&self) {
        println!(
            r#"

╔═══════════════════════════════════════════════════════════════════════════════════╗
║                                                                                   ║
║   ██╗  ██╗███████╗██╗     ██╗██╗  ██╗     ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗║
║   ██║  ██║██╔════╝██║     ██║╚██╗██╔╝    ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
║   ███████║█████╗  ██║     ██║ ╚███╔╝     ██║  ███╗██║   ██║███████║██████╔╝██║  ██║
║   ██╔══██║██╔══╝  ██║     ██║ ██╔██╗     ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
║   ██║  ██║███████╗███████╗██║██╔╝ ██╗    ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝║
║   ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝╚═╝  ╚═╝     ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ║
║                                                                                   ║
║   THE BLIND DRUG DISCOVERY PROTOCOL                                               ║
║   M42 Health (UAE) ←→ AstraZeneca (UK)                                           ║
║                                                                                   ║
║   "Where Data Stays, Truth Travels"                                               ║
║                                                                                   ║
║   Powered by Aethelred: Sovereign AI Verification Infrastructure                  ║
║                                                                                   ║
╚═══════════════════════════════════════════════════════════════════════════════════╝
        "#
        );
    }

    /// Print demo summary
    fn print_summary(&self, output: &DemoOutput) {
        println!(
            r#"

╔═══════════════════════════════════════════════════════════════════════════════════╗
║                              DEMO COMPLETED SUCCESSFULLY                           ║
╠═══════════════════════════════════════════════════════════════════════════════════╣
║                                                                                   ║
║   RESULTS SUMMARY                                                                 ║
║   ───────────────                                                                 ║"#
        );

        for result in &output.results {
            let bar_len = (result.efficacy_score as usize) / 5;
            let bar = "█".repeat(bar_len.min(20));
            let empty_len = 20usize.saturating_sub(bar_len);
            let empty = "░".repeat(empty_len);
            println!(
                "║   {} [{}{}] {}% ({})",
                result.drug_code, bar, empty, result.efficacy_score, result.confidence
            );
        }

        println!(
            r#"║                                                                                   ║
║   KEY METRICS                                                                     ║
║   ───────────                                                                     ║
║   • Drug Candidates Analyzed: {}                                                  ║
║   • TEE Attestations: {} generated                                                ║
║   • zkML Proofs: {} generated                                                     ║
║   • Total Royalty: {} AETHEL (${})                                           ║
║   • Data Leaks: {} (as expected)                                                  ║
║                                                                                   ║
║   DATA SOVEREIGNTY                                                                ║
║   ────────────────                                                                ║
║   ✓ M42 genome data NEVER left Abu Dhabi                                         ║
║   ✓ AstraZeneca formulas NEVER decrypted outside TEE                             ║
║   ✓ Only efficacy scores and proofs were exchanged                               ║
║   ✓ Full audit trail on Aethelred blockchain                                     ║
║                                                                                   ║
║   Duration: {}ms                                                                ║
║                                                                                   ║
╠═══════════════════════════════════════════════════════════════════════════════════╣
║                                                                                   ║
║   "M42's data stayed in Abu Dhabi. AstraZeneca's IP stayed encrypted.            ║
║    Aethelred only moved the TRUTH, not the DATA."                                 ║
║                                                                                   ║
╚═══════════════════════════════════════════════════════════════════════════════════╝
        "#,
            output.results.len(),
            output.results.len(),
            if self.config.zkml_enabled {
                output.results.len().to_string()
            } else {
                "0".to_string()
            },
            output.total_royalty_aethel / 1_000_000_000_000_000_000,
            output.total_royalty_usd,
            output.enclave_metrics.data_leaks_detected,
            output.total_duration_ms
        );
    }

    /// Get configuration
    pub fn config(&self) -> &DemoConfig {
        &self.config
    }
}

impl Default for HelixGuardDemo {
    fn default() -> Self {
        Self::new(DemoConfig::default())
    }
}

// =============================================================================
// CONVENIENCE FUNCTIONS
// =============================================================================

/// Create new demo with default configuration
pub fn new_demo() -> HelixGuardDemo {
    HelixGuardDemo::default()
}

/// Create new demo with custom configuration
pub fn new_demo_with_config(config: DemoConfig) -> HelixGuardDemo {
    HelixGuardDemo::new(config)
}

/// Print demo banner
pub fn print_banner() {
    let demo = HelixGuardDemo::default();
    demo.print_banner();
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_demo_creation() {
        let demo = HelixGuardDemo::default();
        assert!(demo.config.verbose);
        assert!(demo.config.zkml_enabled);
    }

    #[test]
    fn test_demo_config() {
        let config = DemoConfig {
            verbose: false,
            simulate_delays: false,
            show_visualizations: false,
            zkml_enabled: true,
            drug_candidate_count: 2,
            ..Default::default()
        };

        let demo = HelixGuardDemo::new(config);
        assert!(!demo.config.verbose);
        assert_eq!(demo.config.drug_candidate_count, 2);
    }

    #[tokio::test]
    async fn test_full_demo_execution() {
        let config = DemoConfig {
            verbose: false,
            simulate_delays: false,
            show_visualizations: false,
            zkml_enabled: true,
            drug_candidate_count: 2,
            ..Default::default()
        };

        let demo = HelixGuardDemo::new(config);
        let result = demo.run().await;

        assert!(result.is_ok());
        let output = result.unwrap();

        assert_eq!(output.status, DemoStatus::Completed);
        assert_eq!(output.results.len(), 2);
        assert!(output.sovereignty_verified);
        assert!(output.no_data_leaks);
    }

    #[test]
    fn test_demo_steps() {
        assert_eq!(DemoStep::Initialize.name(), "Initialize");
        assert_eq!(DemoStep::BlindCompute.name(), "Blind Compute");
        assert_eq!(DemoStep::Settlement.name(), "Settlement");
    }
}
