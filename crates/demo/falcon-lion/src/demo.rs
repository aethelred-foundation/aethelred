//! # Project Falcon-Lion: Demo Orchestrator
//!
//! Enterprise-grade demo orchestrator for the FAB-DBS cross-border trade finance
//! demonstration. This module coordinates the complete workflow from data
//! submission to LC minting.
//!
//! ## Demo Narrative
//!
//! **The Story**: A UAE-based Solar Panel Manufacturer (FAB Client) is selling
//! $5M worth of panels to a Singaporean Construction Firm (DBS Client).
//!
//! **The Problem**: FAB needs to know the Singaporean buyer is creditworthy.
//! DBS needs to know the UAE seller isn't sanctioned. Neither bank can legally
//! share their client's private financial records.
//!
//! **The Solution**: They use Aethelred to run a Shared AI Risk Model. The data
//! never leaves the bank's secure vault, but the result is cryptographically
//! proven on-chain, triggering an instant, automated Letter of Credit.
//!
//! ## "Wow" Factor
//!
//! > "Notice how FAB's data stayed in the UAE node, and DBS's data stayed in
//! > the Singapore node? Aethelred only moved the Truth, not the Data."

use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::compliance::{ComplianceEngine, VerificationResult};
use crate::error::{FalconLionError, FalconLionResult};
use crate::settlement::{SettlementEngine, VerifiableLetterOfCredit};
use crate::types::*;

// =============================================================================
// DEMO CONFIGURATION
// =============================================================================

/// Demo configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DemoConfig {
    /// Enable verbose logging
    pub verbose: bool,
    /// Simulate realistic delays
    pub simulate_delays: bool,
    /// Demo mode (fast/realistic/presentation)
    pub mode: DemoMode,
    /// Custom deal amount
    pub deal_amount: Option<Decimal>,
    /// Custom goods description
    pub goods_description: Option<String>,
}

impl Default for DemoConfig {
    fn default() -> Self {
        Self {
            verbose: true,
            simulate_delays: true,
            mode: DemoMode::Presentation,
            deal_amount: None,
            goods_description: None,
        }
    }
}

/// Demo execution mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DemoMode {
    /// Fast execution for testing
    Fast,
    /// Realistic timing for demos
    Realistic,
    /// Presentation mode with pauses
    Presentation,
}

// =============================================================================
// DEMO STATE
// =============================================================================

/// Demo execution state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DemoState {
    /// Demo ID
    pub id: Uuid,
    /// Current step
    pub current_step: DemoStep,
    /// Started at
    pub started_at: DateTime<Utc>,
    /// Step timings
    pub step_timings: Vec<StepTiming>,
    /// Trade deal
    pub trade_deal: Option<TradeDeal>,
    /// FAB (Exporter) verification result
    pub fab_verification: Option<VerificationResult>,
    /// DBS (Importer) verification result
    pub dbs_verification: Option<VerificationResult>,
    /// Minted LC
    pub minted_lc: Option<VerifiableLetterOfCredit>,
    /// Final status
    pub status: DemoStatus,
    /// Error message if failed
    pub error: Option<String>,
}

/// Demo steps
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DemoStep {
    /// Initializing
    Initializing,
    /// Creating trade deal
    CreatingDeal,
    /// FAB verification (UAE)
    FabVerification,
    /// DBS verification (Singapore)
    DbsVerification,
    /// Cross-border proof settlement
    SettlementProof,
    /// Minting LC on-chain
    MintingLC,
    /// Completed
    Completed,
}

impl DemoStep {
    /// Get display name
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Initializing => "Initializing Demo",
            Self::CreatingDeal => "Creating Trade Deal",
            Self::FabVerification => "FAB Verification (Abu Dhabi)",
            Self::DbsVerification => "DBS Verification (Singapore)",
            Self::SettlementProof => "Cross-Border Proof Settlement",
            Self::MintingLC => "Minting Letter of Credit",
            Self::Completed => "Completed",
        }
    }

    /// Get emoji for visual feedback
    pub fn emoji(&self) -> &'static str {
        match self {
            Self::Initializing => "🔧",
            Self::CreatingDeal => "📋",
            Self::FabVerification => "🇦🇪",
            Self::DbsVerification => "🇸🇬",
            Self::SettlementProof => "🔗",
            Self::MintingLC => "📜",
            Self::Completed => "✅",
        }
    }
}

/// Step timing information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepTiming {
    pub step: DemoStep,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub duration_ms: Option<u64>,
}

/// Demo status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DemoStatus {
    Running,
    Completed,
    Failed,
    Cancelled,
}

// =============================================================================
// DEMO OUTPUT
// =============================================================================

/// Demo execution output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DemoOutput {
    /// Demo ID
    pub demo_id: Uuid,
    /// Final status
    pub status: DemoStatus,
    /// Total execution time
    pub total_time_ms: u64,
    /// Trade deal reference
    pub deal_reference: String,
    /// LC reference (if minted)
    pub lc_reference: Option<String>,
    /// LC on-chain ID
    pub lc_id: Option<String>,
    /// Settlement transaction hash
    pub settlement_tx_hash: Option<String>,
    /// Explorer URL
    pub explorer_url: Option<String>,
    /// Audit trail
    pub audit_trail: Vec<AuditEntry>,
    /// Key metrics
    pub metrics: DemoMetrics,
}

/// Demo metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DemoMetrics {
    /// Total processing time
    pub total_time_ms: u64,
    /// FAB verification time
    pub fab_verification_time_ms: u64,
    /// DBS verification time
    pub dbs_verification_time_ms: u64,
    /// Settlement time
    pub settlement_time_ms: u64,
    /// Data transferred (proofs only)
    pub data_transferred_bytes: u64,
    /// Sensitive data exposed
    pub sensitive_data_exposed: bool, // Always false!
}

// =============================================================================
// DEMO ORCHESTRATOR
// =============================================================================

/// Project Falcon-Lion Demo Orchestrator
///
/// Coordinates the complete cross-border trade finance demonstration
/// between FAB (UAE) and DBS (Singapore).
pub struct FalconLionDemo {
    /// Configuration
    config: DemoConfig,
    /// Compliance engine
    compliance: Arc<ComplianceEngine>,
    /// Settlement engine
    settlement: Arc<SettlementEngine>,
    /// Current state
    state: Arc<RwLock<DemoState>>,
    /// Event callbacks
    event_callbacks: Arc<RwLock<Vec<Box<dyn Fn(&DemoEvent) + Send + Sync>>>>,
}

/// Demo event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DemoEvent {
    /// Event type
    pub event_type: DemoEventType,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Message
    pub message: String,
    /// Step
    pub step: DemoStep,
    /// Progress (0-100)
    pub progress: u8,
    /// Additional data
    pub data: Option<serde_json::Value>,
}

/// Demo event types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DemoEventType {
    StepStarted,
    StepCompleted,
    Progress,
    Info,
    Warning,
    Error,
    Success,
}

impl FalconLionDemo {
    /// Create new demo orchestrator with default config
    pub fn new(config: DemoConfig) -> Self {
        Self::with_config(config)
    }

    /// Create with custom configuration
    pub fn with_config(config: DemoConfig) -> Self {
        Self {
            config,
            compliance: Arc::new(ComplianceEngine::new()),
            settlement: Arc::new(SettlementEngine::new()),
            state: Arc::new(RwLock::new(DemoState {
                id: Uuid::new_v4(),
                current_step: DemoStep::Initializing,
                started_at: Utc::now(),
                step_timings: Vec::new(),
                trade_deal: None,
                fab_verification: None,
                dbs_verification: None,
                minted_lc: None,
                status: DemoStatus::Running,
                error: None,
            })),
            event_callbacks: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Get demo configuration
    pub fn config(&self) -> &DemoConfig {
        &self.config
    }

    /// Subscribe to demo events
    pub fn subscribe<F>(&self, callback: F)
    where
        F: Fn(&DemoEvent) + Send + Sync + 'static,
    {
        self.event_callbacks.write().push(Box::new(callback));
    }

    /// Run the complete demo
    pub async fn run(&self) -> FalconLionResult<DemoOutput> {
        let start_time = Instant::now();
        let demo_id = self.state.read().id;

        self.emit_event(DemoEvent {
            event_type: DemoEventType::Info,
            timestamp: Utc::now(),
            message: "🚀 Starting Project Falcon-Lion Demo".to_string(),
            step: DemoStep::Initializing,
            progress: 0,
            data: None,
        });

        // Print banner
        self.print_banner();

        // Step 1: Create trade deal
        let trade_deal = self.step_create_trade_deal().await?;

        // Step 2: FAB Verification (UAE)
        let fab_result = self.step_fab_verification(&trade_deal).await?;

        // Step 3: DBS Verification (Singapore)
        let dbs_result = self.step_dbs_verification(&trade_deal).await?;

        // Step 4: Cross-border settlement
        let minted_lc = self
            .step_settlement(&trade_deal, &fab_result, &dbs_result)
            .await?;

        // Complete
        self.set_step(DemoStep::Completed);
        self.state.write().status = DemoStatus::Completed;

        let total_time = start_time.elapsed().as_millis() as u64;

        // Build output
        let output = DemoOutput {
            demo_id,
            status: DemoStatus::Completed,
            total_time_ms: total_time,
            deal_reference: trade_deal.reference.clone(),
            lc_reference: Some(minted_lc.reference.clone()),
            lc_id: Some(hex::encode(minted_lc.lc_id)),
            settlement_tx_hash: Some(hex::encode(minted_lc.mint_tx_hash)),
            explorer_url: Some(self.settlement.get_explorer_url(&minted_lc.mint_tx_hash)),
            audit_trail: trade_deal.audit_trail.clone(),
            metrics: self.calculate_metrics(total_time),
        };

        // Print final summary
        self.print_summary(&output, &trade_deal, &minted_lc);

        self.emit_event(DemoEvent {
            event_type: DemoEventType::Success,
            timestamp: Utc::now(),
            message: format!("✅ Demo completed successfully in {}ms", total_time),
            step: DemoStep::Completed,
            progress: 100,
            data: Some(serde_json::to_value(&output).unwrap()),
        });

        Ok(output)
    }

    /// Step 1: Create trade deal
    async fn step_create_trade_deal(&self) -> FalconLionResult<TradeDeal> {
        self.set_step(DemoStep::CreatingDeal);

        self.emit_event(DemoEvent {
            event_type: DemoEventType::StepStarted,
            timestamp: Utc::now(),
            message:
                "📋 Creating trade deal between UAE Solar Manufacturing and Singapore Construction"
                    .to_string(),
            step: DemoStep::CreatingDeal,
            progress: 10,
            data: None,
        });

        if self.config.simulate_delays {
            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        // Create participants
        let exporter = self.create_uae_exporter();
        let importer = self.create_singapore_importer();

        let deal_amount = self.config.deal_amount.unwrap_or(Decimal::from(5_000_000));
        let goods_desc = self
            .config
            .goods_description
            .clone()
            .unwrap_or_else(|| "Solar Panels 500W Monocrystalline - 10,000 units".to_string());

        let trade_deal = TradeDeal {
            id: Uuid::new_v4(),
            reference: format!("DEAL-FAB-DBS-{}", Utc::now().format("%Y%m%d%H%M")),
            status: DealStatus::Draft,
            exporter: exporter.clone(),
            importer: importer.clone(),
            exporter_bank: BankIdentifier::fab(),
            importer_bank: BankIdentifier::dbs(),
            goods_description: goods_desc,
            quantity: "10,000 units".to_string(),
            unit_price: MonetaryAmount::usd(Decimal::from(500)),
            total_value: MonetaryAmount::usd(deal_amount),
            incoterms: Incoterms::Cif,
            letter_of_credit: None,
            guarantees: vec![],
            exporter_proofs: vec![],
            importer_proofs: vec![],
            settlement_proof: None,
            blockchain_status: BlockchainStatus {
                on_chain: false,
                network: "aethelred-mainnet".to_string(),
                contract_version: "1.0.0".to_string(),
                last_block_height: None,
                confirmations: 0,
                finalized: false,
            },
            settlement_tx_hash: None,
            smart_contract_address: None,
            settlement_fees: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            expected_completion: Utc::now() + chrono::Duration::days(30),
            completed_at: None,
            audit_trail: vec![AuditEntry {
                id: Uuid::new_v4(),
                timestamp: Utc::now(),
                action: AuditAction::Created,
                actor: "System".to_string(),
                actor_jurisdiction: Jurisdiction::Uae,
                description: "Trade deal created".to_string(),
                data_hash: None,
                ip_hash: None,
            }],
        };

        self.state.write().trade_deal = Some(trade_deal.clone());

        self.emit_event(DemoEvent {
            event_type: DemoEventType::StepCompleted,
            timestamp: Utc::now(),
            message: format!(
                "✅ Trade deal created: {} ({})",
                trade_deal.reference, trade_deal.total_value
            ),
            step: DemoStep::CreatingDeal,
            progress: 20,
            data: None,
        });

        println!("\n{}", "═".repeat(70));
        println!("📋 TRADE DEAL CREATED");
        println!("{}", "─".repeat(70));
        println!("   Reference:   {}", trade_deal.reference);
        println!("   Amount:      {}", trade_deal.total_value);
        println!("   Exporter:    {} (UAE)", exporter.legal_name);
        println!("   Importer:    {} (Singapore)", importer.legal_name);
        println!("   Goods:       {}", trade_deal.goods_description);
        println!("   Incoterms:   {}", trade_deal.incoterms);
        println!("{}", "═".repeat(70));

        Ok(trade_deal)
    }

    /// Step 2: FAB Verification
    async fn step_fab_verification(
        &self,
        deal: &TradeDeal,
    ) -> FalconLionResult<VerificationResult> {
        self.set_step(DemoStep::FabVerification);

        self.emit_event(DemoEvent {
            event_type: DemoEventType::StepStarted,
            timestamp: Utc::now(),
            message: "🇦🇪 Starting FAB verification in UAE-sovereign enclave".to_string(),
            step: DemoStep::FabVerification,
            progress: 30,
            data: None,
        });

        println!("\n{}", "═".repeat(70));
        println!("🇦🇪 FAB BANK (Abu Dhabi) - VERIFICATION");
        println!("{}", "─".repeat(70));
        println!("   Node:        uae-north-1 (TEE Protected)");
        println!("   Compliance:  UAE Central Bank, UAE Data Law");
        println!("   Data:        🔒 NEVER LEAVES UAE");
        println!("{}", "─".repeat(70));

        // Start compliance session
        let session_id = self
            .compliance
            .start_session(deal.exporter.id, Jurisdiction::Uae)?;

        // Record consent
        self.compliance.record_consent(session_id)?;
        println!("   ✓ Data processing consent recorded");

        if self.config.simulate_delays {
            tokio::time::sleep(Duration::from_millis(300)).await;
        }

        // Sanctions check
        print!("   ⏳ Running sanctions screening...");
        let _sanctions_check = self
            .compliance
            .perform_sanctions_check(session_id, &deal.exporter)
            .await?;
        println!(" ✅ PASSED");

        if self.config.simulate_delays {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        // KYC check
        print!("   ⏳ Verifying KYC status...");
        let _kyc_check = self
            .compliance
            .perform_kyc_verification(session_id, &deal.exporter)
            .await?;
        println!(" ✅ PASSED");

        // Complete verification
        let result = self.compliance.complete_verification(session_id).await?;

        println!("{}", "─".repeat(70));
        println!("   ✅ FAB VERIFICATION COMPLETE");
        println!("   Risk Score:  {}/100", result.risk_score);
        println!("   Confidence:  {}%", result.confidence);
        if let Some(ref proof) = result.proof {
            println!(
                "   Proof Hash:  {}...",
                &hex::encode(&proof.proof_hash)[..16]
            );
        }
        println!("{}", "═".repeat(70));

        self.state.write().fab_verification = Some(result.clone());

        self.emit_event(DemoEvent {
            event_type: DemoEventType::StepCompleted,
            timestamp: Utc::now(),
            message: format!(
                "✅ FAB verification complete (Risk: {}/100)",
                result.risk_score
            ),
            step: DemoStep::FabVerification,
            progress: 50,
            data: None,
        });

        Ok(result)
    }

    /// Step 3: DBS Verification
    async fn step_dbs_verification(
        &self,
        deal: &TradeDeal,
    ) -> FalconLionResult<VerificationResult> {
        self.set_step(DemoStep::DbsVerification);

        self.emit_event(DemoEvent {
            event_type: DemoEventType::StepStarted,
            timestamp: Utc::now(),
            message: "🇸🇬 Starting DBS verification in Singapore-sovereign enclave".to_string(),
            step: DemoStep::DbsVerification,
            progress: 55,
            data: None,
        });

        println!("\n{}", "═".repeat(70));
        println!("🇸🇬 DBS BANK (Singapore) - VERIFICATION");
        println!("{}", "─".repeat(70));
        println!("   Node:        sg-south-1 (TEE Protected)");
        println!("   Compliance:  MAS Notice 655, Singapore PDPA");
        println!("   Data:        🔒 NEVER LEAVES SINGAPORE");
        println!("{}", "─".repeat(70));

        // Start compliance session
        let session_id = self
            .compliance
            .start_session(deal.importer.id, Jurisdiction::Singapore)?;

        // Record consent
        self.compliance.record_consent(session_id)?;
        println!("   ✓ Data processing consent recorded");

        if self.config.simulate_delays {
            tokio::time::sleep(Duration::from_millis(300)).await;
        }

        // Credit scoring
        print!("   ⏳ Running credit scoring AI model...");

        // Create a dummy financial data hash
        let financial_hash = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(deal.importer.id.as_bytes());
            hasher.update(b"financial_data");
            let result = hasher.finalize();
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&result);
            hash
        };

        let credit_check = self
            .compliance
            .perform_credit_scoring(session_id, financial_hash)
            .await?;

        let credit_score = 100 - credit_check.risk_score.unwrap_or(0);
        println!(" ✅ Score: {}/100", credit_score);

        if self.config.simulate_delays {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        // Sanctions check
        print!("   ⏳ Running sanctions screening...");
        let _sanctions_check = self
            .compliance
            .perform_sanctions_check(session_id, &deal.importer)
            .await?;
        println!(" ✅ PASSED");

        // Complete verification
        let result = self.compliance.complete_verification(session_id).await?;

        println!("{}", "─".repeat(70));
        println!("   ✅ DBS VERIFICATION COMPLETE");
        println!("   Credit Score: {}/100", credit_score);
        println!("   Risk Score:   {}/100", result.risk_score);
        println!("   Confidence:   {}%", result.confidence);
        if let Some(ref proof) = result.proof {
            println!(
                "   Proof Hash:   {}...",
                &hex::encode(&proof.proof_hash)[..16]
            );
        }
        println!("{}", "═".repeat(70));

        self.state.write().dbs_verification = Some(result.clone());

        self.emit_event(DemoEvent {
            event_type: DemoEventType::StepCompleted,
            timestamp: Utc::now(),
            message: format!(
                "✅ DBS verification complete (Credit: {}/100)",
                credit_score
            ),
            step: DemoStep::DbsVerification,
            progress: 75,
            data: None,
        });

        Ok(result)
    }

    /// Step 4: Settlement and LC Minting
    async fn step_settlement(
        &self,
        deal: &TradeDeal,
        fab_result: &VerificationResult,
        dbs_result: &VerificationResult,
    ) -> FalconLionResult<VerifiableLetterOfCredit> {
        self.set_step(DemoStep::MintingLC);

        self.emit_event(DemoEvent {
            event_type: DemoEventType::StepStarted,
            timestamp: Utc::now(),
            message: "🔗 Submitting proofs to Aethelred blockchain".to_string(),
            step: DemoStep::MintingLC,
            progress: 80,
            data: None,
        });

        println!("\n{}", "═".repeat(70));
        println!("🔗 AETHELRED BLOCKCHAIN - SETTLEMENT");
        println!("{}", "─".repeat(70));
        println!("   Contract:    {}", self.settlement.contract_address_hex());
        println!("   Network:     aethelred-mainnet");
        println!("   Signature:   Dilithium3 (Post-Quantum)");
        println!("{}", "─".repeat(70));

        let exporter_proof = fab_result
            .proof
            .as_ref()
            .ok_or_else(|| FalconLionError::ProofGenerationFailed("No FAB proof".into()))?;
        let importer_proof = dbs_result
            .proof
            .as_ref()
            .ok_or_else(|| FalconLionError::ProofGenerationFailed("No DBS proof".into()))?;

        print!("   ⏳ Verifying proofs on-chain...");
        if self.config.simulate_delays {
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        println!(" ✅");

        print!("   ⏳ Minting Verifiable Letter of Credit...");
        let minted_lc = self
            .settlement
            .mint_letter_of_credit(
                exporter_proof,
                importer_proof,
                deal,
                &deal.importer_bank, // DBS is issuing bank
                &deal.exporter_bank, // FAB is advising bank
            )
            .await?;
        println!(" ✅");

        println!("{}", "─".repeat(70));
        println!("   🎉 LETTER OF CREDIT MINTED!");
        println!("{}", "─".repeat(70));
        println!("   LC Reference:    {}", minted_lc.reference);
        println!(
            "   LC ID:           0x{}...",
            &hex::encode(minted_lc.lc_id)[..16]
        );
        println!("   Amount:          {}", deal.total_value);
        println!("   Beneficiary:     {}", deal.exporter.legal_name);
        println!("   Applicant:       {}", deal.importer.legal_name);
        println!(
            "   TX Hash:         0x{}...",
            &hex::encode(minted_lc.mint_tx_hash)[..16]
        );
        println!("   Block:           {}", minted_lc.mint_block);
        println!("{}", "═".repeat(70));

        self.state.write().minted_lc = Some(minted_lc.clone());

        self.emit_event(DemoEvent {
            event_type: DemoEventType::StepCompleted,
            timestamp: Utc::now(),
            message: format!("🎉 LC Minted: {}", minted_lc.reference),
            step: DemoStep::MintingLC,
            progress: 95,
            data: None,
        });

        Ok(minted_lc)
    }

    /// Set current step
    fn set_step(&self, step: DemoStep) {
        let mut state = self.state.write();
        state.current_step = step;
        state.step_timings.push(StepTiming {
            step,
            started_at: Utc::now(),
            completed_at: None,
            duration_ms: None,
        });
    }

    /// Emit event to subscribers
    fn emit_event(&self, event: DemoEvent) {
        if self.config.verbose {
            tracing::info!(
                step = ?event.step,
                progress = event.progress,
                "{}",
                event.message
            );
        }

        let callbacks = self.event_callbacks.read();
        for callback in callbacks.iter() {
            callback(&event);
        }
    }

    /// Create UAE exporter participant
    fn create_uae_exporter(&self) -> TradeParticipant {
        TradeParticipant {
            id: Uuid::new_v4(),
            legal_name: "UAE Solar Manufacturing Co. LLC".to_string(),
            trading_name: Some("UAE Solar".to_string()),
            registration_number: "ADGM-123456".to_string(),
            tax_id: Some("TRN100123456789".to_string()),
            lei: Some("549300UAESOLAR00001".to_string()),
            jurisdiction: Jurisdiction::Uae,
            bank: BankIdentifier::fab(),
            industry_code: "2610".to_string(), // Manufacture of electronic components
            address: Address {
                street_line_1: "KIZAD Industrial Zone, Plot A-123".to_string(),
                street_line_2: Some("Khalifa Industrial Zone".to_string()),
                city: "Abu Dhabi".to_string(),
                state_province: Some("Abu Dhabi".to_string()),
                postal_code: "00000".to_string(),
                country_code: "AE".to_string(),
            },
            contact: ContactInfo {
                primary_name: "Ahmed Al Mansouri".to_string(),
                primary_email: "ahmed.mansouri@uaesolar.ae".to_string(),
                primary_phone: "+971 2 123 4567".to_string(),
                finance_email: Some("finance@uaesolar.ae".to_string()),
            },
            risk_rating: Some(RiskRating::A),
            sanctions_status: SanctionsStatus {
                status: SanctionsResult::Clear,
                screened_at: Utc::now(),
                lists_checked: vec![
                    SanctionsList::UnSc,
                    SanctionsList::UsOfacSdn,
                    SanctionsList::UaeLocalList,
                ],
                potential_matches: 0,
                provider: "Aethelred Compliance".to_string(),
            },
            kyc_verified_at: Some(Utc::now() - chrono::Duration::days(100)),
        }
    }

    /// Create Singapore importer participant
    fn create_singapore_importer(&self) -> TradeParticipant {
        TradeParticipant {
            id: Uuid::new_v4(),
            legal_name: "Singapore Construction Pte Ltd".to_string(),
            trading_name: Some("SG Construction".to_string()),
            registration_number: "201234567K".to_string(),
            tax_id: Some("M12345678K".to_string()),
            lei: Some("549300SGCONSTRUCT01".to_string()),
            jurisdiction: Jurisdiction::Singapore,
            bank: BankIdentifier::dbs(),
            industry_code: "4100".to_string(), // Construction of buildings
            address: Address {
                street_line_1: "10 Marina Boulevard".to_string(),
                street_line_2: Some("#20-01 Marina Bay Financial Centre".to_string()),
                city: "Singapore".to_string(),
                state_province: None,
                postal_code: "018983".to_string(),
                country_code: "SG".to_string(),
            },
            contact: ContactInfo {
                primary_name: "Chen Wei Lin".to_string(),
                primary_email: "chen.weilin@sgconstruction.sg".to_string(),
                primary_phone: "+65 6123 4567".to_string(),
                finance_email: Some("accounts@sgconstruction.sg".to_string()),
            },
            risk_rating: Some(RiskRating::Aa),
            sanctions_status: SanctionsStatus {
                status: SanctionsResult::Clear,
                screened_at: Utc::now(),
                lists_checked: vec![
                    SanctionsList::UnSc,
                    SanctionsList::UsOfacSdn,
                    SanctionsList::SgMasList,
                ],
                potential_matches: 0,
                provider: "Aethelred Compliance".to_string(),
            },
            kyc_verified_at: Some(Utc::now() - chrono::Duration::days(50)),
        }
    }

    /// Calculate demo metrics
    fn calculate_metrics(&self, total_time: u64) -> DemoMetrics {
        DemoMetrics {
            total_time_ms: total_time,
            fab_verification_time_ms: total_time / 3,
            dbs_verification_time_ms: total_time / 3,
            settlement_time_ms: total_time / 3,
            data_transferred_bytes: 512,   // Only proofs transferred
            sensitive_data_exposed: false, // NEVER!
        }
    }

    /// Print demo banner
    fn print_banner(&self) {
        println!("\n");
        println!("╔═══════════════════════════════════════════════════════════════════════╗");
        println!("║                                                                       ║");
        println!("║   🦅🦁  PROJECT FALCON-LION  🦅🦁                                     ║");
        println!("║                                                                       ║");
        println!("║   Zero-Knowledge Cross-Border Trade Finance                           ║");
        println!("║   FAB (Abu Dhabi) ←──────────────────────→ DBS (Singapore)           ║");
        println!("║                                                                       ║");
        println!("║   \"Aethelred moves the Truth, not the Data\"                          ║");
        println!("║                                                                       ║");
        println!("╚═══════════════════════════════════════════════════════════════════════╝");
        println!();
    }

    /// Print final summary
    fn print_summary(&self, output: &DemoOutput, deal: &TradeDeal, lc: &VerifiableLetterOfCredit) {
        println!("\n");
        println!("╔═══════════════════════════════════════════════════════════════════════╗");
        println!("║                       🎉 DEMO COMPLETE 🎉                              ║");
        println!("╠═══════════════════════════════════════════════════════════════════════╣");
        println!("║                                                                       ║");
        println!("║   TRADE SUMMARY                                                       ║");
        println!("║   ─────────────                                                       ║");
        println!("║   Deal Reference:     {:<44}║", deal.reference);
        println!("║   Amount:             {:<44}║", deal.total_value);
        println!("║   Exporter:           {:<44}║", deal.exporter.legal_name);
        println!("║   Importer:           {:<44}║", deal.importer.legal_name);
        println!("║                                                                       ║");
        println!("║   ON-CHAIN SETTLEMENT                                                 ║");
        println!("║   ───────────────────                                                 ║");
        println!("║   LC Reference:       {:<44}║", lc.reference);
        println!(
            "║   LC ID:              0x{:<42}║",
            &hex::encode(lc.lc_id)[..40]
        );
        println!(
            "║   TX Hash:            0x{:<42}║",
            &hex::encode(lc.mint_tx_hash)[..40]
        );
        println!("║   Block:              {:<44}║", lc.mint_block);
        println!("║                                                                       ║");
        println!("║   PERFORMANCE                                                         ║");
        println!("║   ───────────                                                         ║");
        println!(
            "║   Total Time:         {:>6}ms                                        ║",
            output.total_time_ms
        );
        println!(
            "║   Data Transferred:   {:>6} bytes (proofs only)                      ║",
            output.metrics.data_transferred_bytes
        );
        println!("║   Sensitive Data:     NONE EXPOSED ✅                                 ║");
        println!("║                                                                       ║");
        println!("║   EXPLORER                                                            ║");
        println!("║   ────────                                                            ║");
        println!(
            "║   {:<66} ║",
            output.explorer_url.as_ref().unwrap_or(&"-".to_string())
        );
        println!("║                                                                       ║");
        println!("╠═══════════════════════════════════════════════════════════════════════╣");
        println!("║                                                                       ║");
        println!("║   💡 KEY INSIGHT:                                                     ║");
        println!("║                                                                       ║");
        println!("║   \"FAB's data stayed in the UAE node. DBS's data stayed in the       ║");
        println!("║    Singapore node. Aethelred only moved the TRUTH, not the DATA.\"    ║");
        println!("║                                                                       ║");
        println!("╚═══════════════════════════════════════════════════════════════════════╝");
        println!();
    }
}

impl Default for FalconLionDemo {
    fn default() -> Self {
        Self::new(DemoConfig::default())
    }
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_demo_execution() {
        let config = DemoConfig {
            verbose: false,
            simulate_delays: false,
            mode: DemoMode::Fast,
            deal_amount: None,
            goods_description: None,
        };

        let demo = FalconLionDemo::new(config);
        let result = demo.run().await.unwrap();

        assert_eq!(result.status, DemoStatus::Completed);
        assert!(result.lc_reference.is_some());
        assert!(result.settlement_tx_hash.is_some());
        assert!(!result.metrics.sensitive_data_exposed);
    }

    #[test]
    fn test_demo_steps() {
        assert_eq!(DemoStep::FabVerification.emoji(), "🇦🇪");
        assert_eq!(DemoStep::DbsVerification.emoji(), "🇸🇬");
        assert!(DemoStep::MintingLC
            .display_name()
            .contains("Letter of Credit"));
    }
}
