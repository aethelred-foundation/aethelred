//! Verifiable Truth Dashboard for Aethelred Testnet
//!
//! NOT a boring block explorer showing "From: 0x... To: 0x..."
//! This is a dashboard that proves AI work, not crypto transactions.
//!
//! Visual: "Block #1002: Cured Cancer Candidate (Med42 Model) | Verified by Intel SGX"
//! Visual: "This block consumed 500 Watts and produced 5000 AI Inferences"
//!
//! Features:
//! - Inference-centric block display
//! - Energy-to-Intelligence ratio metrics
//! - TEE attestation visualization
//! - Model verification badges
//! - AI work proof certificates
//! - Real-time compute utilization

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};

// ============ Dashboard Configuration ============

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardConfig {
    /// Highlight inferences over transactions
    pub inference_centric: bool,

    /// Show energy metrics
    pub energy_metrics_enabled: bool,

    /// Show TEE attestation details
    pub attestation_details: bool,

    /// Show model verification badges
    pub model_badges: bool,

    /// Real-time update interval (ms)
    pub update_interval_ms: u64,

    /// Maximum blocks to display
    pub max_blocks_display: usize,

    /// Show proof certificates
    pub proof_certificates: bool,
}

impl Default for DashboardConfig {
    fn default() -> Self {
        Self {
            inference_centric: true,
            energy_metrics_enabled: true,
            attestation_details: true,
            model_badges: true,
            update_interval_ms: 1000,
            max_blocks_display: 100,
            proof_certificates: true,
        }
    }
}

// ============ Verifiable Block Display ============

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiableBlock {
    /// Block number
    pub number: u64,

    /// Block hash
    pub hash: String,

    /// Timestamp
    pub timestamp: u64,

    /// Proposer validator
    pub proposer: ValidatorInfo,

    /// AI Work Summary (the MAIN FOCUS)
    pub ai_work: AIWorkSummary,

    /// Energy consumption
    pub energy: EnergyMetrics,

    /// TEE attestations
    pub attestations: Vec<TEEAttestation>,

    /// Intelligence produced
    pub intelligence: IntelligenceMetrics,

    /// Model verifications
    pub model_verifications: Vec<ModelVerification>,

    /// Traditional block data (secondary)
    pub traditional: TraditionalBlockData,

    /// Proof certificate
    pub certificate: Option<ProofCertificate>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorInfo {
    pub address: String,
    pub moniker: String,
    pub hardware: HardwareInfo,
    pub tee_type: TEEType,
    pub attestation_valid: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareInfo {
    pub gpu: Option<GPUInfo>,
    pub cpu: String,
    pub memory_gb: u32,
    pub tee_certified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GPUInfo {
    pub model: String,
    pub vram_gb: u32,
    pub compute_capability: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum TEEType {
    IntelSGX,
    IntelTDX,
    AMDSEV,
    ARMTrustZone,
    AWSNitro,
    None,
}

impl TEEType {
    pub fn display_name(&self) -> &str {
        match self {
            Self::IntelSGX => "Intel SGX",
            Self::IntelTDX => "Intel TDX",
            Self::AMDSEV => "AMD SEV",
            Self::ARMTrustZone => "ARM TrustZone",
            Self::AWSNitro => "AWS Nitro",
            Self::None => "None",
        }
    }
}

// ============ AI Work Summary ============

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIWorkSummary {
    /// Total inferences in this block
    pub total_inferences: u64,

    /// Total FLOPs computed
    pub total_flops: u128,

    /// Seals created
    pub seals_created: u64,

    /// Jobs completed
    pub jobs_completed: u64,

    /// Headline inference (most significant)
    pub headline: Option<HeadlineInference>,

    /// All inferences in this block
    pub inferences: Vec<InferenceSummary>,

    /// Verified outputs
    pub verified_outputs: u64,

    /// Proof types used
    pub proof_types: Vec<ProofType>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeadlineInference {
    /// Catchy description
    pub description: String,

    /// Model used
    pub model: ModelInfo,

    /// Impact category
    pub category: ImpactCategory,

    /// TEE verification
    pub verified_by: String,

    /// Significance score (0-100)
    pub significance: u8,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ImpactCategory {
    Healthcare,
    Finance,
    Science,
    Environment,
    Security,
    General,
}

impl ImpactCategory {
    pub fn icon(&self) -> &str {
        match self {
            Self::Healthcare => "🏥",
            Self::Finance => "💰",
            Self::Science => "🔬",
            Self::Environment => "🌍",
            Self::Security => "🔒",
            Self::General => "🤖",
        }
    }

    pub fn label(&self) -> &str {
        match self {
            Self::Healthcare => "Healthcare AI",
            Self::Finance => "Financial AI",
            Self::Science => "Scientific AI",
            Self::Environment => "Environmental AI",
            Self::Security => "Security AI",
            Self::General => "General AI",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceSummary {
    /// Inference ID
    pub id: String,

    /// Human-readable description
    pub description: String,

    /// Model info
    pub model: ModelInfo,

    /// Input summary (anonymized)
    pub input_summary: String,

    /// Output summary
    pub output_summary: String,

    /// Confidence/probability
    pub confidence: Option<f64>,

    /// FLOPs used
    pub flops: u64,

    /// Verification status
    pub verified: bool,

    /// TEE used
    pub tee_type: TEEType,

    /// Timestamp
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelInfo {
    /// Model hash
    pub hash: String,

    /// Model name
    pub name: String,

    /// Model type
    pub model_type: ModelType,

    /// Publisher
    pub publisher: String,

    /// Verification badges
    pub badges: Vec<ModelBadge>,

    /// Seal count (how many times used)
    pub seal_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ModelType {
    CreditScoring,
    FraudDetection,
    MedicalDiagnosis,
    DrugDiscovery,
    RiskAssessment,
    ImageClassification,
    NaturalLanguage,
    Recommendation,
    Forecasting,
    Custom(String),
}

impl ModelType {
    pub fn display_name(&self) -> &str {
        match self {
            Self::CreditScoring => "Credit Scoring",
            Self::FraudDetection => "Fraud Detection",
            Self::MedicalDiagnosis => "Medical Diagnosis",
            Self::DrugDiscovery => "Drug Discovery",
            Self::RiskAssessment => "Risk Assessment",
            Self::ImageClassification => "Image Classification",
            Self::NaturalLanguage => "Natural Language",
            Self::Recommendation => "Recommendation",
            Self::Forecasting => "Forecasting",
            Self::Custom(name) => name,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelBadge {
    pub badge_type: BadgeType,
    pub issued_by: String,
    pub issued_at: u64,
    pub expires_at: Option<u64>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum BadgeType {
    /// Model has been audited
    Audited,

    /// FDA/regulatory approved
    RegulatoryApproved,

    /// Passes fairness tests
    FairnessCertified,

    /// Has explainability
    Explainable,

    /// HIPAA compliant
    HIPAACompliant,

    /// GDPR compliant
    GDPRCompliant,

    /// Energy efficient
    GreenCertified,

    /// Community verified
    CommunityVerified,
}

impl BadgeType {
    pub fn icon(&self) -> &str {
        match self {
            Self::Audited => "🔍",
            Self::RegulatoryApproved => "✅",
            Self::FairnessCertified => "⚖️",
            Self::Explainable => "💡",
            Self::HIPAACompliant => "🏥",
            Self::GDPRCompliant => "🇪🇺",
            Self::GreenCertified => "🌿",
            Self::CommunityVerified => "👥",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ProofType {
    TEEAttestation,
    ZKProof,
    TEEPlusZK,
    MultiPartyCompute,
}

// ============ Energy Metrics ============

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnergyMetrics {
    /// Total energy consumed (Watt-hours)
    pub total_wh: f64,

    /// Energy per inference (Wh)
    pub wh_per_inference: f64,

    /// Energy efficiency rating
    pub efficiency_rating: EfficiencyRating,

    /// Comparison to traditional compute
    pub vs_traditional: f64,

    /// Carbon footprint (kg CO2)
    pub carbon_kg: f64,

    /// Energy source breakdown
    pub sources: Vec<EnergySource>,

    /// Energy-to-Intelligence ratio
    pub e2i_ratio: f64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum EfficiencyRating {
    /// Best in class
    Excellent,

    /// Good efficiency
    Good,

    /// Average
    Average,

    /// Below average
    Poor,
}

impl EfficiencyRating {
    pub fn icon(&self) -> &str {
        match self {
            Self::Excellent => "🌟",
            Self::Good => "✅",
            Self::Average => "➖",
            Self::Poor => "⚠️",
        }
    }

    pub fn color(&self) -> &str {
        match self {
            Self::Excellent => "#00ff00",
            Self::Good => "#90EE90",
            Self::Average => "#ffff00",
            Self::Poor => "#ff6b6b",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnergySource {
    pub source_type: EnergySourceType,
    pub percentage: f64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum EnergySourceType {
    Solar,
    Wind,
    Hydro,
    Nuclear,
    Natural,
    Grid,
}

// ============ Intelligence Metrics ============

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelligenceMetrics {
    /// Total AI inferences
    pub inferences: u64,

    /// Inferences per second
    pub ips: f64,

    /// Intelligence quotient (custom metric)
    pub iq_score: f64,

    /// Model diversity
    pub model_diversity: u32,

    /// Category breakdown
    pub by_category: HashMap<String, u64>,

    /// Value created (estimated)
    pub estimated_value_usd: f64,
}

// ============ TEE Attestation ============

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TEEAttestation {
    /// Attestation ID
    pub id: String,

    /// TEE type
    pub tee_type: TEEType,

    /// Attestation quote (truncated)
    pub quote_preview: String,

    /// Full quote hash
    pub quote_hash: String,

    /// Enclave measurement
    pub mrenclave: String,

    /// Signer measurement
    pub mrsigner: String,

    /// Security version
    pub isv_svn: u16,

    /// Attestation timestamp
    pub timestamp: u64,

    /// Verification status
    pub status: AttestationStatus,

    /// Verified by
    pub verified_by: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum AttestationStatus {
    Valid,
    Expired,
    Revoked,
    Pending,
}

// ============ Model Verification ============

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelVerification {
    /// Model hash
    pub model_hash: String,

    /// Model name
    pub model_name: String,

    /// Verification type
    pub verification_type: VerificationType,

    /// Verifiers
    pub verifiers: Vec<String>,

    /// Consensus reached
    pub consensus: bool,

    /// Outputs matched
    pub outputs_matched: bool,

    /// Verification proof
    pub proof: VerificationProof,

    /// Timestamp
    pub timestamp: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum VerificationType {
    /// Single TEE verification
    SingleTEE,

    /// Multiple TEE cross-verification
    MultiTEE,

    /// TEE + ZK proof
    Hybrid,

    /// Full cryptographic proof
    FullZK,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationProof {
    pub proof_type: String,
    pub proof_hash: String,
    pub public_inputs_hash: String,
    pub verification_key_hash: String,
}

// ============ Traditional Block Data (Secondary) ============

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraditionalBlockData {
    /// Transaction count (less important)
    pub tx_count: u64,

    /// Gas used
    pub gas_used: u64,

    /// Gas limit
    pub gas_limit: u64,

    /// State root
    pub state_root: String,

    /// Transactions root
    pub transactions_root: String,

    /// Parent hash
    pub parent_hash: String,

    /// Traditional transactions (collapsed by default)
    pub transactions: Vec<TraditionalTx>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraditionalTx {
    pub hash: String,
    pub from: String,
    pub to: Option<String>,
    pub value: String,
    pub tx_type: TxType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TxType {
    Transfer,
    ContractCall,
    ContractDeploy,
    SealRequest,
    JobSubmit,
    JobComplete,
    ModelRegister,
}

// ============ Proof Certificate ============

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofCertificate {
    /// Certificate ID
    pub id: String,

    /// Block number
    pub block_number: u64,

    /// Certificate type
    pub certificate_type: CertificateType,

    /// Summary
    pub summary: String,

    /// All inferences included
    pub inferences_count: u64,

    /// All models used
    pub models: Vec<String>,

    /// Total FLOPs certified
    pub total_flops: u128,

    /// Energy consumed
    pub energy_wh: f64,

    /// TEE attestations
    pub attestation_count: u64,

    /// Merkle root of all proofs
    pub proof_root: String,

    /// Digital signature
    pub signature: String,

    /// Issued at
    pub issued_at: u64,

    /// Valid until
    pub valid_until: u64,

    /// QR code data (for verification)
    pub qr_data: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum CertificateType {
    /// Block-level certificate
    Block,

    /// Model-specific certificate
    Model,

    /// Job completion certificate
    Job,

    /// Batch certificate
    Batch,
}

// ============ Dashboard Aggregates ============

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStats {
    /// Total blocks produced
    pub total_blocks: u64,

    /// Total inferences ever
    pub total_inferences: u128,

    /// Total FLOPs computed
    pub total_flops: u128,

    /// Total energy consumed (kWh)
    pub total_energy_kwh: f64,

    /// Average E2I ratio
    pub avg_e2i_ratio: f64,

    /// Models registered
    pub models_registered: u64,

    /// Seals created
    pub seals_created: u64,

    /// Active validators
    pub active_validators: u64,

    /// TEE-verified percentage
    pub tee_verified_percentage: f64,

    /// Current TPS (transactions)
    pub tps: f64,

    /// Current IPS (inferences)
    pub ips: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceHighlights {
    /// Today's most significant inference
    pub highlight_of_day: Option<HeadlineInference>,

    /// Most active model
    pub most_active_model: Option<ModelInfo>,

    /// Trending categories
    pub trending_categories: Vec<(ImpactCategory, u64)>,

    /// Recent breakthroughs
    pub recent_breakthroughs: Vec<Breakthrough>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Breakthrough {
    pub title: String,
    pub description: String,
    pub model: String,
    pub block_number: u64,
    pub timestamp: u64,
    pub impact_score: u8,
}

// ============ Truth Dashboard Engine ============

pub struct TruthDashboard {
    config: DashboardConfig,
    blocks: VecDeque<VerifiableBlock>,
    network_stats: NetworkStats,
    highlights: InferenceHighlights,
    model_registry: HashMap<String, ModelInfo>,
}

impl TruthDashboard {
    pub fn new(config: DashboardConfig) -> Self {
        Self {
            config,
            blocks: VecDeque::with_capacity(100),
            network_stats: NetworkStats::default(),
            highlights: InferenceHighlights {
                highlight_of_day: None,
                most_active_model: None,
                trending_categories: Vec::new(),
                recent_breakthroughs: Vec::new(),
            },
            model_registry: HashMap::new(),
        }
    }

    /// Add a new block to the dashboard
    pub fn add_block(&mut self, block: VerifiableBlock) {
        // Update network stats
        self.network_stats.total_blocks += 1;
        self.network_stats.total_inferences += block.ai_work.total_inferences as u128;
        self.network_stats.total_flops += block.ai_work.total_flops;
        self.network_stats.total_energy_kwh += block.energy.total_wh / 1000.0;

        // Check for headline
        if let Some(ref headline) = block.ai_work.headline {
            if headline.significance >= 80 {
                self.highlights.highlight_of_day = Some(headline.clone());
            }
        }

        // Store block
        self.blocks.push_front(block);

        // Trim to max size
        while self.blocks.len() > self.config.max_blocks_display {
            self.blocks.pop_back();
        }
    }

    /// Format a block for display
    pub fn format_block_display(&self, block: &VerifiableBlock) -> BlockDisplay {
        let headline = if let Some(ref h) = block.ai_work.headline {
            format!("{} {} | Verified by {}",
                h.category.icon(),
                h.description,
                h.verified_by
            )
        } else if block.ai_work.total_inferences > 0 {
            format!("🤖 {} AI Inferences | {} Models Used",
                block.ai_work.total_inferences,
                block.ai_work.inferences.iter()
                    .map(|i| &i.model.name)
                    .collect::<std::collections::HashSet<_>>()
                    .len()
            )
        } else {
            format!("📦 Block #{}", block.number)
        };

        let energy_display = format!(
            "⚡ {:.2} Wh consumed | {} inferences | E2I: {:.2}",
            block.energy.total_wh,
            block.ai_work.total_inferences,
            block.energy.e2i_ratio
        );

        let attestation_display = if !block.attestations.is_empty() {
            let tee_types: Vec<_> = block.attestations.iter()
                .map(|a| a.tee_type.display_name())
                .collect::<std::collections::HashSet<_>>()
                .into_iter()
                .collect();
            format!("🔐 Verified by: {}", tee_types.join(", "))
        } else {
            "🔐 No TEE attestation".to_string()
        };

        BlockDisplay {
            block_number: block.number,
            headline,
            energy_display,
            attestation_display,
            inference_count: block.ai_work.total_inferences,
            flops: block.ai_work.total_flops,
            energy_wh: block.energy.total_wh,
            efficiency_rating: block.energy.efficiency_rating,
            tee_verified: !block.attestations.is_empty(),
            model_badges: block.ai_work.inferences.iter()
                .flat_map(|i| i.model.badges.clone())
                .collect(),
            timestamp: block.timestamp,
        }
    }

    /// Get network summary for dashboard header
    pub fn network_summary(&self) -> NetworkSummary {
        NetworkSummary {
            total_inferences: format_large_number(self.network_stats.total_inferences),
            total_flops: format_flops(self.network_stats.total_flops),
            total_energy: format!("{:.2} kWh", self.network_stats.total_energy_kwh),
            avg_e2i: format!("{:.2}", self.network_stats.avg_e2i_ratio),
            active_validators: self.network_stats.active_validators,
            tee_verified_pct: format!("{:.1}%", self.network_stats.tee_verified_percentage),
            ips: format!("{:.1} IPS", self.network_stats.ips),
            models_registered: self.network_stats.models_registered,
        }
    }

    /// Get recent blocks
    pub fn recent_blocks(&self, limit: usize) -> Vec<&VerifiableBlock> {
        self.blocks.iter().take(limit).collect()
    }

    /// Get block by number
    pub fn get_block(&self, number: u64) -> Option<&VerifiableBlock> {
        self.blocks.iter().find(|b| b.number == number)
    }

    /// Get highlights
    pub fn highlights(&self) -> &InferenceHighlights {
        &self.highlights
    }

    /// Get network stats
    pub fn stats(&self) -> &NetworkStats {
        &self.network_stats
    }

    /// Generate proof certificate for a block
    pub fn generate_certificate(&self, block: &VerifiableBlock) -> ProofCertificate {
        let models: Vec<String> = block.ai_work.inferences.iter()
            .map(|i| i.model.hash.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        ProofCertificate {
            id: format!("cert_{}", block.number),
            block_number: block.number,
            certificate_type: CertificateType::Block,
            summary: format!(
                "Block #{} certified {} AI inferences using {} models, consuming {:.2} Wh with {} TEE attestations",
                block.number,
                block.ai_work.total_inferences,
                models.len(),
                block.energy.total_wh,
                block.attestations.len()
            ),
            inferences_count: block.ai_work.total_inferences,
            models,
            total_flops: block.ai_work.total_flops,
            energy_wh: block.energy.total_wh,
            attestation_count: block.attestations.len() as u64,
            proof_root: format!("0x{}", block.hash),
            signature: format!("sig_{}", block.hash),
            issued_at: current_timestamp(),
            valid_until: current_timestamp() + 365 * 24 * 3600,
            qr_data: format!("aethelred://verify/{}/{}", block.number, block.hash),
        }
    }
}

impl Default for NetworkStats {
    fn default() -> Self {
        Self {
            total_blocks: 0,
            total_inferences: 0,
            total_flops: 0,
            total_energy_kwh: 0.0,
            avg_e2i_ratio: 0.0,
            models_registered: 0,
            seals_created: 0,
            active_validators: 5,
            tee_verified_percentage: 100.0,
            tps: 0.0,
            ips: 0.0,
        }
    }
}

// ============ Display Types ============

#[derive(Debug, Clone, Serialize)]
pub struct BlockDisplay {
    pub block_number: u64,
    pub headline: String,
    pub energy_display: String,
    pub attestation_display: String,
    pub inference_count: u64,
    pub flops: u128,
    pub energy_wh: f64,
    pub efficiency_rating: EfficiencyRating,
    pub tee_verified: bool,
    pub model_badges: Vec<ModelBadge>,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct NetworkSummary {
    pub total_inferences: String,
    pub total_flops: String,
    pub total_energy: String,
    pub avg_e2i: String,
    pub active_validators: u64,
    pub tee_verified_pct: String,
    pub ips: String,
    pub models_registered: u64,
}

// ============ Sample Data Generator ============

impl VerifiableBlock {
    /// Generate a sample block for demonstration
    pub fn sample(number: u64) -> Self {
        let models = vec![
            ModelInfo {
                hash: "0xabc123...".to_string(),
                name: "CreditScore-XGB-v2".to_string(),
                model_type: ModelType::CreditScoring,
                publisher: "Aethelred Labs".to_string(),
                badges: vec![
                    ModelBadge {
                        badge_type: BadgeType::Audited,
                        issued_by: "SecurityAI".to_string(),
                        issued_at: current_timestamp() - 86400 * 30,
                        expires_at: Some(current_timestamp() + 86400 * 365),
                    },
                    ModelBadge {
                        badge_type: BadgeType::GDPRCompliant,
                        issued_by: "EU-AI-Cert".to_string(),
                        issued_at: current_timestamp() - 86400 * 60,
                        expires_at: None,
                    },
                ],
                seal_count: 15000,
            },
            ModelInfo {
                hash: "0xdef456...".to_string(),
                name: "Med42-Diagnosis".to_string(),
                model_type: ModelType::MedicalDiagnosis,
                publisher: "HealthAI Research".to_string(),
                badges: vec![
                    ModelBadge {
                        badge_type: BadgeType::HIPAACompliant,
                        issued_by: "HHS".to_string(),
                        issued_at: current_timestamp() - 86400 * 90,
                        expires_at: None,
                    },
                ],
                seal_count: 5000,
            },
        ];

        let inferences = vec![
            InferenceSummary {
                id: format!("inf_{}_1", number),
                description: "Credit risk assessment for loan application".to_string(),
                model: models[0].clone(),
                input_summary: "Application #A-2024-1234 (anonymized)".to_string(),
                output_summary: "Score: 742 | Risk: Low".to_string(),
                confidence: Some(0.94),
                flops: 500_000_000,
                verified: true,
                tee_type: TEEType::IntelSGX,
                timestamp: current_timestamp(),
            },
            InferenceSummary {
                id: format!("inf_{}_2", number),
                description: "Preliminary cancer screening analysis".to_string(),
                model: models[1].clone(),
                input_summary: "Scan #M-2024-5678 (de-identified)".to_string(),
                output_summary: "No abnormalities detected".to_string(),
                confidence: Some(0.98),
                flops: 2_000_000_000,
                verified: true,
                tee_type: TEEType::IntelSGX,
                timestamp: current_timestamp(),
            },
        ];

        let headline = HeadlineInference {
            description: "Cancer Screening Analysis - No Abnormalities Detected".to_string(),
            model: models[1].clone(),
            category: ImpactCategory::Healthcare,
            verified_by: "Intel SGX".to_string(),
            significance: 85,
        };

        VerifiableBlock {
            number,
            hash: format!("0x{:064x}", number * 12345),
            timestamp: current_timestamp(),
            proposer: ValidatorInfo {
                address: "aethelred1validator...".to_string(),
                moniker: "AbuDhabi-Node-1".to_string(),
                hardware: HardwareInfo {
                    gpu: Some(GPUInfo {
                        model: "NVIDIA A100".to_string(),
                        vram_gb: 80,
                        compute_capability: "8.0".to_string(),
                    }),
                    cpu: "Intel Xeon Platinum 8380".to_string(),
                    memory_gb: 512,
                    tee_certified: true,
                },
                tee_type: TEEType::IntelSGX,
                attestation_valid: true,
            },
            ai_work: AIWorkSummary {
                total_inferences: inferences.len() as u64,
                total_flops: inferences.iter().map(|i| i.flops as u128).sum(),
                seals_created: 2,
                jobs_completed: 2,
                headline: Some(headline),
                inferences,
                verified_outputs: 2,
                proof_types: vec![ProofType::TEEAttestation],
            },
            energy: EnergyMetrics {
                total_wh: 0.5,
                wh_per_inference: 0.25,
                efficiency_rating: EfficiencyRating::Excellent,
                vs_traditional: 0.1,
                carbon_kg: 0.0002,
                sources: vec![
                    EnergySource {
                        source_type: EnergySourceType::Solar,
                        percentage: 60.0,
                    },
                    EnergySource {
                        source_type: EnergySourceType::Nuclear,
                        percentage: 40.0,
                    },
                ],
                e2i_ratio: 10000.0,
            },
            attestations: vec![
                TEEAttestation {
                    id: "att_1".to_string(),
                    tee_type: TEEType::IntelSGX,
                    quote_preview: "SGX Quote: 0x12ab...".to_string(),
                    quote_hash: "0xquote_hash".to_string(),
                    mrenclave: "0xmrenclave...".to_string(),
                    mrsigner: "0xmrsigner...".to_string(),
                    isv_svn: 1,
                    timestamp: current_timestamp(),
                    status: AttestationStatus::Valid,
                    verified_by: vec!["Intel Attestation Service".to_string()],
                },
            ],
            intelligence: IntelligenceMetrics {
                inferences: 2,
                ips: 100.0,
                iq_score: 95.0,
                model_diversity: 2,
                by_category: HashMap::from([
                    ("Finance".to_string(), 1),
                    ("Healthcare".to_string(), 1),
                ]),
                estimated_value_usd: 15.0,
            },
            model_verifications: vec![],
            traditional: TraditionalBlockData {
                tx_count: 150,
                gas_used: 15_000_000,
                gas_limit: 30_000_000,
                state_root: "0xstate...".to_string(),
                transactions_root: "0xtxroot...".to_string(),
                parent_hash: format!("0x{:064x}", (number - 1) * 12345),
                transactions: vec![],
            },
            certificate: None,
        }
    }
}

// ============ Helper Functions ============

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn format_large_number(n: u128) -> String {
    if n >= 1_000_000_000_000 {
        format!("{:.2}T", n as f64 / 1_000_000_000_000.0)
    } else if n >= 1_000_000_000 {
        format!("{:.2}B", n as f64 / 1_000_000_000.0)
    } else if n >= 1_000_000 {
        format!("{:.2}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.2}K", n as f64 / 1_000.0)
    } else {
        format!("{}", n)
    }
}

fn format_flops(flops: u128) -> String {
    if flops >= 1_000_000_000_000_000_000 {
        format!("{:.2} ExaFLOPS", flops as f64 / 1_000_000_000_000_000_000.0)
    } else if flops >= 1_000_000_000_000_000 {
        format!("{:.2} PetaFLOPS", flops as f64 / 1_000_000_000_000_000.0)
    } else if flops >= 1_000_000_000_000 {
        format!("{:.2} TeraFLOPS", flops as f64 / 1_000_000_000_000.0)
    } else if flops >= 1_000_000_000 {
        format!("{:.2} GigaFLOPS", flops as f64 / 1_000_000_000.0)
    } else {
        format!("{} FLOPS", flops)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dashboard_creation() {
        let config = DashboardConfig::default();
        let dashboard = TruthDashboard::new(config);

        assert!(dashboard.blocks.is_empty());
    }

    #[test]
    fn test_add_block() {
        let config = DashboardConfig::default();
        let mut dashboard = TruthDashboard::new(config);

        let block = VerifiableBlock::sample(1);
        dashboard.add_block(block);

        assert_eq!(dashboard.blocks.len(), 1);
        assert_eq!(dashboard.network_stats.total_blocks, 1);
    }

    #[test]
    fn test_block_display() {
        let config = DashboardConfig::default();
        let dashboard = TruthDashboard::new(config);

        let block = VerifiableBlock::sample(1);
        let display = dashboard.format_block_display(&block);

        assert!(display.headline.contains("Healthcare"));
        assert!(display.tee_verified);
    }

    #[test]
    fn test_certificate_generation() {
        let config = DashboardConfig::default();
        let dashboard = TruthDashboard::new(config);

        let block = VerifiableBlock::sample(100);
        let cert = dashboard.generate_certificate(&block);

        assert_eq!(cert.block_number, 100);
        assert!(!cert.summary.is_empty());
    }

    #[test]
    fn test_format_flops() {
        assert!(format_flops(1_000_000_000_000).contains("Tera"));
        assert!(format_flops(1_000_000_000_000_000).contains("Peta"));
    }
}
