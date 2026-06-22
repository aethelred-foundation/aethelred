//! Pillar 1: Proof of Useful Work (PoUW)
//!
//! ## The Competitor Gap
//!
//! - **Bitcoin**: Wastes energy on meaningless hashes (PoW)
//! - **Ethereum/Solana**: Rewards passive capital (PoS) - A validator with $10M
//!   secures the network but adds **zero productivity**
//!
//! ## The Aethelred Advantage
//!
//! 80% of hashing power directed at **useful AI inference**:
//! - Protein folding
//! - Medical image analysis
//! - Financial risk modeling
//! - Climate simulations
//!
//! Only 20% is consensus overhead.
//!
//! ## The Useful Work Router
//!
//! A mempool layer that splits transactions into:
//! - **Financial Txs** (fast, lightweight) → High TPS for payments
//! - **Compute Jobs** (heavy, AI inference) → Utilizes idle GPU power
//!
//! This ensures the network is always productive, not just secure.

use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, VecDeque};
use std::time::{Duration, SystemTime};

// ============================================================================
// Work Categories
// ============================================================================

/// Categories of useful work the network can perform
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum UsefulWorkCategory {
    /// Scientific research computations
    Scientific {
        domain: ScientificDomain,
        priority: ResearchPriority,
    },
    /// Financial AI computations
    Financial {
        model_type: FinancialModelType,
        urgency: Urgency,
    },
    /// Healthcare AI computations
    Healthcare {
        computation_type: HealthcareComputation,
        hipaa_required: bool,
    },
    /// Environmental/Climate modeling
    Environmental {
        simulation_type: EnvironmentalSimulation,
    },
    /// General ML inference
    GeneralML {
        model_hash: [u8; 32],
        framework: MLFramework,
    },
    /// Rendering and graphics
    Rendering { render_type: RenderType },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ScientificDomain {
    /// Protein structure prediction (AlphaFold-style)
    ProteinFolding,
    /// Drug discovery and molecular docking
    DrugDiscovery,
    /// Genomic analysis
    Genomics,
    /// Astronomical data processing
    Astronomy,
    /// Particle physics simulations
    ParticlePhysics,
    /// Materials science
    MaterialsScience,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ResearchPriority {
    /// Urgent research (pandemic response, etc.)
    Critical,
    /// High-priority funded research
    High,
    /// Standard academic research
    Normal,
    /// Background computation
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum FinancialModelType {
    /// Credit risk scoring
    CreditScoring,
    /// Fraud detection
    FraudDetection,
    /// Market risk (VaR, etc.)
    MarketRisk,
    /// Anti-money laundering
    AML,
    /// Algorithmic trading signals
    TradingSignals,
    /// Insurance underwriting
    InsuranceUnderwriting,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Urgency {
    /// Real-time (< 100ms)
    RealTime,
    /// Near real-time (< 1s)
    NearRealTime,
    /// Batch processing (< 1 hour)
    Batch,
    /// Background (best effort)
    Background,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum HealthcareComputation {
    /// Medical image analysis (X-ray, MRI, CT)
    MedicalImaging,
    /// Diagnostic AI
    Diagnosis,
    /// Treatment recommendation
    TreatmentPlan,
    /// Drug interaction analysis
    DrugInteraction,
    /// Patient risk stratification
    RiskStratification,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum EnvironmentalSimulation {
    /// Climate modeling
    ClimateModeling,
    /// Weather prediction
    WeatherPrediction,
    /// Carbon footprint analysis
    CarbonAnalysis,
    /// Biodiversity modeling
    BiodiversityModeling,
    /// Ocean current simulation
    OceanSimulation,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum MLFramework {
    ONNX,
    TensorFlow,
    PyTorch,
    JAX,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum RenderType {
    /// 3D scene rendering
    Scene3D,
    /// Neural radiance fields
    NeRF,
    /// Diffusion model image generation
    DiffusionModel,
    /// Video encoding/transcoding
    VideoProcessing,
}

// ============================================================================
// Transaction Types
// ============================================================================

/// A transaction in the Aethelred network
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AethelredTransaction {
    /// Standard financial transaction (fast path)
    Financial(FinancialTransaction),
    /// Compute job (useful work path)
    Compute(ComputeJob),
    /// Governance transaction
    Governance(GovernanceTransaction),
    /// Bridge transaction
    Bridge(BridgeTransaction),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinancialTransaction {
    /// Transaction hash
    pub hash: [u8; 32],
    /// Sender address
    pub from: [u8; 32],
    /// Recipient address
    pub to: [u8; 32],
    /// Amount in smallest unit
    pub amount: u128,
    /// Gas price
    pub gas_price: u64,
    /// Gas limit
    pub gas_limit: u64,
    /// Nonce
    pub nonce: u64,
    /// Standard signature (Ed25519)
    #[serde(with = "crate::serde_byte_array_64")]
    pub signature: [u8; 64],
    /// Post-quantum signature (Dilithium3)
    pub pq_signature: Option<Vec<u8>>,
    /// Timestamp
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputeJob {
    /// Job ID
    pub id: [u8; 32],
    /// Work category
    pub category: UsefulWorkCategory,
    /// Model hash (SHA-256 of model weights)
    pub model_hash: [u8; 32],
    /// Input data hash
    pub input_hash: [u8; 32],
    /// Encrypted input data (for TEE processing)
    pub encrypted_input: Vec<u8>,
    /// Requester address
    pub requester: [u8; 32],
    /// Compute bounty (payment for work)
    pub bounty: u128,
    /// Maximum execution time
    pub max_execution_time: Duration,
    /// Required TEE platform
    pub required_tee: Option<TEERequirement>,
    /// Deadline
    pub deadline: Option<u64>,
    /// Priority multiplier (higher = more priority, more cost)
    pub priority_multiplier: f64,
    /// Signature
    #[serde(with = "crate::serde_byte_array_64")]
    pub signature: [u8; 64],
    /// Post-quantum signature
    pub pq_signature: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceTransaction {
    pub hash: [u8; 32],
    pub proposer: [u8; 32],
    pub action: GovernanceAction,
    #[serde(with = "crate::serde_byte_array_64")]
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GovernanceAction {
    Propose {
        proposal_id: u64,
        description: String,
    },
    Vote {
        proposal_id: u64,
        vote: bool,
    },
    Veto {
        proposal_id: u64,
        reason: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeTransaction {
    pub hash: [u8; 32],
    pub source_chain: String,
    pub destination_chain: String,
    pub payload: Vec<u8>,
    #[serde(with = "crate::serde_byte_array_64")]
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum TEERequirement {
    IntelSGX { min_svn: u16 },
    AMDSEV { variant: String },
    AWSNitro,
    Any,
}

// ============================================================================
// Energy & cost metering
// ============================================================================
//
// PoUW's claim — "every watt is spent on useful inference" — is only credible if
// the watts are *measured*, not asserted. These types carry a real per-job
// measurement of energy and cost, with an explicit honesty label distinguishing
// a live hardware power reading from a device-profile estimate. Nothing here
// fabricates a number: aggregates are summed from measurements, and the only
// constants are governance-set conversion factors in `EnergyModel`.

/// Where a power figure came from — the energy analogue of the TEE hardware
/// boundary. An aggregate is only `Measured` if every contributing job was.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnergyBasis {
    /// Average power read from a live hardware meter (RAPL, NVML, BMC, PDU).
    Measured,
    /// Average power inferred from a device power profile (e.g. TDP x
    /// utilization) because no live meter was available. Honest estimate.
    DeviceProfileEstimate,
}

impl EnergyBasis {
    /// Combine two bases: the result is `Measured` only if both are.
    pub fn combine(self, other: EnergyBasis) -> EnergyBasis {
        match (self, other) {
            (EnergyBasis::Measured, EnergyBasis::Measured) => EnergyBasis::Measured,
            _ => EnergyBasis::DeviceProfileEstimate,
        }
    }
}

/// A real measurement of the work one compute job consumed.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct WorkMeasurement {
    /// Device-seconds consumed (wall-clock seconds x active accelerators).
    pub device_seconds: f64,
    /// Average power draw of the accelerators during execution, in watts.
    pub average_power_watts: f64,
    /// Whether `average_power_watts` is a live reading or a profile estimate.
    pub energy_basis: EnergyBasis,
}

impl WorkMeasurement {
    /// A measurement taken from a live hardware power meter.
    pub fn measured(device_seconds: f64, average_power_watts: f64) -> Self {
        WorkMeasurement {
            device_seconds: device_seconds.max(0.0),
            average_power_watts: average_power_watts.max(0.0),
            energy_basis: EnergyBasis::Measured,
        }
    }

    /// A measurement inferred from a device power profile when no meter exists:
    /// `average_power = rated_tdp_watts * utilization`. Labeled as an estimate.
    pub fn from_device_profile(
        device_seconds: f64,
        rated_tdp_watts: f64,
        utilization: f64,
    ) -> Self {
        WorkMeasurement {
            device_seconds: device_seconds.max(0.0),
            average_power_watts: rated_tdp_watts.max(0.0) * utilization.clamp(0.0, 1.0),
            energy_basis: EnergyBasis::DeviceProfileEstimate,
        }
    }

    /// Energy at the accelerator, in joules (watts x seconds).
    pub fn device_joules(&self) -> f64 {
        self.average_power_watts * self.device_seconds
    }
}

/// Governance-set conversion factors. These are the *only* constants in the
/// energy accounting, and each is an explicit, auditable parameter rather than
/// a literal buried in a function. Defaults are documented and UAE-representative.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct EnergyModel {
    /// Power Usage Effectiveness: total facility power / IT power. Accounts for
    /// cooling and delivery overhead on top of the accelerator draw.
    pub pue: f64,
    /// Grid carbon intensity in kg CO2e per kWh.
    pub grid_carbon_intensity_kg_per_kwh: f64,
    /// Delivered electricity cost in USD per kWh.
    pub electricity_cost_usd_per_kwh: f64,
    /// Fraction of equivalent-security proof-of-work energy that yields no
    /// useful output. 1.0 = a PoW chain wastes 100% on hashes. Used only for the
    /// clearly-labeled "energy saved vs PoW" comparison.
    pub pow_baseline_wasted_ratio: f64,
}

impl Default for EnergyModel {
    fn default() -> Self {
        EnergyModel {
            pue: 1.2,
            grid_carbon_intensity_kg_per_kwh: 0.40,
            electricity_cost_usd_per_kwh: 0.08,
            pow_baseline_wasted_ratio: 1.0,
        }
    }
}

impl EnergyModel {
    const JOULES_PER_KWH: f64 = 3_600_000.0;

    /// Facility energy in kWh for a device-level measurement, including PUE.
    pub fn facility_kwh(&self, m: &WorkMeasurement) -> f64 {
        (m.device_joules() / Self::JOULES_PER_KWH) * self.pue
    }

    /// Delivered electricity cost in USD for a measurement.
    pub fn cost_usd(&self, m: &WorkMeasurement) -> f64 {
        self.facility_kwh(m) * self.electricity_cost_usd_per_kwh
    }

    /// Carbon footprint in kg CO2e for a measurement.
    pub fn carbon_kg(&self, m: &WorkMeasurement) -> f64 {
        self.facility_kwh(m) * self.grid_carbon_intensity_kg_per_kwh
    }
}

// ============================================================================
// The Useful Work Router
// ============================================================================

/// The Useful Work Router - Heart of the PoUW consensus
///
/// Splits the mempool into two lanes:
/// 1. **Fast Lane**: Financial transactions (high TPS, low latency)
/// 2. **Compute Lane**: AI inference jobs (high value, parallel execution)
pub struct UsefulWorkRouter {
    /// Fast lane for financial transactions
    fast_lane: VecDeque<FinancialTransaction>,
    /// Compute lane for AI jobs (priority queue)
    compute_lane: BinaryHeap<PrioritizedComputeJob>,
    /// Governance transactions
    governance_queue: VecDeque<GovernanceTransaction>,
    /// Bridge transactions
    bridge_queue: VecDeque<BridgeTransaction>,
    /// Active compute jobs being processed
    active_jobs: HashMap<[u8; 32], ActiveJob>,
    /// Completed jobs awaiting finalization
    completed_jobs: HashMap<[u8; 32], CompletedJob>,
    /// Router configuration
    config: RouterConfig,
    /// Metrics
    metrics: RouterMetrics,
}

#[derive(Debug, Clone)]
pub struct RouterConfig {
    /// Maximum transactions in fast lane
    pub max_fast_lane_size: usize,
    /// Maximum jobs in compute lane
    pub max_compute_lane_size: usize,
    /// Target ratio of useful work (0.8 = 80%)
    pub useful_work_ratio: f64,
    /// Minimum bounty for compute jobs
    pub min_compute_bounty: u128,
    /// Maximum parallel compute jobs
    pub max_parallel_jobs: usize,
    /// Block time target
    pub block_time_target: Duration,
    /// Conversion factors for energy, cost, and carbon accounting.
    pub energy_model: EnergyModel,
}

impl Default for RouterConfig {
    fn default() -> Self {
        RouterConfig {
            max_fast_lane_size: 10_000,
            max_compute_lane_size: 1_000,
            useful_work_ratio: 0.80,       // 80% useful work
            min_compute_bounty: 1_000_000, // Minimum 0.001 AETHEL
            max_parallel_jobs: 64,
            block_time_target: Duration::from_millis(400),
            energy_model: EnergyModel::default(),
        }
    }
}

/// A compute job with priority for the heap
#[derive(Debug, Clone)]
struct PrioritizedComputeJob {
    job: ComputeJob,
    priority_score: u64,
    received_at: SystemTime,
}

impl PartialEq for PrioritizedComputeJob {
    fn eq(&self, other: &Self) -> bool {
        self.priority_score == other.priority_score
    }
}

impl Eq for PrioritizedComputeJob {}

impl PartialOrd for PrioritizedComputeJob {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PrioritizedComputeJob {
    fn cmp(&self, other: &Self) -> Ordering {
        // Higher priority first
        self.priority_score.cmp(&other.priority_score)
    }
}

#[derive(Debug, Clone)]
pub struct ActiveJob {
    pub job: ComputeJob,
    pub assigned_validator: [u8; 32],
    pub started_at: SystemTime,
    pub tee_attestation: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct CompletedJob {
    pub job_id: [u8; 32],
    pub result_hash: [u8; 32],
    pub validator: [u8; 32],
    pub execution_time: Duration,
    pub tee_attestation: Vec<u8>,
    pub useful_work_units: u64,
    pub completed_at: SystemTime,
    /// Measured energy/cost for this job. `None` means the worker reported no
    /// measurement, in which case the job contributes zero energy to the
    /// aggregates — we never fabricate a figure for an unmetered job.
    pub measurement: Option<WorkMeasurement>,
}

#[derive(Debug, Clone, Default)]
pub struct RouterMetrics {
    /// Total financial transactions processed
    pub total_financial_txs: u64,
    /// Total compute jobs processed
    pub total_compute_jobs: u64,
    /// Total useful work units generated
    pub total_useful_work_units: u64,
    /// Measured facility energy spent on useful work, in kWh (summed from job
    /// measurements, including PUE). Zero for unmetered jobs.
    pub useful_work_energy_kwh: f64,
    /// Measured energy attributed to consensus/overhead, in kWh, as reported by
    /// validators. Kept separate so the useful-work ratio is computed from real
    /// numbers, not a configured target.
    pub consensus_overhead_energy_kwh: f64,
    /// Estimated kWh an equivalent-security PoW chain would burn on useless
    /// hashing for the same useful output. A clearly-labeled comparison.
    pub energy_saved_kwh: f64,
    /// Measured delivered electricity cost of useful work, in USD.
    pub useful_work_energy_cost_usd: f64,
    /// Measured carbon footprint of useful work, in kg CO2e.
    pub useful_work_carbon_kg: f64,
    /// Number of completed jobs that carried a real measurement.
    pub measured_job_count: u64,
    /// Worst (least trustworthy) energy basis seen across measured jobs.
    pub energy_basis: Option<EnergyBasis>,
    /// Average compute job execution time
    pub avg_job_execution_time: Duration,
    /// Current useful work ratio
    pub current_useful_work_ratio: f64,
}

impl UsefulWorkRouter {
    pub fn new(config: RouterConfig) -> Self {
        UsefulWorkRouter {
            fast_lane: VecDeque::new(),
            compute_lane: BinaryHeap::new(),
            governance_queue: VecDeque::new(),
            bridge_queue: VecDeque::new(),
            active_jobs: HashMap::new(),
            completed_jobs: HashMap::new(),
            config,
            metrics: RouterMetrics::default(),
        }
    }

    /// Submit a transaction to the router
    pub fn submit(&mut self, tx: AethelredTransaction) -> Result<(), RouterError> {
        match tx {
            AethelredTransaction::Financial(ftx) => {
                if self.fast_lane.len() >= self.config.max_fast_lane_size {
                    return Err(RouterError::FastLaneFull);
                }
                self.fast_lane.push_back(ftx);
            }
            AethelredTransaction::Compute(job) => {
                if job.bounty < self.config.min_compute_bounty {
                    return Err(RouterError::BountyTooLow {
                        provided: job.bounty,
                        minimum: self.config.min_compute_bounty,
                    });
                }
                if self.compute_lane.len() >= self.config.max_compute_lane_size {
                    return Err(RouterError::ComputeLaneFull);
                }
                let priority_score = self.calculate_priority(&job);
                self.compute_lane.push(PrioritizedComputeJob {
                    job,
                    priority_score,
                    received_at: SystemTime::now(),
                });
            }
            AethelredTransaction::Governance(gtx) => {
                self.governance_queue.push_back(gtx);
            }
            AethelredTransaction::Bridge(btx) => {
                self.bridge_queue.push_back(btx);
            }
        }
        Ok(())
    }

    /// Calculate priority score for a compute job
    fn calculate_priority(&self, job: &ComputeJob) -> u64 {
        let mut score: u64 = 0;

        // Base score from bounty (logarithmic to prevent plutocracy)
        score += (job.bounty as f64).log2() as u64 * 100;

        // Category-based priority
        score += match &job.category {
            UsefulWorkCategory::Healthcare { .. } => 500, // Healthcare gets priority
            UsefulWorkCategory::Scientific { priority, .. } => match priority {
                ResearchPriority::Critical => 1000,
                ResearchPriority::High => 400,
                ResearchPriority::Normal => 200,
                ResearchPriority::Low => 50,
            },
            UsefulWorkCategory::Financial { urgency, .. } => match urgency {
                Urgency::RealTime => 800,
                Urgency::NearRealTime => 400,
                Urgency::Batch => 100,
                Urgency::Background => 25,
            },
            UsefulWorkCategory::Environmental { .. } => 300,
            UsefulWorkCategory::GeneralML { .. } => 100,
            UsefulWorkCategory::Rendering { .. } => 50,
        };

        // Deadline urgency
        if let Some(deadline) = job.deadline {
            let now = SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            if deadline > now {
                let time_left = deadline - now;
                if time_left < 60 {
                    score += 500; // Less than 1 minute
                } else if time_left < 300 {
                    score += 200; // Less than 5 minutes
                }
            }
        }

        // Priority multiplier
        score = (score as f64 * job.priority_multiplier) as u64;

        score
    }

    /// Build the next block with optimal useful work ratio
    pub fn build_block(&mut self, block_gas_limit: u64) -> BlockProposal {
        let mut proposal = BlockProposal {
            financial_txs: Vec::new(),
            compute_jobs: Vec::new(),
            governance_txs: Vec::new(),
            bridge_txs: Vec::new(),
            useful_work_ratio: 0.0,
            estimated_gas: 0,
        };

        let target_useful_work_gas =
            (block_gas_limit as f64 * self.config.useful_work_ratio) as u64;
        let target_financial_gas = block_gas_limit - target_useful_work_gas;

        // Fill compute jobs first (useful work)
        let mut compute_gas_used: u64 = 0;
        while let Some(pjob) = self.compute_lane.peek() {
            let job_gas = self.estimate_compute_gas(&pjob.job);
            if compute_gas_used + job_gas > target_useful_work_gas {
                break;
            }
            if let Some(pjob) = self.compute_lane.pop() {
                compute_gas_used += job_gas;
                proposal.compute_jobs.push(pjob.job);
            }
        }

        // Fill financial transactions
        let mut financial_gas_used: u64 = 0;
        while let Some(ftx) = self.fast_lane.front() {
            let tx_gas = ftx.gas_limit;
            if financial_gas_used + tx_gas > target_financial_gas {
                break;
            }
            if let Some(ftx) = self.fast_lane.pop_front() {
                financial_gas_used += tx_gas;
                proposal.financial_txs.push(ftx);
            }
        }

        // Add governance and bridge transactions (low gas, high priority)
        while let Some(gtx) = self.governance_queue.pop_front() {
            proposal.governance_txs.push(gtx);
        }
        while let Some(btx) = self.bridge_queue.pop_front() {
            proposal.bridge_txs.push(btx);
        }

        // Calculate actual useful work ratio
        let total_gas = compute_gas_used + financial_gas_used;
        proposal.useful_work_ratio = if total_gas > 0 {
            compute_gas_used as f64 / total_gas as f64
        } else {
            0.0
        };
        proposal.estimated_gas = total_gas;

        proposal
    }

    fn estimate_compute_gas(&self, job: &ComputeJob) -> u64 {
        // Base gas for compute job
        let base_gas = 100_000u64;

        // Category-specific gas estimation
        let category_gas = match &job.category {
            UsefulWorkCategory::Scientific { domain, .. } => match domain {
                ScientificDomain::ProteinFolding => 5_000_000,
                ScientificDomain::DrugDiscovery => 3_000_000,
                ScientificDomain::Genomics => 2_000_000,
                ScientificDomain::Astronomy => 1_500_000,
                ScientificDomain::ParticlePhysics => 4_000_000,
                ScientificDomain::MaterialsScience => 2_500_000,
            },
            UsefulWorkCategory::Healthcare {
                computation_type, ..
            } => match computation_type {
                HealthcareComputation::MedicalImaging => 2_000_000,
                HealthcareComputation::Diagnosis => 1_000_000,
                HealthcareComputation::TreatmentPlan => 1_500_000,
                HealthcareComputation::DrugInteraction => 500_000,
                HealthcareComputation::RiskStratification => 800_000,
            },
            UsefulWorkCategory::Financial { model_type, .. } => match model_type {
                FinancialModelType::CreditScoring => 500_000,
                FinancialModelType::FraudDetection => 300_000,
                FinancialModelType::MarketRisk => 1_000_000,
                FinancialModelType::AML => 700_000,
                FinancialModelType::TradingSignals => 200_000,
                FinancialModelType::InsuranceUnderwriting => 600_000,
            },
            UsefulWorkCategory::Environmental { simulation_type } => match simulation_type {
                EnvironmentalSimulation::ClimateModeling => 10_000_000,
                EnvironmentalSimulation::WeatherPrediction => 3_000_000,
                EnvironmentalSimulation::CarbonAnalysis => 1_000_000,
                EnvironmentalSimulation::BiodiversityModeling => 2_000_000,
                EnvironmentalSimulation::OceanSimulation => 5_000_000,
            },
            UsefulWorkCategory::GeneralML { .. } => 1_000_000,
            UsefulWorkCategory::Rendering { render_type } => match render_type {
                RenderType::Scene3D => 2_000_000,
                RenderType::NeRF => 5_000_000,
                RenderType::DiffusionModel => 3_000_000,
                RenderType::VideoProcessing => 1_500_000,
            },
        };

        base_gas + category_gas
    }

    /// Record a completed job, accumulating its *measured* energy, cost, and
    /// carbon into the metrics. Unmetered jobs contribute no energy — we never
    /// invent a figure.
    pub fn complete_job(&mut self, completed: CompletedJob) {
        self.metrics.total_compute_jobs += 1;
        self.metrics.total_useful_work_units += completed.useful_work_units;

        if let Some(m) = completed.measurement {
            let model = &self.config.energy_model;
            let kwh = model.facility_kwh(&m);
            self.metrics.useful_work_energy_kwh += kwh;
            self.metrics.useful_work_energy_cost_usd += model.cost_usd(&m);
            self.metrics.useful_work_carbon_kg += model.carbon_kg(&m);
            // On a PoW chain this same useful output would require burning
            // comparable energy on hashes that produce nothing.
            self.metrics.energy_saved_kwh += kwh * model.pow_baseline_wasted_ratio;
            self.metrics.measured_job_count += 1;
            self.metrics.energy_basis = Some(match self.metrics.energy_basis {
                Some(existing) => existing.combine(m.energy_basis),
                None => m.energy_basis,
            });
        }

        self.completed_jobs.insert(completed.job_id, completed);
    }

    /// Report measured energy attributed to consensus/overhead for a block, so
    /// the useful-work ratio reflects measured reality rather than a target.
    pub fn record_consensus_overhead_kwh(&mut self, kwh: f64) {
        self.metrics.consensus_overhead_energy_kwh += kwh.max(0.0);
    }

    /// Get current metrics
    pub fn metrics(&self) -> &RouterMetrics {
        &self.metrics
    }

    /// Calculate ESG impact from *measured* energy. Every figure here is either
    /// summed from real per-job measurements or derived via an explicit
    /// `EnergyModel` factor — there are no fabricated baselines or magic
    /// divisors. `energy_basis` reports whether the underlying power figures
    /// were live readings or device-profile estimates.
    pub fn calculate_esg_impact(&self) -> ESGImpact {
        let useful_kwh = self.metrics.useful_work_energy_kwh;
        let overhead_kwh = self.metrics.consensus_overhead_energy_kwh;
        let total_kwh = useful_kwh + overhead_kwh;
        // Measured ratio of energy that went to useful work. Undefined with no
        // measured energy, in which case we report 0.0 rather than a target.
        let measured_useful_work_ratio = if total_kwh > 0.0 {
            useful_kwh / total_kwh
        } else {
            0.0
        };
        ESGImpact {
            measured_useful_energy_kwh: useful_kwh,
            measured_total_energy_kwh: total_kwh,
            measured_useful_work_ratio,
            energy_cost_usd: self.metrics.useful_work_energy_cost_usd,
            carbon_footprint_kg: self.metrics.useful_work_carbon_kg,
            estimated_pow_equivalent_waste_kwh: self.metrics.energy_saved_kwh,
            useful_work_units: self.metrics.total_useful_work_units,
            completed_jobs: self.metrics.total_compute_jobs,
            measured_jobs: self.metrics.measured_job_count,
            // Default to an estimate label until at least one real measurement
            // upgrades it; an all-measured run reports `Measured`.
            energy_basis: self
                .metrics
                .energy_basis
                .unwrap_or(EnergyBasis::DeviceProfileEstimate),
        }
    }
}

#[derive(Debug, Clone)]
pub struct BlockProposal {
    pub financial_txs: Vec<FinancialTransaction>,
    pub compute_jobs: Vec<ComputeJob>,
    pub governance_txs: Vec<GovernanceTransaction>,
    pub bridge_txs: Vec<BridgeTransaction>,
    pub useful_work_ratio: f64,
    pub estimated_gas: u64,
}

/// Measured ESG impact of the network's useful work. Every field is grounded in
/// real measurements or explicit `EnergyModel` factors — no fabricated baselines.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ESGImpact {
    /// Measured facility energy that went to useful work, in kWh.
    pub measured_useful_energy_kwh: f64,
    /// Measured total energy (useful + reported consensus overhead), in kWh.
    pub measured_total_energy_kwh: f64,
    /// Measured useful-work ratio (useful / total); 0.0 if nothing measured yet.
    pub measured_useful_work_ratio: f64,
    /// Measured delivered electricity cost of useful work, in USD.
    pub energy_cost_usd: f64,
    /// Measured carbon footprint of useful work, in kg CO2e.
    pub carbon_footprint_kg: f64,
    /// Estimated kWh an equivalent-security PoW chain would waste for the same
    /// useful output. A clearly-labeled comparison, not a measurement.
    pub estimated_pow_equivalent_waste_kwh: f64,
    /// Measured useful work units produced.
    pub useful_work_units: u64,
    /// Total completed compute jobs.
    pub completed_jobs: u64,
    /// Completed jobs that carried a real measurement.
    pub measured_jobs: u64,
    /// Whether the energy figures rest on live meters or device-profile estimates.
    pub energy_basis: EnergyBasis,
}

#[derive(Debug, Clone)]
pub enum RouterError {
    FastLaneFull,
    ComputeLaneFull,
    BountyTooLow { provided: u128, minimum: u128 },
    InvalidJob(String),
}

impl std::fmt::Display for RouterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RouterError::FastLaneFull => write!(f, "Fast lane is full"),
            RouterError::ComputeLaneFull => write!(f, "Compute lane is full"),
            RouterError::BountyTooLow { provided, minimum } => {
                write!(f, "Bounty {} is below minimum {}", provided, minimum)
            }
            RouterError::InvalidJob(msg) => write!(f, "Invalid job: {}", msg),
        }
    }
}

impl std::error::Error for RouterError {}

// ============================================================================
// Useful Work Validator
// ============================================================================

/// A validator in the Proof of Useful Work consensus
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsefulWorkValidator {
    /// Validator address
    pub address: [u8; 32],
    /// Staked amount
    pub stake: u128,
    /// Available compute resources
    pub compute_resources: ComputeResources,
    /// TEE capabilities
    pub tee_capabilities: Vec<TEERequirement>,
    /// Total useful work units completed
    pub total_useful_work: u64,
    /// Reputation score (0-100)
    pub reputation: u8,
    /// Specializations (work categories they're good at)
    pub specializations: Vec<UsefulWorkCategory>,
    /// Online status
    pub is_online: bool,
    /// Last seen timestamp
    pub last_seen: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputeResources {
    /// GPU type
    pub gpu_type: String,
    /// GPU memory in GB
    pub gpu_memory_gb: u32,
    /// Number of GPUs
    pub gpu_count: u8,
    /// CPU cores
    pub cpu_cores: u32,
    /// RAM in GB
    pub ram_gb: u32,
    /// Available storage in GB
    pub storage_gb: u64,
    /// Network bandwidth in Gbps
    pub bandwidth_gbps: f64,
}

/// Validator selection for compute jobs
pub struct ValidatorSelector {
    validators: Vec<UsefulWorkValidator>,
}

impl ValidatorSelector {
    pub fn new(validators: Vec<UsefulWorkValidator>) -> Self {
        ValidatorSelector { validators }
    }

    /// Select the best validator for a compute job
    pub fn select_for_job(&self, job: &ComputeJob) -> Option<&UsefulWorkValidator> {
        self.validators
            .iter()
            .filter(|v| v.is_online)
            .filter(|v| self.can_handle_job(v, job))
            .max_by_key(|v| self.score_validator_for_job(v, job))
    }

    fn can_handle_job(&self, validator: &UsefulWorkValidator, job: &ComputeJob) -> bool {
        // Check TEE requirements
        if let Some(ref required_tee) = job.required_tee {
            if !validator.tee_capabilities.contains(required_tee) {
                return false;
            }
        }

        // Check if validator has enough resources
        // (simplified - real implementation would check GPU memory, etc.)
        true
    }

    fn score_validator_for_job(&self, validator: &UsefulWorkValidator, job: &ComputeJob) -> u64 {
        let mut score: u64 = 0;

        // Reputation bonus
        score += validator.reputation as u64 * 10;

        // Specialization bonus
        if validator.specializations.contains(&job.category) {
            score += 500;
        }

        // Useful work track record
        score += (validator.total_useful_work as f64).log2() as u64 * 50;

        // Stake weight (but capped to prevent plutocracy)
        score += (validator.stake as f64).log2().min(100.0) as u64;

        score
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_router_creation() {
        let router = UsefulWorkRouter::new(RouterConfig::default());
        assert_eq!(router.config.useful_work_ratio, 0.80);
    }

    #[test]
    fn test_compute_job_submission() {
        let mut router = UsefulWorkRouter::new(RouterConfig::default());

        let job = ComputeJob {
            id: [1u8; 32],
            category: UsefulWorkCategory::Healthcare {
                computation_type: HealthcareComputation::MedicalImaging,
                hipaa_required: true,
            },
            model_hash: [2u8; 32],
            input_hash: [3u8; 32],
            encrypted_input: vec![0u8; 100],
            requester: [4u8; 32],
            bounty: 10_000_000, // Above minimum
            max_execution_time: Duration::from_secs(60),
            required_tee: Some(TEERequirement::IntelSGX { min_svn: 10 }),
            deadline: None,
            priority_multiplier: 1.0,
            signature: [0u8; 64],
            pq_signature: None,
        };

        let result = router.submit(AethelredTransaction::Compute(job));
        assert!(result.is_ok());
    }

    #[test]
    fn test_bounty_too_low() {
        let mut router = UsefulWorkRouter::new(RouterConfig::default());

        let job = ComputeJob {
            id: [1u8; 32],
            category: UsefulWorkCategory::GeneralML {
                model_hash: [0u8; 32],
                framework: MLFramework::ONNX,
            },
            model_hash: [2u8; 32],
            input_hash: [3u8; 32],
            encrypted_input: vec![],
            requester: [4u8; 32],
            bounty: 100, // Below minimum
            max_execution_time: Duration::from_secs(60),
            required_tee: None,
            deadline: None,
            priority_multiplier: 1.0,
            signature: [0u8; 64],
            pq_signature: None,
        };

        let result = router.submit(AethelredTransaction::Compute(job));
        assert!(matches!(result, Err(RouterError::BountyTooLow { .. })));
    }

    #[test]
    fn test_block_building() {
        let mut router = UsefulWorkRouter::new(RouterConfig::default());

        // Submit some compute jobs
        for i in 0..5 {
            let job = ComputeJob {
                id: [i; 32],
                category: UsefulWorkCategory::Scientific {
                    domain: ScientificDomain::ProteinFolding,
                    priority: ResearchPriority::High,
                },
                model_hash: [2u8; 32],
                input_hash: [3u8; 32],
                encrypted_input: vec![],
                requester: [4u8; 32],
                bounty: 10_000_000,
                max_execution_time: Duration::from_secs(60),
                required_tee: None,
                deadline: None,
                priority_multiplier: 1.0,
                signature: [0u8; 64],
                pq_signature: None,
            };
            router.submit(AethelredTransaction::Compute(job)).unwrap();
        }

        // Submit some financial transactions
        for i in 0..10 {
            let ftx = FinancialTransaction {
                hash: [i; 32],
                from: [1u8; 32],
                to: [2u8; 32],
                amount: 1000,
                gas_price: 1,
                gas_limit: 21000,
                nonce: i as u64,
                signature: [0u8; 64],
                pq_signature: None,
                timestamp: 0,
            };
            router.submit(AethelredTransaction::Financial(ftx)).unwrap();
        }

        let proposal = router.build_block(30_000_000);
        assert!(!proposal.compute_jobs.is_empty());
        assert!(!proposal.financial_txs.is_empty());
        // Should be close to 80% useful work ratio
        assert!(proposal.useful_work_ratio > 0.5);
    }

    fn completed(id: u8, measurement: Option<WorkMeasurement>, uwu: u64) -> CompletedJob {
        CompletedJob {
            job_id: [id; 32],
            result_hash: [1u8; 32],
            validator: [2u8; 32],
            execution_time: Duration::from_secs(1),
            tee_attestation: vec![],
            useful_work_units: uwu,
            completed_at: SystemTime::UNIX_EPOCH,
            measurement,
        }
    }

    #[test]
    fn test_esg_impact_empty_is_zero_not_fabricated() {
        // The whole point of the rewrite: with no measured work, every ESG
        // figure is zero. A fresh chain does not get to claim research value.
        let router = UsefulWorkRouter::new(RouterConfig::default());
        let impact = router.calculate_esg_impact();
        assert_eq!(impact.measured_useful_energy_kwh, 0.0);
        assert_eq!(impact.measured_total_energy_kwh, 0.0);
        assert_eq!(impact.measured_useful_work_ratio, 0.0);
        assert_eq!(impact.energy_cost_usd, 0.0);
        assert_eq!(impact.carbon_footprint_kg, 0.0);
        assert_eq!(impact.measured_jobs, 0);
        assert_eq!(impact.energy_basis, EnergyBasis::DeviceProfileEstimate);
    }

    #[test]
    fn test_measured_job_accumulates_energy_cost_carbon() {
        let mut router = UsefulWorkRouter::new(RouterConfig::default());
        // 720 W for 100 device-seconds = 72 kJ = 0.02 kWh at the device; x1.2 PUE.
        router.complete_job(completed(
            1,
            Some(WorkMeasurement::measured(100.0, 720.0)),
            500,
        ));
        let m = router.metrics();
        assert!((m.useful_work_energy_kwh - 0.024).abs() < 1e-9);
        assert!((m.useful_work_energy_cost_usd - 0.024 * 0.08).abs() < 1e-9);
        assert!((m.useful_work_carbon_kg - 0.024 * 0.40).abs() < 1e-9);
        assert!((m.energy_saved_kwh - 0.024).abs() < 1e-9); // pow_baseline_wasted_ratio = 1.0
        assert_eq!(m.measured_job_count, 1);
        assert_eq!(m.energy_basis, Some(EnergyBasis::Measured));
        let impact = router.calculate_esg_impact();
        assert_eq!(impact.energy_basis, EnergyBasis::Measured);
        assert_eq!(impact.useful_work_units, 500);
    }

    #[test]
    fn test_unmetered_job_contributes_zero_energy_but_counts() {
        let mut router = UsefulWorkRouter::new(RouterConfig::default());
        router.complete_job(completed(1, None, 300));
        let m = router.metrics();
        assert_eq!(m.total_compute_jobs, 1);
        assert_eq!(m.total_useful_work_units, 300);
        assert_eq!(m.useful_work_energy_kwh, 0.0); // never fabricated
        assert_eq!(m.measured_job_count, 0);
        assert_eq!(m.energy_basis, None);
    }

    #[test]
    fn test_energy_basis_downgrades_to_estimate_when_mixed() {
        let mut router = UsefulWorkRouter::new(RouterConfig::default());
        router.complete_job(completed(
            1,
            Some(WorkMeasurement::measured(10.0, 300.0)),
            1,
        ));
        assert_eq!(router.metrics().energy_basis, Some(EnergyBasis::Measured));
        // A device-profile estimate downgrades the aggregate basis.
        router.complete_job(completed(
            2,
            Some(WorkMeasurement::from_device_profile(10.0, 300.0, 0.5)),
            1,
        ));
        assert_eq!(
            router.metrics().energy_basis,
            Some(EnergyBasis::DeviceProfileEstimate)
        );
    }

    #[test]
    fn test_measured_useful_work_ratio_uses_real_overhead() {
        let mut router = UsefulWorkRouter::new(RouterConfig::default());
        // 0.024 kWh useful (computed as above), plus 0.006 kWh reported overhead.
        router.complete_job(completed(
            1,
            Some(WorkMeasurement::measured(100.0, 720.0)),
            1,
        ));
        router.record_consensus_overhead_kwh(0.006);
        let impact = router.calculate_esg_impact();
        assert!((impact.measured_total_energy_kwh - 0.030).abs() < 1e-9);
        assert!((impact.measured_useful_work_ratio - 0.024 / 0.030).abs() < 1e-9);
        // 0.8
    }

    #[test]
    fn test_work_measurement_profile_and_joules() {
        let measured = WorkMeasurement::measured(5.0, 200.0);
        assert_eq!(measured.energy_basis, EnergyBasis::Measured);
        assert!((measured.device_joules() - 1000.0).abs() < 1e-9);
        // Profile: power = tdp x utilization, clamped, labeled as an estimate.
        let est = WorkMeasurement::from_device_profile(5.0, 400.0, 0.5);
        assert_eq!(est.energy_basis, EnergyBasis::DeviceProfileEstimate);
        assert!((est.average_power_watts - 200.0).abs() < 1e-9);
        // Negative/over-range inputs are sanitized, never negative energy.
        let clamped = WorkMeasurement::from_device_profile(-1.0, 400.0, 2.0);
        assert_eq!(clamped.device_seconds, 0.0);
        assert!((clamped.average_power_watts - 400.0).abs() < 1e-9); // utilization clamped to 1.0
    }

    #[test]
    fn test_energy_model_conversions_include_pue() {
        let model = EnergyModel::default();
        let m = WorkMeasurement::measured(3600.0, 1000.0); // 1000 W for 1 hour = 1 kWh device
        assert!((model.facility_kwh(&m) - 1.2).abs() < 1e-9); // x PUE
        assert!((model.cost_usd(&m) - 1.2 * 0.08).abs() < 1e-9);
        assert!((model.carbon_kg(&m) - 1.2 * 0.40).abs() < 1e-9);
    }
}
