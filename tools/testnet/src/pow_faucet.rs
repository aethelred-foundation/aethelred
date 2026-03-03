//! Proof-of-Work Faucet for Aethelred Testnet
//!
//! NOT a commodity "click-to-get-tokens" faucet. This is an educational tool
//! that teaches developers the core PoUW (Proof of Useful Work) consensus
//! mechanism by requiring them to complete actual AI inference work.
//!
//! "You must do useful work to get paid" - the core Aethelred philosophy.
//!
//! Features:
//! - Browser-based ONNX model execution
//! - Tiered rewards based on compute difficulty
//! - Work verification using model fingerprints
//! - Progressive learning path for developers
//! - Leaderboards and achievements

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};

// ============ Proof-of-Work Configuration ============

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoWFaucetConfig {
    /// Enabled work challenges
    pub challenges: Vec<WorkChallenge>,

    /// Base reward (tokens)
    pub base_reward: u128,

    /// Reward multipliers by difficulty
    pub difficulty_multipliers: HashMap<Difficulty, f64>,

    /// Maximum daily rewards per address
    pub max_daily_rewards: u128,

    /// Work verification strictness
    pub verification_strictness: VerificationStrictness,

    /// Enable learning path
    pub learning_path_enabled: bool,

    /// Enable achievements
    pub achievements_enabled: bool,

    /// Leaderboard size
    pub leaderboard_size: usize,
}

impl Default for PoWFaucetConfig {
    fn default() -> Self {
        let mut difficulty_multipliers = HashMap::new();
        difficulty_multipliers.insert(Difficulty::Trivial, 0.5);
        difficulty_multipliers.insert(Difficulty::Easy, 1.0);
        difficulty_multipliers.insert(Difficulty::Medium, 2.5);
        difficulty_multipliers.insert(Difficulty::Hard, 5.0);
        difficulty_multipliers.insert(Difficulty::Expert, 10.0);

        Self {
            challenges: WorkChallenge::default_challenges(),
            base_reward: 10_000_000_000_000_000_000, // 10 tAETH
            difficulty_multipliers,
            max_daily_rewards: 1000_000_000_000_000_000_000, // 1000 tAETH/day
            verification_strictness: VerificationStrictness::Standard,
            learning_path_enabled: true,
            achievements_enabled: true,
            leaderboard_size: 100,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Difficulty {
    Trivial,  // ~100ms inference
    Easy,     // ~500ms inference
    Medium,   // ~2s inference
    Hard,     // ~10s inference
    Expert,   // ~30s+ inference
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum VerificationStrictness {
    /// Accept approximate results (for learning)
    Lenient,
    /// Standard verification
    Standard,
    /// Strict bit-exact verification
    Strict,
}

// ============ Work Challenges ============

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkChallenge {
    /// Unique challenge ID
    pub id: String,

    /// Human-readable name
    pub name: String,

    /// Description of what the challenge teaches
    pub description: String,

    /// Learning objective
    pub learning_objective: String,

    /// Difficulty level
    pub difficulty: Difficulty,

    /// Model information
    pub model: ModelInfo,

    /// Input specification
    pub input_spec: InputSpec,

    /// Expected output format
    pub output_spec: OutputSpec,

    /// Verification method
    pub verification: VerificationMethod,

    /// Reward multiplier (on top of difficulty)
    pub reward_multiplier: f64,

    /// Prerequisites (other challenge IDs)
    pub prerequisites: Vec<String>,

    /// Category
    pub category: ChallengeCategory,

    /// Estimated completion time (seconds)
    pub estimated_time_seconds: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelInfo {
    /// Model identifier
    pub id: String,

    /// Model name
    pub name: String,

    /// Model hash (for verification)
    pub hash: String,

    /// ONNX file URL (CDN)
    pub onnx_url: String,

    /// Model size (bytes)
    pub size_bytes: u64,

    /// Input shape
    pub input_shape: Vec<i64>,

    /// Output shape
    pub output_shape: Vec<i64>,

    /// Model type
    pub model_type: ModelType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ModelType {
    Classification,
    Regression,
    NLP,
    ImageProcessing,
    Embedding,
    CreditScoring,
    FraudDetection,
    RiskAssessment,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputSpec {
    /// Input type
    pub input_type: InputType,

    /// Sample data URL (for testing)
    pub sample_data_url: Option<String>,

    /// Input generation method
    pub generation: InputGeneration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InputType {
    /// Random numerical tensor
    RandomTensor { shape: Vec<i64>, dtype: String },

    /// Fixed challenge input
    FixedInput { data_hash: String },

    /// User-provided input
    UserProvided { schema: serde_json::Value },

    /// Real-world sample data
    SampleData { dataset: String, index: usize },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InputGeneration {
    /// Server generates input
    ServerGenerated,

    /// Client generates with seed
    SeededRandom { seed: u64 },

    /// Client chooses from options
    ClientChoice { options: Vec<String> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputSpec {
    /// Expected output type
    pub output_type: OutputType,

    /// Tolerance for numerical outputs
    pub tolerance: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OutputType {
    /// Classification label
    ClassLabel { num_classes: usize },

    /// Probability distribution
    Probabilities { num_classes: usize },

    /// Single numerical value
    Scalar,

    /// Vector output
    Vector { length: usize },

    /// Embedding
    Embedding { dimension: usize },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VerificationMethod {
    /// Hash of output tensor
    OutputHash,

    /// Top-k classes match
    TopKMatch { k: usize },

    /// Value within tolerance
    ValueTolerance { tolerance: f64 },

    /// Embedding similarity
    EmbeddingSimilarity { min_cosine: f64 },

    /// Custom verification script
    Custom { script_hash: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChallengeCategory {
    /// Introduction to PoUW
    Introduction,

    /// Financial AI (credit scoring, fraud detection)
    FinancialAI,

    /// Healthcare AI
    HealthcareAI,

    /// Natural Language Processing
    NLP,

    /// Computer Vision
    ComputerVision,

    /// Enterprise AI
    EnterpriseAI,
}

impl WorkChallenge {
    pub fn default_challenges() -> Vec<WorkChallenge> {
        vec![
            // ===== INTRODUCTION CHALLENGES =====
            WorkChallenge {
                id: "intro_001".to_string(),
                name: "Hello Inference".to_string(),
                description: "Your first AI inference on Aethelred. Run a tiny model to understand the basics.".to_string(),
                learning_objective: "Understand that tokens are earned through useful AI work, not just clicking.".to_string(),
                difficulty: Difficulty::Trivial,
                model: ModelInfo {
                    id: "tiny_classifier".to_string(),
                    name: "Tiny MNIST Classifier".to_string(),
                    hash: "0x1234...".to_string(),
                    onnx_url: "https://models.aethelred.ai/tiny_mnist.onnx".to_string(),
                    size_bytes: 50_000,
                    input_shape: vec![1, 1, 28, 28],
                    output_shape: vec![1, 10],
                    model_type: ModelType::Classification,
                },
                input_spec: InputSpec {
                    input_type: InputType::RandomTensor {
                        shape: vec![1, 1, 28, 28],
                        dtype: "float32".to_string(),
                    },
                    sample_data_url: None,
                    generation: InputGeneration::SeededRandom { seed: 42 },
                },
                output_spec: OutputSpec {
                    output_type: OutputType::Probabilities { num_classes: 10 },
                    tolerance: Some(0.01),
                },
                verification: VerificationMethod::TopKMatch { k: 3 },
                reward_multiplier: 1.0,
                prerequisites: vec![],
                category: ChallengeCategory::Introduction,
                estimated_time_seconds: 5,
            },

            WorkChallenge {
                id: "intro_002".to_string(),
                name: "Understanding Useful Work".to_string(),
                description: "Run a sentiment analysis model - see how language understanding creates value.".to_string(),
                learning_objective: "Learn that AI inference produces verifiable, useful outputs.".to_string(),
                difficulty: Difficulty::Easy,
                model: ModelInfo {
                    id: "sentiment_tiny".to_string(),
                    name: "TinyBERT Sentiment".to_string(),
                    hash: "0x5678...".to_string(),
                    onnx_url: "https://models.aethelred.ai/sentiment_tiny.onnx".to_string(),
                    size_bytes: 500_000,
                    input_shape: vec![1, 128],
                    output_shape: vec![1, 3],
                    model_type: ModelType::NLP,
                },
                input_spec: InputSpec {
                    input_type: InputType::FixedInput {
                        data_hash: "0xsentiment_input...".to_string(),
                    },
                    sample_data_url: Some("https://data.aethelred.ai/sentiment_samples.json".to_string()),
                    generation: InputGeneration::ServerGenerated,
                },
                output_spec: OutputSpec {
                    output_type: OutputType::ClassLabel { num_classes: 3 },
                    tolerance: None,
                },
                verification: VerificationMethod::OutputHash,
                reward_multiplier: 1.0,
                prerequisites: vec!["intro_001".to_string()],
                category: ChallengeCategory::Introduction,
                estimated_time_seconds: 10,
            },

            // ===== FINANCIAL AI CHALLENGES =====
            WorkChallenge {
                id: "finance_001".to_string(),
                name: "Credit Score Inference".to_string(),
                description: "Run a credit scoring model - the exact use case banks like FAB need verified.".to_string(),
                learning_objective: "Experience how Aethelred verifies financial AI decisions.".to_string(),
                difficulty: Difficulty::Medium,
                model: ModelInfo {
                    id: "credit_scorer_v1".to_string(),
                    name: "XGBoost Credit Scorer".to_string(),
                    hash: "0xcredit123...".to_string(),
                    onnx_url: "https://models.aethelred.ai/credit_scorer.onnx".to_string(),
                    size_bytes: 2_000_000,
                    input_shape: vec![1, 23],
                    output_shape: vec![1, 1],
                    model_type: ModelType::CreditScoring,
                },
                input_spec: InputSpec {
                    input_type: InputType::SampleData {
                        dataset: "anonymized_credit_applications".to_string(),
                        index: 0,
                    },
                    sample_data_url: Some("https://data.aethelred.ai/credit_samples.json".to_string()),
                    generation: InputGeneration::ServerGenerated,
                },
                output_spec: OutputSpec {
                    output_type: OutputType::Scalar,
                    tolerance: Some(0.001),
                },
                verification: VerificationMethod::ValueTolerance { tolerance: 0.001 },
                reward_multiplier: 2.0,
                prerequisites: vec!["intro_002".to_string()],
                category: ChallengeCategory::FinancialAI,
                estimated_time_seconds: 15,
            },

            WorkChallenge {
                id: "finance_002".to_string(),
                name: "Fraud Detection Challenge".to_string(),
                description: "Detect fraudulent transactions - see how Aethelred protects financial systems.".to_string(),
                learning_objective: "Understand real-time fraud detection verification.".to_string(),
                difficulty: Difficulty::Medium,
                model: ModelInfo {
                    id: "fraud_detector_v1".to_string(),
                    name: "Fraud Detection Neural Net".to_string(),
                    hash: "0xfraud456...".to_string(),
                    onnx_url: "https://models.aethelred.ai/fraud_detector.onnx".to_string(),
                    size_bytes: 5_000_000,
                    input_shape: vec![1, 30],
                    output_shape: vec![1, 2],
                    model_type: ModelType::FraudDetection,
                },
                input_spec: InputSpec {
                    input_type: InputType::SampleData {
                        dataset: "synthetic_transactions".to_string(),
                        index: 0,
                    },
                    sample_data_url: None,
                    generation: InputGeneration::ServerGenerated,
                },
                output_spec: OutputSpec {
                    output_type: OutputType::Probabilities { num_classes: 2 },
                    tolerance: Some(0.01),
                },
                verification: VerificationMethod::TopKMatch { k: 1 },
                reward_multiplier: 2.5,
                prerequisites: vec!["finance_001".to_string()],
                category: ChallengeCategory::FinancialAI,
                estimated_time_seconds: 20,
            },

            WorkChallenge {
                id: "finance_003".to_string(),
                name: "Risk Assessment Engine".to_string(),
                description: "Run a full risk assessment model - enterprise-grade financial AI.".to_string(),
                learning_objective: "Master complex financial model verification.".to_string(),
                difficulty: Difficulty::Hard,
                model: ModelInfo {
                    id: "risk_engine_v1".to_string(),
                    name: "Enterprise Risk Assessment".to_string(),
                    hash: "0xrisk789...".to_string(),
                    onnx_url: "https://models.aethelred.ai/risk_engine.onnx".to_string(),
                    size_bytes: 20_000_000,
                    input_shape: vec![1, 100],
                    output_shape: vec![1, 5],
                    model_type: ModelType::RiskAssessment,
                },
                input_spec: InputSpec {
                    input_type: InputType::SampleData {
                        dataset: "enterprise_risk_scenarios".to_string(),
                        index: 0,
                    },
                    sample_data_url: None,
                    generation: InputGeneration::ServerGenerated,
                },
                output_spec: OutputSpec {
                    output_type: OutputType::Vector { length: 5 },
                    tolerance: Some(0.001),
                },
                verification: VerificationMethod::ValueTolerance { tolerance: 0.001 },
                reward_multiplier: 3.0,
                prerequisites: vec!["finance_002".to_string()],
                category: ChallengeCategory::FinancialAI,
                estimated_time_seconds: 45,
            },

            // ===== HEALTHCARE AI CHALLENGES =====
            WorkChallenge {
                id: "health_001".to_string(),
                name: "Medical Image Analysis".to_string(),
                description: "Analyze a chest X-ray - see how Aethelred can verify medical AI.".to_string(),
                learning_objective: "Understand healthcare AI verification requirements.".to_string(),
                difficulty: Difficulty::Hard,
                model: ModelInfo {
                    id: "chest_xray_v1".to_string(),
                    name: "ChestX-ray14 Classifier".to_string(),
                    hash: "0xchest123...".to_string(),
                    onnx_url: "https://models.aethelred.ai/chest_xray.onnx".to_string(),
                    size_bytes: 50_000_000,
                    input_shape: vec![1, 1, 224, 224],
                    output_shape: vec![1, 14],
                    model_type: ModelType::ImageProcessing,
                },
                input_spec: InputSpec {
                    input_type: InputType::SampleData {
                        dataset: "nih_chest_xray_samples".to_string(),
                        index: 0,
                    },
                    sample_data_url: None,
                    generation: InputGeneration::ServerGenerated,
                },
                output_spec: OutputSpec {
                    output_type: OutputType::Probabilities { num_classes: 14 },
                    tolerance: Some(0.01),
                },
                verification: VerificationMethod::TopKMatch { k: 5 },
                reward_multiplier: 4.0,
                prerequisites: vec!["intro_002".to_string()],
                category: ChallengeCategory::HealthcareAI,
                estimated_time_seconds: 60,
            },

            // ===== EXPERT CHALLENGES =====
            WorkChallenge {
                id: "expert_001".to_string(),
                name: "Full PoUW Simulation".to_string(),
                description: "Complete a full Proof-of-Useful-Work cycle as a validator would.".to_string(),
                learning_objective: "Understand the complete PoUW consensus mechanism.".to_string(),
                difficulty: Difficulty::Expert,
                model: ModelInfo {
                    id: "full_pouw_sim".to_string(),
                    name: "Multi-Model PoUW Simulation".to_string(),
                    hash: "0xpouw_full...".to_string(),
                    onnx_url: "https://models.aethelred.ai/pouw_simulation.onnx".to_string(),
                    size_bytes: 100_000_000,
                    input_shape: vec![1, 512],
                    output_shape: vec![1, 256],
                    model_type: ModelType::Embedding,
                },
                input_spec: InputSpec {
                    input_type: InputType::RandomTensor {
                        shape: vec![1, 512],
                        dtype: "float32".to_string(),
                    },
                    sample_data_url: None,
                    generation: InputGeneration::SeededRandom { seed: 0 },
                },
                output_spec: OutputSpec {
                    output_type: OutputType::Embedding { dimension: 256 },
                    tolerance: Some(0.0001),
                },
                verification: VerificationMethod::EmbeddingSimilarity { min_cosine: 0.9999 },
                reward_multiplier: 10.0,
                prerequisites: vec!["finance_003".to_string(), "health_001".to_string()],
                category: ChallengeCategory::EnterpriseAI,
                estimated_time_seconds: 120,
            },
        ]
    }
}

// ============ Work Submission ============

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkSubmission {
    /// Unique submission ID
    pub id: String,

    /// Developer address
    pub address: String,

    /// Challenge ID
    pub challenge_id: String,

    /// Challenge instance (with specific input)
    pub instance: ChallengeInstance,

    /// Submitted output
    pub output: WorkOutput,

    /// Execution metrics
    pub metrics: ExecutionMetrics,

    /// Client info (for debugging)
    pub client_info: ClientInfo,

    /// Submission timestamp
    pub submitted_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeInstance {
    /// Instance ID
    pub instance_id: String,

    /// Input data hash
    pub input_hash: String,

    /// Random seed used (if applicable)
    pub seed: Option<u64>,

    /// Created timestamp
    pub created_at: u64,

    /// Expires at
    pub expires_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkOutput {
    /// Output tensor hash
    pub output_hash: String,

    /// Output data (for verification)
    pub output_data: serde_json::Value,

    /// Model hash used
    pub model_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionMetrics {
    /// Total execution time (ms)
    pub execution_time_ms: u64,

    /// Model load time (ms)
    pub model_load_time_ms: u64,

    /// Inference time (ms)
    pub inference_time_ms: u64,

    /// Memory used (bytes)
    pub memory_used_bytes: u64,

    /// FLOPS performed (estimated)
    pub flops_performed: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientInfo {
    /// Browser user agent
    pub user_agent: Option<String>,

    /// WebGL renderer (GPU info)
    pub webgl_renderer: Option<String>,

    /// ONNX runtime version
    pub onnx_runtime_version: String,

    /// Execution backend (wasm, webgl, webgpu)
    pub execution_backend: String,
}

// ============ Verification Result ============

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    /// Submission ID
    pub submission_id: String,

    /// Verification status
    pub status: VerificationStatus,

    /// Reward earned
    pub reward: RewardInfo,

    /// Verification details
    pub details: VerificationDetails,

    /// Learning feedback
    pub feedback: LearningFeedback,

    /// Achievements unlocked
    pub achievements_unlocked: Vec<Achievement>,

    /// Verified at
    pub verified_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationStatus {
    /// Work verified successfully
    Verified,

    /// Work failed verification
    Failed,

    /// Partial credit (close but not exact)
    PartialCredit,

    /// Challenge expired
    Expired,

    /// Duplicate submission
    Duplicate,

    /// Invalid submission format
    Invalid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewardInfo {
    /// Base reward
    pub base_reward: u128,

    /// Difficulty multiplier
    pub difficulty_multiplier: f64,

    /// Challenge multiplier
    pub challenge_multiplier: f64,

    /// Speed bonus (for fast completion)
    pub speed_bonus: f64,

    /// First completion bonus
    pub first_completion_bonus: f64,

    /// Total reward
    pub total_reward: u128,

    /// Transaction hash (when tokens sent)
    pub tx_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationDetails {
    /// Expected output hash
    pub expected_hash: Option<String>,

    /// Actual output hash
    pub actual_hash: String,

    /// Match score (0.0 - 1.0)
    pub match_score: f64,

    /// Detailed comparison
    pub comparison: Option<serde_json::Value>,

    /// Verification method used
    pub method: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearningFeedback {
    /// What you learned
    pub learned: String,

    /// Next challenge suggestion
    pub next_challenge: Option<String>,

    /// Progress in learning path
    pub learning_path_progress: f64,

    /// Tips for improvement
    pub tips: Vec<String>,
}

// ============ Achievements ============

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Achievement {
    pub id: String,
    pub name: String,
    pub description: String,
    pub icon: String,
    pub rarity: AchievementRarity,
    pub unlocked_at: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum AchievementRarity {
    Common,
    Rare,
    Epic,
    Legendary,
}

impl Achievement {
    pub fn first_work() -> Self {
        Achievement {
            id: "first_work".to_string(),
            name: "First Useful Work".to_string(),
            description: "Completed your first AI inference on Aethelred".to_string(),
            icon: "🎯".to_string(),
            rarity: AchievementRarity::Common,
            unlocked_at: 0,
        }
    }

    pub fn financial_ai_expert() -> Self {
        Achievement {
            id: "financial_expert".to_string(),
            name: "Financial AI Expert".to_string(),
            description: "Completed all Financial AI challenges".to_string(),
            icon: "💰".to_string(),
            rarity: AchievementRarity::Epic,
            unlocked_at: 0,
        }
    }

    pub fn speed_demon() -> Self {
        Achievement {
            id: "speed_demon".to_string(),
            name: "Speed Demon".to_string(),
            description: "Completed a challenge 2x faster than average".to_string(),
            icon: "⚡".to_string(),
            rarity: AchievementRarity::Rare,
            unlocked_at: 0,
        }
    }

    pub fn pouw_master() -> Self {
        Achievement {
            id: "pouw_master".to_string(),
            name: "PoUW Master".to_string(),
            description: "Completed the Expert PoUW Simulation".to_string(),
            icon: "👑".to_string(),
            rarity: AchievementRarity::Legendary,
            unlocked_at: 0,
        }
    }
}

// ============ Leaderboard ============

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaderboardEntry {
    pub rank: usize,
    pub address: String,
    pub display_name: Option<String>,
    pub total_work_completed: u64,
    pub total_rewards_earned: u128,
    pub total_flops_performed: u128,
    pub highest_difficulty_completed: Difficulty,
    pub achievements_count: usize,
    pub last_active: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Leaderboard {
    pub entries: Vec<LeaderboardEntry>,
    pub updated_at: u64,
    pub period: LeaderboardPeriod,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum LeaderboardPeriod {
    Daily,
    Weekly,
    Monthly,
    AllTime,
}

// ============ Developer Profile ============

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeveloperProfile {
    pub address: String,
    pub display_name: Option<String>,

    /// Work statistics
    pub stats: WorkStats,

    /// Completed challenges
    pub completed_challenges: Vec<CompletedChallenge>,

    /// Achievements
    pub achievements: Vec<Achievement>,

    /// Learning path progress
    pub learning_progress: LearningProgress,

    /// Daily reward tracking
    pub daily_rewards: DailyRewards,

    /// Registered at
    pub registered_at: u64,

    /// Last active
    pub last_active: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WorkStats {
    pub total_challenges_completed: u64,
    pub total_submissions: u64,
    pub successful_submissions: u64,
    pub failed_submissions: u64,
    pub total_rewards_earned: u128,
    pub total_flops_performed: u128,
    pub total_inference_time_ms: u64,
    pub average_accuracy: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompletedChallenge {
    pub challenge_id: String,
    pub completed_at: u64,
    pub reward_earned: u128,
    pub execution_time_ms: u64,
    pub attempts: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LearningProgress {
    pub introduction_completed: bool,
    pub financial_ai_completed: bool,
    pub healthcare_ai_completed: bool,
    pub nlp_completed: bool,
    pub computer_vision_completed: bool,
    pub enterprise_ai_completed: bool,
    pub overall_progress: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DailyRewards {
    pub date: String,
    pub rewards_earned: u128,
    pub challenges_completed: u64,
}

// ============ PoW Faucet Engine ============

pub struct PoWFaucet {
    config: PoWFaucetConfig,
    challenges: HashMap<String, WorkChallenge>,
    active_instances: HashMap<String, ChallengeInstance>,
    profiles: HashMap<String, DeveloperProfile>,
    leaderboards: HashMap<LeaderboardPeriod, Leaderboard>,
    submissions: VecDeque<WorkSubmission>,
    metrics: PoWFaucetMetrics,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct PoWFaucetMetrics {
    pub total_challenges_issued: u64,
    pub total_submissions: u64,
    pub successful_verifications: u64,
    pub failed_verifications: u64,
    pub total_rewards_distributed: u128,
    pub total_flops_computed: u128,
    pub unique_developers: u64,
    pub challenges_by_difficulty: HashMap<String, u64>,
    pub average_completion_time_ms: f64,
}

impl PoWFaucet {
    pub fn new(config: PoWFaucetConfig) -> Self {
        let mut challenges = HashMap::new();
        for challenge in &config.challenges {
            challenges.insert(challenge.id.clone(), challenge.clone());
        }

        Self {
            config,
            challenges,
            active_instances: HashMap::new(),
            profiles: HashMap::new(),
            leaderboards: HashMap::new(),
            submissions: VecDeque::with_capacity(10000),
            metrics: PoWFaucetMetrics::default(),
        }
    }

    /// Request a work challenge
    pub fn request_challenge(
        &mut self,
        address: &str,
        challenge_id: Option<&str>,
        difficulty: Option<Difficulty>,
    ) -> Result<ChallengeInstance, String> {
        // Get or create profile
        let profile = self.get_or_create_profile(address);

        // Select challenge
        let challenge = if let Some(id) = challenge_id {
            self.challenges.get(id)
                .ok_or_else(|| format!("Challenge {} not found", id))?
                .clone()
        } else {
            self.select_appropriate_challenge(&profile, difficulty)?
        };

        // Check prerequisites
        for prereq in &challenge.prerequisites {
            let completed = profile.completed_challenges.iter()
                .any(|c| &c.challenge_id == prereq);
            if !completed {
                return Err(format!("Prerequisite challenge {} not completed", prereq));
            }
        }

        // Create instance
        let now = current_timestamp();
        let instance = ChallengeInstance {
            instance_id: format!("inst_{}", generate_id()),
            input_hash: generate_input_hash(&challenge),
            seed: match &challenge.input_spec.generation {
                InputGeneration::SeededRandom { seed } => Some(*seed ^ now),
                _ => None,
            },
            created_at: now,
            expires_at: now + 3600, // 1 hour expiry
        };

        self.active_instances.insert(instance.instance_id.clone(), instance.clone());
        self.metrics.total_challenges_issued += 1;

        Ok(instance)
    }

    /// Submit completed work
    pub fn submit_work(&mut self, submission: WorkSubmission) -> Result<VerificationResult, String> {
        // Validate instance
        let instance = self.active_instances.get(&submission.instance.instance_id)
            .ok_or("Challenge instance not found or expired")?
            .clone();

        if current_timestamp() > instance.expires_at {
            return Ok(VerificationResult {
                submission_id: submission.id.clone(),
                status: VerificationStatus::Expired,
                reward: RewardInfo::zero(),
                details: VerificationDetails {
                    expected_hash: None,
                    actual_hash: submission.output.output_hash.clone(),
                    match_score: 0.0,
                    comparison: None,
                    method: "expired".to_string(),
                },
                feedback: LearningFeedback {
                    learned: "Challenge expired. Try to complete within the time limit.".to_string(),
                    next_challenge: Some(submission.challenge_id.clone()),
                    learning_path_progress: 0.0,
                    tips: vec!["Start the challenge only when ready".to_string()],
                },
                achievements_unlocked: vec![],
                verified_at: current_timestamp(),
            });
        }

        // Get challenge
        let challenge = self.challenges.get(&submission.challenge_id)
            .ok_or("Challenge not found")?
            .clone();

        // Verify work
        let verification = self.verify_work(&challenge, &submission)?;

        // Update profile
        self.update_profile(&submission, &verification);

        // Remove used instance
        self.active_instances.remove(&submission.instance.instance_id);

        // Store submission
        self.submissions.push_front(submission);
        if self.submissions.len() > 10000 {
            self.submissions.pop_back();
        }

        self.metrics.total_submissions += 1;
        if verification.status == VerificationStatus::Verified {
            self.metrics.successful_verifications += 1;
            self.metrics.total_rewards_distributed += verification.reward.total_reward;
        } else {
            self.metrics.failed_verifications += 1;
        }

        Ok(verification)
    }

    fn verify_work(&self, challenge: &WorkChallenge, submission: &WorkSubmission) -> Result<VerificationResult, String> {
        let now = current_timestamp();

        // Compute expected result (in production, this would re-execute or use precomputed)
        let expected_hash = compute_expected_hash(challenge, &submission.instance);
        let match_score = compute_match_score(&expected_hash, &submission.output.output_hash);

        let (status, match_score) = match &challenge.verification {
            VerificationMethod::OutputHash => {
                if submission.output.output_hash == expected_hash {
                    (VerificationStatus::Verified, 1.0)
                } else {
                    (VerificationStatus::Failed, 0.0)
                }
            }
            VerificationMethod::TopKMatch { k } => {
                // Simplified - would compare top-k classes
                if match_score >= 0.9 {
                    (VerificationStatus::Verified, match_score)
                } else if match_score >= 0.5 {
                    (VerificationStatus::PartialCredit, match_score)
                } else {
                    (VerificationStatus::Failed, match_score)
                }
            }
            VerificationMethod::ValueTolerance { tolerance } => {
                if match_score >= 1.0 - tolerance {
                    (VerificationStatus::Verified, match_score)
                } else {
                    (VerificationStatus::Failed, match_score)
                }
            }
            VerificationMethod::EmbeddingSimilarity { min_cosine } => {
                if match_score >= *min_cosine {
                    (VerificationStatus::Verified, match_score)
                } else {
                    (VerificationStatus::Failed, match_score)
                }
            }
            VerificationMethod::Custom { .. } => {
                // Custom verification would run script
                (VerificationStatus::Verified, 1.0)
            }
        };

        // Calculate reward
        let reward = if status == VerificationStatus::Verified {
            self.calculate_reward(challenge, submission, match_score)
        } else if status == VerificationStatus::PartialCredit {
            let mut r = self.calculate_reward(challenge, submission, match_score);
            r.total_reward = (r.total_reward as f64 * match_score) as u128;
            r
        } else {
            RewardInfo::zero()
        };

        // Generate feedback
        let feedback = self.generate_feedback(challenge, &status, match_score);

        // Check achievements
        let achievements = self.check_achievements(&submission.address, challenge, &status);

        Ok(VerificationResult {
            submission_id: submission.id.clone(),
            status,
            reward,
            details: VerificationDetails {
                expected_hash: Some(expected_hash),
                actual_hash: submission.output.output_hash.clone(),
                match_score,
                comparison: None,
                method: format!("{:?}", challenge.verification),
            },
            feedback,
            achievements_unlocked: achievements,
            verified_at: now,
        })
    }

    fn calculate_reward(&self, challenge: &WorkChallenge, submission: &WorkSubmission, match_score: f64) -> RewardInfo {
        let difficulty_mult = self.config.difficulty_multipliers
            .get(&challenge.difficulty)
            .copied()
            .unwrap_or(1.0);

        let challenge_mult = challenge.reward_multiplier;

        // Speed bonus: 50% bonus for completing in half the estimated time
        let estimated_ms = challenge.estimated_time_seconds as u64 * 1000;
        let speed_bonus = if submission.metrics.execution_time_ms < estimated_ms / 2 {
            0.5
        } else if submission.metrics.execution_time_ms < estimated_ms {
            0.25
        } else {
            0.0
        };

        let total_multiplier = difficulty_mult * challenge_mult * (1.0 + speed_bonus);
        let total_reward = (self.config.base_reward as f64 * total_multiplier) as u128;

        RewardInfo {
            base_reward: self.config.base_reward,
            difficulty_multiplier: difficulty_mult,
            challenge_multiplier: challenge_mult,
            speed_bonus,
            first_completion_bonus: 0.0, // TODO: Track first completions
            total_reward,
            tx_hash: None,
        }
    }

    fn generate_feedback(&self, challenge: &WorkChallenge, status: &VerificationStatus, match_score: f64) -> LearningFeedback {
        let learned = match status {
            VerificationStatus::Verified => format!(
                "You successfully completed {}. {}",
                challenge.name,
                challenge.learning_objective
            ),
            VerificationStatus::PartialCredit => format!(
                "Almost there! Your result was {:.1}% accurate. {}",
                match_score * 100.0,
                "Try running the inference again with more precision."
            ),
            VerificationStatus::Failed => format!(
                "The output didn't match the expected result. {}",
                "Make sure you're using the correct model and input data."
            ),
            _ => "Challenge attempt recorded.".to_string(),
        };

        let next = match &challenge.category {
            ChallengeCategory::Introduction => Some("finance_001".to_string()),
            ChallengeCategory::FinancialAI => Some("health_001".to_string()),
            _ => None,
        };

        let tips = match status {
            VerificationStatus::Failed => vec![
                "Ensure you downloaded the correct ONNX model".to_string(),
                "Check that input data matches the expected format".to_string(),
                "Verify your ONNX runtime version is compatible".to_string(),
            ],
            VerificationStatus::PartialCredit => vec![
                "Use float32 precision for better accuracy".to_string(),
                "Try the WebGPU backend if available".to_string(),
            ],
            _ => vec![],
        };

        LearningFeedback {
            learned,
            next_challenge: next,
            learning_path_progress: 0.0, // TODO: Calculate
            tips,
        }
    }

    fn check_achievements(&self, address: &str, challenge: &WorkChallenge, status: &VerificationStatus) -> Vec<Achievement> {
        if *status != VerificationStatus::Verified {
            return vec![];
        }

        let mut achievements = Vec::new();
        let profile = self.profiles.get(address);

        // First work achievement
        if profile.map_or(true, |p| p.completed_challenges.is_empty()) {
            let mut ach = Achievement::first_work();
            ach.unlocked_at = current_timestamp();
            achievements.push(ach);
        }

        // Expert challenge
        if challenge.id == "expert_001" {
            let mut ach = Achievement::pouw_master();
            ach.unlocked_at = current_timestamp();
            achievements.push(ach);
        }

        achievements
    }

    fn select_appropriate_challenge(&self, profile: &DeveloperProfile, difficulty: Option<Difficulty>) -> Result<WorkChallenge, String> {
        let completed_ids: std::collections::HashSet<_> = profile.completed_challenges
            .iter()
            .map(|c| &c.challenge_id)
            .collect();

        // Find next uncompleted challenge
        for challenge in self.challenges.values() {
            if completed_ids.contains(&challenge.id) {
                continue;
            }

            if let Some(d) = difficulty {
                if challenge.difficulty != d {
                    continue;
                }
            }

            // Check prerequisites
            let prereqs_met = challenge.prerequisites.iter()
                .all(|p| completed_ids.contains(p));

            if prereqs_met {
                return Ok(challenge.clone());
            }
        }

        // Return first intro challenge if nothing else available
        self.challenges.get("intro_001")
            .cloned()
            .ok_or_else(|| "No challenges available".to_string())
    }

    fn get_or_create_profile(&mut self, address: &str) -> DeveloperProfile {
        if !self.profiles.contains_key(address) {
            let profile = DeveloperProfile {
                address: address.to_string(),
                display_name: None,
                stats: WorkStats::default(),
                completed_challenges: Vec::new(),
                achievements: Vec::new(),
                learning_progress: LearningProgress::default(),
                daily_rewards: DailyRewards {
                    date: chrono::Utc::now().format("%Y-%m-%d").to_string(),
                    rewards_earned: 0,
                    challenges_completed: 0,
                },
                registered_at: current_timestamp(),
                last_active: current_timestamp(),
            };
            self.profiles.insert(address.to_string(), profile);
            self.metrics.unique_developers += 1;
        }

        self.profiles.get(address).unwrap().clone()
    }

    fn update_profile(&mut self, submission: &WorkSubmission, result: &VerificationResult) {
        if let Some(profile) = self.profiles.get_mut(&submission.address) {
            profile.last_active = current_timestamp();
            profile.stats.total_submissions += 1;

            if result.status == VerificationStatus::Verified {
                profile.stats.successful_submissions += 1;
                profile.stats.total_rewards_earned += result.reward.total_reward;
                profile.stats.total_flops_performed += submission.metrics.flops_performed as u128;

                profile.completed_challenges.push(CompletedChallenge {
                    challenge_id: submission.challenge_id.clone(),
                    completed_at: current_timestamp(),
                    reward_earned: result.reward.total_reward,
                    execution_time_ms: submission.metrics.execution_time_ms,
                    attempts: 1,
                });

                // Add new achievements
                for ach in &result.achievements_unlocked {
                    profile.achievements.push(ach.clone());
                }
            } else {
                profile.stats.failed_submissions += 1;
            }
        }
    }

    /// Get available challenges
    pub fn get_challenges(&self, category: Option<ChallengeCategory>) -> Vec<&WorkChallenge> {
        self.challenges.values()
            .filter(|c| category.as_ref().map_or(true, |cat| {
                std::mem::discriminant(&c.category) == std::mem::discriminant(cat)
            }))
            .collect()
    }

    /// Get developer profile
    pub fn get_profile(&self, address: &str) -> Option<&DeveloperProfile> {
        self.profiles.get(address)
    }

    /// Get leaderboard
    pub fn get_leaderboard(&self, period: LeaderboardPeriod) -> Option<&Leaderboard> {
        self.leaderboards.get(&period)
    }

    /// Get metrics
    pub fn metrics(&self) -> &PoWFaucetMetrics {
        &self.metrics
    }
}

impl RewardInfo {
    fn zero() -> Self {
        Self {
            base_reward: 0,
            difficulty_multiplier: 0.0,
            challenge_multiplier: 0.0,
            speed_bonus: 0.0,
            first_completion_bonus: 0.0,
            total_reward: 0,
            tx_hash: None,
        }
    }
}

// ============ Helper Functions ============

fn generate_id() -> String {
    use rand::Rng;
    let random: u64 = rand::thread_rng().gen();
    format!("{:x}", random)
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn generate_input_hash(challenge: &WorkChallenge) -> String {
    format!("0x{}_{}", challenge.id, current_timestamp())
}

fn compute_expected_hash(challenge: &WorkChallenge, instance: &ChallengeInstance) -> String {
    // In production, this would compute the actual expected output
    format!("0xexpected_{}_{}", challenge.id, instance.instance_id)
}

fn compute_match_score(expected: &str, actual: &str) -> f64 {
    // Simplified - in production would compute actual similarity
    if expected == actual {
        1.0
    } else {
        0.8 // Simulated partial match
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pow_faucet_creation() {
        let config = PoWFaucetConfig::default();
        let faucet = PoWFaucet::new(config);

        assert!(!faucet.challenges.is_empty());
    }

    #[test]
    fn test_challenge_request() {
        let config = PoWFaucetConfig::default();
        let mut faucet = PoWFaucet::new(config);

        let result = faucet.request_challenge("0xtest", None, None);
        assert!(result.is_ok());

        let instance = result.unwrap();
        assert!(!instance.instance_id.is_empty());
    }

    #[test]
    fn test_learning_path() {
        let challenges = WorkChallenge::default_challenges();

        // Intro has no prerequisites
        let intro = challenges.iter().find(|c| c.id == "intro_001").unwrap();
        assert!(intro.prerequisites.is_empty());

        // Finance requires intro
        let finance = challenges.iter().find(|c| c.id == "finance_001").unwrap();
        assert!(finance.prerequisites.contains(&"intro_002".to_string()));
    }
}
