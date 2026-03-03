//! Chaos Event System for Aethelred Testnet
//!
//! NOT a boring weekly reset. This is "Purge Night" - a gamified stress test
//! that builds community culture around "breaking the chain."
//!
//! Before wiping the chain:
//! - Fees drop to zero
//! - Difficulty spikes to maximum
//! - Network conditions become hostile
//! - Community competes to break things
//!
//! Features:
//! - Gamified chaos challenges with rewards
//! - Real-time stress metrics dashboard
//! - Community leaderboards for chaos mode
//! - Historical "Purge Night" statistics
//! - Break-it-to-prove-it resilience testing

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};

// ============ Chaos Event Configuration ============

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChaosEventConfig {
    /// Duration of chaos event (hours)
    pub duration_hours: u32,

    /// Hours before reset to start chaos
    pub start_hours_before_reset: u32,

    /// Enable zero fees during chaos
    pub zero_fees: bool,

    /// Maximum difficulty multiplier
    pub max_difficulty_multiplier: f64,

    /// Enable network chaos
    pub network_chaos_enabled: bool,

    /// Enable validator chaos
    pub validator_chaos_enabled: bool,

    /// Enable mempool flood
    pub mempool_flood_enabled: bool,

    /// Challenges configuration
    pub challenges: Vec<ChaosChallenge>,

    /// Rewards configuration
    pub rewards: ChaosRewardsConfig,

    /// Leaderboard configuration
    pub leaderboard: LeaderboardConfig,

    /// Announcement channels
    pub announcements: AnnouncementConfig,
}

impl Default for ChaosEventConfig {
    fn default() -> Self {
        Self {
            duration_hours: 4,
            start_hours_before_reset: 4,
            zero_fees: true,
            max_difficulty_multiplier: 10.0,
            network_chaos_enabled: true,
            validator_chaos_enabled: true,
            mempool_flood_enabled: true,
            challenges: ChaosChallenge::default_challenges(),
            rewards: ChaosRewardsConfig::default(),
            leaderboard: LeaderboardConfig::default(),
            announcements: AnnouncementConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChaosRewardsConfig {
    /// Base chaos participation reward
    pub base_participation_reward: u128,

    /// Reward for completing challenges
    pub challenge_completion_multiplier: f64,

    /// Top breaker bonus
    pub top_breaker_bonus: u128,

    /// Survivor bonus (for maintaining services during chaos)
    pub survivor_bonus: u128,

    /// NFT badges for achievements
    pub nft_badges_enabled: bool,
}

impl Default for ChaosRewardsConfig {
    fn default() -> Self {
        Self {
            base_participation_reward: 100_000_000_000_000_000_000, // 100 tokens
            challenge_completion_multiplier: 2.0,
            top_breaker_bonus: 1000_000_000_000_000_000_000, // 1000 tokens
            survivor_bonus: 500_000_000_000_000_000_000, // 500 tokens
            nft_badges_enabled: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaderboardConfig {
    pub max_entries: usize,
    pub categories: Vec<LeaderboardCategory>,
}

impl Default for LeaderboardConfig {
    fn default() -> Self {
        Self {
            max_entries: 100,
            categories: vec![
                LeaderboardCategory::MostTransactions,
                LeaderboardCategory::MostChaosPoints,
                LeaderboardCategory::MostChallengesCompleted,
                LeaderboardCategory::FirstToBreak,
                LeaderboardCategory::BestSurvivor,
            ],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LeaderboardCategory {
    MostTransactions,
    MostChaosPoints,
    MostChallengesCompleted,
    FirstToBreak,
    BestSurvivor,
    HighestGasUsed,
    MostContractsDeployed,
    LongestUptime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnnouncementConfig {
    pub discord_webhook: Option<String>,
    pub twitter_enabled: bool,
    pub telegram_bot: Option<String>,
    pub countdown_intervals_hours: Vec<u32>,
}

impl Default for AnnouncementConfig {
    fn default() -> Self {
        Self {
            discord_webhook: None,
            twitter_enabled: true,
            telegram_bot: None,
            countdown_intervals_hours: vec![24, 12, 6, 1],
        }
    }
}

// ============ Chaos Challenges ============

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChaosChallenge {
    pub id: String,
    pub name: String,
    pub description: String,
    pub category: ChallengeCategoryType,
    pub difficulty: ChallengeDifficulty,
    pub objective: ChallengeObjective,
    pub points: u32,
    pub badge: Option<ChaosBadge>,
    pub time_limit_minutes: Option<u32>,
    pub max_completions: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChallengeCategoryType {
    TransactionFlood,
    ContractStress,
    ValidatorHunting,
    NetworkBreaker,
    GasWars,
    Survival,
    Creative,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ChallengeDifficulty {
    Easy,
    Medium,
    Hard,
    Insane,
    Legendary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChallengeObjective {
    /// Submit N transactions in M seconds
    TransactionBurst { count: u64, seconds: u32 },

    /// Deploy N contracts
    ContractDeploy { count: u64 },

    /// Cause a specific error type
    TriggerError { error_type: String },

    /// Fill mempool to capacity
    MempoolFlood { target_size: usize },

    /// Make a validator miss blocks
    ValidatorMiss { count: u32 },

    /// Cause a reorg
    TriggerReorg { depth: u64 },

    /// Use maximum gas in single tx
    MaxGasUsage { target_gas: u64 },

    /// Keep a service running during chaos
    Survival { uptime_minutes: u32 },

    /// First to discover a specific condition
    FirstToFind { condition: String },

    /// Custom challenge
    Custom { script: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChaosBadge {
    pub id: String,
    pub name: String,
    pub description: String,
    pub image_url: String,
    pub rarity: BadgeRarity,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum BadgeRarity {
    Common,
    Uncommon,
    Rare,
    Epic,
    Legendary,
    Mythic,
}

impl ChaosChallenge {
    pub fn default_challenges() -> Vec<ChaosChallenge> {
        vec![
            // Transaction Flood Challenges
            ChaosChallenge {
                id: "tx_storm".to_string(),
                name: "Transaction Storm".to_string(),
                description: "Submit 100 transactions in 60 seconds".to_string(),
                category: ChallengeCategoryType::TransactionFlood,
                difficulty: ChallengeDifficulty::Medium,
                objective: ChallengeObjective::TransactionBurst { count: 100, seconds: 60 },
                points: 500,
                badge: Some(ChaosBadge {
                    id: "storm_bringer".to_string(),
                    name: "Storm Bringer".to_string(),
                    description: "Brought the transaction storm".to_string(),
                    image_url: "https://badges.aethelred.ai/storm.png".to_string(),
                    rarity: BadgeRarity::Rare,
                }),
                time_limit_minutes: Some(10),
                max_completions: None,
            },

            ChaosChallenge {
                id: "tx_tsunami".to_string(),
                name: "Transaction Tsunami".to_string(),
                description: "Submit 1000 transactions in 5 minutes".to_string(),
                category: ChallengeCategoryType::TransactionFlood,
                difficulty: ChallengeDifficulty::Hard,
                objective: ChallengeObjective::TransactionBurst { count: 1000, seconds: 300 },
                points: 2000,
                badge: Some(ChaosBadge {
                    id: "tsunami_master".to_string(),
                    name: "Tsunami Master".to_string(),
                    description: "Unleashed a tsunami of transactions".to_string(),
                    image_url: "https://badges.aethelred.ai/tsunami.png".to_string(),
                    rarity: BadgeRarity::Epic,
                }),
                time_limit_minutes: Some(30),
                max_completions: Some(10),
            },

            // Contract Stress Challenges
            ChaosChallenge {
                id: "contract_army".to_string(),
                name: "Contract Army".to_string(),
                description: "Deploy 50 contracts during chaos".to_string(),
                category: ChallengeCategoryType::ContractStress,
                difficulty: ChallengeDifficulty::Medium,
                objective: ChallengeObjective::ContractDeploy { count: 50 },
                points: 750,
                badge: None,
                time_limit_minutes: None,
                max_completions: None,
            },

            // Validator Hunting
            ChaosChallenge {
                id: "validator_hunter".to_string(),
                name: "Validator Hunter".to_string(),
                description: "Cause a validator to miss 3 blocks".to_string(),
                category: ChallengeCategoryType::ValidatorHunting,
                difficulty: ChallengeDifficulty::Insane,
                objective: ChallengeObjective::ValidatorMiss { count: 3 },
                points: 5000,
                badge: Some(ChaosBadge {
                    id: "validator_slayer".to_string(),
                    name: "Validator Slayer".to_string(),
                    description: "Made validators sweat".to_string(),
                    image_url: "https://badges.aethelred.ai/slayer.png".to_string(),
                    rarity: BadgeRarity::Legendary,
                }),
                time_limit_minutes: None,
                max_completions: Some(3),
            },

            // Network Breaker
            ChaosChallenge {
                id: "mempool_flood".to_string(),
                name: "Mempool Flooder".to_string(),
                description: "Fill the mempool to 90% capacity".to_string(),
                category: ChallengeCategoryType::NetworkBreaker,
                difficulty: ChallengeDifficulty::Hard,
                objective: ChallengeObjective::MempoolFlood { target_size: 9000 },
                points: 1500,
                badge: None,
                time_limit_minutes: Some(15),
                max_completions: Some(5),
            },

            ChaosChallenge {
                id: "chain_reorg".to_string(),
                name: "Chain Reorganizer".to_string(),
                description: "Trigger a 2-block reorg".to_string(),
                category: ChallengeCategoryType::NetworkBreaker,
                difficulty: ChallengeDifficulty::Legendary,
                objective: ChallengeObjective::TriggerReorg { depth: 2 },
                points: 10000,
                badge: Some(ChaosBadge {
                    id: "reorg_master".to_string(),
                    name: "Reorg Master".to_string(),
                    description: "Bent the chain to your will".to_string(),
                    image_url: "https://badges.aethelred.ai/reorg.png".to_string(),
                    rarity: BadgeRarity::Mythic,
                }),
                time_limit_minutes: None,
                max_completions: Some(1),
            },

            // Gas Wars
            ChaosChallenge {
                id: "gas_guzzler".to_string(),
                name: "Gas Guzzler".to_string(),
                description: "Use 10 million gas in a single transaction".to_string(),
                category: ChallengeCategoryType::GasWars,
                difficulty: ChallengeDifficulty::Medium,
                objective: ChallengeObjective::MaxGasUsage { target_gas: 10_000_000 },
                points: 300,
                badge: None,
                time_limit_minutes: None,
                max_completions: None,
            },

            ChaosChallenge {
                id: "block_filler".to_string(),
                name: "Block Filler".to_string(),
                description: "Use 95% of a block's gas limit".to_string(),
                category: ChallengeCategoryType::GasWars,
                difficulty: ChallengeDifficulty::Hard,
                objective: ChallengeObjective::MaxGasUsage { target_gas: 28_500_000 },
                points: 1000,
                badge: Some(ChaosBadge {
                    id: "block_hog".to_string(),
                    name: "Block Hog".to_string(),
                    description: "Dominated entire blocks".to_string(),
                    image_url: "https://badges.aethelred.ai/hog.png".to_string(),
                    rarity: BadgeRarity::Rare,
                }),
                time_limit_minutes: None,
                max_completions: Some(10),
            },

            // Survival Challenges
            ChaosChallenge {
                id: "survivor".to_string(),
                name: "Chaos Survivor".to_string(),
                description: "Keep your service running for the entire chaos event".to_string(),
                category: ChallengeCategoryType::Survival,
                difficulty: ChallengeDifficulty::Hard,
                objective: ChallengeObjective::Survival { uptime_minutes: 240 },
                points: 3000,
                badge: Some(ChaosBadge {
                    id: "survivor".to_string(),
                    name: "Chaos Survivor".to_string(),
                    description: "Weathered the storm".to_string(),
                    image_url: "https://badges.aethelred.ai/survivor.png".to_string(),
                    rarity: BadgeRarity::Epic,
                }),
                time_limit_minutes: None,
                max_completions: None,
            },

            // First to Find
            ChaosChallenge {
                id: "first_revert".to_string(),
                name: "First Blood".to_string(),
                description: "Be the first to trigger a specific revert condition".to_string(),
                category: ChallengeCategoryType::Creative,
                difficulty: ChallengeDifficulty::Insane,
                objective: ChallengeObjective::FirstToFind { condition: "OUT_OF_GAS_DEEP_CALL".to_string() },
                points: 2500,
                badge: Some(ChaosBadge {
                    id: "first_blood".to_string(),
                    name: "First Blood".to_string(),
                    description: "Drew first blood in chaos".to_string(),
                    image_url: "https://badges.aethelred.ai/first_blood.png".to_string(),
                    rarity: BadgeRarity::Legendary,
                }),
                time_limit_minutes: Some(30),
                max_completions: Some(1),
            },
        ]
    }
}

// ============ Chaos Event State ============

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChaosEvent {
    /// Unique event ID
    pub id: String,

    /// Event number (Purge Night #N)
    pub event_number: u32,

    /// Event name
    pub name: String,

    /// Current phase
    pub phase: ChaosPhase,

    /// Start time
    pub started_at: u64,

    /// End time
    pub ends_at: u64,

    /// Reset time (after chaos ends)
    pub reset_at: u64,

    /// Active modifiers
    pub modifiers: Vec<ChaosModifier>,

    /// Real-time metrics
    pub metrics: ChaosMetrics,

    /// Participant tracking
    pub participants: HashMap<String, ChaosParticipant>,

    /// Challenge completions
    pub challenge_completions: Vec<ChallengeCompletion>,

    /// Leaderboards
    pub leaderboards: HashMap<LeaderboardCategory, Vec<LeaderboardEntry>>,

    /// Event log
    pub event_log: VecDeque<ChaosLogEntry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChaosPhase {
    /// Before chaos starts
    Countdown,

    /// Chaos is active - break everything!
    Active,

    /// Cooling down before reset
    CoolDown,

    /// Reset in progress
    Resetting,

    /// Event complete
    Complete,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChaosModifier {
    pub id: String,
    pub name: String,
    pub description: String,
    pub modifier_type: ModifierType,
    pub intensity: f64,
    pub started_at: u64,
    pub duration_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ModifierType {
    /// Zero transaction fees
    ZeroFees,

    /// Increased block gas limit
    IncreasedGasLimit { multiplier: f64 },

    /// Reduced block time
    FastBlocks { block_time_ms: u64 },

    /// Network latency injection
    NetworkLatency { min_ms: u64, max_ms: u64 },

    /// Random transaction drops
    PacketLoss { percentage: f64 },

    /// Validator instability
    ValidatorChaos { failure_rate: f64 },

    /// Mempool size increase
    LargeMempol { size: usize },

    /// Random difficulty spikes
    DifficultySpikes { multiplier: f64 },

    /// Block reorg chance
    ReorgChance { probability: f64 },
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChaosMetrics {
    /// Transactions during chaos
    pub total_transactions: u64,

    /// Peak TPS achieved
    pub peak_tps: f64,

    /// Contracts deployed
    pub contracts_deployed: u64,

    /// Total gas used
    pub total_gas_used: u128,

    /// Failed transactions
    pub failed_transactions: u64,

    /// Reverts triggered
    pub reverts_triggered: u64,

    /// Validator misses
    pub validator_misses: u64,

    /// Block reorgs
    pub reorgs_triggered: u64,

    /// Mempool peak size
    pub mempool_peak_size: usize,

    /// Unique participants
    pub unique_participants: u64,

    /// Total chaos points earned
    pub total_chaos_points: u64,

    /// Challenges completed
    pub challenges_completed: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChaosParticipant {
    pub address: String,
    pub display_name: Option<String>,
    pub joined_at: u64,
    pub transactions_sent: u64,
    pub contracts_deployed: u64,
    pub gas_used: u128,
    pub chaos_points: u64,
    pub challenges_completed: Vec<String>,
    pub badges_earned: Vec<ChaosBadge>,
    pub uptime_seconds: u64,
    pub is_survivor: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeCompletion {
    pub challenge_id: String,
    pub participant_address: String,
    pub completed_at: u64,
    pub time_taken_seconds: u64,
    pub points_earned: u32,
    pub badge_earned: Option<ChaosBadge>,
    pub rank: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaderboardEntry {
    pub rank: usize,
    pub address: String,
    pub display_name: Option<String>,
    pub score: u64,
    pub metric_details: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChaosLogEntry {
    pub timestamp: u64,
    pub event_type: ChaosLogEventType,
    pub description: String,
    pub participant: Option<String>,
    pub details: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChaosLogEventType {
    EventStarted,
    EventEnded,
    ModifierActivated,
    ModifierDeactivated,
    ChallengeCompleted,
    RecordBroken,
    MilestoneReached,
    ValidatorDown,
    ReorgOccurred,
    ParticipantJoined,
    BadgeAwarded,
}

// ============ Chaos Event Manager ============

pub struct ChaosEventManager {
    config: ChaosEventConfig,
    current_event: Option<ChaosEvent>,
    event_history: Vec<ChaosEventSummary>,
    all_time_records: AllTimeRecords,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChaosEventSummary {
    pub id: String,
    pub event_number: u32,
    pub started_at: u64,
    pub ended_at: u64,
    pub participants: u64,
    pub peak_tps: f64,
    pub total_transactions: u64,
    pub challenges_completed: u64,
    pub top_participant: String,
    pub top_score: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AllTimeRecords {
    pub highest_tps: RecordEntry,
    pub most_transactions: RecordEntry,
    pub fastest_challenge: RecordEntry,
    pub most_chaos_points: RecordEntry,
    pub longest_survival: RecordEntry,
    pub first_reorg: RecordEntry,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RecordEntry {
    pub holder: String,
    pub value: u64,
    pub event_number: u32,
    pub achieved_at: u64,
}

impl ChaosEventManager {
    pub fn new(config: ChaosEventConfig) -> Self {
        Self {
            config,
            current_event: None,
            event_history: Vec::new(),
            all_time_records: AllTimeRecords::default(),
        }
    }

    /// Start a new chaos event
    pub fn start_event(&mut self, event_number: u32, reset_at: u64) -> Result<&ChaosEvent, String> {
        if self.current_event.is_some() {
            return Err("Chaos event already in progress".to_string());
        }

        let now = current_timestamp();
        let duration_seconds = self.config.duration_hours as u64 * 3600;

        let mut modifiers = Vec::new();

        // Add zero fees modifier
        if self.config.zero_fees {
            modifiers.push(ChaosModifier {
                id: "zero_fees".to_string(),
                name: "Zero Fees".to_string(),
                description: "All transaction fees are zero!".to_string(),
                modifier_type: ModifierType::ZeroFees,
                intensity: 1.0,
                started_at: now,
                duration_seconds,
            });
        }

        // Add difficulty spike
        modifiers.push(ChaosModifier {
            id: "difficulty_spike".to_string(),
            name: "Maximum Difficulty".to_string(),
            description: format!("Difficulty multiplied by {}x", self.config.max_difficulty_multiplier),
            modifier_type: ModifierType::DifficultySpikes {
                multiplier: self.config.max_difficulty_multiplier,
            },
            intensity: self.config.max_difficulty_multiplier,
            started_at: now,
            duration_seconds,
        });

        // Add network chaos
        if self.config.network_chaos_enabled {
            modifiers.push(ChaosModifier {
                id: "network_chaos".to_string(),
                name: "Network Instability".to_string(),
                description: "Random latency and packet loss".to_string(),
                modifier_type: ModifierType::NetworkLatency { min_ms: 100, max_ms: 2000 },
                intensity: 0.5,
                started_at: now,
                duration_seconds,
            });
        }

        let event = ChaosEvent {
            id: format!("purge_{}", event_number),
            event_number,
            name: format!("Purge Night #{}", event_number),
            phase: ChaosPhase::Active,
            started_at: now,
            ends_at: now + duration_seconds,
            reset_at,
            modifiers,
            metrics: ChaosMetrics::default(),
            participants: HashMap::new(),
            challenge_completions: Vec::new(),
            leaderboards: HashMap::new(),
            event_log: VecDeque::with_capacity(1000),
        };

        // Log event start
        self.log_event(&event, ChaosLogEventType::EventStarted, "Purge Night has begun!", None);

        self.current_event = Some(event);
        Ok(self.current_event.as_ref().unwrap())
    }

    /// Record a transaction during chaos
    pub fn record_transaction(&mut self, address: &str, gas_used: u64, success: bool) {
        if let Some(ref mut event) = self.current_event {
            if event.phase != ChaosPhase::Active {
                return;
            }

            // Update metrics
            event.metrics.total_transactions += 1;
            event.metrics.total_gas_used += gas_used as u128;

            if !success {
                event.metrics.failed_transactions += 1;
            }

            // Update participant
            let participant = event.participants.entry(address.to_string())
                .or_insert_with(|| ChaosParticipant {
                    address: address.to_string(),
                    display_name: None,
                    joined_at: current_timestamp(),
                    transactions_sent: 0,
                    contracts_deployed: 0,
                    gas_used: 0,
                    chaos_points: 0,
                    challenges_completed: Vec::new(),
                    badges_earned: Vec::new(),
                    uptime_seconds: 0,
                    is_survivor: false,
                });

            participant.transactions_sent += 1;
            participant.gas_used += gas_used as u128;
            participant.chaos_points += 10; // Base points per transaction

            // Update unique participants
            event.metrics.unique_participants = event.participants.len() as u64;
        }
    }

    /// Record a contract deployment
    pub fn record_contract_deploy(&mut self, address: &str) {
        if let Some(ref mut event) = self.current_event {
            if event.phase != ChaosPhase::Active {
                return;
            }

            event.metrics.contracts_deployed += 1;

            if let Some(participant) = event.participants.get_mut(address) {
                participant.contracts_deployed += 1;
                participant.chaos_points += 50; // Bonus for contract deployment
            }

            // Check contract army challenge
            self.check_challenge_completion(address, "contract_army");
        }
    }

    /// Record a revert
    pub fn record_revert(&mut self, address: &str, error_type: &str) {
        if let Some(ref mut event) = self.current_event {
            event.metrics.reverts_triggered += 1;

            if let Some(participant) = event.participants.get_mut(address) {
                participant.chaos_points += 25; // Points for triggering reverts
            }
        }
    }

    /// Record validator miss
    pub fn record_validator_miss(&mut self, validator: &str) {
        if let Some(ref mut event) = self.current_event {
            event.metrics.validator_misses += 1;

            self.log_event(
                event,
                ChaosLogEventType::ValidatorDown,
                &format!("Validator {} missed a block!", validator),
                None,
            );
        }
    }

    /// Record reorg
    pub fn record_reorg(&mut self, depth: u64, triggered_by: Option<&str>) {
        if let Some(ref mut event) = self.current_event {
            event.metrics.reorgs_triggered += 1;

            self.log_event(
                event,
                ChaosLogEventType::ReorgOccurred,
                &format!("Chain reorg of depth {} detected!", depth),
                triggered_by.map(|s| s.to_string()),
            );

            // Award points and possibly badge
            if let Some(address) = triggered_by {
                if let Some(participant) = event.participants.get_mut(address) {
                    participant.chaos_points += 1000;
                }

                // Check reorg challenge
                self.check_challenge_completion(address, "chain_reorg");
            }

            // Check if this is a new record
            if event.event_number > self.all_time_records.first_reorg.event_number {
                if let Some(address) = triggered_by {
                    self.all_time_records.first_reorg = RecordEntry {
                        holder: address.to_string(),
                        value: depth,
                        event_number: event.event_number,
                        achieved_at: current_timestamp(),
                    };
                }
            }
        }
    }

    /// Check challenge completion
    fn check_challenge_completion(&mut self, address: &str, challenge_id: &str) {
        let challenge = self.config.challenges.iter()
            .find(|c| c.id == challenge_id)
            .cloned();

        if let Some(challenge) = challenge {
            if let Some(ref mut event) = self.current_event {
                // Check if already completed (respecting max_completions)
                let completions = event.challenge_completions.iter()
                    .filter(|c| c.challenge_id == challenge_id)
                    .count();

                if let Some(max) = challenge.max_completions {
                    if completions >= max as usize {
                        return;
                    }
                }

                // Check if this participant already completed it
                if let Some(participant) = event.participants.get(address) {
                    if participant.challenges_completed.contains(&challenge_id.to_string()) {
                        return;
                    }
                }

                // Record completion
                let completion = ChallengeCompletion {
                    challenge_id: challenge_id.to_string(),
                    participant_address: address.to_string(),
                    completed_at: current_timestamp(),
                    time_taken_seconds: current_timestamp() - event.started_at,
                    points_earned: challenge.points,
                    badge_earned: challenge.badge.clone(),
                    rank: (completions + 1) as u32,
                };

                event.challenge_completions.push(completion);
                event.metrics.challenges_completed += 1;

                // Update participant
                if let Some(participant) = event.participants.get_mut(address) {
                    participant.challenges_completed.push(challenge_id.to_string());
                    participant.chaos_points += challenge.points as u64;

                    if let Some(badge) = challenge.badge.clone() {
                        participant.badges_earned.push(badge.clone());

                        self.log_event(
                            event,
                            ChaosLogEventType::BadgeAwarded,
                            &format!("{} earned the {} badge!", address, badge.name),
                            Some(address.to_string()),
                        );
                    }
                }

                self.log_event(
                    event,
                    ChaosLogEventType::ChallengeCompleted,
                    &format!("{} completed challenge: {}", address, challenge.name),
                    Some(address.to_string()),
                );
            }
        }
    }

    fn log_event(&self, event: &ChaosEvent, event_type: ChaosLogEventType, description: &str, participant: Option<String>) {
        // In a real implementation, this would push to event.event_log
        // For now, we just print
        println!("[CHAOS] {} - {:?}: {}", event.name, event_type, description);
    }

    /// Update TPS metrics
    pub fn update_tps(&mut self, current_tps: f64) {
        if let Some(ref mut event) = self.current_event {
            if current_tps > event.metrics.peak_tps {
                event.metrics.peak_tps = current_tps;
            }
        }
    }

    /// End the chaos event
    pub fn end_event(&mut self) -> Option<ChaosEventSummary> {
        if let Some(mut event) = self.current_event.take() {
            event.phase = ChaosPhase::Complete;

            // Find top participant
            let top_participant = event.participants.values()
                .max_by_key(|p| p.chaos_points)
                .map(|p| p.address.clone())
                .unwrap_or_default();

            let top_score = event.participants.get(&top_participant)
                .map(|p| p.chaos_points)
                .unwrap_or(0);

            let summary = ChaosEventSummary {
                id: event.id.clone(),
                event_number: event.event_number,
                started_at: event.started_at,
                ended_at: current_timestamp(),
                participants: event.participants.len() as u64,
                peak_tps: event.metrics.peak_tps,
                total_transactions: event.metrics.total_transactions,
                challenges_completed: event.metrics.challenges_completed,
                top_participant,
                top_score,
            };

            // Update records
            self.update_records(&event);

            // Store in history
            self.event_history.push(summary.clone());

            Some(summary)
        } else {
            None
        }
    }

    fn update_records(&mut self, event: &ChaosEvent) {
        // Update highest TPS record
        if event.metrics.peak_tps > self.all_time_records.highest_tps.value as f64 {
            // Find who achieved it
            let holder = event.participants.values()
                .max_by_key(|p| p.transactions_sent)
                .map(|p| p.address.clone())
                .unwrap_or_default();

            self.all_time_records.highest_tps = RecordEntry {
                holder,
                value: event.metrics.peak_tps as u64,
                event_number: event.event_number,
                achieved_at: current_timestamp(),
            };
        }

        // Update most transactions record
        if let Some(top) = event.participants.values().max_by_key(|p| p.transactions_sent) {
            if top.transactions_sent > self.all_time_records.most_transactions.value {
                self.all_time_records.most_transactions = RecordEntry {
                    holder: top.address.clone(),
                    value: top.transactions_sent,
                    event_number: event.event_number,
                    achieved_at: current_timestamp(),
                };
            }
        }
    }

    /// Get current event
    pub fn current_event(&self) -> Option<&ChaosEvent> {
        self.current_event.as_ref()
    }

    /// Get event history
    pub fn history(&self) -> &[ChaosEventSummary] {
        &self.event_history
    }

    /// Get all-time records
    pub fn records(&self) -> &AllTimeRecords {
        &self.all_time_records
    }

    /// Get leaderboard for category
    pub fn get_leaderboard(&self, category: LeaderboardCategory) -> Vec<LeaderboardEntry> {
        if let Some(ref event) = self.current_event {
            let mut entries: Vec<_> = match category {
                LeaderboardCategory::MostTransactions => {
                    event.participants.values()
                        .map(|p| (p.address.clone(), p.transactions_sent, serde_json::json!({"tx": p.transactions_sent})))
                        .collect()
                }
                LeaderboardCategory::MostChaosPoints => {
                    event.participants.values()
                        .map(|p| (p.address.clone(), p.chaos_points, serde_json::json!({"points": p.chaos_points})))
                        .collect()
                }
                LeaderboardCategory::HighestGasUsed => {
                    event.participants.values()
                        .map(|p| (p.address.clone(), p.gas_used as u64, serde_json::json!({"gas": p.gas_used})))
                        .collect()
                }
                _ => Vec::new(),
            };

            entries.sort_by(|a, b| b.1.cmp(&a.1));

            entries.iter()
                .take(self.config.leaderboard.max_entries)
                .enumerate()
                .map(|(i, (addr, score, details))| LeaderboardEntry {
                    rank: i + 1,
                    address: addr.clone(),
                    display_name: None,
                    score: *score,
                    metric_details: details.clone(),
                })
                .collect()
        } else {
            Vec::new()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chaos_event_creation() {
        let config = ChaosEventConfig::default();
        let mut manager = ChaosEventManager::new(config);

        let result = manager.start_event(1, current_timestamp() + 86400);
        assert!(result.is_ok());

        let event = result.unwrap();
        assert_eq!(event.event_number, 1);
        assert_eq!(event.phase, ChaosPhase::Active);
    }

    #[test]
    fn test_participant_tracking() {
        let config = ChaosEventConfig::default();
        let mut manager = ChaosEventManager::new(config);

        manager.start_event(1, current_timestamp() + 86400).unwrap();

        manager.record_transaction("0xtest", 21000, true);
        manager.record_transaction("0xtest", 21000, true);
        manager.record_contract_deploy("0xtest");

        let event = manager.current_event().unwrap();
        let participant = event.participants.get("0xtest").unwrap();

        assert_eq!(participant.transactions_sent, 2);
        assert_eq!(participant.contracts_deployed, 1);
        assert!(participant.chaos_points > 0);
    }

    #[test]
    fn test_default_challenges() {
        let challenges = ChaosChallenge::default_challenges();

        assert!(!challenges.is_empty());
        assert!(challenges.iter().any(|c| c.id == "tx_storm"));
        assert!(challenges.iter().any(|c| c.id == "chain_reorg"));
    }

    #[test]
    fn test_event_end() {
        let config = ChaosEventConfig::default();
        let mut manager = ChaosEventManager::new(config);

        manager.start_event(1, current_timestamp() + 86400).unwrap();
        manager.record_transaction("0xtest", 21000, true);

        let summary = manager.end_event();
        assert!(summary.is_some());

        let summary = summary.unwrap();
        assert_eq!(summary.event_number, 1);
        assert_eq!(summary.participants, 1);
    }
}
