//! # Adversarial War Room
//!
//! **"Inject Evil, Watch Defenses React"**
//!
//! This module simulates malicious actors in the network. Users can:
//!
//! 1. Inject a "Lazy Prover" that submits fake zkML proofs
//! 2. Inject a "Data Leaker" that tries to exfiltrate data
//! 3. Watch the system detect and slash the attacker
//!
//! ## The War Room Interface
//!
//! ```text
//! ╔═══════════════════════════════════════════════════════════════════════════════╗
//! ║                        🟠 ADVERSARIAL WAR ROOM                                ║
//! ╠═══════════════════════════════════════════════════════════════════════════════╣
//! ║                                                                               ║
//! ║  INJECT MALICIOUS NODES                                                       ║
//! ║                                                                               ║
//! ║  ┌─────────────────────────────────────────────────────────────────────────┐ ║
//! ║  │  [🦥 Lazy Prover]  [📤 Data Leaker]  [🔀 Result Manipulator]           │ ║
//! ║  │                                                                         │ ║
//! ║  │  [💥 Crash Node]   [⏩ Front-Runner]  [🕵️ Eclipse Attack]              │ ║
//! ║  └─────────────────────────────────────────────────────────────────────────┘ ║
//! ║                                                                               ║
//! ║  ACTIVE THREATS: 2                                                            ║
//! ║  ┌─────────────────────────────────────────────────────────────────────────┐ ║
//! ║  │  🦥 Lazy Prover      Node-7     Submitting fake proofs                  │ ║
//! ║  │  📤 Data Leaker      Node-12    Attempting exfiltration                  │ ║
//! ║  └─────────────────────────────────────────────────────────────────────────┘ ║
//! ║                                                                               ║
//! ║  DETECTION STATUS:                                                            ║
//! ║  ┌─────────────────────────────────────────────────────────────────────────┐ ║
//! ║  │  ✅ Lazy Prover DETECTED - Invalid proof hash                           │ ║
//! ║  │  ⚠️  Data Leaker SUSPECTED - Anomalous egress patterns                  │ ║
//! ║  └─────────────────────────────────────────────────────────────────────────┘ ║
//! ║                                                                               ║
//! ╚═══════════════════════════════════════════════════════════════════════════════╝
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::SystemTime;

// ============================================================================
// Attack Types
// ============================================================================

/// Types of adversarial attacks
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AttackType {
    /// Node submits fake proofs (saves compute, steals rewards)
    LazyProver {
        /// Percentage of proofs that are faked
        fake_proof_rate: u8,
    },

    /// Node attempts to exfiltrate sensitive data
    DataLeaker {
        /// Target data type
        target: LeakTarget,
        /// Exfiltration method
        method: ExfiltrationMethod,
    },

    /// Node returns incorrect computation results
    ResultManipulator {
        /// How results are manipulated
        manipulation: ManipulationType,
    },

    /// Node goes offline at critical moments
    CrashNode {
        /// When to crash
        trigger: CrashTrigger,
    },

    /// Node reorders transactions for profit
    FrontRunner {
        /// MEV extraction strategy
        strategy: MEVStrategy,
    },

    /// Isolate victim from honest network
    EclipseAttack {
        /// Target victim
        victim: String,
        /// Number of malicious peers
        sybil_count: u32,
    },

    /// Spam network with invalid transactions
    SpamAttack {
        /// Transactions per second
        tps: u32,
    },

    /// Long-range attack on consensus
    LongRangeAttack {
        /// Fork point (block height)
        fork_height: u64,
    },

    /// Grinding attack on randomness
    GrindingAttack {
        /// Computational budget
        compute_budget: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LeakTarget {
    ModelWeights,
    TrainingData,
    InferenceInputs,
    InferenceOutputs,
    PrivateKeys,
    CustomerPII,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExfiltrationMethod {
    SideChannel,       // Timing, power analysis
    MemoryDump,        // Direct memory access
    CovertChannel,     // Encoded in outputs
    NetworkEgress,     // Plaintext exfiltration
    AttestationBypass, // Fake attestation
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ManipulationType {
    AddBias { bias: i32 },          // Add constant bias
    MultiplyScale { factor: f64 },  // Scale results
    RandomNoise { magnitude: f64 }, // Add noise
    InvertSign,                     // Flip positive/negative
    TargetedChange { target: i32 }, // Specific value manipulation
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CrashTrigger {
    RandomInterval { avg_seconds: u64 },
    OnProofRequest,
    OnConsensusVote,
    OnHighValueTx { threshold_usd: u64 },
    OnSpecificBlock { height: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MEVStrategy {
    Sandwich,        // Front + back run
    JustInTime,      // JIT liquidity
    AtomicArbitrage, // Cross-DEX arb
    Liquidation,     // Liquidation sniping
    NFTSniping,      // NFT mint sniping
}

// ============================================================================
// Malicious Nodes
// ============================================================================

/// A malicious node in the simulation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaliciousNode {
    /// Node ID
    pub id: String,
    /// Display name
    pub name: String,
    /// Attack type
    pub attack: AttackType,
    /// Stake amount (for slashing)
    pub stake: u64,
    /// Status
    pub status: NodeStatus,
    /// Attack log
    pub attack_log: Vec<AttackEvent>,
    /// Detection events
    pub detections: Vec<DetectionEvent>,
    /// Created at
    pub created_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeStatus {
    Active,
    Detected,
    Slashed,
    Jailed,
    Evicted,
}

/// An attack event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackEvent {
    /// Timestamp
    pub timestamp: u64,
    /// Event type
    pub event_type: AttackEventType,
    /// Target
    pub target: Option<String>,
    /// Success
    pub success: bool,
    /// Details
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AttackEventType {
    FakeProofSubmitted,
    DataExfiltrationAttempt,
    ResultManipulated,
    NodeCrashed,
    FrontRunExecuted,
    SybilCreated,
    SpamSent,
}

/// A detection event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionEvent {
    /// Timestamp
    pub timestamp: u64,
    /// Detection method
    pub method: DetectionMethod,
    /// Confidence (0-100)
    pub confidence: u8,
    /// Evidence
    pub evidence: Vec<Evidence>,
    /// Action taken
    pub action: DetectionAction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DetectionMethod {
    ProofVerification,   // Cryptographic proof failed
    StatisticalAnomaly,  // Output distribution unusual
    BehaviorAnalysis,    // Activity pattern analysis
    CrossValidation,     // Multiple validators disagree
    TEEAttestation,      // TEE detected tampering
    NetworkMonitoring,   // Unusual network patterns
    HoneypotTriggered,   // Decoy data accessed
    WhistleblowerReport, // Another node reported
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    /// Evidence type
    pub evidence_type: String,
    /// Description
    pub description: String,
    /// Hash of proof
    pub proof_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DetectionAction {
    Alert,                  // Warning issued
    Quarantine,             // Isolated from network
    Slash { amount: u64 },  // Stake slashed
    Jail { duration: u64 }, // Temporarily banned
    Evict,                  // Permanently removed
}

// ============================================================================
// The Adversarial War Room
// ============================================================================

/// The Adversarial War Room - manages attack simulations
pub struct AdversarialWarRoom {
    /// Active malicious nodes
    nodes: HashMap<String, MaliciousNode>,
    /// Defense configuration
    defenses: DefenseConfiguration,
    /// Attack statistics
    stats: AttackStatistics,
    /// Simulation mode
    #[allow(dead_code)]
    simulation_mode: SimulationMode,
}

#[derive(Debug, Clone)]
pub struct DefenseConfiguration {
    /// Enable proof verification
    pub proof_verification: bool,
    /// Enable statistical anomaly detection
    pub statistical_detection: bool,
    /// Enable cross-validation
    pub cross_validation: bool,
    /// Enable TEE attestation checks
    pub tee_attestation: bool,
    /// Enable network monitoring
    pub network_monitoring: bool,
    /// Slashing enabled
    pub slashing_enabled: bool,
    /// Slashing percentage (of stake)
    pub slashing_percentage: u8,
}

impl Default for DefenseConfiguration {
    fn default() -> Self {
        DefenseConfiguration {
            proof_verification: true,
            statistical_detection: true,
            cross_validation: true,
            tee_attestation: true,
            network_monitoring: true,
            slashing_enabled: true,
            slashing_percentage: 10,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct AttackStatistics {
    /// Total attacks attempted
    pub total_attacks: u64,
    /// Attacks detected
    pub attacks_detected: u64,
    /// Attacks succeeded
    pub attacks_succeeded: u64,
    /// Total stake slashed
    pub stake_slashed: u64,
    /// Nodes evicted
    pub nodes_evicted: u32,
    /// Average detection time (ms)
    pub avg_detection_time: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SimulationMode {
    /// Real-time simulation with delays
    RealTime,
    /// Fast simulation (no delays)
    Fast,
    /// Step-by-step (manual advancement)
    StepByStep,
}

impl AdversarialWarRoom {
    pub fn new() -> Self {
        AdversarialWarRoom {
            nodes: HashMap::new(),
            defenses: DefenseConfiguration::default(),
            stats: AttackStatistics::default(),
            simulation_mode: SimulationMode::Fast,
        }
    }

    /// Inject a malicious node
    pub fn inject_node(&mut self, attack: AttackType) -> String {
        let node_id = format!("malicious-{}", uuid::Uuid::new_v4());
        let name = self.generate_node_name(&attack);

        let node = MaliciousNode {
            id: node_id.clone(),
            name,
            attack,
            stake: 100_000, // 100k tokens staked
            status: NodeStatus::Active,
            attack_log: Vec::new(),
            detections: Vec::new(),
            created_at: SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        self.nodes.insert(node_id.clone(), node);
        node_id
    }

    fn generate_node_name(&self, attack: &AttackType) -> String {
        let prefix = match attack {
            AttackType::LazyProver { .. } => "🦥 Lazy Prover",
            AttackType::DataLeaker { .. } => "📤 Data Leaker",
            AttackType::ResultManipulator { .. } => "🔀 Manipulator",
            AttackType::CrashNode { .. } => "💥 Crash Node",
            AttackType::FrontRunner { .. } => "⏩ Front-Runner",
            AttackType::EclipseAttack { .. } => "🕵️ Eclipse",
            AttackType::SpamAttack { .. } => "📨 Spammer",
            AttackType::LongRangeAttack { .. } => "📏 Long-Range",
            AttackType::GrindingAttack { .. } => "⚙️ Grinder",
        };
        format!("{}-{}", prefix, self.nodes.len() + 1)
    }

    /// Execute an attack
    pub fn execute_attack(&mut self, node_id: &str) -> Result<AttackResult, WarRoomError> {
        let attack = {
            let node = self.nodes.get(node_id).ok_or(WarRoomError::NodeNotFound)?;
            if node.status != NodeStatus::Active {
                return Err(WarRoomError::NodeNotActive);
            }
            node.attack.clone()
        };

        let now = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        self.stats.total_attacks += 1;

        // Execute the attack
        let (event, detected, evidence) = self.simulate_attack(&attack);
        let detection_method = detected.then(|| self.determine_detection_method(&attack));
        let action = detected.then(|| self.determine_action(&attack));

        let node = self
            .nodes
            .get_mut(node_id)
            .ok_or(WarRoomError::NodeNotFound)?;

        node.attack_log.push(AttackEvent {
            timestamp: now,
            event_type: event.clone(),
            target: None,
            success: !detected,
            details: format!("Attack executed at timestamp {}", now),
        });

        // Detection logic
        if detected {
            self.stats.attacks_detected += 1;

            let detection = DetectionEvent {
                timestamp: now,
                method: detection_method
                    .clone()
                    .expect("detection method must exist when detected"),
                confidence: 95,
                evidence,
                action: action.clone().expect("action must exist when detected"),
            };

            node.detections.push(detection);

            // Apply action
            match action.clone().expect("action must exist when detected") {
                DetectionAction::Slash { amount } => {
                    self.stats.stake_slashed += amount;
                    node.status = NodeStatus::Slashed;
                }
                DetectionAction::Evict => {
                    self.stats.nodes_evicted += 1;
                    node.status = NodeStatus::Evicted;
                }
                DetectionAction::Jail { .. } => {
                    node.status = NodeStatus::Jailed;
                }
                _ => {
                    node.status = NodeStatus::Detected;
                }
            }

            Ok(AttackResult {
                success: false,
                detected: true,
                detection_method,
                action_taken: action,
                message: "Attack detected and neutralized".to_string(),
            })
        } else {
            self.stats.attacks_succeeded += 1;

            Ok(AttackResult {
                success: true,
                detected: false,
                detection_method: None,
                action_taken: None,
                message: "Attack succeeded (defenses bypassed)".to_string(),
            })
        }
    }

    fn simulate_attack(&self, attack: &AttackType) -> (AttackEventType, bool, Vec<Evidence>) {
        match attack {
            AttackType::LazyProver { fake_proof_rate } => {
                let detected = self.defenses.proof_verification && *fake_proof_rate > 0;
                let event = AttackEventType::FakeProofSubmitted;
                let evidence = if detected {
                    vec![Evidence {
                        evidence_type: "Proof Verification".to_string(),
                        description: "zkML proof hash mismatch - computation not performed"
                            .to_string(),
                        proof_hash: Some("0xdeadbeef...".to_string()),
                    }]
                } else {
                    vec![]
                };
                (event, detected, evidence)
            }

            AttackType::DataLeaker { target, method } => {
                let detected = match method {
                    ExfiltrationMethod::SideChannel => self.defenses.statistical_detection,
                    ExfiltrationMethod::MemoryDump => self.defenses.tee_attestation,
                    ExfiltrationMethod::CovertChannel => self.defenses.network_monitoring,
                    ExfiltrationMethod::NetworkEgress => self.defenses.network_monitoring,
                    ExfiltrationMethod::AttestationBypass => self.defenses.tee_attestation,
                };
                let event = AttackEventType::DataExfiltrationAttempt;
                let evidence = if detected {
                    vec![Evidence {
                        evidence_type: "Data Leak Detection".to_string(),
                        description: format!(
                            "Attempted exfiltration of {:?} via {:?}",
                            target, method
                        ),
                        proof_hash: None,
                    }]
                } else {
                    vec![]
                };
                (event, detected, evidence)
            }

            AttackType::ResultManipulator { manipulation } => {
                let detected =
                    self.defenses.cross_validation || self.defenses.statistical_detection;
                let event = AttackEventType::ResultManipulated;
                let evidence = if detected {
                    vec![Evidence {
                        evidence_type: "Cross-Validation".to_string(),
                        description: format!(
                            "Result deviation detected - manipulation: {:?}",
                            manipulation
                        ),
                        proof_hash: None,
                    }]
                } else {
                    vec![]
                };
                (event, detected, evidence)
            }

            AttackType::FrontRunner { strategy } => {
                let detected = self.defenses.network_monitoring;
                let event = AttackEventType::FrontRunExecuted;
                let evidence = if detected {
                    vec![Evidence {
                        evidence_type: "MEV Detection".to_string(),
                        description: format!(
                            "Suspicious transaction ordering - strategy: {:?}",
                            strategy
                        ),
                        proof_hash: None,
                    }]
                } else {
                    vec![]
                };
                (event, detected, evidence)
            }

            AttackType::CrashNode { .. } => {
                // Crash nodes are always "detected" (node goes offline)
                (
                    AttackEventType::NodeCrashed,
                    true,
                    vec![Evidence {
                        evidence_type: "Liveness Check".to_string(),
                        description: "Node failed to respond to heartbeat".to_string(),
                        proof_hash: None,
                    }],
                )
            }

            _ => (
                AttackEventType::FakeProofSubmitted,
                self.defenses.proof_verification,
                vec![],
            ),
        }
    }

    fn determine_detection_method(&self, attack: &AttackType) -> DetectionMethod {
        match attack {
            AttackType::LazyProver { .. } => DetectionMethod::ProofVerification,
            AttackType::DataLeaker {
                method: ExfiltrationMethod::SideChannel,
                ..
            } => DetectionMethod::StatisticalAnomaly,
            AttackType::DataLeaker {
                method: ExfiltrationMethod::MemoryDump,
                ..
            } => DetectionMethod::TEEAttestation,
            AttackType::DataLeaker { .. } => DetectionMethod::NetworkMonitoring,
            AttackType::ResultManipulator { .. } => DetectionMethod::CrossValidation,
            AttackType::FrontRunner { .. } => DetectionMethod::BehaviorAnalysis,
            AttackType::CrashNode { .. } => DetectionMethod::NetworkMonitoring,
            _ => DetectionMethod::BehaviorAnalysis,
        }
    }

    fn determine_action(&self, attack: &AttackType) -> DetectionAction {
        if !self.defenses.slashing_enabled {
            return DetectionAction::Alert;
        }

        match attack {
            AttackType::LazyProver { fake_proof_rate } if *fake_proof_rate > 50 => {
                DetectionAction::Slash {
                    amount: 50_000, // 50% of stake
                }
            }
            AttackType::DataLeaker {
                target: LeakTarget::PrivateKeys,
                ..
            } => DetectionAction::Evict,
            AttackType::DataLeaker {
                target: LeakTarget::CustomerPII,
                ..
            } => DetectionAction::Evict,
            AttackType::ResultManipulator { .. } => {
                DetectionAction::Slash {
                    amount: 25_000, // 25% of stake
                }
            }
            AttackType::CrashNode { .. } => {
                DetectionAction::Jail { duration: 3600 } // 1 hour
            }
            _ => {
                DetectionAction::Slash {
                    amount: 10_000, // 10% of stake
                }
            }
        }
    }

    /// Get all active threats
    pub fn get_active_threats(&self) -> Vec<&MaliciousNode> {
        self.nodes
            .values()
            .filter(|n| n.status == NodeStatus::Active)
            .collect()
    }

    /// Get detection summary
    pub fn get_detection_summary(&self) -> Vec<DetectionSummary> {
        self.nodes
            .values()
            .flat_map(|n| {
                n.detections.iter().map(move |d| DetectionSummary {
                    node_name: n.name.clone(),
                    method: d.method.clone(),
                    confidence: d.confidence,
                    action: d.action.clone(),
                })
            })
            .collect()
    }

    /// Generate war room report
    pub fn generate_report(&self) -> String {
        let active_threats = self.get_active_threats();
        let detections = self.get_detection_summary();

        let mut report = format!(
            r#"
╔═══════════════════════════════════════════════════════════════════════════════╗
║                        🟠 ADVERSARIAL WAR ROOM                                ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║  INJECT MALICIOUS NODES                                                       ║
║  ┌─────────────────────────────────────────────────────────────────────────┐ ║
║  │  [🦥 Lazy Prover]  [📤 Data Leaker]  [🔀 Result Manipulator]           │ ║
║  │  [💥 Crash Node]   [⏩ Front-Runner]  [🕵️ Eclipse Attack]              │ ║
║  └─────────────────────────────────────────────────────────────────────────┘ ║
║                                                                               ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║  ACTIVE THREATS: {}                                                           ║
╠═══════════════════════════════════════════════════════════════════════════════╣
"#,
            active_threats.len()
        );

        if active_threats.is_empty() {
            report.push_str(
                "║  No active threats. Inject a malicious node to begin simulation.          ║\n",
            );
        } else {
            for node in &active_threats {
                let attack_desc = self.describe_attack(&node.attack);
                report.push_str(&format!(
                    "║  {:20} {:15} {}\n",
                    node.name,
                    node.id[..15].to_string(),
                    attack_desc
                ));
            }
        }

        report.push_str(
            r#"║                                                                               ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║  DETECTION STATUS                                                             ║
╠═══════════════════════════════════════════════════════════════════════════════╣
"#,
        );

        if detections.is_empty() {
            report.push_str("║  No detections yet.                                                          ║\n");
        } else {
            for detection in &detections {
                let icon = match &detection.action {
                    DetectionAction::Evict => "🚫",
                    DetectionAction::Slash { .. } => "⚡",
                    DetectionAction::Jail { .. } => "🔒",
                    DetectionAction::Quarantine => "🔶",
                    DetectionAction::Alert => "⚠️",
                };
                report.push_str(&format!(
                    "║  {} {:20} {:?} ({}% confidence)\n",
                    icon, detection.node_name, detection.method, detection.confidence
                ));
            }
        }

        report.push_str(&format!(
            r#"║                                                                               ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║  STATISTICS                                                                   ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║  Total Attacks:     {}                                                        ║
║  Detected:          {} ({:.1}%)                                               ║
║  Succeeded:         {} ({:.1}%)                                               ║
║  Stake Slashed:     {} tokens                                                 ║
║  Nodes Evicted:     {}                                                        ║
║                                                                               ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║  DEFENSE CONFIGURATION                                                        ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║  {} Proof Verification        {} Statistical Detection                       ║
║  {} Cross-Validation          {} TEE Attestation                             ║
║  {} Network Monitoring        {} Slashing ({}%)                              ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"#,
            self.stats.total_attacks,
            self.stats.attacks_detected,
            if self.stats.total_attacks > 0 {
                self.stats.attacks_detected as f64 / self.stats.total_attacks as f64 * 100.0
            } else {
                0.0
            },
            self.stats.attacks_succeeded,
            if self.stats.total_attacks > 0 {
                self.stats.attacks_succeeded as f64 / self.stats.total_attacks as f64 * 100.0
            } else {
                0.0
            },
            self.stats.stake_slashed,
            self.stats.nodes_evicted,
            if self.defenses.proof_verification {
                "✅"
            } else {
                "❌"
            },
            if self.defenses.statistical_detection {
                "✅"
            } else {
                "❌"
            },
            if self.defenses.cross_validation {
                "✅"
            } else {
                "❌"
            },
            if self.defenses.tee_attestation {
                "✅"
            } else {
                "❌"
            },
            if self.defenses.network_monitoring {
                "✅"
            } else {
                "❌"
            },
            if self.defenses.slashing_enabled {
                "✅"
            } else {
                "❌"
            },
            self.defenses.slashing_percentage,
        ));

        report
    }

    fn describe_attack(&self, attack: &AttackType) -> &'static str {
        match attack {
            AttackType::LazyProver { .. } => "Submitting fake proofs",
            AttackType::DataLeaker { .. } => "Attempting exfiltration",
            AttackType::ResultManipulator { .. } => "Manipulating results",
            AttackType::CrashNode { .. } => "Strategic crashes",
            AttackType::FrontRunner { .. } => "Transaction reordering",
            AttackType::EclipseAttack { .. } => "Network isolation",
            AttackType::SpamAttack { .. } => "Spamming network",
            AttackType::LongRangeAttack { .. } => "Consensus attack",
            AttackType::GrindingAttack { .. } => "Randomness grinding",
        }
    }

    /// Configure defenses
    pub fn configure_defenses(&mut self, config: DefenseConfiguration) {
        self.defenses = config;
    }

    /// Disable a defense for testing
    pub fn disable_defense(&mut self, defense: &str) {
        match defense {
            "proof_verification" => self.defenses.proof_verification = false,
            "statistical_detection" => self.defenses.statistical_detection = false,
            "cross_validation" => self.defenses.cross_validation = false,
            "tee_attestation" => self.defenses.tee_attestation = false,
            "network_monitoring" => self.defenses.network_monitoring = false,
            "slashing" => self.defenses.slashing_enabled = false,
            _ => {}
        }
    }
}

impl Default for AdversarialWarRoom {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Result Types
// ============================================================================

#[derive(Debug, Clone)]
pub struct AttackResult {
    pub success: bool,
    pub detected: bool,
    pub detection_method: Option<DetectionMethod>,
    pub action_taken: Option<DetectionAction>,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct DetectionSummary {
    pub node_name: String,
    pub method: DetectionMethod,
    pub confidence: u8,
    pub action: DetectionAction,
}

#[derive(Debug, Clone)]
pub enum WarRoomError {
    NodeNotFound,
    NodeNotActive,
    InvalidAttack,
}

impl std::fmt::Display for WarRoomError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WarRoomError::NodeNotFound => write!(f, "Malicious node not found"),
            WarRoomError::NodeNotActive => write!(f, "Node is no longer active"),
            WarRoomError::InvalidAttack => write!(f, "Invalid attack configuration"),
        }
    }
}

impl std::error::Error for WarRoomError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inject_and_detect_lazy_prover() {
        let mut war_room = AdversarialWarRoom::new();

        let node_id = war_room.inject_node(AttackType::LazyProver {
            fake_proof_rate: 100,
        });

        let result = war_room.execute_attack(&node_id).unwrap();

        assert!(result.detected);
        assert!(!result.success);
        assert_eq!(
            result.detection_method,
            Some(DetectionMethod::ProofVerification)
        );
    }

    #[test]
    fn test_data_leaker_eviction() {
        let mut war_room = AdversarialWarRoom::new();

        let node_id = war_room.inject_node(AttackType::DataLeaker {
            target: LeakTarget::PrivateKeys,
            method: ExfiltrationMethod::MemoryDump,
        });

        let result = war_room.execute_attack(&node_id).unwrap();

        assert!(result.detected);
        assert_eq!(result.action_taken, Some(DetectionAction::Evict));
    }

    #[test]
    fn test_defense_disabling() {
        let mut war_room = AdversarialWarRoom::new();
        war_room.disable_defense("proof_verification");

        let node_id = war_room.inject_node(AttackType::LazyProver {
            fake_proof_rate: 100,
        });

        let result = war_room.execute_attack(&node_id).unwrap();

        // With proof verification disabled, attack should succeed
        assert!(result.success);
        assert!(!result.detected);
    }
}
