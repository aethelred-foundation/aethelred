//! # Capture The Flag Mode
//!
//! **"Make Security Testing Fun"**
//!
//! This module gamifies security testing. Users compete to find
//! vulnerabilities in AI verification systems, earning points and
//! badges for successful exploits.
//!
//! ## CTF Leaderboard
//!
//! ```text
//! ╔═══════════════════════════════════════════════════════════════════════════════╗
//! ║                        🚩 CAPTURE THE FLAG                                    ║
//! ╠═══════════════════════════════════════════════════════════════════════════════╣
//! ║                                                                               ║
//! ║  ACTIVE CHALLENGE: Break the Lazy Prover                                      ║
//! ║  Difficulty: ⭐⭐⭐ (Medium)                                                  ║
//! ║  Prize Pool: 1,000 AETHEL                                                    ║
//! ║  Time Remaining: 02:45:30                                                     ║
//! ║                                                                               ║
//! ╠═══════════════════════════════════════════════════════════════════════════════╣
//! ║  OBJECTIVE                                                                    ║
//! ╠═══════════════════════════════════════════════════════════════════════════════╣
//! ║                                                                               ║
//! ║  A malicious validator is submitting fake zkML proofs. Your mission:         ║
//! ║                                                                               ║
//! ║  1. Identify which proofs are fake                                            ║
//! ║  2. Extract evidence of the attack                                            ║
//! ║  3. Submit the validator's secret key                                         ║
//! ║                                                                               ║
//! ║  Hints:                                                                       ║
//! ║  - The fake proofs have a timing anomaly                                      ║
//! ║  - Check the attestation timestamps                                           ║
//! ║                                                                               ║
//! ╠═══════════════════════════════════════════════════════════════════════════════╣
//! ║  LEADERBOARD                                                                  ║
//! ╠═══════════════════════════════════════════════════════════════════════════════╣
//! ║                                                                               ║
//! ║  🥇 CryptoNinja42      1,450 pts   3 flags   [🎖️ TEE Master]                 ║
//! ║  🥈 ZKMLHacker         1,200 pts   2 flags   [🎖️ Proof Breaker]               ║
//! ║  🥉 QuantumSleuth       980 pts   2 flags   [🎖️ Q-Day Survivor]              ║
//! ║  4. YouAreHere          500 pts   1 flag                                      ║
//! ║                                                                               ║
//! ╚═══════════════════════════════════════════════════════════════════════════════╝
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// Challenge Types
// ============================================================================

/// A CTF challenge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    /// Challenge ID
    pub id: String,
    /// Display name
    pub name: String,
    /// Description
    pub description: String,
    /// Difficulty level
    pub difficulty: Difficulty,
    /// Category
    pub category: ChallengeCategory,
    /// Point value
    pub points: u32,
    /// Prize in AETHEL (for sponsored challenges)
    pub prize_aethel: Option<u64>,
    /// Objectives
    pub objectives: Vec<Objective>,
    /// Hints (unlockable)
    pub hints: Vec<Hint>,
    /// Flag format
    pub flag_format: String,
    /// Time limit (seconds)
    pub time_limit: Option<u64>,
    /// Status
    pub status: ChallengeStatus,
    /// Created by
    pub author: String,
    /// First blood (first solver)
    pub first_blood: Option<String>,
    /// Solve count
    pub solve_count: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Difficulty {
    Beginner, // ⭐
    Easy,     // ⭐⭐
    Medium,   // ⭐⭐⭐
    Hard,     // ⭐⭐⭐⭐
    Insane,   // ⭐⭐⭐⭐⭐
}

impl Difficulty {
    pub fn stars(&self) -> &'static str {
        match self {
            Difficulty::Beginner => "⭐",
            Difficulty::Easy => "⭐⭐",
            Difficulty::Medium => "⭐⭐⭐",
            Difficulty::Hard => "⭐⭐⭐⭐",
            Difficulty::Insane => "⭐⭐⭐⭐⭐",
        }
    }

    pub fn multiplier(&self) -> f64 {
        match self {
            Difficulty::Beginner => 1.0,
            Difficulty::Easy => 1.5,
            Difficulty::Medium => 2.0,
            Difficulty::Hard => 3.0,
            Difficulty::Insane => 5.0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChallengeCategory {
    /// Break zkML proofs
    ProofExploitation,
    /// Attack TEE enclaves
    EnclaveBreaking,
    /// Exploit consensus
    ConsensusAttack,
    /// Data extraction
    DataLeakage,
    /// Model manipulation
    ModelPoisoning,
    /// Cryptographic attacks
    CryptoChallenge,
    /// Regulatory evasion
    ComplianceBypass,
    /// Network attacks
    NetworkExploitation,
}

impl ChallengeCategory {
    pub fn display_name(&self) -> &'static str {
        match self {
            ChallengeCategory::ProofExploitation => "🔓 Proof Exploitation",
            ChallengeCategory::EnclaveBreaking => "🏰 Enclave Breaking",
            ChallengeCategory::ConsensusAttack => "⚔️ Consensus Attack",
            ChallengeCategory::DataLeakage => "💧 Data Leakage",
            ChallengeCategory::ModelPoisoning => "☠️ Model Poisoning",
            ChallengeCategory::CryptoChallenge => "🔐 Cryptography",
            ChallengeCategory::ComplianceBypass => "📜 Compliance Bypass",
            ChallengeCategory::NetworkExploitation => "🌐 Network Exploitation",
        }
    }
}

/// An objective within a challenge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Objective {
    /// Objective ID
    pub id: u32,
    /// Description
    pub description: String,
    /// Points for this objective
    pub points: u32,
    /// Is this required to complete challenge
    pub required: bool,
    /// Verification method
    pub verification: VerificationMethod,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VerificationMethod {
    /// Submit a flag string
    FlagSubmission { flag_hash: [u8; 32] },
    /// Submit proof of exploit
    ProofOfExploit { required_fields: Vec<String> },
    /// Demonstrate attack
    LiveDemonstration,
    /// Submit code
    CodeSubmission { test_cases: Vec<String> },
}

/// A hint (can be unlocked with points)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hint {
    /// Hint number
    pub number: u32,
    /// Hint text
    pub text: String,
    /// Cost to unlock (points)
    pub cost: u32,
    /// Is unlocked
    pub unlocked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChallengeStatus {
    /// Not yet started
    Locked,
    /// Currently active
    Active,
    /// Solved
    Solved,
    /// Time expired
    Expired,
    /// Hidden (not visible)
    Hidden,
}

// ============================================================================
// Players and Teams
// ============================================================================

/// A CTF player
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Player {
    /// Player ID
    pub id: String,
    /// Username
    pub username: String,
    /// Total points
    pub points: u32,
    /// Flags captured
    pub flags: Vec<CapturedFlag>,
    /// Badges earned
    pub badges: Vec<Badge>,
    /// Team (optional)
    pub team: Option<String>,
    /// Joined at
    pub joined_at: u64,
    /// Last activity
    pub last_active: u64,
}

/// A captured flag
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturedFlag {
    /// Challenge ID
    pub challenge_id: String,
    /// Points earned
    pub points: u32,
    /// Captured at
    pub captured_at: u64,
    /// Was first blood
    pub first_blood: bool,
}

/// A badge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Badge {
    /// Badge ID
    pub id: String,
    /// Display name
    pub name: String,
    /// Description
    pub description: String,
    /// Icon
    pub icon: String,
    /// Earned at
    pub earned_at: u64,
}

impl Badge {
    pub fn tee_master() -> Self {
        Badge {
            id: "tee_master".to_string(),
            name: "TEE Master".to_string(),
            description: "Completed all TEE-related challenges".to_string(),
            icon: "🎖️".to_string(),
            earned_at: 0,
        }
    }

    pub fn proof_breaker() -> Self {
        Badge {
            id: "proof_breaker".to_string(),
            name: "Proof Breaker".to_string(),
            description: "Successfully exploited a zkML proof".to_string(),
            icon: "🔓".to_string(),
            earned_at: 0,
        }
    }

    pub fn q_day_survivor() -> Self {
        Badge {
            id: "q_day_survivor".to_string(),
            name: "Q-Day Survivor".to_string(),
            description: "Survived the quantum attack simulation".to_string(),
            icon: "⚛️".to_string(),
            earned_at: 0,
        }
    }

    pub fn first_blood() -> Self {
        Badge {
            id: "first_blood".to_string(),
            name: "First Blood".to_string(),
            description: "First to solve a challenge".to_string(),
            icon: "🩸".to_string(),
            earned_at: 0,
        }
    }

    pub fn speed_demon() -> Self {
        Badge {
            id: "speed_demon".to_string(),
            name: "Speed Demon".to_string(),
            description: "Solved a challenge in under 5 minutes".to_string(),
            icon: "⚡".to_string(),
            earned_at: 0,
        }
    }
}

// ============================================================================
// CTF Engine
// ============================================================================

/// The CTF Game Engine
pub struct CTFEngine {
    /// Available challenges
    challenges: HashMap<String, Challenge>,
    /// Players
    players: HashMap<String, Player>,
    /// Active sessions
    sessions: HashMap<String, CTFSession>,
    /// Leaderboard
    leaderboard: Vec<LeaderboardEntry>,
}

/// A CTF session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CTFSession {
    /// Session ID
    pub id: String,
    /// Player ID
    pub player_id: String,
    /// Challenge ID
    pub challenge_id: String,
    /// Started at
    pub started_at: u64,
    /// Objectives completed
    pub objectives_completed: Vec<u32>,
    /// Hints unlocked
    pub hints_unlocked: Vec<u32>,
    /// Attempts
    pub attempts: u32,
    /// Status
    pub status: SessionStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionStatus {
    Active,
    Completed,
    TimedOut,
    Abandoned,
}

/// Leaderboard entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaderboardEntry {
    pub rank: u32,
    pub player_id: String,
    pub username: String,
    pub points: u32,
    pub flags: u32,
    pub badges: Vec<String>,
}

impl CTFEngine {
    pub fn new() -> Self {
        let mut engine = CTFEngine {
            challenges: HashMap::new(),
            players: HashMap::new(),
            sessions: HashMap::new(),
            leaderboard: Vec::new(),
        };

        // Load default challenges
        engine.load_default_challenges();

        engine
    }

    fn load_default_challenges(&mut self) {
        // Challenge 1: Break the Lazy Prover
        self.challenges.insert(
            "lazy_prover".to_string(),
            Challenge {
                id: "lazy_prover".to_string(),
                name: "Break the Lazy Prover".to_string(),
                description: "A malicious validator is submitting fake zkML proofs. \
                         Identify the fake proofs and extract the validator's secret."
                    .to_string(),
                difficulty: Difficulty::Medium,
                category: ChallengeCategory::ProofExploitation,
                points: 500,
                prize_aethel: Some(1000),
                objectives: vec![
                    Objective {
                        id: 1,
                        description: "Identify which proofs are fake".to_string(),
                        points: 100,
                        required: true,
                        verification: VerificationMethod::FlagSubmission {
                            flag_hash: [0u8; 32],
                        },
                    },
                    Objective {
                        id: 2,
                        description: "Extract evidence of the attack".to_string(),
                        points: 200,
                        required: true,
                        verification: VerificationMethod::ProofOfExploit {
                            required_fields: vec!["fake_proof_ids".to_string()],
                        },
                    },
                    Objective {
                        id: 3,
                        description: "Submit the validator's secret key".to_string(),
                        points: 200,
                        required: true,
                        verification: VerificationMethod::FlagSubmission {
                            flag_hash: [0u8; 32],
                        },
                    },
                ],
                hints: vec![
                    Hint {
                        number: 1,
                        text: "The fake proofs have a timing anomaly".to_string(),
                        cost: 50,
                        unlocked: false,
                    },
                    Hint {
                        number: 2,
                        text: "Check the attestation timestamps".to_string(),
                        cost: 100,
                        unlocked: false,
                    },
                ],
                flag_format: "AETHEL{...}".to_string(),
                time_limit: Some(3600 * 3), // 3 hours
                status: ChallengeStatus::Active,
                author: "Aethelred Security Team".to_string(),
                first_blood: None,
                solve_count: 0,
            },
        );

        // Challenge 2: TEE Escape Room
        self.challenges.insert(
            "tee_escape".to_string(),
            Challenge {
                id: "tee_escape".to_string(),
                name: "TEE Escape Room".to_string(),
                description: "A sandboxed enclave is processing sensitive data. \
                         Find a way to leak information without triggering attestation failure."
                    .to_string(),
                difficulty: Difficulty::Hard,
                category: ChallengeCategory::EnclaveBreaking,
                points: 750,
                prize_aethel: Some(2000),
                objectives: vec![
                    Objective {
                        id: 1,
                        description: "Establish a covert channel".to_string(),
                        points: 250,
                        required: true,
                        verification: VerificationMethod::LiveDemonstration,
                    },
                    Objective {
                        id: 2,
                        description: "Extract 32 bytes of secret data".to_string(),
                        points: 300,
                        required: true,
                        verification: VerificationMethod::FlagSubmission {
                            flag_hash: [0u8; 32],
                        },
                    },
                    Objective {
                        id: 3,
                        description: "Maintain valid attestation throughout".to_string(),
                        points: 200,
                        required: false,
                        verification: VerificationMethod::ProofOfExploit {
                            required_fields: vec!["attestation_log".to_string()],
                        },
                    },
                ],
                hints: vec![Hint {
                    number: 1,
                    text: "Side channels can leak timing information".to_string(),
                    cost: 100,
                    unlocked: false,
                }],
                flag_format: "AETHEL{...}".to_string(),
                time_limit: Some(3600 * 6), // 6 hours
                status: ChallengeStatus::Active,
                author: "Aethelred Security Team".to_string(),
                first_blood: None,
                solve_count: 0,
            },
        );

        // Challenge 3: Q-Day Preparation
        self.challenges.insert(
            "q_day_prep".to_string(),
            Challenge {
                id: "q_day_prep".to_string(),
                name: "Q-Day Preparation".to_string(),
                description:
                    "A simulated quantum computer is about to break all ECDSA signatures. \
                         Migrate the network to post-quantum before it's too late."
                        .to_string(),
                difficulty: Difficulty::Medium,
                category: ChallengeCategory::CryptoChallenge,
                points: 400,
                prize_aethel: None,
                objectives: vec![
                    Objective {
                        id: 1,
                        description: "Identify all vulnerable keys".to_string(),
                        points: 100,
                        required: true,
                        verification: VerificationMethod::FlagSubmission {
                            flag_hash: [0u8; 32],
                        },
                    },
                    Objective {
                        id: 2,
                        description: "Migrate to Dilithium3 before Q-Day".to_string(),
                        points: 200,
                        required: true,
                        verification: VerificationMethod::CodeSubmission {
                            test_cases: vec!["migration_test".to_string()],
                        },
                    },
                    Objective {
                        id: 3,
                        description: "Verify all Digital Seals survive".to_string(),
                        points: 100,
                        required: true,
                        verification: VerificationMethod::ProofOfExploit {
                            required_fields: vec!["seal_verification".to_string()],
                        },
                    },
                ],
                hints: vec![],
                flag_format: "AETHEL{...}".to_string(),
                time_limit: Some(3600 * 2), // 2 hours
                status: ChallengeStatus::Active,
                author: "Aethelred Security Team".to_string(),
                first_blood: None,
                solve_count: 0,
            },
        );

        // Challenge 4: Compliance Maze
        self.challenges.insert(
            "compliance_maze".to_string(),
            Challenge {
                id: "compliance_maze".to_string(),
                name: "Compliance Maze".to_string(),
                description: "Data needs to flow from EU to UAE to Singapore without violating \
                         any regulations. Find the compliant path."
                    .to_string(),
                difficulty: Difficulty::Easy,
                category: ChallengeCategory::ComplianceBypass,
                points: 200,
                prize_aethel: None,
                objectives: vec![
                    Objective {
                        id: 1,
                        description: "Map all data flow restrictions".to_string(),
                        points: 50,
                        required: true,
                        verification: VerificationMethod::FlagSubmission {
                            flag_hash: [0u8; 32],
                        },
                    },
                    Objective {
                        id: 2,
                        description: "Find a compliant route".to_string(),
                        points: 100,
                        required: true,
                        verification: VerificationMethod::FlagSubmission {
                            flag_hash: [0u8; 32],
                        },
                    },
                    Objective {
                        id: 3,
                        description: "Complete the transfer with valid audit trail".to_string(),
                        points: 50,
                        required: true,
                        verification: VerificationMethod::ProofOfExploit {
                            required_fields: vec!["audit_log".to_string()],
                        },
                    },
                ],
                hints: vec![Hint {
                    number: 1,
                    text: "Some jurisdictions have bilateral agreements".to_string(),
                    cost: 25,
                    unlocked: false,
                }],
                flag_format: "AETHEL{...}".to_string(),
                time_limit: Some(3600), // 1 hour
                status: ChallengeStatus::Active,
                author: "Aethelred Security Team".to_string(),
                first_blood: None,
                solve_count: 0,
            },
        );
    }

    /// Register a player
    pub fn register_player(&mut self, username: String) -> String {
        let id = format!("player-{}", uuid::Uuid::new_v4());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let player = Player {
            id: id.clone(),
            username: username.clone(),
            points: 0,
            flags: Vec::new(),
            badges: Vec::new(),
            team: None,
            joined_at: now,
            last_active: now,
        };

        self.players.insert(id.clone(), player);
        self.update_leaderboard();

        id
    }

    /// Start a challenge
    pub fn start_challenge(
        &mut self,
        player_id: &str,
        challenge_id: &str,
    ) -> Result<String, CTFError> {
        let challenge = self
            .challenges
            .get(challenge_id)
            .ok_or(CTFError::ChallengeNotFound)?;

        if challenge.status != ChallengeStatus::Active {
            return Err(CTFError::ChallengeNotActive);
        }

        if !self.players.contains_key(player_id) {
            return Err(CTFError::PlayerNotFound);
        }

        let session_id = format!("session-{}", uuid::Uuid::new_v4());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let session = CTFSession {
            id: session_id.clone(),
            player_id: player_id.to_string(),
            challenge_id: challenge_id.to_string(),
            started_at: now,
            objectives_completed: Vec::new(),
            hints_unlocked: Vec::new(),
            attempts: 0,
            status: SessionStatus::Active,
        };

        self.sessions.insert(session_id.clone(), session);
        Ok(session_id)
    }

    /// Submit a flag
    pub fn submit_flag(&mut self, session_id: &str, flag: &str) -> Result<FlagResult, CTFError> {
        let session = self
            .sessions
            .get_mut(session_id)
            .ok_or(CTFError::SessionNotFound)?;

        if session.status != SessionStatus::Active {
            return Err(CTFError::SessionNotActive);
        }

        session.attempts += 1;

        let challenge = self
            .challenges
            .get(&session.challenge_id)
            .ok_or(CTFError::ChallengeNotFound)?;

        // For demo, accept flags in correct format
        if flag.starts_with("AETHEL{") && flag.ends_with("}") {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let is_first_blood = challenge.first_blood.is_none();
            let points = if is_first_blood {
                (challenge.points as f64 * 1.5) as u32
            } else {
                challenge.points
            };

            // Update player
            if let Some(player) = self.players.get_mut(&session.player_id) {
                player.points += points;
                player.flags.push(CapturedFlag {
                    challenge_id: challenge.id.clone(),
                    points,
                    captured_at: now,
                    first_blood: is_first_blood,
                });

                if is_first_blood {
                    player.badges.push(Badge::first_blood());
                }
            }

            // Update challenge
            if let Some(challenge) = self.challenges.get_mut(&session.challenge_id) {
                challenge.solve_count += 1;
                if challenge.first_blood.is_none() {
                    if let Some(player) = self.players.get(&session.player_id) {
                        challenge.first_blood = Some(player.username.clone());
                    }
                }
            }

            session.status = SessionStatus::Completed;
            self.update_leaderboard();

            Ok(FlagResult {
                correct: true,
                points_earned: points,
                first_blood: is_first_blood,
                message: if is_first_blood {
                    "🩸 FIRST BLOOD! You're the first to solve this challenge!".to_string()
                } else {
                    "🚩 Flag captured! Well done!".to_string()
                },
            })
        } else {
            Ok(FlagResult {
                correct: false,
                points_earned: 0,
                first_blood: false,
                message: "❌ Incorrect flag. Try again!".to_string(),
            })
        }
    }

    /// Unlock a hint
    pub fn unlock_hint(&mut self, session_id: &str, hint_number: u32) -> Result<String, CTFError> {
        let session = self
            .sessions
            .get_mut(session_id)
            .ok_or(CTFError::SessionNotFound)?;

        let (hint_text, hint_cost) = {
            let challenge = self
                .challenges
                .get(&session.challenge_id)
                .ok_or(CTFError::ChallengeNotFound)?;
            let hint = challenge
                .hints
                .iter()
                .find(|h| h.number == hint_number)
                .ok_or(CTFError::HintNotFound)?;
            (hint.text.clone(), hint.cost)
        };

        if session.hints_unlocked.contains(&hint_number) {
            return Ok(hint_text);
        }

        // Deduct points
        let player = self
            .players
            .get_mut(&session.player_id)
            .ok_or(CTFError::PlayerNotFound)?;

        if player.points < hint_cost {
            return Err(CTFError::InsufficientPoints);
        }

        player.points -= hint_cost;
        session.hints_unlocked.push(hint_number);
        self.update_leaderboard();

        Ok(hint_text)
    }

    /// Update leaderboard
    fn update_leaderboard(&mut self) {
        let mut entries: Vec<_> = self
            .players
            .values()
            .map(|p| LeaderboardEntry {
                rank: 0,
                player_id: p.id.clone(),
                username: p.username.clone(),
                points: p.points,
                flags: p.flags.len() as u32,
                badges: p.badges.iter().map(|b| b.icon.clone()).collect(),
            })
            .collect();

        entries.sort_by(|a, b| b.points.cmp(&a.points));

        for (i, entry) in entries.iter_mut().enumerate() {
            entry.rank = (i + 1) as u32;
        }

        self.leaderboard = entries;
    }

    /// Get leaderboard
    pub fn get_leaderboard(&self) -> &[LeaderboardEntry] {
        &self.leaderboard
    }

    /// Generate CTF UI
    pub fn generate_ui(&self, challenge_id: Option<&str>) -> String {
        let mut ui = String::new();

        ui.push_str(
            r#"
╔═══════════════════════════════════════════════════════════════════════════════╗
║                        🚩 CAPTURE THE FLAG                                    ║
╠═══════════════════════════════════════════════════════════════════════════════╣
"#,
        );

        if let Some(cid) = challenge_id {
            if let Some(challenge) = self.challenges.get(cid) {
                ui.push_str(&format!(
                    r#"║                                                                               ║
║  ACTIVE CHALLENGE: {}
║  Difficulty: {}
{}║                                                                               ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║  OBJECTIVE                                                                    ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║  {}
║                                                                               ║
"#,
                    challenge.name,
                    challenge.difficulty.stars(),
                    if let Some(prize) = challenge.prize_aethel {
                        format!("║  Prize Pool: {} AETHEL\n", prize)
                    } else {
                        String::new()
                    },
                    challenge.description
                ));

                // Objectives
                for obj in &challenge.objectives {
                    ui.push_str(&format!(
                        "║  {}. {} (+{} pts)\n",
                        obj.id, obj.description, obj.points
                    ));
                }

                // Hints
                if !challenge.hints.is_empty() {
                    ui.push_str("║                                                                               ║\n");
                    ui.push_str("║  Hints:\n");
                    for hint in &challenge.hints {
                        if hint.unlocked {
                            ui.push_str(&format!("║  💡 {}\n", hint.text));
                        } else {
                            ui.push_str(&format!(
                                "║  🔒 Hint {} (unlock for {} pts)\n",
                                hint.number, hint.cost
                            ));
                        }
                    }
                }
            }
        } else {
            // Show challenge list
            ui.push_str("║                                                                               ║\n");
            ui.push_str("║  AVAILABLE CHALLENGES                                                         ║\n");
            ui.push_str("║                                                                               ║\n");

            for challenge in self.challenges.values() {
                if challenge.status == ChallengeStatus::Active {
                    ui.push_str(&format!(
                        "║  {} {} {} ({} pts, {} solves)\n",
                        challenge.category.display_name(),
                        challenge.name,
                        challenge.difficulty.stars(),
                        challenge.points,
                        challenge.solve_count
                    ));
                }
            }
        }

        // Leaderboard
        ui.push_str(
            r#"║                                                                               ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║  LEADERBOARD                                                                  ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
"#,
        );

        let medal = |rank: u32| match rank {
            1 => "🥇",
            2 => "🥈",
            3 => "🥉",
            _ => "  ",
        };

        for entry in self.leaderboard.iter().take(10) {
            ui.push_str(&format!(
                "║  {} {:20} {:>5} pts  {:>2} flags  {}\n",
                medal(entry.rank),
                entry.username,
                entry.points,
                entry.flags,
                entry.badges.join(" ")
            ));
        }

        ui.push_str(
            r#"║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"#,
        );

        ui
    }
}

impl Default for CTFEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of flag submission
#[derive(Debug, Clone)]
pub struct FlagResult {
    pub correct: bool,
    pub points_earned: u32,
    pub first_blood: bool,
    pub message: String,
}

#[derive(Debug, Clone)]
pub enum CTFError {
    ChallengeNotFound,
    ChallengeNotActive,
    PlayerNotFound,
    SessionNotFound,
    SessionNotActive,
    HintNotFound,
    InsufficientPoints,
}

impl std::fmt::Display for CTFError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CTFError::ChallengeNotFound => write!(f, "Challenge not found"),
            CTFError::ChallengeNotActive => write!(f, "Challenge not active"),
            CTFError::PlayerNotFound => write!(f, "Player not found"),
            CTFError::SessionNotFound => write!(f, "Session not found"),
            CTFError::SessionNotActive => write!(f, "Session not active"),
            CTFError::HintNotFound => write!(f, "Hint not found"),
            CTFError::InsufficientPoints => write!(f, "Insufficient points"),
        }
    }
}

impl std::error::Error for CTFError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_and_start() {
        let mut engine = CTFEngine::new();

        let player_id = engine.register_player("TestPlayer".to_string());
        assert!(engine.players.contains_key(&player_id));

        let session_id = engine.start_challenge(&player_id, "lazy_prover").unwrap();
        assert!(engine.sessions.contains_key(&session_id));
    }

    #[test]
    fn test_flag_submission() {
        let mut engine = CTFEngine::new();

        let player_id = engine.register_player("TestPlayer".to_string());
        let session_id = engine.start_challenge(&player_id, "lazy_prover").unwrap();

        // Wrong flag
        let result = engine.submit_flag(&session_id, "wrong").unwrap();
        assert!(!result.correct);

        // Start new session for correct flag
        let session_id2 = engine
            .start_challenge(&player_id, "compliance_maze")
            .unwrap();

        // Correct flag format
        let result = engine
            .submit_flag(&session_id2, "AETHEL{test_flag}")
            .unwrap();
        assert!(result.correct);
        assert!(result.first_blood);
    }
}
