//! # Quantum Time-Machine
//!
//! **"The Q-Day Simulator"**
//!
//! This module lets users simulate the day quantum computers break
//! ECDSA and RSA. With a single button press, the sandbox:
//!
//! 1. Marks all ECDSA/RSA signatures as "BROKEN"
//! 2. Shows which assets are vulnerable
//! 3. Demonstrates that Dilithium3 signatures survive
//!
//! ## The Red Button Experience
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    🔴 QUANTUM TIME-MACHINE                      │
//! ├─────────────────────────────────────────────────────────────────┤
//! │                                                                 │
//! │  Press the button to simulate Q-Day: the day quantum computers │
//! │  can break ECDSA in seconds.                                   │
//! │                                                                 │
//! │                   ┌────────────────────┐                        │
//! │                   │                    │                        │
//! │                   │    🔴 BREAK IT     │                        │
//! │                   │                    │                        │
//! │                   └────────────────────┘                        │
//! │                                                                 │
//! │  Warning: This will show all vulnerable signatures as BROKEN   │
//! │                                                                 │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## After Q-Day
//!
//! ```text
//! ╔═══════════════════════════════════════════════════════════════════════════════╗
//! ║ ⚠️  Q-DAY SIMULATION ACTIVE                                                   ║
//! ╠═══════════════════════════════════════════════════════════════════════════════╣
//! ║                                                                               ║
//! ║  ALGORITHM STATUS:                                                            ║
//! ║  ┌─────────────────────────────────────────────────────────────────────────┐ ║
//! ║  │  ❌ ECDSA (secp256k1)    BROKEN - Shor's Algorithm                      │ ║
//! ║  │  ❌ RSA-2048             BROKEN - Shor's Algorithm                      │ ║
//! ║  │  ❌ Ed25519              BROKEN - Shor's Algorithm                      │ ║
//! ║  │  ✅ Dilithium3           SECURE - Lattice-based                         │ ║
//! ║  │  ✅ Falcon-512           SECURE - NTRU Lattices                         │ ║
//! ║  │  ✅ SPHINCS+             SECURE - Hash-based                            │ ║
//! ║  └─────────────────────────────────────────────────────────────────────────┘ ║
//! ║                                                                               ║
//! ║  IMPACT ASSESSMENT:                                                           ║
//! ║  • 847 signatures invalidated                                                 ║
//! ║  • $2.3B in assets at risk                                                    ║
//! ║  • 12 wallets compromised                                                     ║
//! ║                                                                               ║
//! ║  AETHELRED PROTECTION:                                                        ║
//! ║  • All Digital Seals remain valid (Dilithium3)                               ║
//! ║  • Hybrid signatures provide fallback                                         ║
//! ║  • Zero compromised transactions                                              ║
//! ║                                                                               ║
//! ╚═══════════════════════════════════════════════════════════════════════════════╝
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// Cryptographic Algorithms
// ============================================================================

/// Cryptographic algorithm classification
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CryptoAlgorithm {
    // Classical (Vulnerable to Quantum)
    ECDSA_P256,
    ECDSA_Secp256k1,
    RSA_2048,
    RSA_4096,
    Ed25519,
    X25519,

    // Post-Quantum (Lattice-based)
    Dilithium2,
    Dilithium3,
    Dilithium5,
    Kyber512,
    Kyber768,
    Kyber1024,

    // Post-Quantum (NTRU)
    Falcon512,
    Falcon1024,

    // Post-Quantum (Hash-based)
    SPHINCS_SHA256_128f,
    SPHINCS_SHA256_256f,

    // Hybrid
    Hybrid {
        classical: Box<CryptoAlgorithm>,
        post_quantum: Box<CryptoAlgorithm>,
    },
}

impl CryptoAlgorithm {
    /// Is this algorithm quantum-vulnerable?
    pub fn is_quantum_vulnerable(&self) -> bool {
        match self {
            CryptoAlgorithm::ECDSA_P256
            | CryptoAlgorithm::ECDSA_Secp256k1
            | CryptoAlgorithm::RSA_2048
            | CryptoAlgorithm::RSA_4096
            | CryptoAlgorithm::Ed25519
            | CryptoAlgorithm::X25519 => true,

            CryptoAlgorithm::Dilithium2
            | CryptoAlgorithm::Dilithium3
            | CryptoAlgorithm::Dilithium5
            | CryptoAlgorithm::Kyber512
            | CryptoAlgorithm::Kyber768
            | CryptoAlgorithm::Kyber1024
            | CryptoAlgorithm::Falcon512
            | CryptoAlgorithm::Falcon1024
            | CryptoAlgorithm::SPHINCS_SHA256_128f
            | CryptoAlgorithm::SPHINCS_SHA256_256f => false,

            CryptoAlgorithm::Hybrid {
                classical: _,
                post_quantum,
            } => {
                // Hybrid is only vulnerable if PQ component is also vulnerable
                post_quantum.is_quantum_vulnerable()
            }
        }
    }

    /// Get NIST security level (1-5)
    pub fn security_level(&self) -> u8 {
        match self {
            CryptoAlgorithm::ECDSA_P256 => 3,
            CryptoAlgorithm::ECDSA_Secp256k1 => 3,
            CryptoAlgorithm::RSA_2048 => 2,
            CryptoAlgorithm::RSA_4096 => 3,
            CryptoAlgorithm::Ed25519 => 3,
            CryptoAlgorithm::X25519 => 3,
            CryptoAlgorithm::Dilithium2 => 2,
            CryptoAlgorithm::Dilithium3 => 3,
            CryptoAlgorithm::Dilithium5 => 5,
            CryptoAlgorithm::Kyber512 => 1,
            CryptoAlgorithm::Kyber768 => 3,
            CryptoAlgorithm::Kyber1024 => 5,
            CryptoAlgorithm::Falcon512 => 1,
            CryptoAlgorithm::Falcon1024 => 5,
            CryptoAlgorithm::SPHINCS_SHA256_128f => 1,
            CryptoAlgorithm::SPHINCS_SHA256_256f => 5,
            CryptoAlgorithm::Hybrid { post_quantum, .. } => post_quantum.security_level(),
        }
    }

    /// Get algorithm category
    pub fn category(&self) -> AlgorithmCategory {
        match self {
            CryptoAlgorithm::ECDSA_P256 | CryptoAlgorithm::ECDSA_Secp256k1 => {
                AlgorithmCategory::EllipticCurve
            }

            CryptoAlgorithm::RSA_2048 | CryptoAlgorithm::RSA_4096 => AlgorithmCategory::RSA,

            CryptoAlgorithm::Ed25519 | CryptoAlgorithm::X25519 => AlgorithmCategory::Edwards,

            CryptoAlgorithm::Dilithium2
            | CryptoAlgorithm::Dilithium3
            | CryptoAlgorithm::Dilithium5
            | CryptoAlgorithm::Kyber512
            | CryptoAlgorithm::Kyber768
            | CryptoAlgorithm::Kyber1024 => AlgorithmCategory::Lattice,

            CryptoAlgorithm::Falcon512 | CryptoAlgorithm::Falcon1024 => AlgorithmCategory::NTRU,

            CryptoAlgorithm::SPHINCS_SHA256_128f | CryptoAlgorithm::SPHINCS_SHA256_256f => {
                AlgorithmCategory::HashBased
            }

            CryptoAlgorithm::Hybrid { .. } => AlgorithmCategory::Hybrid,
        }
    }

    /// Get attack vector if broken by quantum
    pub fn quantum_attack_vector(&self) -> Option<&'static str> {
        if self.is_quantum_vulnerable() {
            Some(match self {
                CryptoAlgorithm::RSA_2048 | CryptoAlgorithm::RSA_4096 => {
                    "Shor's Algorithm - Integer Factorization"
                }
                CryptoAlgorithm::ECDSA_P256
                | CryptoAlgorithm::ECDSA_Secp256k1
                | CryptoAlgorithm::Ed25519
                | CryptoAlgorithm::X25519 => "Shor's Algorithm - Discrete Logarithm Problem",
                _ => "Unknown",
            })
        } else {
            None
        }
    }

    /// Get display name
    pub fn display_name(&self) -> String {
        match self {
            CryptoAlgorithm::ECDSA_P256 => "ECDSA (P-256)".to_string(),
            CryptoAlgorithm::ECDSA_Secp256k1 => "ECDSA (secp256k1)".to_string(),
            CryptoAlgorithm::RSA_2048 => "RSA-2048".to_string(),
            CryptoAlgorithm::RSA_4096 => "RSA-4096".to_string(),
            CryptoAlgorithm::Ed25519 => "Ed25519".to_string(),
            CryptoAlgorithm::X25519 => "X25519".to_string(),
            CryptoAlgorithm::Dilithium2 => "CRYSTALS-Dilithium2".to_string(),
            CryptoAlgorithm::Dilithium3 => "CRYSTALS-Dilithium3".to_string(),
            CryptoAlgorithm::Dilithium5 => "CRYSTALS-Dilithium5".to_string(),
            CryptoAlgorithm::Kyber512 => "CRYSTALS-Kyber512".to_string(),
            CryptoAlgorithm::Kyber768 => "CRYSTALS-Kyber768".to_string(),
            CryptoAlgorithm::Kyber1024 => "CRYSTALS-Kyber1024".to_string(),
            CryptoAlgorithm::Falcon512 => "Falcon-512".to_string(),
            CryptoAlgorithm::Falcon1024 => "Falcon-1024".to_string(),
            CryptoAlgorithm::SPHINCS_SHA256_128f => "SPHINCS+-SHA256-128f".to_string(),
            CryptoAlgorithm::SPHINCS_SHA256_256f => "SPHINCS+-SHA256-256f".to_string(),
            CryptoAlgorithm::Hybrid {
                classical,
                post_quantum,
            } => {
                format!(
                    "{} + {}",
                    classical.display_name(),
                    post_quantum.display_name()
                )
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlgorithmCategory {
    RSA,
    EllipticCurve,
    Edwards,
    Lattice,
    NTRU,
    HashBased,
    Hybrid,
}

// ============================================================================
// Assets and Signatures
// ============================================================================

/// A cryptographic asset (key, signature, etc.)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoAsset {
    /// Asset ID
    pub id: String,
    /// Asset type
    pub asset_type: AssetType,
    /// Algorithm used
    pub algorithm: CryptoAlgorithm,
    /// Value protected (for reporting)
    pub protected_value: Option<ProtectedValue>,
    /// Creation timestamp
    pub created_at: u64,
    /// Owner
    pub owner: Option<String>,
    /// Status in current simulation
    pub status: AssetStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AssetType {
    PrivateKey,
    PublicKey,
    Signature,
    Certificate,
    DigitalSeal,
    WalletAddress,
    SmartContract,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectedValue {
    /// Currency
    pub currency: String,
    /// Amount in smallest unit
    pub amount: u64,
    /// Description
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AssetStatus {
    Secure,
    Vulnerable,
    Broken,
    Migrating,
}

// ============================================================================
// Quantum Time Machine
// ============================================================================

/// The Quantum Time Machine - simulates Q-Day
pub struct QuantumTimeMachine {
    /// Is Q-Day active?
    q_day_active: bool,
    /// Assets in simulation
    assets: HashMap<String, CryptoAsset>,
    /// Q-Day activation timestamp
    q_day_timestamp: Option<u64>,
    /// Simulation results
    results: Option<QDaySimulationResults>,
}

/// Results of Q-Day simulation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QDaySimulationResults {
    /// Total assets analyzed
    pub total_assets: usize,
    /// Assets broken
    pub broken_assets: usize,
    /// Assets secure
    pub secure_assets: usize,
    /// Value at risk
    pub value_at_risk: ValueAtRisk,
    /// Algorithm breakdown
    pub algorithm_breakdown: HashMap<String, AlgorithmStatus>,
    /// Time to break estimate
    pub time_to_break: HashMap<String, String>,
    /// Aethelred protection summary
    pub aethelred_protection: AethelredProtection,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValueAtRisk {
    /// Currency
    pub currency: String,
    /// Total vulnerable value
    pub vulnerable: u64,
    /// Total secure value
    pub secure: u64,
    /// Protection ratio
    pub protection_ratio: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlgorithmStatus {
    /// Algorithm name
    pub name: String,
    /// Count of assets using this algorithm
    pub count: usize,
    /// Status after Q-Day
    pub status: String,
    /// Is it vulnerable?
    pub vulnerable: bool,
    /// Attack vector
    pub attack_vector: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AethelredProtection {
    /// Digital Seals protected
    pub seals_protected: usize,
    /// Hybrid signatures working
    pub hybrid_signatures: usize,
    /// Migration capability
    pub can_migrate: bool,
    /// Recovery plan
    pub recovery_plan: Vec<String>,
}

impl QuantumTimeMachine {
    pub fn new() -> Self {
        QuantumTimeMachine {
            q_day_active: false,
            assets: HashMap::new(),
            q_day_timestamp: None,
            results: None,
        }
    }

    /// Register an asset for simulation
    pub fn register_asset(&mut self, asset: CryptoAsset) {
        let status = if self.q_day_active && asset.algorithm.is_quantum_vulnerable() {
            AssetStatus::Broken
        } else if asset.algorithm.is_quantum_vulnerable() {
            AssetStatus::Vulnerable
        } else {
            AssetStatus::Secure
        };

        let mut asset = asset;
        asset.status = status;
        self.assets.insert(asset.id.clone(), asset);
    }

    /// Press the red button - activate Q-Day
    pub fn activate_q_day(&mut self) -> QDaySimulationResults {
        self.q_day_active = true;
        self.q_day_timestamp = Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        );

        // Break all vulnerable assets
        for asset in self.assets.values_mut() {
            if asset.algorithm.is_quantum_vulnerable() {
                asset.status = AssetStatus::Broken;
            }
        }

        // Generate results
        let results = self.generate_results();
        self.results = Some(results.clone());
        results
    }

    /// Deactivate Q-Day
    pub fn deactivate_q_day(&mut self) {
        self.q_day_active = false;
        self.q_day_timestamp = None;
        self.results = None;

        // Reset asset statuses
        for asset in self.assets.values_mut() {
            asset.status = if asset.algorithm.is_quantum_vulnerable() {
                AssetStatus::Vulnerable
            } else {
                AssetStatus::Secure
            };
        }
    }

    /// Generate simulation results
    fn generate_results(&self) -> QDaySimulationResults {
        let mut broken_assets = 0;
        let mut secure_assets = 0;
        let mut vulnerable_value: u64 = 0;
        let mut secure_value: u64 = 0;
        let mut algorithm_counts: HashMap<String, (usize, bool)> = HashMap::new();
        let mut seals_protected = 0;
        let mut hybrid_count = 0;

        for asset in self.assets.values() {
            let algo_name = asset.algorithm.display_name();
            let is_vulnerable = asset.algorithm.is_quantum_vulnerable();

            let entry = algorithm_counts
                .entry(algo_name.clone())
                .or_insert((0, is_vulnerable));
            entry.0 += 1;

            if is_vulnerable {
                broken_assets += 1;
                if let Some(value) = &asset.protected_value {
                    vulnerable_value += value.amount;
                }
            } else {
                secure_assets += 1;
                if let Some(value) = &asset.protected_value {
                    secure_value += value.amount;
                }
                if matches!(asset.asset_type, AssetType::DigitalSeal) {
                    seals_protected += 1;
                }
            }

            if matches!(asset.algorithm, CryptoAlgorithm::Hybrid { .. }) {
                hybrid_count += 1;
            }
        }

        let total_value = vulnerable_value + secure_value;
        let protection_ratio = if total_value > 0 {
            secure_value as f64 / total_value as f64
        } else {
            1.0
        };

        let mut algorithm_breakdown = HashMap::new();
        for (name, (count, vulnerable)) in algorithm_counts {
            let algo = self.find_algorithm_by_name(&name);
            algorithm_breakdown.insert(
                name.clone(),
                AlgorithmStatus {
                    name: name.clone(),
                    count,
                    status: if vulnerable {
                        "BROKEN".to_string()
                    } else {
                        "SECURE".to_string()
                    },
                    vulnerable,
                    attack_vector: algo.and_then(|a| a.quantum_attack_vector().map(String::from)),
                },
            );
        }

        let mut time_to_break = HashMap::new();
        time_to_break.insert(
            "ECDSA (secp256k1)".to_string(),
            "~4 hours on 4000-qubit machine".to_string(),
        );
        time_to_break.insert(
            "RSA-2048".to_string(),
            "~8 hours on 4000-qubit machine".to_string(),
        );
        time_to_break.insert(
            "Ed25519".to_string(),
            "~4 hours on 4000-qubit machine".to_string(),
        );

        QDaySimulationResults {
            total_assets: self.assets.len(),
            broken_assets,
            secure_assets,
            value_at_risk: ValueAtRisk {
                currency: "USD".to_string(),
                vulnerable: vulnerable_value,
                secure: secure_value,
                protection_ratio,
            },
            algorithm_breakdown,
            time_to_break,
            aethelred_protection: AethelredProtection {
                seals_protected,
                hybrid_signatures: hybrid_count,
                can_migrate: true,
                recovery_plan: vec![
                    "All Aethelred Digital Seals use Dilithium3 (quantum-safe)".to_string(),
                    "Hybrid signatures provide immediate fallback".to_string(),
                    "Emergency key rotation to post-quantum algorithms".to_string(),
                    "Zero-downtime migration path via ABCI++".to_string(),
                ],
            },
        }
    }

    fn find_algorithm_by_name(&self, name: &str) -> Option<&CryptoAlgorithm> {
        self.assets
            .values()
            .find(|a| a.algorithm.display_name() == name)
            .map(|a| &a.algorithm)
    }

    /// Generate the Q-Day report
    pub fn generate_report(&self) -> String {
        if !self.q_day_active {
            return self.pre_qday_report();
        }

        let results = self
            .results
            .as_ref()
            .expect("Results should exist when Q-Day active");

        let mut report = format!(
            r#"
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║   ██████╗        ██████╗  █████╗ ██╗   ██╗                                   ║
║  ██╔═══██╗       ██╔══██╗██╔══██╗╚██╗ ██╔╝                                   ║
║  ██║   ██║ █████╗██║  ██║███████║ ╚████╔╝                                    ║
║  ██║▄▄ ██║ ╚════╝██║  ██║██╔══██║  ╚██╔╝                                     ║
║  ╚██████╔╝       ██████╔╝██║  ██║   ██║                                      ║
║   ╚══▀▀═╝        ╚═════╝ ╚═╝  ╚═╝   ╚═╝                                      ║
║                                                                               ║
║                    ⚠️  SIMULATION ACTIVE                                       ║
║                                                                               ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║  Quantum computers have achieved cryptographic relevance.                     ║
║  Shor's algorithm can now break ECDSA and RSA in hours.                      ║
║                                                                               ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║  ALGORITHM STATUS                                                             ║
╠═══════════════════════════════════════════════════════════════════════════════╣
"#
        );

        // Algorithm breakdown
        let mut sorted_algos: Vec<_> = results.algorithm_breakdown.values().collect();
        sorted_algos.sort_by(|a, b| b.vulnerable.cmp(&a.vulnerable));

        for algo in sorted_algos {
            let icon = if algo.vulnerable { "❌" } else { "✅" };
            let status = if algo.vulnerable { "BROKEN" } else { "SECURE" };
            let attack = algo.attack_vector.as_deref().unwrap_or("N/A");

            report.push_str(&format!(
                "║  {} {:30} {:8} ({})\n",
                icon, algo.name, status, attack
            ));
        }

        report.push_str(&format!(
            r#"║                                                                               ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║  IMPACT ASSESSMENT                                                            ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║  📊 ASSET ANALYSIS                                                            ║
║     Total Assets: {}                                                        ║
║     🔴 Broken:    {} ({:.1}%)                                                ║
║     🟢 Secure:    {} ({:.1}%)                                                ║
║                                                                               ║
║  💰 VALUE AT RISK                                                             ║
║     Vulnerable:  ${:>15}                                                    ║
║     Protected:   ${:>15}                                                    ║
║     Protection:  {:.1}%                                                      ║
║                                                                               ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║  🛡️  AETHELRED PROTECTION STATUS                                              ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║  ✅ Digital Seals Protected:     {}                                          ║
║  ✅ Hybrid Signatures Active:    {}                                          ║
║  ✅ Migration Capability:        {}                                      ║
║                                                                               ║
║  RECOVERY PLAN:                                                               ║
"#,
            results.total_assets,
            results.broken_assets,
            (results.broken_assets as f64 / results.total_assets.max(1) as f64) * 100.0,
            results.secure_assets,
            (results.secure_assets as f64 / results.total_assets.max(1) as f64) * 100.0,
            Self::format_currency(results.value_at_risk.vulnerable),
            Self::format_currency(results.value_at_risk.secure),
            results.value_at_risk.protection_ratio * 100.0,
            results.aethelred_protection.seals_protected,
            results.aethelred_protection.hybrid_signatures,
            if results.aethelred_protection.can_migrate {
                "READY"
            } else {
                "PENDING"
            },
        ));

        for (i, step) in results
            .aethelred_protection
            .recovery_plan
            .iter()
            .enumerate()
        {
            report.push_str(&format!("║  {}. {}\n", i + 1, step));
        }

        report.push_str(
            r#"║                                                                               ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║  TIME TO BREAK (estimated)                                                    ║
╠═══════════════════════════════════════════════════════════════════════════════╣
"#,
        );

        for (algo, time) in &results.time_to_break {
            report.push_str(&format!("║  • {:25} {}\n", algo, time));
        }

        report.push_str(
            r#"║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"#,
        );

        report
    }

    fn pre_qday_report(&self) -> String {
        let mut vulnerable_count = 0;
        let mut secure_count = 0;

        for asset in self.assets.values() {
            if asset.algorithm.is_quantum_vulnerable() {
                vulnerable_count += 1;
            } else {
                secure_count += 1;
            }
        }

        format!(
            r#"
╔═══════════════════════════════════════════════════════════════════════════════╗
║                        🔴 QUANTUM TIME-MACHINE                                ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║  Press the button to simulate Q-Day: the day quantum computers can break     ║
║  ECDSA and RSA in hours.                                                     ║
║                                                                               ║
║                      ┌──────────────────────────┐                             ║
║                      │                          │                             ║
║                      │      🔴 BREAK IT         │                             ║
║                      │                          │                             ║
║                      └──────────────────────────┘                             ║
║                                                                               ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║  CURRENT STATUS                                                               ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║  Assets in simulation: {}                                                    ║
║  ⚠️  Vulnerable to quantum: {}                                                ║
║  ✅ Quantum-safe: {}                                                          ║
║                                                                               ║
║  Estimated Q-Day:       2030-2035 (Optimistic)                               ║
║                         2035-2040 (Conservative)                              ║
║                                                                               ║
║  NIST Post-Quantum Algorithms:                                                ║
║  • CRYSTALS-Dilithium (Signatures) - STANDARDIZED                            ║
║  • CRYSTALS-Kyber (KEMs) - STANDARDIZED                                       ║
║  • Falcon (Signatures) - STANDARDIZED                                         ║
║  • SPHINCS+ (Signatures) - STANDARDIZED                                       ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"#,
            self.assets.len(),
            vulnerable_count,
            secure_count,
        )
    }

    fn format_currency(amount: u64) -> String {
        if amount >= 1_000_000_000 {
            format!("{:.2}B", amount as f64 / 1_000_000_000.0)
        } else if amount >= 1_000_000 {
            format!("{:.2}M", amount as f64 / 1_000_000.0)
        } else if amount >= 1_000 {
            format!("{:.2}K", amount as f64 / 1_000.0)
        } else {
            amount.to_string()
        }
    }

    /// Generate demo assets for simulation
    pub fn load_demo_assets(&mut self) {
        // Ethereum-style assets (vulnerable)
        self.register_asset(CryptoAsset {
            id: "eth-wallet-1".to_string(),
            asset_type: AssetType::WalletAddress,
            algorithm: CryptoAlgorithm::ECDSA_Secp256k1,
            protected_value: Some(ProtectedValue {
                currency: "USD".to_string(),
                amount: 1_500_000_000_00, // $1.5B
                description: "Ethereum Wallet".to_string(),
            }),
            created_at: 0,
            owner: Some("Exchange A".to_string()),
            status: AssetStatus::Vulnerable,
        });

        self.register_asset(CryptoAsset {
            id: "eth-wallet-2".to_string(),
            asset_type: AssetType::WalletAddress,
            algorithm: CryptoAlgorithm::ECDSA_Secp256k1,
            protected_value: Some(ProtectedValue {
                currency: "USD".to_string(),
                amount: 800_000_000_00, // $800M
                description: "DeFi Protocol Treasury".to_string(),
            }),
            created_at: 0,
            owner: Some("DeFi Protocol".to_string()),
            status: AssetStatus::Vulnerable,
        });

        // RSA Certificates (vulnerable)
        self.register_asset(CryptoAsset {
            id: "cert-1".to_string(),
            asset_type: AssetType::Certificate,
            algorithm: CryptoAlgorithm::RSA_2048,
            protected_value: None,
            created_at: 0,
            owner: Some("Bank Auth Server".to_string()),
            status: AssetStatus::Vulnerable,
        });

        // Aethelred Digital Seals (secure)
        self.register_asset(CryptoAsset {
            id: "seal-1".to_string(),
            asset_type: AssetType::DigitalSeal,
            algorithm: CryptoAlgorithm::Dilithium3,
            protected_value: Some(ProtectedValue {
                currency: "USD".to_string(),
                amount: 500_000_000_00, // $500M
                description: "Trade Finance Digital Seal".to_string(),
            }),
            created_at: 0,
            owner: Some("FAB".to_string()),
            status: AssetStatus::Secure,
        });

        self.register_asset(CryptoAsset {
            id: "seal-2".to_string(),
            asset_type: AssetType::DigitalSeal,
            algorithm: CryptoAlgorithm::Dilithium3,
            protected_value: Some(ProtectedValue {
                currency: "USD".to_string(),
                amount: 300_000_000_00, // $300M
                description: "Credit Scoring Verification".to_string(),
            }),
            created_at: 0,
            owner: Some("DBS".to_string()),
            status: AssetStatus::Secure,
        });

        // Hybrid signatures
        self.register_asset(CryptoAsset {
            id: "hybrid-1".to_string(),
            asset_type: AssetType::Signature,
            algorithm: CryptoAlgorithm::Hybrid {
                classical: Box::new(CryptoAlgorithm::Ed25519),
                post_quantum: Box::new(CryptoAlgorithm::Dilithium3),
            },
            protected_value: Some(ProtectedValue {
                currency: "USD".to_string(),
                amount: 100_000_000_00, // $100M
                description: "Cross-border Settlement".to_string(),
            }),
            created_at: 0,
            owner: Some("Aethelred Validator".to_string()),
            status: AssetStatus::Secure,
        });
    }

    /// Is Q-Day active?
    pub fn is_q_day_active(&self) -> bool {
        self.q_day_active
    }
}

impl Default for QuantumTimeMachine {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Quantum Threat Timeline
// ============================================================================

/// Timeline of quantum computing milestones
pub struct QuantumThreatTimeline;

impl QuantumThreatTimeline {
    pub fn display() -> String {
        r#"
╔═══════════════════════════════════════════════════════════════════════════════╗
║                    QUANTUM THREAT TIMELINE                                    ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║  2019 │ Google claims "quantum supremacy" (53 qubits)                        ║
║       │                                                                       ║
║  2021 │ IBM unveils 127-qubit Eagle processor                                ║
║       │                                                                       ║
║  2022 │ NIST standardizes first post-quantum algorithms                      ║
║       │                                                                       ║
║  2023 │ IBM announces 1,121-qubit Condor processor                           ║
║       │                                                                       ║
║  2024 │ Google claims error-corrected logical qubits                         ║
║       ├───────────────────────────────────────────────────────────────────── ║
║  2025 │ ← YOU ARE HERE                                                       ║
║       ├───────────────────────────────────────────────────────────────────── ║
║  2027 │ Expected: 10,000+ physical qubits                                    ║
║       │                                                                       ║
║  2030 │ RISK WINDOW OPENS                                                    ║
║       │ Optimistic Q-Day estimate                                            ║
║       │ ~4,000 logical qubits needed for ECDSA                              ║
║       │                                                                       ║
║  2035 │ CONSERVATIVE Q-DAY                                                   ║
║       │ Most estimates place cryptographic threat here                       ║
║       │                                                                       ║
║  2040 │ Widespread quantum computing expected                                ║
║       │                                                                       ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║  ⚠️  HARVEST NOW, DECRYPT LATER                                               ║
║  Adversaries are already collecting encrypted data to decrypt post-Q-Day.    ║
║  Long-term secrets (medical records, state secrets) need protection NOW.     ║
║                                                                               ║
║  🛡️  AETHELRED APPROACH                                                       ║
║  • Hybrid signatures (Ed25519 + Dilithium3) provide immediate protection     ║
║  • All Digital Seals use NIST-standardized post-quantum algorithms           ║
║  • Seamless migration path when new standards emerge                         ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
        "#
        .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_algorithm_vulnerability() {
        assert!(CryptoAlgorithm::ECDSA_Secp256k1.is_quantum_vulnerable());
        assert!(CryptoAlgorithm::RSA_2048.is_quantum_vulnerable());
        assert!(CryptoAlgorithm::Ed25519.is_quantum_vulnerable());

        assert!(!CryptoAlgorithm::Dilithium3.is_quantum_vulnerable());
        assert!(!CryptoAlgorithm::Falcon512.is_quantum_vulnerable());
        assert!(!CryptoAlgorithm::SPHINCS_SHA256_128f.is_quantum_vulnerable());
    }

    #[test]
    fn test_q_day_activation() {
        let mut machine = QuantumTimeMachine::new();
        machine.load_demo_assets();

        assert!(!machine.is_q_day_active());

        let results = machine.activate_q_day();

        assert!(machine.is_q_day_active());
        assert!(results.broken_assets > 0);
        assert!(results.secure_assets > 0);
    }

    #[test]
    fn test_hybrid_algorithm() {
        let hybrid = CryptoAlgorithm::Hybrid {
            classical: Box::new(CryptoAlgorithm::Ed25519),
            post_quantum: Box::new(CryptoAlgorithm::Dilithium3),
        };

        // Hybrid is NOT vulnerable because PQ component is secure
        assert!(!hybrid.is_quantum_vulnerable());
        assert_eq!(hybrid.security_level(), 3); // Dilithium3 level
    }
}
