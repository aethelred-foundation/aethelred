//! Core Sandbox Infrastructure
//!
//! The foundation of the Infinity Sandbox - managing sessions,
//! execution context, and the unified simulation state.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

// ============================================================================
// Sandbox Session
// ============================================================================

/// A sandbox session representing a complete simulation environment
#[derive(Debug, Clone)]
pub struct SandboxSession {
    /// Unique session ID
    pub id: SessionId,
    /// Session owner
    pub owner: ParticipantId,
    /// All participants in this session
    pub participants: Vec<Participant>,
    /// Current jurisdiction setting
    pub jurisdiction: Jurisdiction,
    /// Hardware target
    pub hardware_target: HardwareTarget,
    /// Threat level (normal, quantum attack, etc.)
    pub threat_level: ThreatLevel,
    /// Loaded scenario
    pub scenario: Option<ScenarioId>,
    /// Session state
    pub state: SessionState,
    /// Execution logs
    pub logs: Vec<ExecutionLog>,
    /// Compliance results
    pub compliance_results: Vec<ComplianceResult>,
    /// Created at
    pub created_at: SystemTime,
    /// Configuration
    pub config: SandboxConfig,
}

/// Unique session identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(pub String);

impl SessionId {
    pub fn new() -> Self {
        SessionId(format!("sandbox-{}", uuid::Uuid::new_v4()))
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

/// Unique participant identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ParticipantId(pub String);

/// Scenario identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ScenarioId(pub String);

/// A participant in the sandbox session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Participant {
    /// Participant ID
    pub id: ParticipantId,
    /// Display name
    pub name: String,
    /// Organization
    pub organization: String,
    /// Role in session
    pub role: ParticipantRole,
    /// Secret variables (hidden from other participants)
    pub secret_variables: HashMap<String, SecretVariable>,
    /// Joined at
    pub joined_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ParticipantRole {
    /// Session owner with full control
    Owner,
    /// Collaborator with limited control
    Collaborator,
    /// Observer (read-only)
    Observer,
    /// Attacker in adversarial mode
    RedTeam,
    /// Defender in adversarial mode
    BlueTeam,
}

/// A secret variable that is hidden from other participants
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretVariable {
    /// Variable name
    pub name: String,
    /// Variable value (encrypted in storage, only visible to owner)
    pub value_hash: [u8; 32],
    /// Actual value (only in memory, never serialized)
    #[serde(skip)]
    pub actual_value: Option<String>,
    /// Data type
    pub data_type: VariableType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VariableType {
    String,
    Number,
    Boolean,
    Currency,
    Address,
    Encrypted,
}

// ============================================================================
// Jurisdiction & Compliance
// ============================================================================

/// Legal jurisdiction for the simulation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Jurisdiction {
    /// No compliance checks (for testing)
    WildWest,
    /// UAE Data Sovereignty (strictest)
    UAEDataSovereignty {
        allow_gcc_transfer: bool,
        require_local_storage: bool,
    },
    /// Singapore MAS regulations
    SingaporeMAS { pdpa_strict: bool },
    /// European GDPR
    GDPRStrict { allow_adequacy_countries: bool },
    /// US regulations
    USRegulatory {
        hipaa: bool,
        sox: bool,
        ofac_screening: bool,
    },
    /// Swiss banking regulations
    SwissBanking,
    /// Custom jurisdiction
    Custom {
        name: String,
        rules: Vec<ComplianceRule>,
    },
}

impl Jurisdiction {
    /// Get display name
    pub fn display_name(&self) -> &str {
        match self {
            Jurisdiction::WildWest => "Wild West (No Checks)",
            Jurisdiction::UAEDataSovereignty { .. } => "🇦🇪 UAE Data Sovereignty",
            Jurisdiction::SingaporeMAS { .. } => "🇸🇬 Singapore MAS",
            Jurisdiction::GDPRStrict { .. } => "🇪🇺 GDPR Strict",
            Jurisdiction::USRegulatory { .. } => "🇺🇸 US Regulatory",
            Jurisdiction::SwissBanking => "🇨🇭 Swiss Banking",
            Jurisdiction::Custom { name, .. } => name,
        }
    }

    /// Get applicable laws
    pub fn applicable_laws(&self) -> Vec<&'static str> {
        match self {
            Jurisdiction::WildWest => vec![],
            Jurisdiction::UAEDataSovereignty { .. } => vec![
                "UAE Federal Decree-Law No. 45/2021 (Personal Data Protection)",
                "CBUAE Consumer Protection Standards",
                "DIFC Data Protection Law",
                "ADGM Data Protection Regulations",
            ],
            Jurisdiction::SingaporeMAS { .. } => vec![
                "Personal Data Protection Act (PDPA)",
                "MAS Technology Risk Management Guidelines",
                "MAS Notice on Cyber Hygiene",
            ],
            Jurisdiction::GDPRStrict { .. } => vec![
                "GDPR Article 44 (Transfer Restrictions)",
                "GDPR Article 17 (Right to Erasure)",
                "GDPR Article 25 (Data Protection by Design)",
            ],
            Jurisdiction::USRegulatory { hipaa, sox, .. } => {
                let mut laws = vec![];
                if *hipaa {
                    laws.push("HIPAA Privacy Rule");
                    laws.push("HIPAA Security Rule");
                }
                if *sox {
                    laws.push("Sarbanes-Oxley Act Section 404");
                }
                laws
            }
            Jurisdiction::SwissBanking => vec![
                "Swiss Banking Secrecy (Art. 47 Banking Act)",
                "Swiss Data Protection Act (DSG)",
                "FINMA Circulars",
            ],
            Jurisdiction::Custom { .. } => vec!["Custom Rules"],
        }
    }
}

/// A compliance rule
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceRule {
    /// Rule ID
    pub id: String,
    /// Rule name
    pub name: String,
    /// Legal citation
    pub citation: String,
    /// Description
    pub description: String,
    /// Condition that triggers violation
    pub violation_condition: ViolationCondition,
    /// Severity
    pub severity: ViolationSeverity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ViolationCondition {
    /// Data crosses border
    CrossBorderTransfer {
        from_regions: Vec<String>,
        to_regions: Vec<String>,
    },
    /// Unencrypted PII
    UnencryptedPII,
    /// Missing consent
    MissingConsent { data_type: String },
    /// Retention exceeded
    RetentionExceeded { max_days: u32 },
    /// Sanctioned entity
    SanctionedEntity,
    /// Audit trail missing
    MissingAuditTrail,
    /// Custom condition
    Custom { expression: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ViolationSeverity {
    /// Informational
    Info,
    /// Warning (may proceed)
    Warning,
    /// Error (blocked but recoverable)
    Error,
    /// Critical (immediate halt)
    Critical,
}

// ============================================================================
// Hardware Targets
// ============================================================================

/// Hardware execution target
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HardwareTarget {
    /// Generic CPU (no TEE)
    GenericCPU,
    /// Intel SGX Enclave
    IntelSGX {
        location: DataCenterLocation,
        svn: u16,
    },
    /// AMD SEV
    AMDSEV {
        location: DataCenterLocation,
        variant: String,
    },
    /// AWS Nitro Enclave
    AWSNitro { region: String },
    /// NVIDIA GPU (H100)
    NvidiaH100 {
        location: DataCenterLocation,
        gpu_count: u8,
    },
    /// NVIDIA GPU (A100)
    NvidiaA100 {
        location: DataCenterLocation,
        gpu_count: u8,
    },
    /// Simulated/Mock
    Simulated { simulates: Box<HardwareTarget> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataCenterLocation {
    /// Country code
    pub country: String,
    /// City
    pub city: String,
    /// Cloud provider
    pub provider: CloudProvider,
    /// Data center ID
    pub dc_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CloudProvider {
    AWS,
    Azure,
    GCP,
    OracleCloud,
    Alibaba,
    OnPremise,
    Aethelred, // Our own nodes
}

impl HardwareTarget {
    /// Get display name
    pub fn display_name(&self) -> String {
        match self {
            HardwareTarget::GenericCPU => "Generic CPU".to_string(),
            HardwareTarget::IntelSGX { location, .. } => {
                format!("Intel SGX ({})", location.city)
            }
            HardwareTarget::AMDSEV { location, .. } => {
                format!("AMD SEV ({})", location.city)
            }
            HardwareTarget::AWSNitro { region } => {
                format!("AWS Nitro ({})", region)
            }
            HardwareTarget::NvidiaH100 {
                location,
                gpu_count,
            } => {
                format!("{}x NVIDIA H100 ({})", gpu_count, location.city)
            }
            HardwareTarget::NvidiaA100 {
                location,
                gpu_count,
            } => {
                format!("{}x NVIDIA A100 ({})", gpu_count, location.city)
            }
            HardwareTarget::Simulated { simulates } => {
                format!("[SIM] {}", simulates.display_name())
            }
        }
    }

    /// Is this a TEE target?
    pub fn is_tee(&self) -> bool {
        match self {
            HardwareTarget::IntelSGX { .. }
            | HardwareTarget::AMDSEV { .. }
            | HardwareTarget::AWSNitro { .. } => true,
            HardwareTarget::Simulated { simulates } => simulates.is_tee(),
            _ => false,
        }
    }

    /// Get the data location country
    pub fn data_location(&self) -> Option<&str> {
        match self {
            HardwareTarget::IntelSGX { location, .. }
            | HardwareTarget::AMDSEV { location, .. }
            | HardwareTarget::NvidiaH100 { location, .. }
            | HardwareTarget::NvidiaA100 { location, .. } => Some(&location.country),
            HardwareTarget::AWSNitro { region } => {
                // Parse AWS region to country
                if region.starts_with("me-") {
                    Some("AE") // Middle East = UAE
                } else if region.starts_with("ap-southeast-1") {
                    Some("SG") // Singapore
                } else if region.starts_with("eu-") {
                    Some("EU")
                } else if region.starts_with("us-") {
                    Some("US")
                } else {
                    None
                }
            }
            HardwareTarget::Simulated { simulates } => simulates.data_location(),
            HardwareTarget::GenericCPU => None,
        }
    }
}

// ============================================================================
// Threat Levels
// ============================================================================

/// Current threat level in the simulation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreatLevel {
    /// Normal operation
    Normal,
    /// Quantum attack active (ECDSA broken)
    QuantumAttack {
        /// Algorithms considered broken
        broken_algorithms: Vec<String>,
    },
    /// Adversarial nodes injected
    AdversarialMode {
        /// Number of malicious nodes
        malicious_node_count: u32,
        /// Attack types active
        attack_types: Vec<AdversarialAttackType>,
    },
    /// Network partition
    NetworkPartition {
        /// Partitioned regions
        partitions: Vec<Vec<String>>,
    },
    /// High latency simulation
    HighLatency {
        /// Added latency in ms
        latency_ms: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdversarialAttackType {
    /// Node submits fake proofs
    LazyProver,
    /// Node tries to extract data
    DataLeaker,
    /// Node submits wrong results
    ResultManipulator,
    /// Node goes offline
    CrashNode,
    /// Node reorders transactions
    FrontRunner,
}

// ============================================================================
// Session State
// ============================================================================

/// Current state of the sandbox session
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionState {
    /// Session created but not started
    Created,
    /// Loading scenario
    LoadingScenario,
    /// Ready to execute
    Ready,
    /// Currently executing code
    Executing {
        started_at: u64,
        current_step: String,
    },
    /// Execution paused
    Paused { reason: String },
    /// Execution completed
    Completed {
        success: bool,
        result_hash: [u8; 32],
    },
    /// Execution failed
    Failed { error: String, recoverable: bool },
    /// Session closed
    Closed,
}

// ============================================================================
// Execution Logs
// ============================================================================

/// An execution log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionLog {
    /// Timestamp
    pub timestamp: u64,
    /// Log level
    pub level: LogLevel,
    /// Log category
    pub category: LogCategory,
    /// Message
    pub message: String,
    /// Additional data
    pub data: Option<serde_json::Value>,
    /// Source participant
    pub source: Option<ParticipantId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogLevel {
    Debug,
    Info,
    Warning,
    Error,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogCategory {
    /// System boot/initialization
    System,
    /// TEE attestation
    Attestation,
    /// Compliance check
    Compliance,
    /// Data transfer
    DataTransfer,
    /// Cryptography
    Crypto,
    /// AI/ML execution
    AIExecution,
    /// Network
    Network,
    /// Security event
    Security,
    /// User action
    UserAction,
}

// ============================================================================
// Compliance Results
// ============================================================================

/// Result of a compliance check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceResult {
    /// Check ID
    pub id: String,
    /// Rule that was checked
    pub rule: ComplianceRule,
    /// Whether the check passed
    pub passed: bool,
    /// Violation details (if failed)
    pub violation: Option<ViolationDetails>,
    /// Timestamp
    pub checked_at: u64,
    /// Context
    pub context: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViolationDetails {
    /// Legal citation
    pub citation: String,
    /// Description
    pub description: String,
    /// Remediation steps
    pub remediation: Vec<String>,
    /// Estimated fine (if applicable)
    pub estimated_fine: Option<FineEstimate>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FineEstimate {
    /// Currency
    pub currency: String,
    /// Minimum fine
    pub min_amount: u64,
    /// Maximum fine
    pub max_amount: u64,
    /// Basis for calculation
    pub basis: String,
}

// ============================================================================
// Sandbox Configuration
// ============================================================================

/// Configuration for the sandbox session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfig {
    /// Enable strict mode (all checks)
    pub strict_mode: bool,
    /// Auto-export audit logs
    pub auto_export_audit: bool,
    /// Maximum execution time
    pub max_execution_time: Duration,
    /// Enable AI copilot
    pub ai_copilot_enabled: bool,
    /// Enable visual effects (attestation animations)
    pub visual_effects: bool,
    /// Record session for replay
    pub record_session: bool,
    /// CTF mode enabled
    pub ctf_mode: bool,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        SandboxConfig {
            strict_mode: true,
            auto_export_audit: true,
            max_execution_time: Duration::from_secs(300),
            ai_copilot_enabled: true,
            visual_effects: true,
            record_session: true,
            ctf_mode: false,
        }
    }
}

// ============================================================================
// The Sandbox Engine
// ============================================================================

/// The main Infinity Sandbox engine
pub struct InfinitySandbox {
    /// Active sessions
    sessions: Arc<RwLock<HashMap<SessionId, SandboxSession>>>,
    /// Global configuration
    config: SandboxGlobalConfig,
}

#[derive(Debug, Clone)]
pub struct SandboxGlobalConfig {
    /// Maximum concurrent sessions
    pub max_sessions: usize,
    /// Default jurisdiction
    pub default_jurisdiction: Jurisdiction,
    /// Available hardware targets
    pub available_targets: Vec<HardwareTarget>,
}

impl Default for SandboxGlobalConfig {
    fn default() -> Self {
        SandboxGlobalConfig {
            max_sessions: 100,
            default_jurisdiction: Jurisdiction::UAEDataSovereignty {
                allow_gcc_transfer: true,
                require_local_storage: true,
            },
            available_targets: vec![
                HardwareTarget::GenericCPU,
                HardwareTarget::IntelSGX {
                    location: DataCenterLocation {
                        country: "AE".to_string(),
                        city: "Abu Dhabi".to_string(),
                        provider: CloudProvider::Aethelred,
                        dc_id: Some("AD-01".to_string()),
                    },
                    svn: 15,
                },
                HardwareTarget::NvidiaH100 {
                    location: DataCenterLocation {
                        country: "SG".to_string(),
                        city: "Singapore".to_string(),
                        provider: CloudProvider::AWS,
                        dc_id: None,
                    },
                    gpu_count: 8,
                },
            ],
        }
    }
}

impl InfinitySandbox {
    pub fn new(config: SandboxGlobalConfig) -> Self {
        InfinitySandbox {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    /// Create a new sandbox session
    pub fn create_session(
        &self,
        owner: ParticipantId,
        owner_name: String,
        organization: String,
    ) -> Result<SessionId, SandboxError> {
        let sessions = self.sessions.read().unwrap();
        if sessions.len() >= self.config.max_sessions {
            return Err(SandboxError::TooManySessions);
        }
        drop(sessions);

        let session_id = SessionId::new();
        let now = SystemTime::now();

        let owner_participant = Participant {
            id: owner.clone(),
            name: owner_name,
            organization,
            role: ParticipantRole::Owner,
            secret_variables: HashMap::new(),
            joined_at: now.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
        };

        let session = SandboxSession {
            id: session_id.clone(),
            owner,
            participants: vec![owner_participant],
            jurisdiction: self.config.default_jurisdiction.clone(),
            hardware_target: HardwareTarget::GenericCPU,
            threat_level: ThreatLevel::Normal,
            scenario: None,
            state: SessionState::Created,
            logs: vec![ExecutionLog {
                timestamp: now.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
                level: LogLevel::Info,
                category: LogCategory::System,
                message: "Sandbox session created".to_string(),
                data: None,
                source: None,
            }],
            compliance_results: Vec::new(),
            created_at: now,
            config: SandboxConfig::default(),
        };

        self.sessions
            .write()
            .unwrap()
            .insert(session_id.clone(), session);
        Ok(session_id)
    }

    /// Get a session
    pub fn get_session(&self, id: &SessionId) -> Option<SandboxSession> {
        self.sessions.read().unwrap().get(id).cloned()
    }

    /// Set jurisdiction for a session
    pub fn set_jurisdiction(
        &self,
        session_id: &SessionId,
        jurisdiction: Jurisdiction,
    ) -> Result<(), SandboxError> {
        let mut sessions = self.sessions.write().unwrap();
        let session = sessions
            .get_mut(session_id)
            .ok_or(SandboxError::SessionNotFound)?;

        session.jurisdiction = jurisdiction.clone();
        session.logs.push(ExecutionLog {
            timestamp: SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            level: LogLevel::Info,
            category: LogCategory::Compliance,
            message: format!("Jurisdiction changed to: {}", jurisdiction.display_name()),
            data: None,
            source: None,
        });

        Ok(())
    }

    /// Set hardware target for a session
    pub fn set_hardware_target(
        &self,
        session_id: &SessionId,
        target: HardwareTarget,
    ) -> Result<(), SandboxError> {
        let mut sessions = self.sessions.write().unwrap();
        let session = sessions
            .get_mut(session_id)
            .ok_or(SandboxError::SessionNotFound)?;

        session.hardware_target = target.clone();
        session.logs.push(ExecutionLog {
            timestamp: SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            level: LogLevel::Info,
            category: LogCategory::System,
            message: format!("Hardware target set: {}", target.display_name()),
            data: None,
            source: None,
        });

        Ok(())
    }

    /// Activate threat level
    pub fn set_threat_level(
        &self,
        session_id: &SessionId,
        threat: ThreatLevel,
    ) -> Result<(), SandboxError> {
        let mut sessions = self.sessions.write().unwrap();
        let session = sessions
            .get_mut(session_id)
            .ok_or(SandboxError::SessionNotFound)?;

        let threat_name = match &threat {
            ThreatLevel::Normal => "🟢 Normal",
            ThreatLevel::QuantumAttack { .. } => "🔴 QUANTUM ATTACK",
            ThreatLevel::AdversarialMode { .. } => "🟠 Adversarial Mode",
            ThreatLevel::NetworkPartition { .. } => "🟡 Network Partition",
            ThreatLevel::HighLatency { .. } => "🟡 High Latency",
        };

        session.threat_level = threat;
        session.logs.push(ExecutionLog {
            timestamp: SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            level: LogLevel::Warning,
            category: LogCategory::Security,
            message: format!("Threat level changed: {}", threat_name),
            data: None,
            source: None,
        });

        Ok(())
    }

    /// Welcome message
    pub fn welcome_message() -> String {
        r#"
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║     █████╗ ███████╗████████╗██╗  ██╗███████╗██╗     ██████╗ ███████╗██████╗   ║
║    ██╔══██╗██╔════╝╚══██╔══╝██║  ██║██╔════╝██║     ██╔══██╗██╔════╝██╔══██╗  ║
║    ███████║█████╗     ██║   ███████║█████╗  ██║     ██████╔╝█████╗  ██║  ██║  ║
║    ██╔══██║██╔══╝     ██║   ██╔══██║██╔══╝  ██║     ██╔══██╗██╔══╝  ██║  ██║  ║
║    ██║  ██║███████╗   ██║   ██║  ██║███████╗███████╗██║  ██║███████╗██████╔╝  ║
║    ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚═════╝   ║
║                                                                               ║
║              ██╗███╗   ██╗███████╗██╗███╗   ██╗██╗████████╗██╗   ██╗          ║
║              ██║████╗  ██║██╔════╝██║████╗  ██║██║╚══██╔══╝╚██╗ ██╔╝          ║
║              ██║██╔██╗ ██║█████╗  ██║██╔██╗ ██║██║   ██║    ╚████╔╝           ║
║              ██║██║╚██╗██║██╔══╝  ██║██║╚██╗██║██║   ██║     ╚██╔╝            ║
║              ██║██║ ╚████║██║     ██║██║ ╚████║██║   ██║      ██║             ║
║              ╚═╝╚═╝  ╚═══╝╚═╝     ╚═╝╚═╝  ╚═══╝╚═╝   ╚═╝      ╚═╝             ║
║                                                                               ║
║                         SANDBOX                                               ║
║                                                                               ║
║           "The World's First Sovereign AI Risk Simulator"                     ║
║                                                                               ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║  This is not just a developer tool.                                          ║
║  This is a C-LEVEL RISK SIMULATOR.                                           ║
║                                                                               ║
║  Most sandboxes answer:  "Does my code work?"                                 ║
║  The Infinity Sandbox answers:                                                ║
║    "Will my bank survive a subpoena, a quantum attack, or a data leak?"      ║
║                                                                               ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║  CONTROLS:                                                                    ║
║  ┌─────────────────────────────────────────────────────────────────────────┐ ║
║  │  🎚️  JURISDICTION SLIDER                                                │ ║
║  │  [Wild West] ─────|───── [UAE Strict] ─────|───── [GDPR] ─────|───── [SG]│ ║
║  │                                                                         │ ║
║  │  🎯 HARDWARE TARGET                                                      │ ║
║  │  ( ) Generic CPU  (●) Intel SGX (UAE)  ( ) NVIDIA H100 (SG)             │ ║
║  │                                                                         │ ║
║  │  ⚠️  THREAT LEVEL                                                        │ ║
║  │  [🟢 Normal]  [🔴 Quantum Attack]  [🟠 Adversarial]  [🟡 Network Chaos] │ ║
║  └─────────────────────────────────────────────────────────────────────────┘ ║
║                                                                               ║
║  SCENARIOS:                                                                   ║
║  ┌─────────────────────────────────────────────────────────────────────────┐ ║
║  │  📄 UAE-Singapore Trade Finance                                         │ ║
║  │  🧬 M42 Genomic Blind Compute                                           │ ║
║  │  💳 Cross-Border Payment Settlement                                     │ ║
║  │  🏦 Anti-Money Laundering Check                                         │ ║
║  │  🔒 OFAC Sanctions Screening                                            │ ║
║  └─────────────────────────────────────────────────────────────────────────┘ ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
        "#
        .to_string()
    }
}

impl Default for InfinitySandbox {
    fn default() -> Self {
        Self::new(SandboxGlobalConfig::default())
    }
}

// ============================================================================
// Errors
// ============================================================================

#[derive(Debug, Clone)]
pub enum SandboxError {
    SessionNotFound,
    TooManySessions,
    NotAuthorized,
    InvalidConfiguration(String),
    ExecutionFailed(String),
    ComplianceViolation(String),
}

impl std::fmt::Display for SandboxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SandboxError::SessionNotFound => write!(f, "Session not found"),
            SandboxError::TooManySessions => write!(f, "Maximum session limit reached"),
            SandboxError::NotAuthorized => write!(f, "Not authorized for this action"),
            SandboxError::InvalidConfiguration(msg) => write!(f, "Invalid configuration: {}", msg),
            SandboxError::ExecutionFailed(msg) => write!(f, "Execution failed: {}", msg),
            SandboxError::ComplianceViolation(msg) => write!(f, "Compliance violation: {}", msg),
        }
    }
}

impl std::error::Error for SandboxError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_creation() {
        let sandbox = InfinitySandbox::default();
        let owner = ParticipantId("user-1".to_string());

        let session_id = sandbox
            .create_session(owner, "John Doe".to_string(), "FAB".to_string())
            .unwrap();

        let session = sandbox.get_session(&session_id).unwrap();
        assert_eq!(session.participants.len(), 1);
        assert_eq!(session.state, SessionState::Created);
    }

    #[test]
    fn test_jurisdiction_change() {
        let sandbox = InfinitySandbox::default();
        let owner = ParticipantId("user-1".to_string());
        let session_id = sandbox
            .create_session(owner, "Test".to_string(), "Test".to_string())
            .unwrap();

        sandbox
            .set_jurisdiction(
                &session_id,
                Jurisdiction::GDPRStrict {
                    allow_adequacy_countries: false,
                },
            )
            .unwrap();

        let session = sandbox.get_session(&session_id).unwrap();
        assert!(matches!(
            session.jurisdiction,
            Jurisdiction::GDPRStrict { .. }
        ));
    }
}
