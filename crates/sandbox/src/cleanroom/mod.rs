//! # Multi-Party Clean Rooms
//!
//! **"Bring Your Secrets, Keep Them Hidden"**
//!
//! This module enables collaborative computation where each party
//! contributes data without revealing it to others. Like a real
//! clean room, but for data.
//!
//! ## Clean Room Interface
//!
//! ```text
//! ╔═══════════════════════════════════════════════════════════════════════════════╗
//! ║                        🔐 MULTI-PARTY CLEAN ROOM                              ║
//! ╠═══════════════════════════════════════════════════════════════════════════════╣
//! ║                                                                               ║
//! ║  CLEAN ROOM: Trade Finance Settlement                                         ║
//! ║  Session ID: clean-room-7f3a2b                                               ║
//! ║  Status: ● ACTIVE                                                             ║
//! ║                                                                               ║
//! ╠═══════════════════════════════════════════════════════════════════════════════╣
//! ║  PARTICIPANTS                                                                 ║
//! ╠═══════════════════════════════════════════════════════════════════════════════╣
//! ║                                                                               ║
//! ║  ┌─────────────────────────────────────────────────────────────────────────┐ ║
//! ║  │  🏦 First Abu Dhabi Bank (FAB)                              OWNER       │ ║
//! ║  │     Secret Variables: [credit_score, risk_limit]                        │ ║
//! ║  │     Status: ✅ Ready                                                     │ ║
//! ║  │                                                                         │ ║
//! ║  │  🏦 DBS Bank Singapore                                      COLLABORATOR │ ║
//! ║  │     Secret Variables: [counterparty_rating, exposure]                   │ ║
//! ║  │     Status: ✅ Ready                                                     │ ║
//! ║  │                                                                         │ ║
//! ║  │  📊 Aethelred Validator                                     COMPUTE      │ ║
//! ║  │     Role: TEE Executor (Intel SGX)                                      │ ║
//! ║  │     Status: ✅ Attested                                                  │ ║
//! ║  └─────────────────────────────────────────────────────────────────────────┘ ║
//! ║                                                                               ║
//! ╠═══════════════════════════════════════════════════════════════════════════════╣
//! ║  COMPUTATION                                                                  ║
//! ╠═══════════════════════════════════════════════════════════════════════════════╣
//! ║                                                                               ║
//! ║  Function: calculate_settlement_terms()                                       ║
//! ║  Inputs:  FAB.credit_score + DBS.counterparty_rating                        ║
//! ║  Output:  settlement_approved: bool (visible to all)                        ║
//! ║           settlement_terms: encrypted (visible to FAB and DBS only)         ║
//! ║                                                                               ║
//! ║  ┌─────────────────────────────────────────────────────────────────────────┐ ║
//! ║  │  [👁️ View My Secrets]  [🔐 Contribute Data]  [▶️ Run Computation]       │ ║
//! ║  └─────────────────────────────────────────────────────────────────────────┘ ║
//! ║                                                                               ║
//! ╚═══════════════════════════════════════════════════════════════════════════════╝
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::core::{ParticipantId, VariableType};

// ============================================================================
// Clean Room Types
// ============================================================================

/// A Multi-Party Clean Room session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CleanRoom {
    /// Clean room ID
    pub id: String,
    /// Display name
    pub name: String,
    /// Description
    pub description: String,
    /// Owner
    pub owner: ParticipantId,
    /// All participants
    pub participants: Vec<CleanRoomParticipant>,
    /// Computation definition
    pub computation: Computation,
    /// Status
    pub status: CleanRoomStatus,
    /// Access policy
    pub access_policy: AccessPolicy,
    /// Audit log
    pub audit_log: Vec<AuditEntry>,
    /// Created at
    pub created_at: u64,
    /// Expires at
    pub expires_at: Option<u64>,
}

/// A participant in the clean room
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CleanRoomParticipant {
    /// Participant ID
    pub id: ParticipantId,
    /// Display name
    pub name: String,
    /// Organization
    pub organization: String,
    /// Role in clean room
    pub role: CleanRoomRole,
    /// Secret variables contributed
    pub secret_variables: Vec<ContributedVariable>,
    /// Status
    pub status: ParticipantStatus,
    /// Joined at
    pub joined_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CleanRoomRole {
    /// Clean room owner
    Owner,
    /// Data contributor
    DataProvider,
    /// Computation provider (validator)
    ComputeProvider,
    /// Observer (can see results, not secrets)
    Observer,
    /// Auditor (can see everything for compliance)
    Auditor,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ParticipantStatus {
    Invited,
    Joined,
    Ready,
    Contributing,
    Waiting,
    Completed,
    Left,
}

/// A contributed secret variable
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContributedVariable {
    /// Variable name
    pub name: String,
    /// Variable type
    pub var_type: VariableType,
    /// Commitment hash (for verification)
    pub commitment: [u8; 32],
    /// Is the value ready (contributed)
    pub is_ready: bool,
    /// Who can see the raw value
    pub visibility: Visibility,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Visibility {
    /// Only the contributor
    Private,
    /// Specific participants
    Shared(Vec<ParticipantId>),
    /// All participants
    AllParticipants,
    /// Public (in results)
    Public,
}

// ============================================================================
// Computation Definition
// ============================================================================

/// Definition of the computation to perform
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Computation {
    /// Computation name
    pub name: String,
    /// Computation type
    pub computation_type: ComputationType,
    /// Input bindings
    pub inputs: Vec<InputBinding>,
    /// Output definitions
    pub outputs: Vec<OutputDefinition>,
    /// Code hash (for verification)
    pub code_hash: [u8; 32],
    /// Execution constraints
    pub constraints: ExecutionConstraints,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComputationType {
    /// Pre-defined function
    Predefined(String),
    /// Custom WASM module
    CustomWasm,
    /// AI inference
    AIInference { model_id: String },
    /// Secure aggregation
    SecureAggregation,
    /// Private set intersection
    PrivateSetIntersection,
}

/// Binding of input variable to participant's secret
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputBinding {
    /// Input name in computation
    pub input_name: String,
    /// Source participant
    pub source_participant: ParticipantId,
    /// Source variable name
    pub source_variable: String,
    /// Transform (optional)
    pub transform: Option<Transform>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Transform {
    /// No transform
    Identity,
    /// Normalize to 0-1
    Normalize { min: f64, max: f64 },
    /// Bucketize
    Bucketize { buckets: Vec<f64> },
    /// Hash
    Hash,
}

/// Definition of computation output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputDefinition {
    /// Output name
    pub name: String,
    /// Output type
    pub output_type: VariableType,
    /// Who can see this output
    pub visibility: Visibility,
    /// Include in Digital Seal
    pub include_in_seal: bool,
}

/// Constraints on execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionConstraints {
    /// Minimum participants required
    pub min_participants: u32,
    /// Timeout in seconds
    pub timeout_secs: u64,
    /// Require TEE
    pub require_tee: bool,
    /// Require zkML proof
    pub require_zkml: bool,
    /// Allow re-execution
    pub allow_reexecution: bool,
}

// ============================================================================
// Clean Room Status and Results
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CleanRoomStatus {
    /// Clean room created, waiting for participants
    WaitingForParticipants,
    /// All participants joined, waiting for data
    WaitingForData,
    /// Ready to execute
    Ready,
    /// Executing computation
    Executing,
    /// Completed successfully
    Completed { result_id: String },
    /// Failed
    Failed { error: String },
    /// Expired
    Expired,
    /// Cancelled
    Cancelled,
}

/// Access policy for the clean room
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessPolicy {
    /// Require invitation
    pub invite_only: bool,
    /// Require KYB verification
    pub require_kyb: bool,
    /// Allowed jurisdictions
    pub allowed_jurisdictions: Vec<String>,
    /// Required certifications
    pub required_certifications: Vec<String>,
    /// Data usage agreement required
    pub require_dua: bool,
}

impl Default for AccessPolicy {
    fn default() -> Self {
        AccessPolicy {
            invite_only: true,
            require_kyb: true,
            allowed_jurisdictions: vec!["AE".to_string(), "SG".to_string()],
            required_certifications: vec!["SOC2".to_string()],
            require_dua: true,
        }
    }
}

/// Audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Timestamp
    pub timestamp: u64,
    /// Actor
    pub actor: ParticipantId,
    /// Action
    pub action: AuditAction,
    /// Details
    pub details: String,
    /// Hash of entry (for chaining)
    pub hash: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditAction {
    CleanRoomCreated,
    ParticipantInvited,
    ParticipantJoined,
    ParticipantLeft,
    DataContributed,
    ComputationStarted,
    ComputationCompleted,
    ResultViewed,
    CleanRoomClosed,
}

// ============================================================================
// Clean Room Engine
// ============================================================================

/// The Clean Room Engine
pub struct CleanRoomEngine {
    /// Active clean rooms
    clean_rooms: HashMap<String, CleanRoom>,
    /// Pending invitations
    invitations: Vec<Invitation>,
}

/// An invitation to join a clean room
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invitation {
    pub id: String,
    pub clean_room_id: String,
    pub invitee: String,
    pub inviter: ParticipantId,
    pub role: CleanRoomRole,
    pub expires_at: u64,
}

impl CleanRoomEngine {
    pub fn new() -> Self {
        CleanRoomEngine {
            clean_rooms: HashMap::new(),
            invitations: Vec::new(),
        }
    }

    /// Create a new clean room
    pub fn create_clean_room(
        &mut self,
        name: String,
        description: String,
        owner: ParticipantId,
        owner_name: String,
        owner_org: String,
        computation: Computation,
    ) -> Result<String, CleanRoomError> {
        let id = format!("clean-room-{}", &uuid::Uuid::new_v4().to_string()[..8]);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let owner_participant = CleanRoomParticipant {
            id: owner.clone(),
            name: owner_name,
            organization: owner_org,
            role: CleanRoomRole::Owner,
            secret_variables: Vec::new(),
            status: ParticipantStatus::Joined,
            joined_at: now,
        };

        let clean_room = CleanRoom {
            id: id.clone(),
            name,
            description,
            owner,
            participants: vec![owner_participant],
            computation,
            status: CleanRoomStatus::WaitingForParticipants,
            access_policy: AccessPolicy::default(),
            audit_log: vec![AuditEntry {
                timestamp: now,
                actor: ParticipantId("system".to_string()),
                action: AuditAction::CleanRoomCreated,
                details: "Clean room created".to_string(),
                hash: [0u8; 32],
            }],
            created_at: now,
            expires_at: Some(now + 86400 * 7), // 7 days
        };

        self.clean_rooms.insert(id.clone(), clean_room);
        Ok(id)
    }

    /// Invite a participant
    pub fn invite_participant(
        &mut self,
        clean_room_id: &str,
        inviter: &ParticipantId,
        invitee: &str,
        role: CleanRoomRole,
    ) -> Result<String, CleanRoomError> {
        let clean_room = self
            .clean_rooms
            .get_mut(clean_room_id)
            .ok_or(CleanRoomError::CleanRoomNotFound)?;

        // Check inviter is owner
        let inviter_participant = clean_room
            .participants
            .iter()
            .find(|p| &p.id == inviter)
            .ok_or(CleanRoomError::NotAuthorized)?;

        if inviter_participant.role != CleanRoomRole::Owner {
            return Err(CleanRoomError::NotAuthorized);
        }

        let invitation_id = format!("invite-{}", uuid::Uuid::new_v4());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        self.invitations.push(Invitation {
            id: invitation_id.clone(),
            clean_room_id: clean_room_id.to_string(),
            invitee: invitee.to_string(),
            inviter: inviter.clone(),
            role,
            expires_at: now + 86400, // 24 hours
        });

        Ok(invitation_id)
    }

    /// Join a clean room
    pub fn join_clean_room(
        &mut self,
        invitation_id: &str,
        participant_id: ParticipantId,
        name: String,
        organization: String,
    ) -> Result<(), CleanRoomError> {
        let invitation = self
            .invitations
            .iter()
            .find(|i| i.id == invitation_id)
            .ok_or(CleanRoomError::InvitationNotFound)?
            .clone();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if now > invitation.expires_at {
            return Err(CleanRoomError::InvitationExpired);
        }

        let clean_room = self
            .clean_rooms
            .get_mut(&invitation.clean_room_id)
            .ok_or(CleanRoomError::CleanRoomNotFound)?;

        let participant = CleanRoomParticipant {
            id: participant_id.clone(),
            name,
            organization,
            role: invitation.role,
            secret_variables: Vec::new(),
            status: ParticipantStatus::Joined,
            joined_at: now,
        };

        clean_room.participants.push(participant);
        clean_room.audit_log.push(AuditEntry {
            timestamp: now,
            actor: participant_id,
            action: AuditAction::ParticipantJoined,
            details: "Participant joined clean room".to_string(),
            hash: [0u8; 32],
        });

        // Remove used invitation
        self.invitations.retain(|i| i.id != invitation_id);

        // Check if all required participants are present
        self.check_ready_status(&invitation.clean_room_id);

        Ok(())
    }

    /// Contribute a secret variable
    pub fn contribute_secret(
        &mut self,
        clean_room_id: &str,
        participant_id: &ParticipantId,
        variable: ContributedVariable,
    ) -> Result<(), CleanRoomError> {
        let clean_room = self
            .clean_rooms
            .get_mut(clean_room_id)
            .ok_or(CleanRoomError::CleanRoomNotFound)?;

        let participant = clean_room
            .participants
            .iter_mut()
            .find(|p| &p.id == participant_id)
            .ok_or(CleanRoomError::ParticipantNotFound)?;

        participant.secret_variables.push(variable);
        participant.status = ParticipantStatus::Ready;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        clean_room.audit_log.push(AuditEntry {
            timestamp: now,
            actor: participant_id.clone(),
            action: AuditAction::DataContributed,
            details: "Secret variable contributed".to_string(),
            hash: [0u8; 32],
        });

        self.check_ready_status(clean_room_id);
        Ok(())
    }

    /// Check if clean room is ready to execute
    fn check_ready_status(&mut self, clean_room_id: &str) {
        if let Some(clean_room) = self.clean_rooms.get_mut(clean_room_id) {
            let all_ready = clean_room
                .participants
                .iter()
                .filter(|p| p.role == CleanRoomRole::DataProvider || p.role == CleanRoomRole::Owner)
                .all(|p| p.status == ParticipantStatus::Ready);

            let enough_participants = clean_room.participants.len() as u32
                >= clean_room.computation.constraints.min_participants;

            if all_ready && enough_participants {
                clean_room.status = CleanRoomStatus::Ready;
            }
        }
    }

    /// Execute the computation
    pub fn execute_computation(
        &mut self,
        clean_room_id: &str,
        executor: &ParticipantId,
    ) -> Result<ComputationResult, CleanRoomError> {
        let clean_room = self
            .clean_rooms
            .get_mut(clean_room_id)
            .ok_or(CleanRoomError::CleanRoomNotFound)?;

        if clean_room.status != CleanRoomStatus::Ready {
            return Err(CleanRoomError::NotReady);
        }

        // Check executor is owner or compute provider
        let executor_participant = clean_room
            .participants
            .iter()
            .find(|p| &p.id == executor)
            .ok_or(CleanRoomError::NotAuthorized)?;

        if executor_participant.role != CleanRoomRole::Owner
            && executor_participant.role != CleanRoomRole::ComputeProvider
        {
            return Err(CleanRoomError::NotAuthorized);
        }

        clean_room.status = CleanRoomStatus::Executing;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Simulate computation
        let result_id = format!("result-{}", uuid::Uuid::new_v4());

        // Generate mock outputs based on computation type
        let outputs = clean_room
            .computation
            .outputs
            .iter()
            .map(|o| ComputationOutput {
                name: o.name.clone(),
                value_hash: [0u8; 32],
                visibility: o.visibility.clone(),
            })
            .collect();

        clean_room.status = CleanRoomStatus::Completed {
            result_id: result_id.clone(),
        };

        clean_room.audit_log.push(AuditEntry {
            timestamp: now,
            actor: executor.clone(),
            action: AuditAction::ComputationCompleted,
            details: format!("Computation completed: {}", result_id),
            hash: [0u8; 32],
        });

        Ok(ComputationResult {
            id: result_id,
            clean_room_id: clean_room_id.to_string(),
            outputs,
            execution_time_ms: 1500, // Simulated
            tee_attestation: Some(vec![0u8; 64]),
            digital_seal_id: Some(format!("seal-{}", uuid::Uuid::new_v4())),
        })
    }

    /// Get clean room status
    pub fn get_clean_room(&self, id: &str) -> Option<&CleanRoom> {
        self.clean_rooms.get(id)
    }

    /// Generate clean room UI
    pub fn generate_ui(&self, clean_room_id: &str, _viewer: &ParticipantId) -> String {
        let clean_room = match self.clean_rooms.get(clean_room_id) {
            Some(cr) => cr,
            None => return "Clean room not found".to_string(),
        };

        let status_indicator = match &clean_room.status {
            CleanRoomStatus::WaitingForParticipants => "⏳ Waiting for Participants",
            CleanRoomStatus::WaitingForData => "⏳ Waiting for Data",
            CleanRoomStatus::Ready => "● READY",
            CleanRoomStatus::Executing => "⚙️ Executing",
            CleanRoomStatus::Completed { .. } => "✅ Completed",
            CleanRoomStatus::Failed { .. } => "❌ Failed",
            CleanRoomStatus::Expired => "⌛ Expired",
            CleanRoomStatus::Cancelled => "🚫 Cancelled",
        };

        let mut ui = format!(
            r#"
╔═══════════════════════════════════════════════════════════════════════════════╗
║                        🔐 MULTI-PARTY CLEAN ROOM                              ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║  CLEAN ROOM: {}
║  Session ID: {}
║  Status: {}
║                                                                               ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║  PARTICIPANTS                                                                 ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║  ┌─────────────────────────────────────────────────────────────────────────┐ ║
"#,
            clean_room.name, clean_room.id, status_indicator
        );

        for participant in &clean_room.participants {
            let role_badge = match participant.role {
                CleanRoomRole::Owner => "OWNER",
                CleanRoomRole::DataProvider => "DATA PROVIDER",
                CleanRoomRole::ComputeProvider => "COMPUTE",
                CleanRoomRole::Observer => "OBSERVER",
                CleanRoomRole::Auditor => "AUDITOR",
            };

            let status_icon = match participant.status {
                ParticipantStatus::Ready => "✅",
                ParticipantStatus::Joined => "🔵",
                ParticipantStatus::Contributing => "⏳",
                ParticipantStatus::Completed => "✅",
                _ => "⚪",
            };

            ui.push_str(&format!(
                "║  │  🏦 {} ({})  {}                   │ ║\n",
                participant.name, participant.organization, role_badge
            ));

            if !participant.secret_variables.is_empty() {
                let vars: Vec<_> = participant
                    .secret_variables
                    .iter()
                    .map(|v| v.name.as_str())
                    .collect();
                ui.push_str(&format!(
                    "║  │     Secret Variables: [{}]                          │ ║\n",
                    vars.join(", ")
                ));
            }

            ui.push_str(&format!(
                "║  │     Status: {} {}                                        │ ║\n",
                status_icon,
                match participant.status {
                    ParticipantStatus::Ready => "Ready",
                    ParticipantStatus::Joined => "Joined",
                    _ => "Waiting",
                }
            ));
            ui.push_str("║  │                                                                         │ ║\n");
        }

        ui.push_str(
            r#"║  └─────────────────────────────────────────────────────────────────────────┘ ║
║                                                                               ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║  COMPUTATION                                                                  ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
"#,
        );

        ui.push_str(&format!(
            "║  Function: {}                                      ║\n",
            clean_room.computation.name
        ));

        let inputs: Vec<_> = clean_room
            .computation
            .inputs
            .iter()
            .map(|i| format!("{}.{}", i.source_participant.0, i.source_variable))
            .collect();
        ui.push_str(&format!(
            "║  Inputs:  {}                    ║\n",
            inputs.join(" + ")
        ));

        ui.push_str("║  Outputs:\n");
        for output in &clean_room.computation.outputs {
            let vis = match &output.visibility {
                Visibility::Private => "private",
                Visibility::AllParticipants => "all participants",
                Visibility::Public => "public",
                Visibility::Shared(_) => "shared",
            };
            ui.push_str(&format!(
                "║    - {}: {:?} ({})\n",
                output.name, output.output_type, vis
            ));
        }

        ui.push_str(
            r#"║                                                                               ║
║  ┌─────────────────────────────────────────────────────────────────────────┐ ║
║  │  [👁️ View My Secrets]  [🔐 Contribute Data]  [▶️ Run Computation]       │ ║
║  └─────────────────────────────────────────────────────────────────────────┘ ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"#,
        );

        ui
    }
}

impl Default for CleanRoomEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of computation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputationResult {
    pub id: String,
    pub clean_room_id: String,
    pub outputs: Vec<ComputationOutput>,
    pub execution_time_ms: u64,
    pub tee_attestation: Option<Vec<u8>>,
    pub digital_seal_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputationOutput {
    pub name: String,
    pub value_hash: [u8; 32],
    pub visibility: Visibility,
}

#[derive(Debug, Clone)]
pub enum CleanRoomError {
    CleanRoomNotFound,
    ParticipantNotFound,
    InvitationNotFound,
    InvitationExpired,
    NotAuthorized,
    NotReady,
    AlreadyExecuted,
}

impl std::fmt::Display for CleanRoomError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CleanRoomError::CleanRoomNotFound => write!(f, "Clean room not found"),
            CleanRoomError::ParticipantNotFound => write!(f, "Participant not found"),
            CleanRoomError::InvitationNotFound => write!(f, "Invitation not found"),
            CleanRoomError::InvitationExpired => write!(f, "Invitation expired"),
            CleanRoomError::NotAuthorized => write!(f, "Not authorized"),
            CleanRoomError::NotReady => write!(f, "Clean room not ready for execution"),
            CleanRoomError::AlreadyExecuted => write!(f, "Computation already executed"),
        }
    }
}

impl std::error::Error for CleanRoomError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_clean_room() {
        let mut engine = CleanRoomEngine::new();

        let computation = Computation {
            name: "test_computation".to_string(),
            computation_type: ComputationType::SecureAggregation,
            inputs: vec![],
            outputs: vec![],
            code_hash: [0u8; 32],
            constraints: ExecutionConstraints {
                min_participants: 2,
                timeout_secs: 300,
                require_tee: true,
                require_zkml: false,
                allow_reexecution: false,
            },
        };

        let id = engine
            .create_clean_room(
                "Test Room".to_string(),
                "A test clean room".to_string(),
                ParticipantId("owner".to_string()),
                "Owner".to_string(),
                "Test Org".to_string(),
                computation,
            )
            .unwrap();

        assert!(engine.get_clean_room(&id).is_some());
    }
}
