//! Single-import prelude for defense.

pub use crate::fixtures::{DefenseFixture, DefenseFixtures};
pub use crate::regulators::{DefenseJurisdiction, RegulatorCitation, RegulatorView};
pub use crate::sandbox::{DefenseSandbox, DefenseSandboxBuilder};
pub use crate::workflows::autonomous_logistics::{
    AutonomousLogistics, AutonomousLogisticsSeal, MissionDecision, PlatformClass,
};
pub use crate::workflows::cyber_defense::{CyberDecision, CyberDefenseEvent, CyberDefenseSeal};
pub use crate::workflows::inspection_qa::{InspectionOutcome, InspectionQa, InspectionQaSeal};
pub use crate::workflows::sensor_fusion::{
    FusionClassification, SensorFusion, SensorFusionSeal, SensorSource,
};

pub use aethelred_sandbox_core::{
    audit::{AuditFormat, AuditTrail},
    error_code::{ErrorCategory, ErrorCode},
    verify::{VerificationReport, Verifier},
    DigitalSeal, EvidenceBundle, EvidenceLogEntry, ModelReference, RetentionClass, SandboxError,
    SandboxResult, SealEnvelope, Sector, Sha256Digest,
};
