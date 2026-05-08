//! Single-import prelude for healthcare.

pub use crate::fixtures::{HealthcareFixture, HealthcareFixtures};
pub use crate::regulators::{HealthcareJurisdiction, RegulatorCitation, RegulatorView};
pub use crate::sandbox::{HealthcareSandbox, HealthcareSandboxBuilder};
pub use crate::workflows::ambient_scribe::{AmbientNote, AmbientNoteSeal, NoteSection};
pub use crate::workflows::claims::{ClaimDecision, ClaimsAdjudication, ClaimsAdjudicationSeal};
pub use crate::workflows::clinical_ai::{
    ClinicalInference, ClinicalInferenceSeal, ClinicalRecommendation, Modality,
};
pub use crate::workflows::genomics::{
    GenomicsDatasetClass, GenomicsInference, GenomicsInferenceSeal, ReferenceGenome,
    VariantClassification,
};

pub use aethelred_sandbox_core::{
    audit::{AuditFormat, AuditTrail},
    error_code::{ErrorCategory, ErrorCode},
    verify::{VerificationReport, Verifier},
    DigitalSeal, EvidenceBundle, EvidenceLogEntry, ModelReference, RetentionClass, SandboxError,
    SandboxResult, SealEnvelope, Sector, Sha256Digest,
};
