//! `DigitalSeal` — the canonical Aethelred AI-event evidence object.
//!
//! A seal binds together everything a downstream reviewer needs to verify a
//! single AI event: the model that ran, the environment it ran in, the input
//! and output policy classes, the human approvals, and the validator
//! signatures. The seal is **the** product of every sector workflow.
//!
//! ## Canonical schema
//!
//! Field set is stable as `SealVersion::V1`. Backwards-incompatible changes
//! bump the version. The schema is published in this crate's `schemas/`
//! directory under the `schema` feature.
//!
//! ## Serialisation
//!
//! Seals serialize to canonical JSON via `serde_json` with field order fixed
//! by struct declaration. For interop with external producers using
//! RFC 8785 JCS, callers should pre-canonicalise before hashing.

use crate::hashing::Sha256Digest;
use crate::sector::Sector;
use crate::tee::Attestation;
use crate::zkml::ProofArtefact;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use time::OffsetDateTime;
use uuid::Uuid;

/// Seal schema version. Forwards-only; immutable for shipped seals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SealVersion {
    /// Initial production schema.
    V1,
}

impl Default for SealVersion {
    fn default() -> Self {
        Self::V1
    }
}

/// Reference to the AI model that produced the sealed event.
///
/// `model_hash` is the SHA-256 of the canonical model artefact (weights or
/// merkleised weights pointer). `weights_commit_ref` is an optional Git /
/// MLflow / Hugging Face / artefact-store reference for forensic re-fetch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelReference {
    /// Cryptographic hash of the model artefact.
    pub model_hash: Sha256Digest,
    /// Human-readable model id (e.g., `"falcon-h1-7b"`, `"credit_risk_v3.2"`).
    pub model_id: String,
    /// Semantic version, where applicable.
    pub model_version: Option<String>,
    /// Optional pointer to an external commit / artefact registry.
    pub weights_commit_ref: Option<String>,
    /// Framework name (e.g., `"pytorch"`, `"onnx"`, `"tensorrt"`).
    pub framework: Option<String>,
    /// Framework version.
    pub framework_version: Option<String>,
    /// Training-data class identifier (sector-specific vocabulary).
    pub training_data_class: Option<String>,
}

impl ModelReference {
    /// Convenience: a fully-specified reference.
    pub fn new(model_id: impl Into<String>, model_hash: Sha256Digest) -> Self {
        Self {
            model_hash,
            model_id: model_id.into(),
            model_version: None,
            weights_commit_ref: None,
            framework: None,
            framework_version: None,
            training_data_class: None,
        }
    }
}

/// A single human-approval record bound to a seal.
///
/// `approver_ref` is anonymised by default (e.g., role + opaque id) to keep
/// PII off the wire. Production deployments may swap in a directory-issued
/// signed identity if their compliance posture requires it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRecord {
    /// Anonymised reference to the approver (e.g., `"role:underwriter#a3f1"`).
    pub approver_ref: String,
    /// Role (e.g., `"underwriter"`, `"radiologist"`, `"qp"`).
    pub role: String,
    /// Decision outcome (sector vocabulary; common values: `approved`,
    /// `rejected`, `escalated`, `overridden`).
    pub decision: String,
    /// Optional reason class (e.g., `"adverse_action_dti"`).
    pub reason_class: Option<String>,
    /// RFC 3339 timestamp of the approval action.
    #[serde(with = "time::serde::rfc3339")]
    pub timestamp: OffsetDateTime,
    /// Optional cryptographic signature (hybrid ECDSA + Dilithium-3, hex).
    pub signature_hex: Option<String>,
}

impl ApprovalRecord {
    /// Helper for sector workflows that don't yet bind a real signer.
    pub fn unsigned(
        approver_ref: impl Into<String>,
        role: impl Into<String>,
        decision: impl Into<String>,
    ) -> Self {
        Self {
            approver_ref: approver_ref.into(),
            role: role.into(),
            decision: decision.into(),
            reason_class: None,
            timestamp: OffsetDateTime::now_utc(),
            signature_hex: None,
        }
    }
}

/// Retention class for the seal — feeds the customer's records-of-processing
/// policy and regulator retention requirements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionClass {
    /// 1 year (commercial-only, low-stake).
    OneYear,
    /// 5 years (regulatory minimum for many regimes).
    FiveYears,
    /// 7 years (FATF Rec 11, IRS, common AML).
    SevenYears,
    /// 10 years (clinical, EU AI Act high-risk default).
    TenYears,
    /// 25 years (defense / mission AI).
    TwentyFiveYears,
    /// Indefinite (research, sovereign archive).
    Indefinite,
}

impl Default for RetentionClass {
    fn default() -> Self {
        Self::TenYears
    }
}

/// The canonical Digital Seal — sector-agnostic.
///
/// Sector crates extend the seal via the `sector_extension` field, which is a
/// free-form `BTreeMap<String, serde_json::Value>` for sector-specific data
/// (e.g., FHIR resource type for healthcare, FIX message type for finance).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DigitalSeal {
    /// Schema version.
    pub schema_version: SealVersion,

    /// Globally unique seal id (UUIDv7 — time-orderable).
    pub seal_id: Uuid,

    /// RFC 3339 timestamp at the customer connector.
    #[serde(with = "time::serde::rfc3339")]
    pub timestamp: OffsetDateTime,

    /// Sector that produced this seal.
    pub sector: Sector,

    /// Sector-specific event-type discriminator (e.g., `"clinical_inference"`).
    pub event_type: String,

    /// SHA-256 of the canonical event content tuple.
    pub event_hash: Sha256Digest,

    /// AI model that produced the event.
    pub model: ModelReference,

    /// Policy-class identifier (sector vocabulary; e.g., `"po_clin_radiology_v7"`).
    pub policy_id: String,

    /// Hash of the canonicalised input. Input itself never travels.
    pub input_hash: Sha256Digest,

    /// Hash of the canonicalised output. Output content never travels.
    pub output_hash: Sha256Digest,

    /// Human approvals bound to the event.
    pub approvals: Vec<ApprovalRecord>,

    /// Optional TEE attestation for the execution environment.
    pub attestation: Option<Attestation>,

    /// Optional zkML proof artefact reference.
    pub zk_proof: Option<ProofArtefact>,

    /// Tenant id (customer organisation identifier).
    pub tenant_id: String,

    /// Workflow id (per-sector vocabulary).
    pub workflow_id: String,

    /// Jurisdiction tag (e.g., `"AE"`, `"AE-AD-DOH"`, `"EU"`, `"US"`, `"UK"`).
    pub jurisdiction_tag: String,

    /// Retention class.
    pub retention: RetentionClass,

    /// Optional hash of the prior seal in a chained workflow (e.g., agent
    /// action trail).
    pub prior_seal_hash: Option<Sha256Digest>,

    /// Sector-specific extension fields. Sector crates own this namespace.
    #[serde(default)]
    pub sector_extension: BTreeMap<String, serde_json::Value>,

    /// Validator-quorum signature in hex (hybrid ECDSA + Dilithium-3).
    /// `None` until the seal is signed by the validator quorum.
    pub validator_signature_hex: Option<String>,
}

impl DigitalSeal {
    /// Compute the canonical hash of this seal's content excluding the
    /// validator signature. Used by the validator quorum to produce the
    /// signature, and by reviewers to verify it.
    pub fn pre_signature_hash(&self) -> crate::SandboxResult<Sha256Digest> {
        // Strip the signature, serialise canonically, hash.
        let mut clone = self.clone();
        clone.validator_signature_hex = None;
        crate::hashing::Hasher::hash_value(&clone)
    }

    /// Stable string id — `"seal_<uuid>"`. Used in audit URIs.
    pub fn id_string(&self) -> String {
        format!("seal_{}", self.seal_id)
    }

    /// Total number of approval records.
    pub fn approval_count(&self) -> usize {
        self.approvals.len()
    }

    /// `true` if the seal has at least one decision-class approval.
    pub fn has_approval(&self, decision: &str) -> bool {
        self.approvals.iter().any(|a| a.decision == decision)
    }
}

/// A seal envelope — the seal plus an optional Merkle proof of inclusion in
/// an evidence log. This is what reviewers and regulators receive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealEnvelope {
    /// The seal itself.
    pub seal: DigitalSeal,
    /// Optional Merkle proof of the seal's inclusion in an [`crate::EvidenceLog`].
    pub merkle_proof: Option<crate::evidence::MerkleProof>,
    /// Optional anchored block height (from the Aethelred mainnet, when
    /// production-anchored).
    pub anchor_block_height: Option<u64>,
}

impl SealEnvelope {
    /// Construct an envelope with no anchor proof yet.
    pub fn unanchored(seal: DigitalSeal) -> Self {
        Self {
            seal,
            merkle_proof: None,
            anchor_block_height: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hashing::Hasher;
    use uuid::Uuid;

    fn dummy_seal() -> DigitalSeal {
        DigitalSeal {
            schema_version: SealVersion::V1,
            seal_id: Uuid::now_v7(),
            timestamp: OffsetDateTime::now_utc(),
            sector: Sector::Finance,
            event_type: "credit_decision".into(),
            event_hash: Hasher::sha256(b"event"),
            model: ModelReference::new("credit_risk_v3.2", Hasher::sha256(b"weights")),
            policy_id: "po_credit_v1".into(),
            input_hash: Hasher::sha256(b"input"),
            output_hash: Hasher::sha256(b"output"),
            approvals: vec![ApprovalRecord::unsigned(
                "role:underwriter#a3f1",
                "underwriter",
                "approved",
            )],
            attestation: None,
            zk_proof: None,
            tenant_id: "FAB".into(),
            workflow_id: "credit_decision".into(),
            jurisdiction_tag: "AE-CBUAE".into(),
            retention: RetentionClass::SevenYears,
            prior_seal_hash: None,
            sector_extension: BTreeMap::new(),
            validator_signature_hex: None,
        }
    }

    #[test]
    fn pre_signature_hash_excludes_validator_signature() {
        let mut seal = dummy_seal();
        let h1 = seal.pre_signature_hash().unwrap();
        seal.validator_signature_hex = Some("deadbeef".into());
        let h2 = seal.pre_signature_hash().unwrap();
        assert_eq!(h1, h2, "validator signature must not affect pre-sig hash");
    }

    #[test]
    fn id_string_uses_seal_prefix() {
        let s = dummy_seal();
        assert!(s.id_string().starts_with("seal_"));
    }

    #[test]
    fn json_roundtrip() {
        let s = dummy_seal();
        let j = serde_json::to_string(&s).unwrap();
        let s2: DigitalSeal = serde_json::from_str(&j).unwrap();
        assert_eq!(s.event_hash, s2.event_hash);
        assert_eq!(s.policy_id, s2.policy_id);
    }
}
