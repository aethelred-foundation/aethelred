//! `Sandbox` and `SandboxBuilder` — the plug-and-play entry surface every
//! sector crate composes.
//!
//! Sector crates wrap this builder behind a sector-specific façade. For
//! example, `aethelred-sandbox-finance::FinanceSandbox::builder()` returns
//! a builder pre-loaded with the finance gate set, finance regulator views,
//! and finance-specific defaults. This keeps the surface clean for
//! customers while letting the sector crate compose all the
//! sandbox-core primitives under the hood.
//!
//! ## Three escape hatches
//!
//! 1. **Quickstart**: one line, fully default. Used in demos.
//! 2. **Builder**: declarative configuration. Used in pilots.
//! 3. **Direct construction**: full control. Used in production
//!    integrations where the customer wants to inject their own connector,
//!    HSM, validator quorum, etc.

use crate::evidence::EvidenceLog;
use crate::policy::PolicyEngine;
use crate::sector::Sector;
use crate::seal::DigitalSeal;
use crate::tee::TeePlatform;
use crate::zkml::ProofSystem;
use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// Sandbox configuration. Defaults are conservative-friendly for design
/// partners (synthetic data, mock TEE, no zkML).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfig {
    /// Tenant id (the customer organisation, e.g., `"FAB"`).
    pub tenant_id: String,
    /// Sandbox display label.
    pub label: String,
    /// Jurisdiction tag (e.g., `"AE-CBUAE"`, `"EU"`).
    pub jurisdiction_tag: String,
    /// TEE platform.
    pub tee: TeePlatform,
    /// zkML proof system.
    pub zkml: ProofSystem,
    /// Whether the sandbox is allowed to use mock attestation. Production
    /// builds should set this to `false`.
    pub allow_mock_attestation: bool,
    /// Whether a non-zero validator-set signing key has been provisioned.
    pub validator_keys_provisioned: bool,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            tenant_id: "demo-tenant".into(),
            label: "Demo Sandbox".into(),
            jurisdiction_tag: "AE".into(),
            tee: TeePlatform::None,
            zkml: ProofSystem::None,
            allow_mock_attestation: true,
            validator_keys_provisioned: false,
        }
    }
}

/// Sandbox metadata — what the sector sandbox advertises about itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxMetadata {
    /// Sector.
    pub sector: Sector,
    /// Tenant id.
    pub tenant_id: String,
    /// Crate name (set by the sector crate).
    pub crate_name: &'static str,
    /// Crate version.
    pub crate_version: &'static str,
    /// All workflow ids exposed by the sector crate.
    pub workflows: Vec<&'static str>,
}

/// The sandbox runtime — owned by the sector sandbox.
///
/// This is the type sector crates store as a field on their public-facing
/// `<Sector>Sandbox` struct. End users almost never interact with it
/// directly; they call typed methods on the sector sandbox.
pub struct Sandbox {
    sector: Sector,
    config: SandboxConfig,
    policy: PolicyEngine,
    evidence: Arc<EvidenceLog>,
    crate_name: &'static str,
    crate_version: &'static str,
    workflows: Vec<&'static str>,
}

impl Sandbox {
    /// New builder.
    pub fn builder(sector: Sector) -> SandboxBuilder {
        SandboxBuilder::new(sector)
    }

    /// Sector.
    pub fn sector(&self) -> Sector {
        self.sector
    }

    /// Configuration.
    pub fn config(&self) -> &SandboxConfig {
        &self.config
    }

    /// Policy engine.
    pub fn policy(&self) -> &PolicyEngine {
        &self.policy
    }

    /// Evidence log.
    pub fn evidence(&self) -> Arc<EvidenceLog> {
        Arc::clone(&self.evidence)
    }

    /// Append a seal to the evidence log.
    pub fn append_seal(&self, seal: DigitalSeal) -> SandboxResult<crate::evidence::EvidenceLogEntry> {
        self.evidence.append(seal)
    }

    /// Append a batch of seals atomically (best-effort: all-or-nothing
    /// semantics are not provided — the underlying log is append-only and
    /// each successful append is durable). Returns the assigned entries in
    /// order.
    ///
    /// Stops at the first error and returns it. Already-appended entries
    /// remain in the log; callers can inspect [`Sandbox::evidence`] for
    /// recovery.
    pub fn append_seals(
        &self,
        seals: impl IntoIterator<Item = DigitalSeal>,
    ) -> SandboxResult<Vec<crate::evidence::EvidenceLogEntry>> {
        let mut out = Vec::new();
        for seal in seals {
            out.push(self.evidence.append(seal)?);
        }
        Ok(out)
    }

    /// Append a seal and immediately produce its [`crate::SealEnvelope`]
    /// (seal + Merkle proof). One-call enterprise convenience.
    pub fn append_and_envelope(
        &self,
        seal: DigitalSeal,
    ) -> SandboxResult<crate::seal::SealEnvelope> {
        let entry = self.evidence.append(seal)?;
        let proof = self.evidence.proof(entry.index)?;
        Ok(crate::seal::SealEnvelope {
            seal: entry.seal,
            merkle_proof: Some(proof),
            anchor_block_height: None,
        })
    }

    /// Append a batch of seals and return one envelope per seal.
    ///
    /// **Important semantics**: every envelope's Merkle proof is computed
    /// against the *final* state of the log after all appends complete.
    /// Therefore every envelope in the returned batch shares the same root,
    /// which is what enterprise reviewers expect when verifying a batch.
    /// Use [`Sandbox::append_and_envelope`] (singular) when you need
    /// per-append proofs.
    pub fn append_and_envelope_batch(
        &self,
        seals: impl IntoIterator<Item = DigitalSeal>,
    ) -> SandboxResult<Vec<crate::seal::SealEnvelope>> {
        let entries = self.append_seals(seals)?;
        let mut out = Vec::with_capacity(entries.len());
        for entry in entries {
            let proof = self.evidence.proof(entry.index)?;
            out.push(crate::seal::SealEnvelope {
                seal: entry.seal,
                merkle_proof: Some(proof),
                anchor_block_height: None,
            });
        }
        Ok(out)
    }

    /// Export the full evidence bundle (delegates to
    /// [`crate::EvidenceLog::export`]).
    pub fn export_evidence(&self) -> SandboxResult<crate::evidence::EvidenceBundle> {
        self.evidence.export(&self.config.tenant_id, self.sector)
    }

    /// Convenience: render an audit trail in the requested format.
    pub fn audit_trail(&self, format: crate::audit::AuditFormat) -> SandboxResult<String> {
        let bundle = self.export_evidence()?;
        let trail = crate::audit::AuditTrail::from_bundle(&bundle);
        Ok(trail.render(format))
    }

    /// Sandbox metadata snapshot (for catalogues, dashboards).
    pub fn metadata(&self) -> SandboxMetadata {
        SandboxMetadata {
            sector: self.sector,
            tenant_id: self.config.tenant_id.clone(),
            crate_name: self.crate_name,
            crate_version: self.crate_version,
            workflows: self.workflows.clone(),
        }
    }

    /// Number of seals currently in the evidence log.
    pub fn seal_count(&self) -> usize {
        self.evidence.len()
    }

    /// `true` if no seals have been appended yet.
    pub fn is_empty(&self) -> bool {
        self.evidence.is_empty()
    }

    /// Compute the current Merkle root of the evidence log.
    pub fn current_root(&self) -> SandboxResult<crate::Sha256Digest> {
        self.evidence.root()
    }

    /// Construct a [`crate::workflow::WorkflowContext`] bound to this
    /// sandbox. Caller may pass a per-run fault map (used in adversarial
    /// tests).
    pub fn context<'a>(
        &'a self,
        faults: &'a HashMap<String, bool>,
    ) -> crate::workflow::WorkflowContext<'a> {
        crate::workflow::WorkflowContext {
            policy: &self.policy,
            tenant_id: &self.config.tenant_id,
            faults,
        }
    }
}

/// Sandbox builder — the plug-and-play entry point.
///
/// Sector crates wrap this with a sector-specific façade. For example,
/// `FinanceSandbox::builder()` calls `Sandbox::builder(Sector::Finance)` and
/// pre-installs the finance gate set.
pub struct SandboxBuilder {
    sector: Sector,
    config: SandboxConfig,
    policy_gates: Vec<crate::policy::PolicyGate>,
    crate_name: Option<&'static str>,
    crate_version: Option<&'static str>,
    workflows: Vec<&'static str>,
}

impl SandboxBuilder {
    /// New builder for a sector.
    pub fn new(sector: Sector) -> Self {
        Self {
            sector,
            config: SandboxConfig::default(),
            policy_gates: Vec::new(),
            crate_name: None,
            crate_version: None,
            workflows: Vec::new(),
        }
    }

    /// Set the tenant id (the customer org).
    pub fn tenant(mut self, tenant_id: impl Into<String>) -> Self {
        self.config.tenant_id = tenant_id.into();
        self
    }

    /// Set the sandbox label.
    pub fn label(mut self, label: impl Into<String>) -> Self {
        self.config.label = label.into();
        self
    }

    /// Set the jurisdiction tag.
    pub fn jurisdiction(mut self, jurisdiction_tag: impl Into<String>) -> Self {
        self.config.jurisdiction_tag = jurisdiction_tag.into();
        self
    }

    /// Set the TEE platform.
    pub fn tee(mut self, tee: TeePlatform) -> Self {
        self.config.tee = tee;
        self
    }

    /// Set the zkML proof system.
    pub fn zkml(mut self, zkml: ProofSystem) -> Self {
        self.config.zkml = zkml;
        self
    }

    /// Disable mock attestation (production posture).
    pub fn disable_mock_attestation(mut self) -> Self {
        self.config.allow_mock_attestation = false;
        self
    }

    /// Mark validator keys as provisioned.
    pub fn validator_keys_provisioned(mut self, on: bool) -> Self {
        self.config.validator_keys_provisioned = on;
        self
    }

    /// Append a policy gate (sector crates use this to install their gate set).
    pub fn with_gate(mut self, gate: crate::policy::PolicyGate) -> Self {
        self.policy_gates.push(gate);
        self
    }

    /// Append many policy gates at once.
    pub fn with_gates(mut self, gates: impl IntoIterator<Item = crate::policy::PolicyGate>) -> Self {
        self.policy_gates.extend(gates);
        self
    }

    /// Sector-crate identification (sets `metadata.crate_name`).
    pub fn crate_name(mut self, name: &'static str) -> Self {
        self.crate_name = Some(name);
        self
    }

    /// Sector-crate version.
    pub fn crate_version(mut self, v: &'static str) -> Self {
        self.crate_version = Some(v);
        self
    }

    /// Register a workflow id (sector crates list their typed methods here).
    pub fn workflow(mut self, id: &'static str) -> Self {
        self.workflows.push(id);
        self
    }

    /// Build the sandbox. Returns `SandboxError::Configuration` if required
    /// fields were not set.
    pub fn build(self) -> SandboxResult<Sandbox> {
        let crate_name = self
            .crate_name
            .ok_or_else(|| SandboxError::config("crate_name not set"))?;
        let crate_version = self
            .crate_version
            .ok_or_else(|| SandboxError::config("crate_version not set"))?;
        if self.policy_gates.is_empty() {
            return Err(SandboxError::config(
                "no policy gates installed — sector crate must add at least one",
            ));
        }
        Ok(Sandbox {
            sector: self.sector,
            config: self.config,
            policy: PolicyEngine::new(self.policy_gates),
            evidence: Arc::new(EvidenceLog::new()),
            crate_name,
            crate_version,
            workflows: self.workflows,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hashing::Hasher;
    use crate::policy::PolicyGate;
    use crate::seal::{ApprovalRecord, ModelReference, RetentionClass, SealVersion};
    use std::collections::BTreeMap;
    use time::OffsetDateTime;
    use uuid::Uuid;

    fn dummy_seal() -> DigitalSeal {
        DigitalSeal {
            schema_version: SealVersion::V1,
            seal_id: Uuid::now_v7(),
            timestamp: OffsetDateTime::now_utc(),
            sector: Sector::Finance,
            event_type: "credit_decision".into(),
            event_hash: Hasher::sha256(b"event"),
            model: ModelReference::new("m", Hasher::sha256(b"w")),
            policy_id: "po".into(),
            input_hash: Hasher::sha256(b"i"),
            output_hash: Hasher::sha256(b"o"),
            approvals: vec![ApprovalRecord::unsigned("u", "r", "approved")],
            attestation: None,
            zk_proof: None,
            tenant_id: "FAB".into(),
            workflow_id: "credit_decision".into(),
            jurisdiction_tag: "AE".into(),
            retention: RetentionClass::SevenYears,
            prior_seal_hash: None,
            sector_extension: BTreeMap::new(),
            validator_signature_hex: None,
        }
    }

    fn fab_sandbox() -> Sandbox {
        SandboxBuilder::new(Sector::Finance)
            .tenant("FAB")
            .label("FAB Finance Sandbox")
            .jurisdiction("AE-CBUAE")
            .tee(TeePlatform::IntelTdx)
            .zkml(ProofSystem::Ezkl)
            .crate_name("aethelred-sandbox-finance")
            .crate_version("0.2.0")
            .workflow("credit_decision")
            .with_gate(PolicyGate::required("t.g", "G", "rule"))
            .build()
            .unwrap()
    }

    #[test]
    fn builder_requires_crate_identity_and_gates() {
        let r = SandboxBuilder::new(Sector::Finance).build();
        assert!(r.is_err(), "should require crate_name + gates");

        let r = SandboxBuilder::new(Sector::Finance)
            .crate_name("test")
            .crate_version("0.0.1")
            .build();
        assert!(r.is_err(), "should still require gates");

        let r = SandboxBuilder::new(Sector::Finance)
            .crate_name("test")
            .crate_version("0.0.1")
            .with_gate(PolicyGate::required("t.g", "G", "rule"))
            .build();
        assert!(r.is_ok(), "should succeed when both crate identity + gates set");
    }

    #[test]
    fn builder_records_metadata() {
        let s = fab_sandbox();
        assert_eq!(s.config().tenant_id, "FAB");
        assert_eq!(s.config().tee, TeePlatform::IntelTdx);
        let m = s.metadata();
        assert_eq!(m.sector, Sector::Finance);
        assert_eq!(m.workflows, vec!["credit_decision"]);
    }

    #[test]
    fn empty_sandbox_reports_empty() {
        let s = fab_sandbox();
        assert!(s.is_empty());
        assert_eq!(s.seal_count(), 0);
    }

    #[test]
    fn append_seals_batch_returns_one_entry_per_input() {
        let s = fab_sandbox();
        let seals: Vec<DigitalSeal> = (0..5).map(|_| dummy_seal()).collect();
        let entries = s.append_seals(seals).unwrap();
        assert_eq!(entries.len(), 5);
        assert_eq!(s.seal_count(), 5);
    }

    #[test]
    fn append_and_envelope_returns_proof() {
        let s = fab_sandbox();
        let env = s.append_and_envelope(dummy_seal()).unwrap();
        assert!(env.merkle_proof.is_some());
        let proof = env.merkle_proof.unwrap();
        assert!(proof.verify());
    }

    #[test]
    fn append_and_envelope_batch_returns_multiple() {
        let s = fab_sandbox();
        let envs = s
            .append_and_envelope_batch((0..3).map(|_| dummy_seal()))
            .unwrap();
        assert_eq!(envs.len(), 3);
        for env in &envs {
            assert!(env.merkle_proof.is_some());
        }
    }

    #[test]
    fn export_evidence_uses_sandbox_metadata() {
        let s = fab_sandbox();
        s.append_seal(dummy_seal()).unwrap();
        let bundle = s.export_evidence().unwrap();
        assert_eq!(bundle.tenant_id, "FAB");
        assert_eq!(bundle.sector, Sector::Finance);
    }

    #[test]
    fn current_root_changes_on_append() {
        let s = fab_sandbox();
        let r1 = s.current_root().unwrap();
        s.append_seal(dummy_seal()).unwrap();
        let r2 = s.current_root().unwrap();
        assert_ne!(r1, r2);
    }

    #[test]
    fn audit_trail_renders_in_three_formats() {
        let s = fab_sandbox();
        s.append_seal(dummy_seal()).unwrap();
        let txt = s.audit_trail(crate::audit::AuditFormat::PlainText).unwrap();
        let md = s.audit_trail(crate::audit::AuditFormat::Markdown).unwrap();
        let csv = s.audit_trail(crate::audit::AuditFormat::Csv).unwrap();
        assert!(!txt.is_empty());
        assert!(md.contains("|"));
        assert!(csv.starts_with("position,"));
    }
}
