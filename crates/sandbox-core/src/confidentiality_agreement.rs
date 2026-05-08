//! Confidentiality / Non-Disclosure Agreement (NDA) register.
//!
//! Maps to **ISO 27001 A.13.2.4** (confidentiality / non-disclosure
//! agreements), **SOC 2 CC2.2** (information communication and
//! confidentiality), and contractual evidence under SOX §404. Every
//! employee, contractor, vendor representative, board member, and any
//! other party with access to confidential information must have a
//! signed NDA on file with a documented effective window.
//!
//! ## Lifecycle
//!
//! `Drafted → Sent → Signed → InEffect → (Expired | Terminated)`
//!
//! Bidirectional NDAs require both parties to sign before transitioning
//! from Sent → Signed; the registry validates this when
//! `signature_complete()` is asserted before `transition(Signed)`.
//!
//! Distinct from [`crate::data_processing_agreement`] (data-protection
//! contracts) and [`crate::access_certification`] (logical access
//! review): this is the **legal commitment** that underpins both.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

// =============================================================================
// AgreementKind
// =============================================================================

/// Kind of NDA.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgreementKind {
    /// One-way (controller's confidential info only).
    OneWay,
    /// Mutual (both parties exchange confidential info).
    Mutual,
    /// Multi-party (more than two parties).
    MultiParty,
    /// Embedded — confidentiality clauses inside another agreement
    /// (e.g., employment contract, MSA).
    EmbeddedInOther,
}

// =============================================================================
// PartyRole
// =============================================================================

/// Role of a counterparty.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PartyRole {
    /// Employee.
    Employee,
    /// Contractor / consultant.
    Contractor,
    /// Vendor representative.
    Vendor,
    /// Customer representative (under reciprocal NDA).
    Customer,
    /// Investor / advisor.
    Investor,
    /// Board member.
    BoardMember,
    /// Other.
    Other,
}

// =============================================================================
// AgreementStage
// =============================================================================

/// Lifecycle stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgreementStage {
    /// Drafted internally; not yet shared.
    Drafted,
    /// Sent to counterparty.
    Sent,
    /// All required parties have signed.
    Signed,
    /// Currently in effect.
    InEffect,
    /// Expired naturally.
    Expired,
    /// Terminated early.
    Terminated,
}

impl AgreementStage {
    /// True if no further state changes expected.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Expired | Self::Terminated)
    }

    /// True if currently authorising disclosure.
    pub fn is_in_effect(self) -> bool {
        matches!(self, Self::InEffect)
    }
}

// =============================================================================
// SignatureRecord
// =============================================================================

/// One signature event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignatureRecord {
    /// Party label (matches `parties`).
    pub party: String,
    /// Signer name / email.
    pub signer: String,
    /// RFC 3339.
    pub at: String,
    /// Optional signature reference.
    pub reference: Option<String>,
}

// =============================================================================
// PartyEntry
// =============================================================================

/// One party to the agreement.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PartyEntry {
    /// Party label (free text, used in signatures).
    pub party_id: String,
    /// Display name.
    pub display_name: String,
    /// Role.
    pub role: PartyRole,
    /// Required to sign? (false = optional witnesses).
    pub required: bool,
}

// =============================================================================
// ConfidentialityAgreement
// =============================================================================

/// One NDA record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConfidentialityAgreement {
    /// Unique id (e.g., "NDA-2025-007").
    pub agreement_id: String,
    /// Tenant scope.
    pub tenant_id: String,
    /// Kind.
    pub kind: AgreementKind,
    /// Title.
    pub title: String,
    /// Free-text scope description.
    pub scope: String,
    /// Parties.
    pub parties: Vec<PartyEntry>,
    /// Signatures collected.
    pub signatures: Vec<SignatureRecord>,
    /// Stage.
    pub stage: AgreementStage,
    /// Term in months (0 = perpetual; non-zero used to compute
    /// `expires_at` when entering InEffect).
    pub term_months: u32,
    /// Optional governing-law jurisdiction.
    pub governing_law: Option<String>,
    /// Document storage URI.
    pub document_uri: Option<String>,
    /// Document SHA-256.
    pub document_sha256: Option<String>,
    /// RFC 3339 — drafted.
    pub drafted_at: String,
    /// RFC 3339 — sent.
    pub sent_at: Option<String>,
    /// RFC 3339 — fully signed.
    pub signed_at: Option<String>,
    /// RFC 3339 — entered effect.
    pub effective_at: Option<String>,
    /// RFC 3339 — scheduled expiry.
    pub expires_at: Option<String>,
    /// RFC 3339 — closed (terminal).
    pub closed_at: Option<String>,
    /// Free-form tags.
    pub tags: Vec<String>,
}

impl ConfidentialityAgreement {
    /// New `Drafted` agreement.
    pub fn new(
        agreement_id: impl Into<String>,
        tenant_id: impl Into<String>,
        kind: AgreementKind,
        title: impl Into<String>,
        scope: impl Into<String>,
        term_months: u32,
        drafted_at: impl Into<String>,
    ) -> Self {
        Self {
            agreement_id: agreement_id.into(),
            tenant_id: tenant_id.into(),
            kind,
            title: title.into(),
            scope: scope.into(),
            parties: Vec::new(),
            signatures: Vec::new(),
            stage: AgreementStage::Drafted,
            term_months,
            governing_law: None,
            document_uri: None,
            document_sha256: None,
            drafted_at: drafted_at.into(),
            sent_at: None,
            signed_at: None,
            effective_at: None,
            expires_at: None,
            closed_at: None,
            tags: Vec::new(),
        }
    }

    /// True if every required party has at least one signature.
    pub fn signatures_complete(&self) -> bool {
        for p in &self.parties {
            if !p.required {
                continue;
            }
            if !self.signatures.iter().any(|s| s.party == p.party_id) {
                return false;
            }
        }
        !self.parties.is_empty()
    }

    /// Required parties still missing a signature.
    pub fn missing_signatures(&self) -> Vec<String> {
        self.parties
            .iter()
            .filter(|p| {
                p.required && !self.signatures.iter().any(|s| s.party == p.party_id)
            })
            .map(|p| p.party_id.clone())
            .collect()
    }

    /// True if the agreement is past its expiry date and still InEffect.
    pub fn is_overdue_review(&self, now: &str) -> bool {
        if !matches!(self.stage, AgreementStage::InEffect) {
            return false;
        }
        match self.expires_at.as_deref() {
            Some(e) => now >= e,
            None => false,
        }
    }
}

// =============================================================================
// Lifecycle transition table
// =============================================================================

fn legal_transition(from: AgreementStage, to: AgreementStage) -> bool {
    use AgreementStage::*;
    matches!(
        (from, to),
        (Drafted, Sent)
            | (Drafted, Terminated)
            | (Sent, Drafted) // re-draft after counterparty pushback
            | (Sent, Signed)
            | (Sent, Terminated)
            | (Signed, InEffect)
            | (Signed, Terminated)
            | (InEffect, Expired)
            | (InEffect, Terminated)
    )
}

// =============================================================================
// ConfidentialityAgreementRegistry
// =============================================================================

/// Thread-safe NDA registry.
#[derive(Debug, Default)]
pub struct ConfidentialityAgreementRegistry {
    inner: RwLock<HashMap<String, ConfidentialityAgreement>>,
}

impl ConfidentialityAgreementRegistry {
    /// New empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new draft.
    pub fn register(&self, agreement: ConfidentialityAgreement) -> SandboxResult<()> {
        if !matches!(agreement.stage, AgreementStage::Drafted) {
            return Err(SandboxError::Other(format!(
                "agreement must start Drafted, got {:?}",
                agreement.stage
            )));
        }
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("nda registry poisoned".into()))?;
        if g.contains_key(&agreement.agreement_id) {
            return Err(SandboxError::Other(format!(
                "agreement already registered: {}",
                agreement.agreement_id
            )));
        }
        g.insert(agreement.agreement_id.clone(), agreement);
        Ok(())
    }

    /// Add a party. Allowed only while the agreement is in Drafted or
    /// Sent (so re-drafts can adjust the party list).
    pub fn add_party(&self, agreement_id: &str, party: PartyEntry) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("nda registry poisoned".into()))?;
        let a = g
            .get_mut(agreement_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown agreement {agreement_id}")))?;
        if !matches!(a.stage, AgreementStage::Drafted | AgreementStage::Sent) {
            return Err(SandboxError::Other(format!(
                "cannot add party to {agreement_id}: stage is {:?}",
                a.stage
            )));
        }
        if a.parties.iter().any(|p| p.party_id == party.party_id) {
            return Err(SandboxError::Other(format!(
                "party already present: {}",
                party.party_id
            )));
        }
        a.parties.push(party);
        Ok(())
    }

    /// Record a signature. Allowed in Sent or Signed stage. Errors if the
    /// `party` is unknown.
    pub fn record_signature(
        &self,
        agreement_id: &str,
        signature: SignatureRecord,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("nda registry poisoned".into()))?;
        let a = g
            .get_mut(agreement_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown agreement {agreement_id}")))?;
        if !matches!(a.stage, AgreementStage::Sent | AgreementStage::Signed) {
            return Err(SandboxError::Other(format!(
                "cannot record signature on {agreement_id}: stage is {:?}",
                a.stage
            )));
        }
        if !a.parties.iter().any(|p| p.party_id == signature.party) {
            return Err(SandboxError::Other(format!(
                "unknown party in signature: {}",
                signature.party
            )));
        }
        a.signatures.push(signature);
        Ok(())
    }

    /// Apply a stage transition with timestamping. The Sent → Signed
    /// transition requires `signatures_complete()` to be true.
    pub fn transition(
        &self,
        agreement_id: &str,
        new_stage: AgreementStage,
        at: impl Into<String>,
    ) -> SandboxResult<ConfidentialityAgreement> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("nda registry poisoned".into()))?;
        let a = g
            .get_mut(agreement_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown agreement {agreement_id}")))?;
        if !legal_transition(a.stage, new_stage) {
            return Err(SandboxError::Other(format!(
                "illegal transition {:?} -> {:?}",
                a.stage, new_stage
            )));
        }
        if matches!(new_stage, AgreementStage::Signed) && !a.signatures_complete() {
            return Err(SandboxError::Other(format!(
                "cannot move {agreement_id} to Signed: missing required signatures from {:?}",
                a.missing_signatures()
            )));
        }
        let when = at.into();
        a.stage = new_stage;
        match new_stage {
            AgreementStage::Sent => a.sent_at = Some(when),
            AgreementStage::Signed => a.signed_at = Some(when),
            AgreementStage::InEffect => {
                a.effective_at = Some(when.clone());
                if a.term_months > 0 && a.expires_at.is_none() {
                    if let Some(exp) = add_months(&when, a.term_months) {
                        a.expires_at = Some(exp);
                    }
                }
            }
            AgreementStage::Expired | AgreementStage::Terminated => {
                a.closed_at = Some(when);
            }
            _ => {}
        }
        Ok(a.clone())
    }

    /// Set explicit expiry (overrides term-based default).
    pub fn set_expires(
        &self,
        agreement_id: &str,
        expires_at: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("nda registry poisoned".into()))?;
        let a = g
            .get_mut(agreement_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown agreement {agreement_id}")))?;
        a.expires_at = Some(expires_at.into());
        Ok(())
    }

    /// Set document storage references.
    pub fn set_document(
        &self,
        agreement_id: &str,
        uri: impl Into<String>,
        sha256: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("nda registry poisoned".into()))?;
        let a = g
            .get_mut(agreement_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown agreement {agreement_id}")))?;
        a.document_uri = Some(uri.into());
        a.document_sha256 = Some(sha256.into());
        Ok(())
    }

    /// Set governing law.
    pub fn set_governing_law(
        &self,
        agreement_id: &str,
        law: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("nda registry poisoned".into()))?;
        let a = g
            .get_mut(agreement_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown agreement {agreement_id}")))?;
        a.governing_law = Some(law.into());
        Ok(())
    }

    /// Add a tag (deduplicated).
    pub fn add_tag(&self, agreement_id: &str, tag: impl Into<String>) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("nda registry poisoned".into()))?;
        let a = g
            .get_mut(agreement_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown agreement {agreement_id}")))?;
        let tag = tag.into();
        if !a.tags.contains(&tag) {
            a.tags.push(tag);
        }
        Ok(())
    }

    /// Look up.
    pub fn get(&self, agreement_id: &str) -> Option<ConfidentialityAgreement> {
        let g = self.inner.read().ok()?;
        g.get(agreement_id).cloned()
    }

    /// All agreements.
    pub fn all(&self) -> Vec<ConfidentialityAgreement> {
        match self.inner.read() {
            Ok(g) => g.values().cloned().collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Agreements for a tenant.
    pub fn for_tenant(&self, tenant_id: &str) -> Vec<ConfidentialityAgreement> {
        self.all()
            .into_iter()
            .filter(|a| a.tenant_id == tenant_id)
            .collect()
    }

    /// Agreements involving a specific party.
    pub fn for_party(&self, party_id: &str) -> Vec<ConfidentialityAgreement> {
        self.all()
            .into_iter()
            .filter(|a| a.parties.iter().any(|p| p.party_id == party_id))
            .collect()
    }

    /// Agreements by stage.
    pub fn by_stage(&self, stage: AgreementStage) -> Vec<ConfidentialityAgreement> {
        self.all().into_iter().filter(|a| a.stage == stage).collect()
    }

    /// In-effect agreements.
    pub fn in_effect(&self) -> Vec<ConfidentialityAgreement> {
        self.by_stage(AgreementStage::InEffect)
    }

    /// In-effect agreements past their expiry.
    pub fn overdue_review(&self, now: &str) -> Vec<ConfidentialityAgreement> {
        self.all()
            .into_iter()
            .filter(|a| a.is_overdue_review(now))
            .collect()
    }

    /// Number of registered agreements.
    pub fn count(&self) -> usize {
        self.inner.read().map(|g| g.len()).unwrap_or(0)
    }
}

/// Add `months` to an RFC 3339 timestamp. Approximates by adding
/// `months * 30 days`. Returns RFC 3339 in UTC, or `None` if parsing fails.
fn add_months(rfc3339: &str, months: u32) -> Option<String> {
    use time::format_description::well_known::Rfc3339;
    let t = time::OffsetDateTime::parse(rfc3339, &Rfc3339).ok()?;
    let d = time::Duration::days(months as i64 * 30);
    (t + d).format(&Rfc3339).ok()
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn nda(id: &str) -> ConfidentialityAgreement {
        ConfidentialityAgreement::new(
            id,
            "tenant-a",
            AgreementKind::Mutual,
            format!("NDA {id}"),
            "Confidential information related to AI platform",
            24,
            "2025-04-01T00:00:00Z",
        )
    }

    fn party(id: &str, role: PartyRole, required: bool) -> PartyEntry {
        PartyEntry {
            party_id: id.into(),
            display_name: format!("Display-{id}"),
            role,
            required,
        }
    }

    fn sig(party: &str, signer: &str) -> SignatureRecord {
        SignatureRecord {
            party: party.into(),
            signer: signer.into(),
            at: "2025-04-15T00:00:00Z".into(),
            reference: Some("DOCUSIGN-NDA-007".into()),
        }
    }

    #[test]
    fn register_and_get() {
        let r = ConfidentialityAgreementRegistry::new();
        r.register(nda("n1")).unwrap();
        assert!(r.get("n1").is_some());
    }

    #[test]
    fn duplicate_register_errors() {
        let r = ConfidentialityAgreementRegistry::new();
        r.register(nda("n1")).unwrap();
        let err = r.register(nda("n1")).unwrap_err();
        assert!(format!("{err}").contains("already registered"));
    }

    #[test]
    fn must_start_drafted() {
        let mut a = nda("n1");
        a.stage = AgreementStage::Signed;
        let r = ConfidentialityAgreementRegistry::new();
        let err = r.register(a).unwrap_err();
        assert!(format!("{err}").contains("must start Drafted"));
    }

    #[test]
    fn legal_transitions() {
        use AgreementStage::*;
        assert!(legal_transition(Drafted, Sent));
        assert!(legal_transition(Sent, Signed));
        assert!(legal_transition(Sent, Drafted));
        assert!(legal_transition(Signed, InEffect));
        assert!(legal_transition(InEffect, Expired));
        // illegal
        assert!(!legal_transition(Drafted, Signed));
        assert!(!legal_transition(Drafted, InEffect));
        assert!(!legal_transition(Expired, InEffect));
    }

    #[test]
    fn happy_path_lifecycle() {
        let r = ConfidentialityAgreementRegistry::new();
        r.register(nda("n1")).unwrap();
        r.add_party("n1", party("controller", PartyRole::Other, true)).unwrap();
        r.add_party("n1", party("counterparty", PartyRole::Vendor, true))
            .unwrap();
        r.transition("n1", AgreementStage::Sent, "2025-04-05T00:00:00Z")
            .unwrap();
        r.record_signature("n1", sig("controller", "alice")).unwrap();
        r.record_signature("n1", sig("counterparty", "bob")).unwrap();
        r.transition("n1", AgreementStage::Signed, "2025-04-15T00:00:00Z")
            .unwrap();
        r.transition("n1", AgreementStage::InEffect, "2025-04-20T00:00:00Z")
            .unwrap();
        let a = r.get("n1").unwrap();
        assert_eq!(a.stage, AgreementStage::InEffect);
        assert!(a.expires_at.is_some());
        assert_eq!(a.signed_at.as_deref(), Some("2025-04-15T00:00:00Z"));
    }

    #[test]
    fn signed_requires_all_required_signatures() {
        let r = ConfidentialityAgreementRegistry::new();
        r.register(nda("n1")).unwrap();
        r.add_party("n1", party("controller", PartyRole::Other, true)).unwrap();
        r.add_party("n1", party("counterparty", PartyRole::Vendor, true))
            .unwrap();
        r.add_party("n1", party("witness", PartyRole::Other, false)).unwrap();
        r.transition("n1", AgreementStage::Sent, "2025-04-05T00:00:00Z")
            .unwrap();
        r.record_signature("n1", sig("controller", "alice")).unwrap();
        // Only one of the two required parties has signed
        let err = r
            .transition("n1", AgreementStage::Signed, "2025-04-15T00:00:00Z")
            .unwrap_err();
        assert!(format!("{err}").contains("missing required signatures"));
        // Sign the second required
        r.record_signature("n1", sig("counterparty", "bob")).unwrap();
        // Now Signed transition succeeds even though witness hasn't signed
        r.transition("n1", AgreementStage::Signed, "2025-04-15T00:00:00Z")
            .unwrap();
    }

    #[test]
    fn signatures_complete_helpers() {
        let r = ConfidentialityAgreementRegistry::new();
        r.register(nda("n1")).unwrap();
        // Empty parties → not complete
        assert!(!r.get("n1").unwrap().signatures_complete());
        r.add_party("n1", party("controller", PartyRole::Other, true)).unwrap();
        r.add_party("n1", party("counterparty", PartyRole::Vendor, true))
            .unwrap();
        let a = r.get("n1").unwrap();
        assert_eq!(
            a.missing_signatures(),
            vec!["controller".to_string(), "counterparty".to_string()]
        );
        assert!(!a.signatures_complete());
    }

    #[test]
    fn record_signature_unknown_party_errors() {
        let r = ConfidentialityAgreementRegistry::new();
        r.register(nda("n1")).unwrap();
        r.add_party("n1", party("controller", PartyRole::Other, true)).unwrap();
        r.transition("n1", AgreementStage::Sent, "2025-04-05T00:00:00Z")
            .unwrap();
        let err = r.record_signature("n1", sig("ghost", "x")).unwrap_err();
        assert!(format!("{err}").contains("unknown party"));
    }

    #[test]
    fn record_signature_outside_window_errors() {
        let r = ConfidentialityAgreementRegistry::new();
        r.register(nda("n1")).unwrap();
        r.add_party("n1", party("p1", PartyRole::Vendor, true)).unwrap();
        // Drafted → cannot sign
        let err = r.record_signature("n1", sig("p1", "alice")).unwrap_err();
        assert!(format!("{err}").contains("cannot record signature"));
    }

    #[test]
    fn add_party_dedupes() {
        let r = ConfidentialityAgreementRegistry::new();
        r.register(nda("n1")).unwrap();
        r.add_party("n1", party("p1", PartyRole::Vendor, true)).unwrap();
        let err = r
            .add_party("n1", party("p1", PartyRole::Customer, true))
            .unwrap_err();
        assert!(format!("{err}").contains("already present"));
    }

    #[test]
    fn add_party_after_signed_errors() {
        let r = ConfidentialityAgreementRegistry::new();
        r.register(nda("n1")).unwrap();
        r.add_party("n1", party("p1", PartyRole::Vendor, true)).unwrap();
        r.transition("n1", AgreementStage::Sent, "2025-04-05T00:00:00Z")
            .unwrap();
        r.record_signature("n1", sig("p1", "alice")).unwrap();
        r.transition("n1", AgreementStage::Signed, "2025-04-15T00:00:00Z")
            .unwrap();
        let err = r
            .add_party("n1", party("p2", PartyRole::Other, true))
            .unwrap_err();
        assert!(format!("{err}").contains("cannot add party"));
    }

    #[test]
    fn term_months_drives_default_expiry() {
        let r = ConfidentialityAgreementRegistry::new();
        let a = ConfidentialityAgreement::new(
            "n1",
            "tenant-a",
            AgreementKind::OneWay,
            "title",
            "scope",
            12,
            "2025-04-01T00:00:00Z",
        );
        r.register(a).unwrap();
        r.add_party("n1", party("p1", PartyRole::Vendor, true)).unwrap();
        r.transition("n1", AgreementStage::Sent, "2025-04-05T00:00:00Z")
            .unwrap();
        r.record_signature("n1", sig("p1", "alice")).unwrap();
        r.transition("n1", AgreementStage::Signed, "2025-04-15T00:00:00Z")
            .unwrap();
        r.transition("n1", AgreementStage::InEffect, "2025-04-20T00:00:00Z")
            .unwrap();
        let g = r.get("n1").unwrap();
        // 12 months ≈ 360 days from 2025-04-20 → 2026-04-15
        assert!(g.expires_at.is_some());
    }

    #[test]
    fn perpetual_term_no_default_expiry() {
        let r = ConfidentialityAgreementRegistry::new();
        let a = ConfidentialityAgreement::new(
            "n1",
            "tenant-a",
            AgreementKind::OneWay,
            "title",
            "scope",
            0,
            "2025-04-01T00:00:00Z",
        );
        r.register(a).unwrap();
        r.add_party("n1", party("p1", PartyRole::Vendor, true)).unwrap();
        r.transition("n1", AgreementStage::Sent, "2025-04-05T00:00:00Z")
            .unwrap();
        r.record_signature("n1", sig("p1", "alice")).unwrap();
        r.transition("n1", AgreementStage::Signed, "2025-04-15T00:00:00Z")
            .unwrap();
        r.transition("n1", AgreementStage::InEffect, "2025-04-20T00:00:00Z")
            .unwrap();
        assert!(r.get("n1").unwrap().expires_at.is_none());
    }

    #[test]
    fn set_expires_overrides_default() {
        let r = ConfidentialityAgreementRegistry::new();
        r.register(nda("n1")).unwrap();
        r.set_expires("n1", "2030-01-01T00:00:00Z").unwrap();
        assert_eq!(
            r.get("n1").unwrap().expires_at.as_deref(),
            Some("2030-01-01T00:00:00Z")
        );
    }

    #[test]
    fn overdue_review_only_in_effect() {
        let r = ConfidentialityAgreementRegistry::new();
        r.register(nda("n1")).unwrap();
        r.add_party("n1", party("p1", PartyRole::Vendor, true)).unwrap();
        r.transition("n1", AgreementStage::Sent, "2025-04-05T00:00:00Z")
            .unwrap();
        r.record_signature("n1", sig("p1", "alice")).unwrap();
        r.transition("n1", AgreementStage::Signed, "2025-04-15T00:00:00Z")
            .unwrap();
        r.set_expires("n1", "2026-01-01T00:00:00Z").unwrap();
        r.transition("n1", AgreementStage::InEffect, "2025-04-20T00:00:00Z")
            .unwrap();
        // Past expiry, in effect
        assert_eq!(r.overdue_review("2026-02-01T00:00:00Z").len(), 1);
        // Move to Expired → no longer overdue
        r.transition("n1", AgreementStage::Expired, "2026-02-01T00:00:00Z")
            .unwrap();
        assert_eq!(r.overdue_review("2026-02-01T00:00:00Z").len(), 0);
    }

    #[test]
    fn set_document_set_law() {
        let r = ConfidentialityAgreementRegistry::new();
        r.register(nda("n1")).unwrap();
        r.set_document("n1", "vault://nda/n1", "abcdef").unwrap();
        r.set_governing_law("n1", "Delaware").unwrap();
        let a = r.get("n1").unwrap();
        assert_eq!(a.document_uri.as_deref(), Some("vault://nda/n1"));
        assert_eq!(a.document_sha256.as_deref(), Some("abcdef"));
        assert_eq!(a.governing_law.as_deref(), Some("Delaware"));
    }

    #[test]
    fn add_tag_dedupes() {
        let r = ConfidentialityAgreementRegistry::new();
        r.register(nda("n1")).unwrap();
        r.add_tag("n1", "annual").unwrap();
        r.add_tag("n1", "annual").unwrap();
        r.add_tag("n1", "engineering").unwrap();
        assert_eq!(r.get("n1").unwrap().tags, vec!["annual", "engineering"]);
    }

    #[test]
    fn unknown_agreement_errors() {
        let r = ConfidentialityAgreementRegistry::new();
        let err = r.set_governing_law("nope", "Delaware").unwrap_err();
        assert!(format!("{err}").contains("unknown agreement"));
    }

    #[test]
    fn for_tenant_for_party_filters() {
        let r = ConfidentialityAgreementRegistry::new();
        r.register(nda("n1")).unwrap();
        r.add_party("n1", party("p1", PartyRole::Vendor, true)).unwrap();
        let mut other = nda("n2");
        other.tenant_id = "tenant-b".into();
        r.register(other).unwrap();
        r.add_party("n2", party("p2", PartyRole::Customer, true)).unwrap();
        assert_eq!(r.for_tenant("tenant-a").len(), 1);
        assert_eq!(r.for_tenant("tenant-b").len(), 1);
        assert_eq!(r.for_party("p1").len(), 1);
        assert_eq!(r.for_party("p2").len(), 1);
    }

    #[test]
    fn in_effect_filter() {
        let r = ConfidentialityAgreementRegistry::new();
        r.register(nda("n1")).unwrap();
        r.add_party("n1", party("p1", PartyRole::Vendor, true)).unwrap();
        r.transition("n1", AgreementStage::Sent, "2025-04-05T00:00:00Z")
            .unwrap();
        r.record_signature("n1", sig("p1", "alice")).unwrap();
        r.transition("n1", AgreementStage::Signed, "2025-04-15T00:00:00Z")
            .unwrap();
        r.transition("n1", AgreementStage::InEffect, "2025-04-20T00:00:00Z")
            .unwrap();
        assert_eq!(r.in_effect().len(), 1);
    }

    #[test]
    fn count_tracks() {
        let r = ConfidentialityAgreementRegistry::new();
        assert_eq!(r.count(), 0);
        r.register(nda("n1")).unwrap();
        assert_eq!(r.count(), 1);
    }

    #[test]
    fn stage_helpers() {
        assert!(AgreementStage::InEffect.is_in_effect());
        assert!(!AgreementStage::Signed.is_in_effect());
        assert!(AgreementStage::Expired.is_terminal());
        assert!(AgreementStage::Terminated.is_terminal());
        assert!(!AgreementStage::InEffect.is_terminal());
    }

    #[test]
    fn nda_serde() {
        let n = nda("n1");
        let j = serde_json::to_string(&n).unwrap();
        let back: ConfidentialityAgreement = serde_json::from_str(&j).unwrap();
        assert_eq!(n, back);
    }

    #[test]
    fn enums_serde() {
        for k in [
            AgreementKind::OneWay,
            AgreementKind::Mutual,
            AgreementKind::MultiParty,
            AgreementKind::EmbeddedInOther,
        ] {
            assert_eq!(
                k,
                serde_json::from_str::<AgreementKind>(&serde_json::to_string(&k).unwrap()).unwrap()
            );
        }
        for r in [
            PartyRole::Employee,
            PartyRole::Contractor,
            PartyRole::Vendor,
            PartyRole::Customer,
            PartyRole::Investor,
            PartyRole::BoardMember,
            PartyRole::Other,
        ] {
            assert_eq!(
                r,
                serde_json::from_str::<PartyRole>(&serde_json::to_string(&r).unwrap()).unwrap()
            );
        }
        for s in [
            AgreementStage::Drafted,
            AgreementStage::Sent,
            AgreementStage::Signed,
            AgreementStage::InEffect,
            AgreementStage::Expired,
            AgreementStage::Terminated,
        ] {
            assert_eq!(
                s,
                serde_json::from_str::<AgreementStage>(&serde_json::to_string(&s).unwrap())
                    .unwrap()
            );
        }
    }
}
