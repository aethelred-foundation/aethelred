//! Data Processing Agreement (DPA) inventory.
//!
//! Maps to **GDPR Art 28** (data processor contracts), **CCPA service-
//! provider agreements**, **HIPAA Business Associate Agreements (BAAs)**,
//! and contractual due-diligence under SOC 2 CC9.2 and ISO 27001 A.15.1.2.
//! Every contract that covers personal-data processing — vendor DPA,
//! controller-controller DPA, BAA, Standard Contractual Clauses (SCC)
//! addendum — has a documented effective window, renewal cadence, and
//! review history.
//!
//! ## Lifecycle
//!
//! `Drafted → InReview → Signed → InEffect → (Renewed | Expired | Terminated)`
//!
//! `InEffect` is the live operational state. `Renewed` chains to a
//! successor agreement; `Expired` covers natural expiry; `Terminated`
//! covers early termination.
//!
//! Distinct from [`crate::subprocessor_register`] (the public list) and
//! [`crate::vendor_assessment`] (DDQ scoring): this is the **contract
//! inventory** itself, the artefact regulators ask for under "show me
//! the DPA you signed with vendor X."

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

// =============================================================================
// AgreementKind
// =============================================================================

/// Kind of agreement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgreementKind {
    /// Standard Data Processing Agreement (controller-processor).
    Dpa,
    /// Controller-controller agreement.
    ControllerController,
    /// Joint-controller agreement (GDPR Art 26).
    JointController,
    /// HIPAA Business Associate Agreement.
    Baa,
    /// Standard Contractual Clauses (cross-border addendum).
    Scc,
    /// Master Service Agreement with embedded data terms.
    Msa,
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
    /// Drafted internally; not yet shared with counterparty.
    Drafted,
    /// Under legal / counterparty review.
    InReview,
    /// Signed but not yet in effect.
    Signed,
    /// Currently in effect.
    InEffect,
    /// Renewed — chained to a successor.
    Renewed,
    /// Naturally expired.
    Expired,
    /// Terminated early by either party.
    Terminated,
}

impl AgreementStage {
    /// True if the agreement currently authorises processing.
    pub fn is_in_effect(self) -> bool {
        matches!(self, Self::InEffect)
    }

    /// True if no further state changes expected.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Renewed | Self::Expired | Self::Terminated)
    }
}

// =============================================================================
// SignatureRecord
// =============================================================================

/// One signature event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignatureRecord {
    /// Party signing ("controller", "processor", "data subject").
    pub party: String,
    /// Signer name / email.
    pub signer: String,
    /// RFC 3339.
    pub at: String,
    /// Optional signature reference (DocuSign envelope id, etc.).
    pub reference: Option<String>,
}

// =============================================================================
// ReviewRecord
// =============================================================================

/// One periodic-review event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReviewRecord {
    /// RFC 3339.
    pub at: String,
    /// Reviewer.
    pub reviewer: String,
    /// Outcome: "no_change", "amendment_required", "renew", "terminate".
    pub outcome: String,
    /// Optional note.
    pub note: Option<String>,
}

// =============================================================================
// DataProcessingAgreement
// =============================================================================

/// One DPA / BAA / SCC entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DataProcessingAgreement {
    /// Unique id (e.g., "DPA-2025-007").
    pub agreement_id: String,
    /// Tenant scope.
    pub tenant_id: String,
    /// Kind.
    pub kind: AgreementKind,
    /// Display title.
    pub title: String,
    /// Counterparty name.
    pub counterparty: String,
    /// Linked vendor id.
    pub linked_vendor_id: Option<String>,
    /// Linked subprocessor id.
    pub linked_subprocessor_id: Option<String>,
    /// Document storage URI.
    pub document_uri: Option<String>,
    /// SHA-256 of document bytes.
    pub document_sha256: Option<String>,
    /// Governing law jurisdiction.
    pub governing_law: Option<String>,
    /// Stage.
    pub stage: AgreementStage,
    /// Signatures.
    pub signatures: Vec<SignatureRecord>,
    /// Review history.
    pub reviews: Vec<ReviewRecord>,
    /// RFC 3339 — drafted.
    pub drafted_at: String,
    /// RFC 3339 — became effective (if InEffect).
    pub effective_at: Option<String>,
    /// RFC 3339 — scheduled to expire / due for renewal.
    pub expires_at: Option<String>,
    /// RFC 3339 — actually expired / terminated / renewed.
    pub closed_at: Option<String>,
    /// Successor agreement id (set on Renewed).
    pub successor_id: Option<String>,
    /// Predecessor agreement id (the agreement this one renewed).
    pub predecessor_id: Option<String>,
    /// Required review cadence in days (0 = no scheduled review).
    pub review_cadence_days: u64,
    /// Free-form tags.
    pub tags: Vec<String>,
}

impl DataProcessingAgreement {
    /// New `Drafted` agreement.
    pub fn new(
        agreement_id: impl Into<String>,
        tenant_id: impl Into<String>,
        kind: AgreementKind,
        title: impl Into<String>,
        counterparty: impl Into<String>,
        drafted_at: impl Into<String>,
    ) -> Self {
        Self {
            agreement_id: agreement_id.into(),
            tenant_id: tenant_id.into(),
            kind,
            title: title.into(),
            counterparty: counterparty.into(),
            linked_vendor_id: None,
            linked_subprocessor_id: None,
            document_uri: None,
            document_sha256: None,
            governing_law: None,
            stage: AgreementStage::Drafted,
            signatures: Vec::new(),
            reviews: Vec::new(),
            drafted_at: drafted_at.into(),
            effective_at: None,
            expires_at: None,
            closed_at: None,
            successor_id: None,
            predecessor_id: None,
            review_cadence_days: 0,
            tags: Vec::new(),
        }
    }

    /// True if `now >= expires_at` and stage is still InEffect.
    pub fn is_overdue_renewal(&self, now: &str) -> bool {
        if !matches!(self.stage, AgreementStage::InEffect) {
            return false;
        }
        match self.expires_at.as_deref() {
            Some(e) => now >= e,
            None => false,
        }
    }

    /// True if last review (or effective_at) is older than cadence.
    pub fn review_overdue(&self, now: &str) -> bool {
        if self.review_cadence_days == 0 || !matches!(self.stage, AgreementStage::InEffect) {
            return false;
        }
        let anchor = self
            .reviews
            .last()
            .map(|r| r.at.as_str())
            .or(self.effective_at.as_deref())
            .unwrap_or("");
        if anchor.is_empty() {
            return false;
        }
        match age_in_days(anchor, now) {
            Some(d) => d >= self.review_cadence_days as i64,
            None => false,
        }
    }
}

fn age_in_days(earlier: &str, later: &str) -> Option<i64> {
    use time::format_description::well_known::Rfc3339;
    let a = time::OffsetDateTime::parse(earlier, &Rfc3339).ok()?;
    let b = time::OffsetDateTime::parse(later, &Rfc3339).ok()?;
    Some((b - a).whole_days())
}

// =============================================================================
// Lifecycle transition table
// =============================================================================

fn legal_transition(from: AgreementStage, to: AgreementStage) -> bool {
    use AgreementStage::*;
    matches!(
        (from, to),
        (Drafted, InReview)
            | (Drafted, Terminated)
            | (InReview, Drafted)
            | (InReview, Signed)
            | (InReview, Terminated)
            | (Signed, InEffect)
            | (Signed, Terminated)
            | (InEffect, Renewed)
            | (InEffect, Expired)
            | (InEffect, Terminated)
    )
}

// =============================================================================
// DataProcessingAgreementRegistry
// =============================================================================

/// Thread-safe DPA registry.
#[derive(Debug, Default)]
pub struct DataProcessingAgreementRegistry {
    inner: RwLock<HashMap<String, DataProcessingAgreement>>,
}

impl DataProcessingAgreementRegistry {
    /// New empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new draft agreement.
    pub fn register(&self, agreement: DataProcessingAgreement) -> SandboxResult<()> {
        if !matches!(agreement.stage, AgreementStage::Drafted) {
            return Err(SandboxError::Other(format!(
                "agreement must start Drafted, got {:?}",
                agreement.stage
            )));
        }
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("dpa registry poisoned".into()))?;
        if g.contains_key(&agreement.agreement_id) {
            return Err(SandboxError::Other(format!(
                "agreement already registered: {}",
                agreement.agreement_id
            )));
        }
        g.insert(agreement.agreement_id.clone(), agreement);
        Ok(())
    }

    /// Apply a stage transition with timestamping side-effects.
    pub fn transition(
        &self,
        agreement_id: &str,
        new_stage: AgreementStage,
        at: impl Into<String>,
    ) -> SandboxResult<DataProcessingAgreement> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("dpa registry poisoned".into()))?;
        let a = g
            .get_mut(agreement_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown agreement {agreement_id}")))?;
        if !legal_transition(a.stage, new_stage) {
            return Err(SandboxError::Other(format!(
                "illegal transition {:?} -> {:?}",
                a.stage, new_stage
            )));
        }
        let when = at.into();
        a.stage = new_stage;
        match new_stage {
            AgreementStage::InEffect => a.effective_at = Some(when),
            AgreementStage::Renewed | AgreementStage::Expired | AgreementStage::Terminated => {
                a.closed_at = Some(when)
            }
            _ => {}
        }
        Ok(a.clone())
    }

    /// Record a signature on an agreement (must be InReview or Signed).
    pub fn record_signature(
        &self,
        agreement_id: &str,
        signature: SignatureRecord,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("dpa registry poisoned".into()))?;
        let a = g
            .get_mut(agreement_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown agreement {agreement_id}")))?;
        if !matches!(a.stage, AgreementStage::InReview | AgreementStage::Signed) {
            return Err(SandboxError::Other(format!(
                "cannot record signature on {agreement_id}: stage is {:?}",
                a.stage
            )));
        }
        a.signatures.push(signature);
        Ok(())
    }

    /// Record a periodic review.
    pub fn record_review(
        &self,
        agreement_id: &str,
        review: ReviewRecord,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("dpa registry poisoned".into()))?;
        let a = g
            .get_mut(agreement_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown agreement {agreement_id}")))?;
        a.reviews.push(review);
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
            .map_err(|_| SandboxError::Other("dpa registry poisoned".into()))?;
        let a = g
            .get_mut(agreement_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown agreement {agreement_id}")))?;
        a.document_uri = Some(uri.into());
        a.document_sha256 = Some(sha256.into());
        Ok(())
    }

    /// Set linked vendor / subprocessor / governing law.
    pub fn set_links(
        &self,
        agreement_id: &str,
        vendor_id: Option<String>,
        subprocessor_id: Option<String>,
        governing_law: Option<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("dpa registry poisoned".into()))?;
        let a = g
            .get_mut(agreement_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown agreement {agreement_id}")))?;
        if let Some(v) = vendor_id {
            a.linked_vendor_id = Some(v);
        }
        if let Some(s) = subprocessor_id {
            a.linked_subprocessor_id = Some(s);
        }
        if let Some(g) = governing_law {
            a.governing_law = Some(g);
        }
        Ok(())
    }

    /// Set expiry date.
    pub fn set_expires(
        &self,
        agreement_id: &str,
        expires_at: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("dpa registry poisoned".into()))?;
        let a = g
            .get_mut(agreement_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown agreement {agreement_id}")))?;
        a.expires_at = Some(expires_at.into());
        Ok(())
    }

    /// Set review cadence in days.
    pub fn set_review_cadence(
        &self,
        agreement_id: &str,
        days: u64,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("dpa registry poisoned".into()))?;
        let a = g
            .get_mut(agreement_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown agreement {agreement_id}")))?;
        a.review_cadence_days = days;
        Ok(())
    }

    /// Link a renewal: marks `older` Renewed, sets cross-references.
    /// `newer` must already be registered. Both must be in the same tenant.
    /// `older` must be currently InEffect.
    pub fn link_renewal(
        &self,
        older_id: &str,
        newer_id: &str,
        at: impl Into<String>,
    ) -> SandboxResult<()> {
        let when = at.into();
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("dpa registry poisoned".into()))?;
        let newer_tenant = g
            .get(newer_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown agreement {newer_id}")))?
            .tenant_id
            .clone();
        let older = g
            .get_mut(older_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown agreement {older_id}")))?;
        if older.tenant_id != newer_tenant {
            return Err(SandboxError::Other(format!(
                "tenant mismatch between {older_id} and {newer_id}"
            )));
        }
        if !matches!(older.stage, AgreementStage::InEffect) {
            return Err(SandboxError::Other(format!(
                "cannot renew {older_id}: stage is {:?}",
                older.stage
            )));
        }
        older.stage = AgreementStage::Renewed;
        older.closed_at = Some(when);
        older.successor_id = Some(newer_id.to_string());
        let newer = g.get_mut(newer_id).expect("checked");
        newer.predecessor_id = Some(older_id.to_string());
        Ok(())
    }

    /// Add a tag (deduplicated).
    pub fn add_tag(&self, agreement_id: &str, tag: impl Into<String>) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("dpa registry poisoned".into()))?;
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
    pub fn get(&self, agreement_id: &str) -> Option<DataProcessingAgreement> {
        let g = self.inner.read().ok()?;
        g.get(agreement_id).cloned()
    }

    /// All agreements.
    pub fn all(&self) -> Vec<DataProcessingAgreement> {
        match self.inner.read() {
            Ok(g) => g.values().cloned().collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Agreements for a tenant.
    pub fn for_tenant(&self, tenant_id: &str) -> Vec<DataProcessingAgreement> {
        self.all()
            .into_iter()
            .filter(|a| a.tenant_id == tenant_id)
            .collect()
    }

    /// Agreements for a counterparty.
    pub fn for_counterparty(&self, counterparty: &str) -> Vec<DataProcessingAgreement> {
        self.all()
            .into_iter()
            .filter(|a| a.counterparty == counterparty)
            .collect()
    }

    /// Agreements at a stage.
    pub fn by_stage(&self, stage: AgreementStage) -> Vec<DataProcessingAgreement> {
        self.all().into_iter().filter(|a| a.stage == stage).collect()
    }

    /// Currently in-effect agreements.
    pub fn in_effect(&self) -> Vec<DataProcessingAgreement> {
        self.by_stage(AgreementStage::InEffect)
    }

    /// In-effect agreements past their expiry at `now`.
    pub fn overdue_renewal(&self, now: &str) -> Vec<DataProcessingAgreement> {
        self.all()
            .into_iter()
            .filter(|a| a.is_overdue_renewal(now))
            .collect()
    }

    /// In-effect agreements whose periodic review is overdue.
    pub fn review_overdue(&self, now: &str) -> Vec<DataProcessingAgreement> {
        self.all()
            .into_iter()
            .filter(|a| a.review_overdue(now))
            .collect()
    }

    /// Number of agreements.
    pub fn count(&self) -> usize {
        self.inner.read().map(|g| g.len()).unwrap_or(0)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn dpa(id: &str) -> DataProcessingAgreement {
        DataProcessingAgreement::new(
            id,
            "tenant-a",
            AgreementKind::Dpa,
            format!("DPA {id}"),
            "Acme Corp",
            "2025-01-01T00:00:00Z",
        )
    }

    fn sig(party: &str, signer: &str) -> SignatureRecord {
        SignatureRecord {
            party: party.into(),
            signer: signer.into(),
            at: "2025-02-01T00:00:00Z".into(),
            reference: Some("DOCUSIGN-007".into()),
        }
    }

    fn rev(outcome: &str, at: &str) -> ReviewRecord {
        ReviewRecord {
            at: at.into(),
            reviewer: "compliance".into(),
            outcome: outcome.into(),
            note: None,
        }
    }

    #[test]
    fn register_and_get() {
        let r = DataProcessingAgreementRegistry::new();
        r.register(dpa("d1")).unwrap();
        assert!(r.get("d1").is_some());
    }

    #[test]
    fn duplicate_register_errors() {
        let r = DataProcessingAgreementRegistry::new();
        r.register(dpa("d1")).unwrap();
        let err = r.register(dpa("d1")).unwrap_err();
        assert!(format!("{err}").contains("already registered"));
    }

    #[test]
    fn must_start_drafted() {
        let mut a = dpa("d1");
        a.stage = AgreementStage::InEffect;
        let r = DataProcessingAgreementRegistry::new();
        let err = r.register(a).unwrap_err();
        assert!(format!("{err}").contains("must start Drafted"));
    }

    #[test]
    fn legal_transitions() {
        use AgreementStage::*;
        assert!(legal_transition(Drafted, InReview));
        assert!(legal_transition(InReview, Signed));
        assert!(legal_transition(InReview, Drafted));
        assert!(legal_transition(Signed, InEffect));
        assert!(legal_transition(InEffect, Renewed));
        assert!(legal_transition(InEffect, Expired));
        // illegal
        assert!(!legal_transition(Drafted, Signed));
        assert!(!legal_transition(Expired, InEffect));
        assert!(!legal_transition(Renewed, InEffect));
    }

    #[test]
    fn happy_path_lifecycle() {
        let r = DataProcessingAgreementRegistry::new();
        r.register(dpa("d1")).unwrap();
        r.transition("d1", AgreementStage::InReview, "2025-01-15T00:00:00Z")
            .unwrap();
        r.record_signature("d1", sig("controller", "alice")).unwrap();
        r.record_signature("d1", sig("processor", "bob")).unwrap();
        r.transition("d1", AgreementStage::Signed, "2025-02-01T00:00:00Z")
            .unwrap();
        r.transition("d1", AgreementStage::InEffect, "2025-02-15T00:00:00Z")
            .unwrap();
        let a = r
            .transition("d1", AgreementStage::Expired, "2026-02-15T00:00:00Z")
            .unwrap();
        assert_eq!(a.stage, AgreementStage::Expired);
        assert!(a.stage.is_terminal());
        assert_eq!(a.effective_at.as_deref(), Some("2025-02-15T00:00:00Z"));
        assert_eq!(a.closed_at.as_deref(), Some("2026-02-15T00:00:00Z"));
        assert_eq!(a.signatures.len(), 2);
    }

    #[test]
    fn record_signature_only_in_review_or_signed() {
        let r = DataProcessingAgreementRegistry::new();
        r.register(dpa("d1")).unwrap();
        let err = r
            .record_signature("d1", sig("controller", "alice"))
            .unwrap_err();
        assert!(format!("{err}").contains("cannot record signature"));
    }

    #[test]
    fn set_document_set_links_set_expires_set_cadence() {
        let r = DataProcessingAgreementRegistry::new();
        r.register(dpa("d1")).unwrap();
        r.set_document("d1", "vault://dpa/d1", "abcdef").unwrap();
        r.set_links(
            "d1",
            Some("VENDOR-007".into()),
            Some("SP-007".into()),
            Some("EU".into()),
        )
        .unwrap();
        r.set_expires("d1", "2026-12-31T23:59:59Z").unwrap();
        r.set_review_cadence("d1", 365).unwrap();
        let a = r.get("d1").unwrap();
        assert_eq!(a.document_uri.as_deref(), Some("vault://dpa/d1"));
        assert_eq!(a.document_sha256.as_deref(), Some("abcdef"));
        assert_eq!(a.linked_vendor_id.as_deref(), Some("VENDOR-007"));
        assert_eq!(a.linked_subprocessor_id.as_deref(), Some("SP-007"));
        assert_eq!(a.governing_law.as_deref(), Some("EU"));
        assert_eq!(a.expires_at.as_deref(), Some("2026-12-31T23:59:59Z"));
        assert_eq!(a.review_cadence_days, 365);
    }

    #[test]
    fn record_review_appends() {
        let r = DataProcessingAgreementRegistry::new();
        r.register(dpa("d1")).unwrap();
        r.record_review("d1", rev("no_change", "2025-03-01T00:00:00Z"))
            .unwrap();
        r.record_review("d1", rev("renew", "2026-01-01T00:00:00Z"))
            .unwrap();
        assert_eq!(r.get("d1").unwrap().reviews.len(), 2);
    }

    #[test]
    fn link_renewal_chains() {
        let r = DataProcessingAgreementRegistry::new();
        r.register(dpa("d1")).unwrap();
        r.transition("d1", AgreementStage::InReview, "2025-01-15T00:00:00Z")
            .unwrap();
        r.transition("d1", AgreementStage::Signed, "2025-02-01T00:00:00Z")
            .unwrap();
        r.transition("d1", AgreementStage::InEffect, "2025-02-15T00:00:00Z")
            .unwrap();
        r.register(dpa("d2")).unwrap();
        r.link_renewal("d1", "d2", "2026-02-15T00:00:00Z").unwrap();
        let old = r.get("d1").unwrap();
        let new = r.get("d2").unwrap();
        assert_eq!(old.stage, AgreementStage::Renewed);
        assert_eq!(old.successor_id.as_deref(), Some("d2"));
        assert_eq!(old.closed_at.as_deref(), Some("2026-02-15T00:00:00Z"));
        assert_eq!(new.predecessor_id.as_deref(), Some("d1"));
    }

    #[test]
    fn link_renewal_only_in_effect() {
        let r = DataProcessingAgreementRegistry::new();
        r.register(dpa("d1")).unwrap();
        r.register(dpa("d2")).unwrap();
        let err = r
            .link_renewal("d1", "d2", "2026-02-15T00:00:00Z")
            .unwrap_err();
        assert!(format!("{err}").contains("cannot renew"));
    }

    #[test]
    fn link_renewal_tenant_mismatch_errors() {
        let r = DataProcessingAgreementRegistry::new();
        r.register(dpa("d1")).unwrap();
        let mut other = dpa("d2");
        other.tenant_id = "tenant-b".into();
        r.register(other).unwrap();
        // Drive d1 to InEffect
        r.transition("d1", AgreementStage::InReview, "2025-01-15T00:00:00Z")
            .unwrap();
        r.transition("d1", AgreementStage::Signed, "2025-02-01T00:00:00Z")
            .unwrap();
        r.transition("d1", AgreementStage::InEffect, "2025-02-15T00:00:00Z")
            .unwrap();
        let err = r
            .link_renewal("d1", "d2", "2026-02-15T00:00:00Z")
            .unwrap_err();
        assert!(format!("{err}").contains("tenant mismatch"));
    }

    #[test]
    fn overdue_renewal_only_in_effect_past_expiry() {
        let r = DataProcessingAgreementRegistry::new();
        r.register(dpa("d1")).unwrap();
        r.transition("d1", AgreementStage::InReview, "2025-01-15T00:00:00Z")
            .unwrap();
        r.transition("d1", AgreementStage::Signed, "2025-02-01T00:00:00Z")
            .unwrap();
        r.transition("d1", AgreementStage::InEffect, "2025-02-15T00:00:00Z")
            .unwrap();
        r.set_expires("d1", "2026-02-15T00:00:00Z").unwrap();
        // Past expiry
        assert_eq!(r.overdue_renewal("2026-03-01T00:00:00Z").len(), 1);
        // Before expiry
        assert_eq!(r.overdue_renewal("2026-01-01T00:00:00Z").len(), 0);
        // Move to Expired → no longer overdue
        r.transition("d1", AgreementStage::Expired, "2026-02-15T00:00:00Z")
            .unwrap();
        assert_eq!(r.overdue_renewal("2026-03-01T00:00:00Z").len(), 0);
    }

    #[test]
    fn review_overdue_uses_last_review_when_present() {
        let r = DataProcessingAgreementRegistry::new();
        r.register(dpa("d1")).unwrap();
        r.transition("d1", AgreementStage::InReview, "2025-01-15T00:00:00Z")
            .unwrap();
        r.transition("d1", AgreementStage::Signed, "2025-02-01T00:00:00Z")
            .unwrap();
        r.transition("d1", AgreementStage::InEffect, "2025-02-15T00:00:00Z")
            .unwrap();
        r.set_review_cadence("d1", 365).unwrap();
        // Effective 2025-02-15; 2026-03-01 is 379d → overdue
        assert_eq!(r.review_overdue("2026-03-01T00:00:00Z").len(), 1);
        // Record a review on 2026-01-01 → reset the clock
        r.record_review("d1", rev("no_change", "2026-01-01T00:00:00Z"))
            .unwrap();
        assert_eq!(r.review_overdue("2026-06-01T00:00:00Z").len(), 0);
    }

    #[test]
    fn review_overdue_zero_cadence_never_due() {
        let r = DataProcessingAgreementRegistry::new();
        r.register(dpa("d1")).unwrap();
        r.transition("d1", AgreementStage::InReview, "2025-01-15T00:00:00Z")
            .unwrap();
        r.transition("d1", AgreementStage::Signed, "2025-02-01T00:00:00Z")
            .unwrap();
        r.transition("d1", AgreementStage::InEffect, "2025-02-15T00:00:00Z")
            .unwrap();
        // cadence stays 0
        assert!(r.review_overdue("2030-01-01T00:00:00Z").is_empty());
    }

    #[test]
    fn add_tag_dedupes() {
        let r = DataProcessingAgreementRegistry::new();
        r.register(dpa("d1")).unwrap();
        r.add_tag("d1", "annual").unwrap();
        r.add_tag("d1", "annual").unwrap();
        r.add_tag("d1", "eu").unwrap();
        assert_eq!(r.get("d1").unwrap().tags, vec!["annual", "eu"]);
    }

    #[test]
    fn unknown_agreement_errors() {
        let r = DataProcessingAgreementRegistry::new();
        let err = r.set_review_cadence("nope", 365).unwrap_err();
        assert!(format!("{err}").contains("unknown agreement"));
    }

    #[test]
    fn for_tenant_for_counterparty_filters() {
        let r = DataProcessingAgreementRegistry::new();
        r.register(dpa("d1")).unwrap();
        let mut other = dpa("d2");
        other.tenant_id = "tenant-b".into();
        other.counterparty = "Globex".into();
        r.register(other).unwrap();
        assert_eq!(r.for_tenant("tenant-a").len(), 1);
        assert_eq!(r.for_tenant("tenant-b").len(), 1);
        assert_eq!(r.for_counterparty("Acme Corp").len(), 1);
        assert_eq!(r.for_counterparty("Globex").len(), 1);
    }

    #[test]
    fn in_effect_filter() {
        let r = DataProcessingAgreementRegistry::new();
        r.register(dpa("d1")).unwrap();
        r.register(dpa("d2")).unwrap();
        r.transition("d1", AgreementStage::InReview, "2025-01-15T00:00:00Z")
            .unwrap();
        r.transition("d1", AgreementStage::Signed, "2025-02-01T00:00:00Z")
            .unwrap();
        r.transition("d1", AgreementStage::InEffect, "2025-02-15T00:00:00Z")
            .unwrap();
        let live = r.in_effect();
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].agreement_id, "d1");
    }

    #[test]
    fn stage_helpers() {
        assert!(AgreementStage::InEffect.is_in_effect());
        assert!(!AgreementStage::Signed.is_in_effect());
        assert!(AgreementStage::Renewed.is_terminal());
        assert!(AgreementStage::Expired.is_terminal());
        assert!(AgreementStage::Terminated.is_terminal());
        assert!(!AgreementStage::InEffect.is_terminal());
    }

    #[test]
    fn count_tracks() {
        let r = DataProcessingAgreementRegistry::new();
        assert_eq!(r.count(), 0);
        r.register(dpa("d1")).unwrap();
        assert_eq!(r.count(), 1);
    }

    #[test]
    fn agreement_serde() {
        let a = dpa("d1");
        let j = serde_json::to_string(&a).unwrap();
        let back: DataProcessingAgreement = serde_json::from_str(&j).unwrap();
        assert_eq!(a, back);
    }

    #[test]
    fn enums_serde() {
        for k in [
            AgreementKind::Dpa,
            AgreementKind::ControllerController,
            AgreementKind::JointController,
            AgreementKind::Baa,
            AgreementKind::Scc,
            AgreementKind::Msa,
            AgreementKind::Other,
        ] {
            assert_eq!(
                k,
                serde_json::from_str::<AgreementKind>(&serde_json::to_string(&k).unwrap()).unwrap()
            );
        }
        for s in [
            AgreementStage::Drafted,
            AgreementStage::InReview,
            AgreementStage::Signed,
            AgreementStage::InEffect,
            AgreementStage::Renewed,
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
