//! GDPR Article 28 subprocessor register.
//!
//! Maps to **GDPR Art 28(2)+(4)** (subprocessor authorisation and
//! notification), **CCPA service-provider tracking**, and SOC 2 CC9.2
//! (vendor management). Every SaaS controller must maintain a
//! **subprocessor list** — a public register of every entity that
//! processes personal data on behalf of the controller. Customer-facing
//! contracts typically commit to a notification window (often 30 days)
//! before adding or replacing a subprocessor; affected customers can
//! object.
//!
//! ## Lifecycle
//!
//! `Proposed → NotificationSent → Approved | Objected | Withdrawn → Active → Retired`
//!
//! `Proposed` covers the internal-only stage before customer notice.
//! `NotificationSent` covers the customer-notice window. `Approved` /
//! `Objected` / `Withdrawn` close the notice phase. `Active` covers live
//! production processing. `Retired` covers post-removal historical record.
//!
//! Distinct from [`crate::third_party_risk`] (vendor risk register) and
//! [`crate::data_processing_agreement`] (the contract). This is the
//! **public-facing list** subject to per-customer notification.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

// =============================================================================
// SubprocessorStage
// =============================================================================

/// Lifecycle stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubprocessorStage {
    /// Internal proposal; no customer notice yet.
    Proposed,
    /// Customer notification sent; in objection window.
    NotificationSent,
    /// Notice window closed without objection; approved.
    Approved,
    /// One or more customers objected; not yet resolved.
    Objected,
    /// Withdrawn before going live (replaced or cancelled).
    Withdrawn,
    /// Live and processing data.
    Active,
    /// Removed from production; historical record retained.
    Retired,
}

impl SubprocessorStage {
    /// True if the subprocessor is currently authorised to process data.
    pub fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }

    /// True if no further state changes expected.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Retired | Self::Withdrawn)
    }
}

// =============================================================================
// ProcessingPurpose
// =============================================================================

/// Purpose for which data is processed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessingPurpose {
    /// Cloud hosting / compute / storage.
    Hosting,
    /// Customer support tooling.
    Support,
    /// Payment processing.
    Payments,
    /// Authentication / identity.
    Identity,
    /// Email / messaging delivery.
    Communications,
    /// Analytics / product telemetry.
    Analytics,
    /// Machine-learning model training / inference.
    Ml,
    /// Customer relationship management.
    Crm,
    /// Other.
    Other,
}

// =============================================================================
// DataCategory
// =============================================================================

/// Category of personal data shared with the subprocessor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataCategory {
    /// Account / contact data.
    AccountData,
    /// Authentication credentials.
    Credentials,
    /// Personal identifiers (name, address, government id).
    PersonalIdentifiers,
    /// Behavioural / usage data.
    BehaviouralData,
    /// Special-category data (health, biometrics, religion, ...).
    SpecialCategory,
    /// Payment / financial data.
    Financial,
    /// Communications content.
    CommunicationsContent,
    /// Other.
    Other,
}

// =============================================================================
// CustomerObjection
// =============================================================================

/// One customer objection to a proposed subprocessor.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CustomerObjection {
    /// Customer / tenant id.
    pub customer_id: String,
    /// RFC 3339 — when the objection was received.
    pub received_at: String,
    /// Free-text reason.
    pub reason: String,
    /// Resolution status: "open", "resolved", "escalated".
    pub status: String,
}

// =============================================================================
// SubprocessorEvent
// =============================================================================

/// One stage transition event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubprocessorEvent {
    /// RFC 3339.
    pub at: String,
    /// Actor.
    pub actor: String,
    /// Stage applied.
    pub stage: SubprocessorStage,
    /// Free-text note.
    pub note: String,
}

// =============================================================================
// SubprocessorEntry
// =============================================================================

/// One subprocessor record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubprocessorEntry {
    /// Unique id (e.g., "SP-2025-007").
    pub entry_id: String,
    /// Tenant scope (controller).
    pub tenant_id: String,
    /// Vendor name (e.g., "Acme Hosting Inc.").
    pub vendor_name: String,
    /// Vendor primary jurisdiction (ISO 3166 alpha-2).
    pub jurisdiction: String,
    /// Purposes for which data is processed.
    pub purposes: Vec<ProcessingPurpose>,
    /// Data categories shared.
    pub categories: Vec<DataCategory>,
    /// Optional URL to vendor's privacy notice / DPA.
    pub vendor_dpa_url: Option<String>,
    /// Linked DPA id (matches [`crate::data_processing_agreement`]).
    pub linked_dpa_id: Option<String>,
    /// Linked vendor id (matches [`crate::third_party_risk`]).
    pub linked_vendor_id: Option<String>,
    /// Current stage.
    pub stage: SubprocessorStage,
    /// RFC 3339 — when proposed.
    pub proposed_at: String,
    /// RFC 3339 — customer notification sent.
    pub notification_sent_at: Option<String>,
    /// Notice window closing time (proposed_at + notice_window_days).
    pub notice_closes_at: Option<String>,
    /// RFC 3339 — went live.
    pub activated_at: Option<String>,
    /// RFC 3339 — retired.
    pub retired_at: Option<String>,
    /// Customer objections received.
    pub objections: Vec<CustomerObjection>,
    /// Event log.
    pub events: Vec<SubprocessorEvent>,
    /// Free-form tags.
    pub tags: Vec<String>,
}

impl SubprocessorEntry {
    /// New `Proposed` entry.
    pub fn new(
        entry_id: impl Into<String>,
        tenant_id: impl Into<String>,
        vendor_name: impl Into<String>,
        jurisdiction: impl Into<String>,
        proposed_at: impl Into<String>,
    ) -> Self {
        Self {
            entry_id: entry_id.into(),
            tenant_id: tenant_id.into(),
            vendor_name: vendor_name.into(),
            jurisdiction: jurisdiction.into(),
            purposes: Vec::new(),
            categories: Vec::new(),
            vendor_dpa_url: None,
            linked_dpa_id: None,
            linked_vendor_id: None,
            stage: SubprocessorStage::Proposed,
            proposed_at: proposed_at.into(),
            notification_sent_at: None,
            notice_closes_at: None,
            activated_at: None,
            retired_at: None,
            objections: Vec::new(),
            events: Vec::new(),
            tags: Vec::new(),
        }
    }

    /// True if processing special-category data.
    pub fn processes_special_category(&self) -> bool {
        self.categories.contains(&DataCategory::SpecialCategory)
    }

    /// True if at least one objection is unresolved.
    pub fn has_unresolved_objection(&self) -> bool {
        self.objections.iter().any(|o| o.status == "open")
    }
}

// =============================================================================
// Lifecycle transition table
// =============================================================================

fn legal_transition(from: SubprocessorStage, to: SubprocessorStage) -> bool {
    use SubprocessorStage::*;
    matches!(
        (from, to),
        (Proposed, NotificationSent)
            | (Proposed, Withdrawn)
            | (NotificationSent, Approved)
            | (NotificationSent, Objected)
            | (NotificationSent, Withdrawn)
            | (Objected, Approved)
            | (Objected, Withdrawn)
            | (Approved, Active)
            | (Approved, Withdrawn)
            | (Active, Retired)
    )
}

// =============================================================================
// SubprocessorRegister
// =============================================================================

/// Thread-safe subprocessor register.
#[derive(Debug, Default)]
pub struct SubprocessorRegister {
    inner: RwLock<HashMap<String, SubprocessorEntry>>,
}

impl SubprocessorRegister {
    /// New empty register.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new proposed subprocessor.
    pub fn register(&self, entry: SubprocessorEntry) -> SandboxResult<()> {
        if !matches!(entry.stage, SubprocessorStage::Proposed) {
            return Err(SandboxError::Other(format!(
                "subprocessor must start Proposed, got {:?}",
                entry.stage
            )));
        }
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("subprocessor register poisoned".into()))?;
        if g.contains_key(&entry.entry_id) {
            return Err(SandboxError::Other(format!(
                "subprocessor already registered: {}",
                entry.entry_id
            )));
        }
        g.insert(entry.entry_id.clone(), entry);
        Ok(())
    }

    /// Apply a stage transition with timestamping side-effects.
    pub fn transition(
        &self,
        entry_id: &str,
        new_stage: SubprocessorStage,
        actor: impl Into<String>,
        note: impl Into<String>,
        at: impl Into<String>,
    ) -> SandboxResult<SubprocessorEntry> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("subprocessor register poisoned".into()))?;
        let e = g
            .get_mut(entry_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown subprocessor {entry_id}")))?;
        if !legal_transition(e.stage, new_stage) {
            return Err(SandboxError::Other(format!(
                "illegal transition {:?} -> {:?}",
                e.stage, new_stage
            )));
        }
        let when = at.into();
        e.stage = new_stage;
        e.events.push(SubprocessorEvent {
            at: when.clone(),
            actor: actor.into(),
            stage: new_stage,
            note: note.into(),
        });
        match new_stage {
            SubprocessorStage::NotificationSent => e.notification_sent_at = Some(when),
            SubprocessorStage::Active => e.activated_at = Some(when),
            SubprocessorStage::Retired => e.retired_at = Some(when),
            _ => {}
        }
        Ok(e.clone())
    }

    /// Set notice window deadline (typically `proposed_at +
    /// notice_window_days`).
    pub fn set_notice_closes(
        &self,
        entry_id: &str,
        closes_at: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("subprocessor register poisoned".into()))?;
        let e = g
            .get_mut(entry_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown subprocessor {entry_id}")))?;
        e.notice_closes_at = Some(closes_at.into());
        Ok(())
    }

    /// Add a processing purpose (deduplicated).
    pub fn add_purpose(
        &self,
        entry_id: &str,
        purpose: ProcessingPurpose,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("subprocessor register poisoned".into()))?;
        let e = g
            .get_mut(entry_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown subprocessor {entry_id}")))?;
        if !e.purposes.contains(&purpose) {
            e.purposes.push(purpose);
        }
        Ok(())
    }

    /// Add a data category (deduplicated).
    pub fn add_category(
        &self,
        entry_id: &str,
        category: DataCategory,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("subprocessor register poisoned".into()))?;
        let e = g
            .get_mut(entry_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown subprocessor {entry_id}")))?;
        if !e.categories.contains(&category) {
            e.categories.push(category);
        }
        Ok(())
    }

    /// Set linked vendor / DPA ids and vendor DPA URL.
    pub fn set_links(
        &self,
        entry_id: &str,
        vendor_id: Option<String>,
        dpa_id: Option<String>,
        vendor_dpa_url: Option<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("subprocessor register poisoned".into()))?;
        let e = g
            .get_mut(entry_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown subprocessor {entry_id}")))?;
        if let Some(v) = vendor_id {
            e.linked_vendor_id = Some(v);
        }
        if let Some(d) = dpa_id {
            e.linked_dpa_id = Some(d);
        }
        if let Some(u) = vendor_dpa_url {
            e.vendor_dpa_url = Some(u);
        }
        Ok(())
    }

    /// Record a customer objection during the notice window. Auto-moves
    /// stage from NotificationSent to Objected if not already.
    pub fn record_objection(
        &self,
        entry_id: &str,
        objection: CustomerObjection,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("subprocessor register poisoned".into()))?;
        let e = g
            .get_mut(entry_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown subprocessor {entry_id}")))?;
        if !matches!(
            e.stage,
            SubprocessorStage::NotificationSent | SubprocessorStage::Objected
        ) {
            return Err(SandboxError::Other(format!(
                "cannot record objection on {entry_id}: stage is {:?}",
                e.stage
            )));
        }
        e.objections.push(objection);
        if matches!(e.stage, SubprocessorStage::NotificationSent) {
            e.stage = SubprocessorStage::Objected;
        }
        Ok(())
    }

    /// Add a tag (deduplicated).
    pub fn add_tag(&self, entry_id: &str, tag: impl Into<String>) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("subprocessor register poisoned".into()))?;
        let e = g
            .get_mut(entry_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown subprocessor {entry_id}")))?;
        let tag = tag.into();
        if !e.tags.contains(&tag) {
            e.tags.push(tag);
        }
        Ok(())
    }

    /// Look up.
    pub fn get(&self, entry_id: &str) -> Option<SubprocessorEntry> {
        let g = self.inner.read().ok()?;
        g.get(entry_id).cloned()
    }

    /// All entries.
    pub fn all(&self) -> Vec<SubprocessorEntry> {
        match self.inner.read() {
            Ok(g) => g.values().cloned().collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Entries for a tenant.
    pub fn for_tenant(&self, tenant_id: &str) -> Vec<SubprocessorEntry> {
        self.all()
            .into_iter()
            .filter(|e| e.tenant_id == tenant_id)
            .collect()
    }

    /// Entries by stage.
    pub fn by_stage(&self, stage: SubprocessorStage) -> Vec<SubprocessorEntry> {
        self.all().into_iter().filter(|e| e.stage == stage).collect()
    }

    /// Currently active subprocessors (the published list).
    pub fn active(&self) -> Vec<SubprocessorEntry> {
        self.by_stage(SubprocessorStage::Active)
    }

    /// Entries currently in the customer notice window.
    pub fn in_notice_window(&self, now: &str) -> Vec<SubprocessorEntry> {
        self.all()
            .into_iter()
            .filter(|e| {
                matches!(e.stage, SubprocessorStage::NotificationSent)
                    && match e.notice_closes_at.as_deref() {
                        Some(c) => now < c,
                        None => true,
                    }
            })
            .collect()
    }

    /// Entries whose notice window has closed without resolution.
    pub fn notice_window_expired(&self, now: &str) -> Vec<SubprocessorEntry> {
        self.all()
            .into_iter()
            .filter(|e| {
                matches!(e.stage, SubprocessorStage::NotificationSent)
                    && match e.notice_closes_at.as_deref() {
                        Some(c) => now >= c,
                        None => false,
                    }
            })
            .collect()
    }

    /// Entries processing special-category data.
    pub fn processing_special_category(&self) -> Vec<SubprocessorEntry> {
        self.all()
            .into_iter()
            .filter(|e| e.processes_special_category())
            .collect()
    }

    /// Entries with unresolved objections.
    pub fn with_unresolved_objections(&self) -> Vec<SubprocessorEntry> {
        self.all()
            .into_iter()
            .filter(|e| e.has_unresolved_objection())
            .collect()
    }

    /// Number of entries.
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

    fn entry(id: &str) -> SubprocessorEntry {
        SubprocessorEntry::new(
            id,
            "tenant-a",
            format!("Vendor {id}"),
            "US",
            "2025-04-01T00:00:00Z",
        )
    }

    fn obj(customer: &str, status: &str) -> CustomerObjection {
        CustomerObjection {
            customer_id: customer.into(),
            received_at: "2025-04-15T00:00:00Z".into(),
            reason: "data residency concerns".into(),
            status: status.into(),
        }
    }

    #[test]
    fn register_and_get() {
        let r = SubprocessorRegister::new();
        r.register(entry("e1")).unwrap();
        let e = r.get("e1").unwrap();
        assert_eq!(e.stage, SubprocessorStage::Proposed);
    }

    #[test]
    fn duplicate_register_errors() {
        let r = SubprocessorRegister::new();
        r.register(entry("e1")).unwrap();
        let err = r.register(entry("e1")).unwrap_err();
        assert!(format!("{err}").contains("already registered"));
    }

    #[test]
    fn must_start_proposed() {
        let mut e = entry("e1");
        e.stage = SubprocessorStage::Active;
        let r = SubprocessorRegister::new();
        let err = r.register(e).unwrap_err();
        assert!(format!("{err}").contains("must start Proposed"));
    }

    #[test]
    fn legal_transitions() {
        use SubprocessorStage::*;
        assert!(legal_transition(Proposed, NotificationSent));
        assert!(legal_transition(NotificationSent, Approved));
        assert!(legal_transition(NotificationSent, Objected));
        assert!(legal_transition(Objected, Approved));
        assert!(legal_transition(Approved, Active));
        assert!(legal_transition(Active, Retired));
        // illegal
        assert!(!legal_transition(Proposed, Active));
        assert!(!legal_transition(Active, Approved));
        assert!(!legal_transition(Retired, Active));
    }

    #[test]
    fn happy_path_lifecycle() {
        let r = SubprocessorRegister::new();
        r.register(entry("e1")).unwrap();
        r.transition(
            "e1",
            SubprocessorStage::NotificationSent,
            "compliance",
            "30-day notice sent",
            "2025-04-02T00:00:00Z",
        )
        .unwrap();
        r.set_notice_closes("e1", "2025-05-02T00:00:00Z").unwrap();
        r.transition(
            "e1",
            SubprocessorStage::Approved,
            "compliance",
            "no objections",
            "2025-05-02T00:00:00Z",
        )
        .unwrap();
        r.transition(
            "e1",
            SubprocessorStage::Active,
            "platform",
            "live",
            "2025-05-15T00:00:00Z",
        )
        .unwrap();
        let e = r
            .transition(
                "e1",
                SubprocessorStage::Retired,
                "platform",
                "decommissioned",
                "2026-01-01T00:00:00Z",
            )
            .unwrap();
        assert_eq!(e.stage, SubprocessorStage::Retired);
        assert!(e.stage.is_terminal());
        assert_eq!(e.activated_at.as_deref(), Some("2025-05-15T00:00:00Z"));
        assert_eq!(e.retired_at.as_deref(), Some("2026-01-01T00:00:00Z"));
        assert_eq!(e.events.len(), 4);
    }

    #[test]
    fn record_objection_auto_moves_stage() {
        let r = SubprocessorRegister::new();
        r.register(entry("e1")).unwrap();
        r.transition(
            "e1",
            SubprocessorStage::NotificationSent,
            "x",
            "n",
            "2025-04-02T00:00:00Z",
        )
        .unwrap();
        r.record_objection("e1", obj("customer-1", "open")).unwrap();
        let e = r.get("e1").unwrap();
        assert_eq!(e.stage, SubprocessorStage::Objected);
        assert!(e.has_unresolved_objection());
    }

    #[test]
    fn record_objection_outside_window_errors() {
        let r = SubprocessorRegister::new();
        r.register(entry("e1")).unwrap();
        let err = r.record_objection("e1", obj("c1", "open")).unwrap_err();
        assert!(format!("{err}").contains("cannot record objection"));
    }

    #[test]
    fn add_purpose_category_dedupes() {
        let r = SubprocessorRegister::new();
        r.register(entry("e1")).unwrap();
        r.add_purpose("e1", ProcessingPurpose::Hosting).unwrap();
        r.add_purpose("e1", ProcessingPurpose::Hosting).unwrap();
        r.add_category("e1", DataCategory::AccountData).unwrap();
        r.add_category("e1", DataCategory::AccountData).unwrap();
        r.add_category("e1", DataCategory::SpecialCategory).unwrap();
        let e = r.get("e1").unwrap();
        assert_eq!(e.purposes, vec![ProcessingPurpose::Hosting]);
        assert_eq!(
            e.categories,
            vec![DataCategory::AccountData, DataCategory::SpecialCategory]
        );
        assert!(e.processes_special_category());
    }

    #[test]
    fn set_links() {
        let r = SubprocessorRegister::new();
        r.register(entry("e1")).unwrap();
        r.set_links(
            "e1",
            Some("VENDOR-007".into()),
            Some("DPA-2025-007".into()),
            Some("https://vendor.test/dpa".into()),
        )
        .unwrap();
        let e = r.get("e1").unwrap();
        assert_eq!(e.linked_vendor_id.as_deref(), Some("VENDOR-007"));
        assert_eq!(e.linked_dpa_id.as_deref(), Some("DPA-2025-007"));
        assert_eq!(e.vendor_dpa_url.as_deref(), Some("https://vendor.test/dpa"));
    }

    #[test]
    fn add_tag_dedupes() {
        let r = SubprocessorRegister::new();
        r.register(entry("e1")).unwrap();
        r.add_tag("e1", "us-east").unwrap();
        r.add_tag("e1", "us-east").unwrap();
        r.add_tag("e1", "regulated").unwrap();
        assert_eq!(r.get("e1").unwrap().tags, vec!["us-east", "regulated"]);
    }

    #[test]
    fn unknown_entry_errors() {
        let r = SubprocessorRegister::new();
        let err = r.add_purpose("nope", ProcessingPurpose::Hosting).unwrap_err();
        assert!(format!("{err}").contains("unknown subprocessor"));
    }

    #[test]
    fn for_tenant_filters() {
        let r = SubprocessorRegister::new();
        r.register(entry("e1")).unwrap();
        let mut other = entry("e2");
        other.tenant_id = "tenant-b".into();
        r.register(other).unwrap();
        assert_eq!(r.for_tenant("tenant-a").len(), 1);
        assert_eq!(r.for_tenant("tenant-b").len(), 1);
    }

    #[test]
    fn active_filter() {
        let r = SubprocessorRegister::new();
        r.register(entry("e1")).unwrap();
        r.register(entry("e2")).unwrap();
        // Drive e1 to Active
        for s in [
            SubprocessorStage::NotificationSent,
            SubprocessorStage::Approved,
            SubprocessorStage::Active,
        ] {
            r.transition("e1", s, "x", "n", "2025-04-02T00:00:00Z").unwrap();
        }
        let active = r.active();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].entry_id, "e1");
    }

    #[test]
    fn in_notice_window_query() {
        let r = SubprocessorRegister::new();
        r.register(entry("e1")).unwrap();
        r.transition(
            "e1",
            SubprocessorStage::NotificationSent,
            "x",
            "n",
            "2025-04-02T00:00:00Z",
        )
        .unwrap();
        r.set_notice_closes("e1", "2025-05-02T00:00:00Z").unwrap();
        // Inside window
        assert_eq!(r.in_notice_window("2025-04-15T00:00:00Z").len(), 1);
        // After window
        assert_eq!(r.in_notice_window("2025-05-15T00:00:00Z").len(), 0);
    }

    #[test]
    fn notice_window_expired_query() {
        let r = SubprocessorRegister::new();
        r.register(entry("e1")).unwrap();
        r.transition(
            "e1",
            SubprocessorStage::NotificationSent,
            "x",
            "n",
            "2025-04-02T00:00:00Z",
        )
        .unwrap();
        r.set_notice_closes("e1", "2025-05-02T00:00:00Z").unwrap();
        // After window — expired without resolution
        assert_eq!(r.notice_window_expired("2025-05-15T00:00:00Z").len(), 1);
        // Inside window — not expired
        assert_eq!(r.notice_window_expired("2025-04-15T00:00:00Z").len(), 0);
    }

    #[test]
    fn processing_special_category_filter() {
        let r = SubprocessorRegister::new();
        r.register(entry("e1")).unwrap();
        r.register(entry("e2")).unwrap();
        r.add_category("e1", DataCategory::SpecialCategory).unwrap();
        r.add_category("e2", DataCategory::AccountData).unwrap();
        let s = r.processing_special_category();
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].entry_id, "e1");
    }

    #[test]
    fn unresolved_objections_filter() {
        let r = SubprocessorRegister::new();
        r.register(entry("e1")).unwrap();
        r.transition(
            "e1",
            SubprocessorStage::NotificationSent,
            "x",
            "n",
            "2025-04-02T00:00:00Z",
        )
        .unwrap();
        r.record_objection("e1", obj("c1", "open")).unwrap();
        r.record_objection("e1", obj("c2", "resolved")).unwrap();
        let u = r.with_unresolved_objections();
        assert_eq!(u.len(), 1);
        assert!(u[0].has_unresolved_objection());
    }

    #[test]
    fn stage_helpers() {
        assert!(SubprocessorStage::Active.is_active());
        assert!(!SubprocessorStage::Approved.is_active());
        assert!(SubprocessorStage::Retired.is_terminal());
        assert!(SubprocessorStage::Withdrawn.is_terminal());
        assert!(!SubprocessorStage::Active.is_terminal());
    }

    #[test]
    fn count_tracks() {
        let r = SubprocessorRegister::new();
        assert_eq!(r.count(), 0);
        r.register(entry("e1")).unwrap();
        assert_eq!(r.count(), 1);
    }

    #[test]
    fn entry_serde() {
        let e = entry("e1");
        let j = serde_json::to_string(&e).unwrap();
        let back: SubprocessorEntry = serde_json::from_str(&j).unwrap();
        assert_eq!(e, back);
    }

    #[test]
    fn enums_serde() {
        for s in [
            SubprocessorStage::Proposed,
            SubprocessorStage::NotificationSent,
            SubprocessorStage::Approved,
            SubprocessorStage::Objected,
            SubprocessorStage::Withdrawn,
            SubprocessorStage::Active,
            SubprocessorStage::Retired,
        ] {
            assert_eq!(
                s,
                serde_json::from_str::<SubprocessorStage>(&serde_json::to_string(&s).unwrap())
                    .unwrap()
            );
        }
        for p in [
            ProcessingPurpose::Hosting,
            ProcessingPurpose::Support,
            ProcessingPurpose::Payments,
            ProcessingPurpose::Identity,
            ProcessingPurpose::Communications,
            ProcessingPurpose::Analytics,
            ProcessingPurpose::Ml,
            ProcessingPurpose::Crm,
            ProcessingPurpose::Other,
        ] {
            assert_eq!(
                p,
                serde_json::from_str::<ProcessingPurpose>(&serde_json::to_string(&p).unwrap())
                    .unwrap()
            );
        }
        for c in [
            DataCategory::AccountData,
            DataCategory::Credentials,
            DataCategory::PersonalIdentifiers,
            DataCategory::BehaviouralData,
            DataCategory::SpecialCategory,
            DataCategory::Financial,
            DataCategory::CommunicationsContent,
            DataCategory::Other,
        ] {
            assert_eq!(
                c,
                serde_json::from_str::<DataCategory>(&serde_json::to_string(&c).unwrap()).unwrap()
            );
        }
    }
}
