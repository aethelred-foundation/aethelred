//! Effective-dated rate card registry.
//!
//! Distinct from [`crate::billing_meter`]'s `RateCard` (which is the
//! *active* rate sheet used to price usage events) and from
//! [`crate::llm_cost_meter`]'s LLM rate card, this module is the
//! **versioning layer**: every rate card has an effective_at /
//! effective_until window, and `current_at(now)` resolves which version
//! of a card is in force at any given timestamp.
//!
//! Maps to FinOps Foundation "Pricing & Discounting" capability and is
//! the source-of-truth that auditors examine when asking "why was this
//! invoice priced at $X on April 15?".
//!
//! ## Effective windows
//!
//! Versions form an ordered chain per `card_name`. They must not overlap;
//! the registry enforces non-overlap on registration. A version with a
//! `None` effective_until is open-ended (current).

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

// =============================================================================
// VersionStatus
// =============================================================================

/// Lifecycle status of a rate-card version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VersionStatus {
    /// Drafted, not yet effective.
    Draft,
    /// Currently authoritative.
    Active,
    /// Superseded by a later version.
    Superseded,
    /// Discarded without being effective.
    Discarded,
}

impl VersionStatus {
    /// True if no further state changes expected.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Superseded | Self::Discarded)
    }
}

// =============================================================================
// RateLine
// =============================================================================

/// One priced line on a rate card.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RateLine {
    /// Stable id within the card.
    pub line_id: String,
    /// Display label.
    pub label: String,
    /// SKU / unit code.
    pub unit: String,
    /// Price per unit, in micro-units (1 USD = 1_000_000).
    pub price_micro: i64,
    /// Optional discount percentage (basis points; 1_000 = 10.00%).
    pub discount_bp: Option<u32>,
    /// Optional minimum-commitment quantity at this rate.
    pub min_quantity: Option<u64>,
}

// =============================================================================
// RateCardVersion
// =============================================================================

/// One versioned rate card entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RateCardVersion {
    /// Unique id (e.g., "RC-LLM-v3").
    pub version_id: String,
    /// Card name (groups versions of the same card).
    pub card_name: String,
    /// Tenant scope (use "global" for tenant-wide cards).
    pub tenant_id: String,
    /// Display title.
    pub title: String,
    /// Long description.
    pub description: String,
    /// Currency.
    pub currency: String,
    /// Lines.
    pub lines: Vec<RateLine>,
    /// Lifecycle status.
    pub status: VersionStatus,
    /// RFC 3339 — when this version becomes effective.
    pub effective_at: String,
    /// RFC 3339 — when this version stops being effective (exclusive).
    /// `None` = open-ended.
    pub effective_until: Option<String>,
    /// RFC 3339 — drafted.
    pub drafted_at: String,
    /// Owner / approver.
    pub owner: String,
    /// Optional reference to a previous version this supersedes.
    pub supersedes: Option<String>,
    /// Optional reference to a successor (set when superseded).
    pub superseded_by: Option<String>,
    /// Free-form tags.
    pub tags: Vec<String>,
}

impl RateCardVersion {
    /// New `Draft` version.
    pub fn new(
        version_id: impl Into<String>,
        card_name: impl Into<String>,
        tenant_id: impl Into<String>,
        title: impl Into<String>,
        description: impl Into<String>,
        currency: impl Into<String>,
        owner: impl Into<String>,
        effective_at: impl Into<String>,
        drafted_at: impl Into<String>,
    ) -> Self {
        Self {
            version_id: version_id.into(),
            card_name: card_name.into(),
            tenant_id: tenant_id.into(),
            title: title.into(),
            description: description.into(),
            currency: currency.into(),
            lines: Vec::new(),
            status: VersionStatus::Draft,
            effective_at: effective_at.into(),
            effective_until: None,
            drafted_at: drafted_at.into(),
            owner: owner.into(),
            supersedes: None,
            superseded_by: None,
            tags: Vec::new(),
        }
    }

    /// True if `now` falls in `[effective_at, effective_until)` and the
    /// version is currently `Active`.
    pub fn covers(&self, now: &str) -> bool {
        if !matches!(self.status, VersionStatus::Active) {
            return false;
        }
        if now < self.effective_at.as_str() {
            return false;
        }
        match self.effective_until.as_deref() {
            Some(end) => now < end,
            None => true,
        }
    }

    /// Look up a line by id.
    pub fn line(&self, line_id: &str) -> Option<&RateLine> {
        self.lines.iter().find(|l| l.line_id == line_id)
    }
}

// =============================================================================
// RateCardRegistry
// =============================================================================

/// Thread-safe rate-card registry.
#[derive(Debug, Default)]
pub struct RateCardRegistry {
    inner: RwLock<HashMap<String, RateCardVersion>>,
}

impl RateCardRegistry {
    /// New empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new version. Errors on duplicate id or malformed window
    /// (effective_at >= effective_until). Drafts are *not* checked for
    /// overlap against active peers — that check fires at `activate()`.
    /// This intentional looseness lets operators draft a successor whose
    /// window overlaps the open-ended incumbent ahead of calling
    /// `supersede(older, newer)` (which closes the incumbent's window).
    pub fn register(&self, version: RateCardVersion) -> SandboxResult<()> {
        if let Some(end) = &version.effective_until {
            if end <= &version.effective_at {
                return Err(SandboxError::Other(format!(
                    "version {} window malformed: effective_at {} >= effective_until {}",
                    version.version_id, version.effective_at, end
                )));
            }
        }
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("rate card registry poisoned".into()))?;
        if g.contains_key(&version.version_id) {
            return Err(SandboxError::Other(format!(
                "version already registered: {}",
                version.version_id
            )));
        }
        g.insert(version.version_id.clone(), version);
        Ok(())
    }

    /// Add a line to a Draft version.
    pub fn add_line(&self, version_id: &str, line: RateLine) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("rate card registry poisoned".into()))?;
        let v = g
            .get_mut(version_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown version {version_id}")))?;
        if !matches!(v.status, VersionStatus::Draft) {
            return Err(SandboxError::Other(format!(
                "cannot add line to {version_id}: status is {:?}",
                v.status
            )));
        }
        if v.lines.iter().any(|l| l.line_id == line.line_id) {
            return Err(SandboxError::Other(format!(
                "line already present: {}",
                line.line_id
            )));
        }
        v.lines.push(line);
        Ok(())
    }

    /// Activate a Draft version. Re-checks overlap against all other
    /// Active versions of the same card (because a Draft may have been
    /// registered without conflict but a peer might have activated since).
    pub fn activate(&self, version_id: &str) -> SandboxResult<RateCardVersion> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("rate card registry poisoned".into()))?;
        // First read peer overlap.
        let target = g
            .get(version_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown version {version_id}")))?
            .clone();
        if !matches!(target.status, VersionStatus::Draft) {
            return Err(SandboxError::Other(format!(
                "cannot activate {version_id}: status is {:?}",
                target.status
            )));
        }
        if target.lines.is_empty() {
            return Err(SandboxError::Other(format!(
                "cannot activate {version_id}: no lines"
            )));
        }
        for existing in g.values() {
            if existing.version_id == version_id
                || existing.card_name != target.card_name
                || existing.tenant_id != target.tenant_id
                || !matches!(existing.status, VersionStatus::Active)
            {
                continue;
            }
            if windows_overlap(
                &target.effective_at,
                target.effective_until.as_deref(),
                &existing.effective_at,
                existing.effective_until.as_deref(),
            ) {
                return Err(SandboxError::Other(format!(
                    "version {version_id} overlaps active version {} of card {}",
                    existing.version_id, target.card_name
                )));
            }
        }
        let v = g.get_mut(version_id).expect("checked");
        v.status = VersionStatus::Active;
        Ok(v.clone())
    }

    /// Mark a Draft version Discarded.
    pub fn discard(&self, version_id: &str) -> SandboxResult<RateCardVersion> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("rate card registry poisoned".into()))?;
        let v = g
            .get_mut(version_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown version {version_id}")))?;
        if !matches!(v.status, VersionStatus::Draft) {
            return Err(SandboxError::Other(format!(
                "cannot discard {version_id}: status is {:?}",
                v.status
            )));
        }
        v.status = VersionStatus::Discarded;
        Ok(v.clone())
    }

    /// Supersede an Active version with a successor. Sets
    /// `older.superseded_by`, `older.effective_until` (if not already set)
    /// to `older.effective_until.unwrap_or(successor.effective_at)`,
    /// transitions older to Superseded, and links `successor.supersedes`.
    /// The successor must already be registered (Draft or Active).
    pub fn supersede(&self, older_id: &str, newer_id: &str) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("rate card registry poisoned".into()))?;
        // Read the successor to grab its effective_at.
        let newer = g
            .get(newer_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown version {newer_id}")))?
            .clone();
        let older = g
            .get_mut(older_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown version {older_id}")))?;
        if older.card_name != newer.card_name || older.tenant_id != newer.tenant_id {
            return Err(SandboxError::Other(format!(
                "card or tenant mismatch between {older_id} and {newer_id}"
            )));
        }
        if !matches!(older.status, VersionStatus::Active) {
            return Err(SandboxError::Other(format!(
                "cannot supersede {older_id}: status is {:?}",
                older.status
            )));
        }
        if older.effective_until.is_none() {
            older.effective_until = Some(newer.effective_at.clone());
        }
        older.status = VersionStatus::Superseded;
        older.superseded_by = Some(newer.version_id.clone());
        let newer = g.get_mut(newer_id).expect("checked");
        newer.supersedes = Some(older_id.to_string());
        Ok(())
    }

    /// Add a tag (deduplicated).
    pub fn add_tag(&self, version_id: &str, tag: impl Into<String>) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("rate card registry poisoned".into()))?;
        let v = g
            .get_mut(version_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown version {version_id}")))?;
        let tag = tag.into();
        if !v.tags.contains(&tag) {
            v.tags.push(tag);
        }
        Ok(())
    }

    /// Look up a version.
    pub fn get(&self, version_id: &str) -> Option<RateCardVersion> {
        let g = self.inner.read().ok()?;
        g.get(version_id).cloned()
    }

    /// All versions.
    pub fn all(&self) -> Vec<RateCardVersion> {
        match self.inner.read() {
            Ok(g) => g.values().cloned().collect(),
            Err(_) => Vec::new(),
        }
    }

    /// All versions for a card name + tenant, sorted by effective_at
    /// ascending.
    pub fn versions_of(&self, card_name: &str, tenant_id: &str) -> Vec<RateCardVersion> {
        let mut out: Vec<RateCardVersion> = self
            .all()
            .into_iter()
            .filter(|v| v.card_name == card_name && v.tenant_id == tenant_id)
            .collect();
        out.sort_by(|a, b| a.effective_at.cmp(&b.effective_at));
        out
    }

    /// Currently active version of a card at `now`. Returns the version
    /// whose window covers `now`.
    pub fn current_at(
        &self,
        card_name: &str,
        tenant_id: &str,
        now: &str,
    ) -> Option<RateCardVersion> {
        self.versions_of(card_name, tenant_id)
            .into_iter()
            .find(|v| v.covers(now))
    }

    /// All versions for a tenant.
    pub fn for_tenant(&self, tenant_id: &str) -> Vec<RateCardVersion> {
        self.all()
            .into_iter()
            .filter(|v| v.tenant_id == tenant_id)
            .collect()
    }

    /// All Active versions.
    pub fn active(&self) -> Vec<RateCardVersion> {
        self.all()
            .into_iter()
            .filter(|v| matches!(v.status, VersionStatus::Active))
            .collect()
    }

    /// Versions by status.
    pub fn by_status(&self, status: VersionStatus) -> Vec<RateCardVersion> {
        self.all().into_iter().filter(|v| v.status == status).collect()
    }

    /// Number of versions.
    pub fn count(&self) -> usize {
        self.inner.read().map(|g| g.len()).unwrap_or(0)
    }
}

/// Two windows `[a_start, a_end)` and `[b_start, b_end)` overlap iff
/// `a_start < b_end && b_start < a_end`.
fn windows_overlap(
    a_start: &str,
    a_end: Option<&str>,
    b_start: &str,
    b_end: Option<&str>,
) -> bool {
    let a_end_lt = match a_end {
        Some(e) => b_start < e,
        None => true,
    };
    let b_end_lt = match b_end {
        Some(e) => a_start < e,
        None => true,
    };
    a_end_lt && b_end_lt
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn ver(
        id: &str,
        card: &str,
        effective_at: &str,
        effective_until: Option<&str>,
    ) -> RateCardVersion {
        let mut v = RateCardVersion::new(
            id,
            card,
            "global",
            format!("title-{id}"),
            "desc",
            "USD",
            "finops",
            effective_at,
            "2025-01-01T00:00:00Z",
        );
        v.effective_until = effective_until.map(String::from);
        v
    }

    fn line(id: &str, price: i64) -> RateLine {
        RateLine {
            line_id: id.into(),
            label: format!("label-{id}"),
            unit: "request".into(),
            price_micro: price,
            discount_bp: None,
            min_quantity: None,
        }
    }

    #[test]
    fn register_and_get() {
        let r = RateCardRegistry::new();
        r.register(ver(
            "v1",
            "card-a",
            "2025-01-01T00:00:00Z",
            Some("2025-04-01T00:00:00Z"),
        ))
        .unwrap();
        assert!(r.get("v1").is_some());
    }

    #[test]
    fn duplicate_register_errors() {
        let r = RateCardRegistry::new();
        r.register(ver("v1", "card-a", "2025-01-01T00:00:00Z", None))
            .unwrap();
        let err = r
            .register(ver("v1", "card-a", "2025-04-01T00:00:00Z", None))
            .unwrap_err();
        assert!(format!("{err}").contains("already registered"));
    }

    #[test]
    fn malformed_window_errors() {
        let r = RateCardRegistry::new();
        let err = r
            .register(ver(
                "v1",
                "card-a",
                "2025-04-01T00:00:00Z",
                Some("2025-01-01T00:00:00Z"),
            ))
            .unwrap_err();
        assert!(format!("{err}").contains("window malformed"));
    }

    #[test]
    fn add_line_to_draft() {
        let r = RateCardRegistry::new();
        r.register(ver("v1", "card-a", "2025-01-01T00:00:00Z", None))
            .unwrap();
        r.add_line("v1", line("l1", 1_000)).unwrap();
        let v = r.get("v1").unwrap();
        assert_eq!(v.lines.len(), 1);
    }

    #[test]
    fn add_line_dedupes_id() {
        let r = RateCardRegistry::new();
        r.register(ver("v1", "card-a", "2025-01-01T00:00:00Z", None))
            .unwrap();
        r.add_line("v1", line("l1", 1_000)).unwrap();
        let err = r.add_line("v1", line("l1", 999)).unwrap_err();
        assert!(format!("{err}").contains("already present"));
    }

    #[test]
    fn add_line_after_active_errors() {
        let r = RateCardRegistry::new();
        r.register(ver("v1", "card-a", "2025-01-01T00:00:00Z", None))
            .unwrap();
        r.add_line("v1", line("l1", 1_000)).unwrap();
        r.activate("v1").unwrap();
        let err = r.add_line("v1", line("l2", 500)).unwrap_err();
        assert!(format!("{err}").contains("cannot add line"));
    }

    #[test]
    fn activate_requires_lines() {
        let r = RateCardRegistry::new();
        r.register(ver("v1", "card-a", "2025-01-01T00:00:00Z", None))
            .unwrap();
        let err = r.activate("v1").unwrap_err();
        assert!(format!("{err}").contains("no lines"));
    }

    #[test]
    fn activate_only_from_draft() {
        let r = RateCardRegistry::new();
        r.register(ver("v1", "card-a", "2025-01-01T00:00:00Z", None))
            .unwrap();
        r.add_line("v1", line("l1", 1_000)).unwrap();
        r.activate("v1").unwrap();
        let err = r.activate("v1").unwrap_err();
        assert!(format!("{err}").contains("cannot activate"));
    }

    #[test]
    fn discard_only_from_draft() {
        let r = RateCardRegistry::new();
        r.register(ver("v1", "card-a", "2025-01-01T00:00:00Z", None))
            .unwrap();
        r.discard("v1").unwrap();
        assert_eq!(r.get("v1").unwrap().status, VersionStatus::Discarded);
    }

    #[test]
    fn discard_active_errors() {
        let r = RateCardRegistry::new();
        r.register(ver("v1", "card-a", "2025-01-01T00:00:00Z", None))
            .unwrap();
        r.add_line("v1", line("l1", 1_000)).unwrap();
        r.activate("v1").unwrap();
        let err = r.discard("v1").unwrap_err();
        assert!(format!("{err}").contains("cannot discard"));
    }

    #[test]
    fn overlap_allowed_at_register_blocked_at_activate() {
        // Draft registration is permissive — activation is the gate.
        let r = RateCardRegistry::new();
        r.register(ver(
            "v1",
            "card-a",
            "2025-01-01T00:00:00Z",
            Some("2025-06-01T00:00:00Z"),
        ))
        .unwrap();
        r.add_line("v1", line("l1", 1_000)).unwrap();
        r.activate("v1").unwrap();
        // Drafting an overlapping v2 is allowed.
        r.register(ver(
            "v2",
            "card-a",
            "2025-03-01T00:00:00Z",
            Some("2025-08-01T00:00:00Z"),
        ))
        .unwrap();
        r.add_line("v2", line("l1", 1_500)).unwrap();
        // Activating v2 fails because the windows overlap.
        let err = r.activate("v2").unwrap_err();
        assert!(format!("{err}").contains("overlaps active version"));
    }

    #[test]
    fn adjacent_windows_can_both_activate() {
        let r = RateCardRegistry::new();
        r.register(ver(
            "v1",
            "card-a",
            "2025-01-01T00:00:00Z",
            Some("2025-04-01T00:00:00Z"),
        ))
        .unwrap();
        r.add_line("v1", line("l1", 1_000)).unwrap();
        r.activate("v1").unwrap();
        // v2 starts exactly when v1 ends — adjacent, not overlapping.
        r.register(ver("v2", "card-a", "2025-04-01T00:00:00Z", None))
            .unwrap();
        r.add_line("v2", line("l1", 1_500)).unwrap();
        r.activate("v2").unwrap();
        assert_eq!(r.active().len(), 2);
    }

    #[test]
    fn supersede_links_chain() {
        let r = RateCardRegistry::new();
        r.register(ver(
            "v1",
            "card-a",
            "2025-01-01T00:00:00Z",
            None,
        ))
        .unwrap();
        r.add_line("v1", line("l1", 1_000)).unwrap();
        r.activate("v1").unwrap();
        // v2 starts where we want to cut over.
        r.register(ver(
            "v2",
            "card-a",
            "2025-04-01T00:00:00Z",
            None,
        ))
        .unwrap();
        r.add_line("v2", line("l1", 1_500)).unwrap();
        r.supersede("v1", "v2").unwrap();
        let old = r.get("v1").unwrap();
        let new = r.get("v2").unwrap();
        assert_eq!(old.status, VersionStatus::Superseded);
        assert_eq!(old.superseded_by.as_deref(), Some("v2"));
        assert_eq!(old.effective_until.as_deref(), Some("2025-04-01T00:00:00Z"));
        assert_eq!(new.supersedes.as_deref(), Some("v1"));
    }

    #[test]
    fn supersede_card_mismatch_errors() {
        let r = RateCardRegistry::new();
        r.register(ver("v1", "card-a", "2025-01-01T00:00:00Z", None))
            .unwrap();
        r.add_line("v1", line("l1", 1_000)).unwrap();
        r.activate("v1").unwrap();
        r.register(ver("v2", "card-b", "2025-02-01T00:00:00Z", None))
            .unwrap();
        let err = r.supersede("v1", "v2").unwrap_err();
        assert!(format!("{err}").contains("mismatch"));
    }

    #[test]
    fn supersede_only_from_active() {
        let r = RateCardRegistry::new();
        r.register(ver("v1", "card-a", "2025-01-01T00:00:00Z", None))
            .unwrap();
        r.register(ver("v2", "card-a", "2025-02-01T00:00:00Z", None))
            .unwrap();
        let err = r.supersede("v1", "v2").unwrap_err();
        assert!(format!("{err}").contains("cannot supersede"));
    }

    #[test]
    fn current_at_resolves() {
        let r = RateCardRegistry::new();
        r.register(ver(
            "v1",
            "card-a",
            "2025-01-01T00:00:00Z",
            Some("2025-04-01T00:00:00Z"),
        ))
        .unwrap();
        r.add_line("v1", line("l1", 1_000)).unwrap();
        r.activate("v1").unwrap();
        r.register(ver(
            "v2",
            "card-a",
            "2025-04-01T00:00:00Z",
            None,
        ))
        .unwrap();
        r.add_line("v2", line("l1", 1_500)).unwrap();
        r.activate("v2").unwrap();
        let c1 = r.current_at("card-a", "global", "2025-02-15T00:00:00Z");
        assert_eq!(c1.unwrap().version_id, "v1");
        let c2 = r.current_at("card-a", "global", "2025-05-15T00:00:00Z");
        assert_eq!(c2.unwrap().version_id, "v2");
        // Before all versions
        assert!(r
            .current_at("card-a", "global", "2024-12-31T00:00:00Z")
            .is_none());
    }

    #[test]
    fn current_at_skips_drafts() {
        let r = RateCardRegistry::new();
        r.register(ver(
            "v1",
            "card-a",
            "2025-01-01T00:00:00Z",
            Some("2025-12-31T00:00:00Z"),
        ))
        .unwrap();
        // Still Draft — should not be returned by current_at
        assert!(r
            .current_at("card-a", "global", "2025-06-15T00:00:00Z")
            .is_none());
    }

    #[test]
    fn versions_of_sorted_by_effective_at() {
        let r = RateCardRegistry::new();
        r.register(ver("b", "card-a", "2025-04-01T00:00:00Z", None))
            .unwrap();
        r.register(ver(
            "a",
            "card-a",
            "2025-01-01T00:00:00Z",
            Some("2025-04-01T00:00:00Z"),
        ))
        .unwrap();
        let ids: Vec<_> = r
            .versions_of("card-a", "global")
            .iter()
            .map(|v| v.version_id.clone())
            .collect();
        assert_eq!(ids, vec!["a", "b"]);
    }

    #[test]
    fn for_tenant_active_by_status_filters() {
        let r = RateCardRegistry::new();
        r.register(ver("v1", "card-a", "2025-01-01T00:00:00Z", None))
            .unwrap();
        r.add_line("v1", line("l1", 1_000)).unwrap();
        r.activate("v1").unwrap();
        let mut other = ver("v2", "card-b", "2025-01-01T00:00:00Z", None);
        other.tenant_id = "tenant-b".into();
        r.register(other).unwrap();
        assert_eq!(r.for_tenant("global").len(), 1);
        assert_eq!(r.for_tenant("tenant-b").len(), 1);
        assert_eq!(r.active().len(), 1);
        assert_eq!(r.by_status(VersionStatus::Draft).len(), 1);
    }

    #[test]
    fn add_tag_dedupes() {
        let r = RateCardRegistry::new();
        r.register(ver("v1", "card-a", "2025-01-01T00:00:00Z", None))
            .unwrap();
        r.add_tag("v1", "promo").unwrap();
        r.add_tag("v1", "promo").unwrap();
        r.add_tag("v1", "q1").unwrap();
        assert_eq!(r.get("v1").unwrap().tags, vec!["promo", "q1"]);
    }

    #[test]
    fn unknown_version_errors() {
        let r = RateCardRegistry::new();
        let err = r.activate("nope").unwrap_err();
        assert!(format!("{err}").contains("unknown version"));
    }

    #[test]
    fn line_lookup() {
        let r = RateCardRegistry::new();
        r.register(ver("v1", "card-a", "2025-01-01T00:00:00Z", None))
            .unwrap();
        r.add_line("v1", line("l1", 1_000)).unwrap();
        let v = r.get("v1").unwrap();
        assert_eq!(v.line("l1").unwrap().price_micro, 1_000);
        assert!(v.line("nope").is_none());
    }

    #[test]
    fn covers_inclusive_start_exclusive_end() {
        let mut v = ver(
            "v1",
            "card-a",
            "2025-01-01T00:00:00Z",
            Some("2025-04-01T00:00:00Z"),
        );
        v.status = VersionStatus::Active;
        assert!(v.covers("2025-01-01T00:00:00Z"));
        assert!(v.covers("2025-03-31T00:00:00Z"));
        assert!(!v.covers("2025-04-01T00:00:00Z"));
        assert!(!v.covers("2024-12-31T00:00:00Z"));
    }

    #[test]
    fn covers_open_ended() {
        let mut v = ver("v1", "card-a", "2025-01-01T00:00:00Z", None);
        v.status = VersionStatus::Active;
        assert!(v.covers("2025-01-01T00:00:00Z"));
        assert!(v.covers("2099-12-31T00:00:00Z"));
        assert!(!v.covers("2024-12-31T00:00:00Z"));
    }

    #[test]
    fn windows_overlap_helper() {
        // [Jan, Apr) vs [Mar, Jun) → overlap
        assert!(windows_overlap(
            "2025-01-01T00:00:00Z",
            Some("2025-04-01T00:00:00Z"),
            "2025-03-01T00:00:00Z",
            Some("2025-06-01T00:00:00Z"),
        ));
        // Adjacent — touching but not overlapping (half-open)
        assert!(!windows_overlap(
            "2025-01-01T00:00:00Z",
            Some("2025-04-01T00:00:00Z"),
            "2025-04-01T00:00:00Z",
            Some("2025-06-01T00:00:00Z"),
        ));
        // Both open-ended → overlap
        assert!(windows_overlap(
            "2025-01-01T00:00:00Z",
            None,
            "2025-06-01T00:00:00Z",
            None,
        ));
    }

    #[test]
    fn count_tracks() {
        let r = RateCardRegistry::new();
        assert_eq!(r.count(), 0);
        r.register(ver("v1", "card-a", "2025-01-01T00:00:00Z", None))
            .unwrap();
        assert_eq!(r.count(), 1);
    }

    #[test]
    fn version_serde() {
        let v = ver("v1", "card-a", "2025-01-01T00:00:00Z", None);
        let j = serde_json::to_string(&v).unwrap();
        let back: RateCardVersion = serde_json::from_str(&j).unwrap();
        assert_eq!(v, back);
    }

    #[test]
    fn line_and_status_serde() {
        let l = line("l1", 1_000);
        assert_eq!(
            l,
            serde_json::from_str::<RateLine>(&serde_json::to_string(&l).unwrap()).unwrap()
        );
        for s in [
            VersionStatus::Draft,
            VersionStatus::Active,
            VersionStatus::Superseded,
            VersionStatus::Discarded,
        ] {
            assert_eq!(
                s,
                serde_json::from_str::<VersionStatus>(&serde_json::to_string(&s).unwrap()).unwrap()
            );
        }
    }
}
