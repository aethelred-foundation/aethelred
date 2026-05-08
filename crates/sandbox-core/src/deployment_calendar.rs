//! Deployment calendar — change windows and freeze periods.
//!
//! Maps to ITIL change-management practice and SOC2 CC8.1: every production
//! deployment fits into a known window, and high-risk periods (peak retail
//! shopping, fiscal year close, FDA review windows) are explicitly frozen.
//!
//! The calendar answers two operational questions:
//!
//! - **`is_deployable_at(now)`** — given a service_id, is a change permitted
//!   right now? Returns either `Allowed` with the current window, or
//!   `Blocked` with the reason (no active window, or active freeze).
//! - **`upcoming(now)`** — what change windows / freeze periods are coming
//!   up in the next N days?
//!
//! Freezes always win over windows: if any active freeze covers a service,
//! deployment is blocked even if a window is also active.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

// =============================================================================
// EntryKind
// =============================================================================

/// Calendar entry kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    /// Permitted change window.
    ChangeWindow,
    /// Hard freeze — no deployments.
    Freeze,
    /// Maintenance window — deployments may be required for incident
    /// response but require explicit override.
    Maintenance,
}

// =============================================================================
// CalendarEntry
// =============================================================================

/// One window or freeze.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CalendarEntry {
    /// Unique entry id.
    pub entry_id: String,
    /// Tenant scope.
    pub tenant_id: String,
    /// Kind.
    pub kind: EntryKind,
    /// Display title.
    pub title: String,
    /// RFC 3339 — start (inclusive).
    pub start_at: String,
    /// RFC 3339 — end (exclusive).
    pub end_at: String,
    /// Specific service ids this entry applies to. Empty = all services.
    pub services: Vec<String>,
    /// Free-text reason / context.
    pub reason: Option<String>,
    /// Owner / authorising operator.
    pub owner: String,
    /// Free-form tags.
    pub tags: Vec<String>,
}

impl CalendarEntry {
    /// True if `now` falls in `[start_at, end_at)`.
    pub fn covers(&self, now: &str) -> bool {
        now >= self.start_at.as_str() && now < self.end_at.as_str()
    }

    /// True if the entry applies to `service_id` — either tenant-wide
    /// (empty `services`) or explicitly listed.
    pub fn applies_to(&self, service_id: &str) -> bool {
        self.services.is_empty() || self.services.iter().any(|s| s == service_id)
    }

    /// True if start < end.
    pub fn is_well_formed(&self) -> bool {
        self.start_at < self.end_at
    }
}

// =============================================================================
// DeployabilityCheck
// =============================================================================

/// Outcome of asking "may we deploy?"
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeployabilityCheck {
    /// Service queried.
    pub service_id: String,
    /// Tenant queried.
    pub tenant_id: String,
    /// RFC 3339 — when the check was made.
    pub checked_at: String,
    /// True if deployment is permitted.
    pub allowed: bool,
    /// Reason / referenced entry.
    pub reason: String,
    /// The active freeze entry, if any.
    pub active_freeze: Option<CalendarEntry>,
    /// The active permitted window, if any.
    pub active_window: Option<CalendarEntry>,
}

// =============================================================================
// DeploymentCalendar
// =============================================================================

/// Thread-safe calendar registry.
#[derive(Debug, Default)]
pub struct DeploymentCalendar {
    inner: RwLock<HashMap<String, CalendarEntry>>,
}

impl DeploymentCalendar {
    /// New empty calendar.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new calendar entry. Errors on duplicate id or malformed
    /// time range.
    pub fn register(&self, entry: CalendarEntry) -> SandboxResult<()> {
        if !entry.is_well_formed() {
            return Err(SandboxError::Other(format!(
                "calendar entry {}: start {} not before end {}",
                entry.entry_id, entry.start_at, entry.end_at
            )));
        }
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("deployment calendar poisoned".into()))?;
        if g.contains_key(&entry.entry_id) {
            return Err(SandboxError::Other(format!(
                "entry already registered: {}",
                entry.entry_id
            )));
        }
        g.insert(entry.entry_id.clone(), entry);
        Ok(())
    }

    /// Add a tag (deduplicated).
    pub fn add_tag(&self, entry_id: &str, tag: impl Into<String>) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("deployment calendar poisoned".into()))?;
        let e = g
            .get_mut(entry_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown entry {entry_id}")))?;
        let tag = tag.into();
        if !e.tags.contains(&tag) {
            e.tags.push(tag);
        }
        Ok(())
    }

    /// Look up an entry.
    pub fn get(&self, entry_id: &str) -> Option<CalendarEntry> {
        let g = self.inner.read().ok()?;
        g.get(entry_id).cloned()
    }

    /// Remove an entry. Returns the removed entry, or `None` if absent.
    pub fn remove(&self, entry_id: &str) -> Option<CalendarEntry> {
        let mut g = self.inner.write().ok()?;
        g.remove(entry_id)
    }

    /// All entries.
    pub fn all(&self) -> Vec<CalendarEntry> {
        match self.inner.read() {
            Ok(g) => g.values().cloned().collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Active entries at `now`, regardless of kind.
    pub fn active_at(&self, now: &str) -> Vec<CalendarEntry> {
        self.all().into_iter().filter(|e| e.covers(now)).collect()
    }

    /// Upcoming entries that start at or after `now`, sorted by start_at.
    pub fn upcoming(&self, now: &str) -> Vec<CalendarEntry> {
        let mut out: Vec<_> = self
            .all()
            .into_iter()
            .filter(|e| e.start_at.as_str() >= now)
            .collect();
        out.sort_by(|a, b| a.start_at.cmp(&b.start_at));
        out
    }

    /// Is `service_id` deployable at `now`?
    pub fn is_deployable_at(
        &self,
        tenant_id: &str,
        service_id: &str,
        now: &str,
    ) -> DeployabilityCheck {
        let active = self.active_at(now);
        let mut applicable_freeze: Option<CalendarEntry> = None;
        let mut applicable_window: Option<CalendarEntry> = None;
        for e in active {
            if e.tenant_id != tenant_id {
                continue;
            }
            if !e.applies_to(service_id) {
                continue;
            }
            match e.kind {
                EntryKind::Freeze => {
                    applicable_freeze = Some(e);
                }
                EntryKind::ChangeWindow => {
                    applicable_window = Some(e);
                }
                EntryKind::Maintenance => {
                    // Maintenance window does not by itself authorise deploy;
                    // the operator must request an override. Treated as a
                    // "neutral" — not freeze, not window.
                }
            }
        }
        if let Some(f) = applicable_freeze.clone() {
            return DeployabilityCheck {
                service_id: service_id.into(),
                tenant_id: tenant_id.into(),
                checked_at: now.into(),
                allowed: false,
                reason: format!("freeze active: {}", f.title),
                active_freeze: Some(f),
                active_window: applicable_window,
            };
        }
        match applicable_window {
            Some(w) => DeployabilityCheck {
                service_id: service_id.into(),
                tenant_id: tenant_id.into(),
                checked_at: now.into(),
                allowed: true,
                reason: format!("change window active: {}", w.title),
                active_freeze: None,
                active_window: Some(w),
            },
            None => DeployabilityCheck {
                service_id: service_id.into(),
                tenant_id: tenant_id.into(),
                checked_at: now.into(),
                allowed: false,
                reason: "no active change window".into(),
                active_freeze: None,
                active_window: None,
            },
        }
    }

    /// Number of registered entries.
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

    fn entry(
        id: &str,
        kind: EntryKind,
        start: &str,
        end: &str,
        services: Vec<String>,
    ) -> CalendarEntry {
        CalendarEntry {
            entry_id: id.into(),
            tenant_id: "tenant-a".into(),
            kind,
            title: format!("entry {id}"),
            start_at: start.into(),
            end_at: end.into(),
            services,
            reason: None,
            owner: "ops".into(),
            tags: Vec::new(),
        }
    }

    #[test]
    fn covers_inclusive_start_exclusive_end() {
        let e = entry(
            "x",
            EntryKind::ChangeWindow,
            "2025-05-08T00:00:00Z",
            "2025-05-08T04:00:00Z",
            Vec::new(),
        );
        assert!(e.covers("2025-05-08T00:00:00Z"));
        assert!(e.covers("2025-05-08T02:00:00Z"));
        assert!(!e.covers("2025-05-08T04:00:00Z"));
        assert!(!e.covers("2025-05-07T23:59:59Z"));
    }

    #[test]
    fn applies_to_empty_means_all() {
        let e = entry(
            "x",
            EntryKind::ChangeWindow,
            "2025-05-08T00:00:00Z",
            "2025-05-08T04:00:00Z",
            Vec::new(),
        );
        assert!(e.applies_to("anything"));
        let e2 = entry(
            "y",
            EntryKind::Freeze,
            "2025-05-08T00:00:00Z",
            "2025-05-09T00:00:00Z",
            vec!["billing".into()],
        );
        assert!(e2.applies_to("billing"));
        assert!(!e2.applies_to("metrics"));
    }

    #[test]
    fn register_and_get() {
        let c = DeploymentCalendar::new();
        c.register(entry(
            "x",
            EntryKind::ChangeWindow,
            "2025-05-08T00:00:00Z",
            "2025-05-08T04:00:00Z",
            Vec::new(),
        ))
        .unwrap();
        assert!(c.get("x").is_some());
    }

    #[test]
    fn duplicate_register_errors() {
        let c = DeploymentCalendar::new();
        let e = entry(
            "x",
            EntryKind::ChangeWindow,
            "2025-05-08T00:00:00Z",
            "2025-05-08T04:00:00Z",
            Vec::new(),
        );
        c.register(e.clone()).unwrap();
        let err = c.register(e).unwrap_err();
        assert!(format!("{err}").contains("already registered"));
    }

    #[test]
    fn malformed_range_errors() {
        let c = DeploymentCalendar::new();
        let err = c
            .register(entry(
                "x",
                EntryKind::Freeze,
                "2025-05-09T00:00:00Z",
                "2025-05-08T00:00:00Z",
                Vec::new(),
            ))
            .unwrap_err();
        assert!(format!("{err}").contains("not before"));
    }

    #[test]
    fn add_tag_dedupes() {
        let c = DeploymentCalendar::new();
        c.register(entry(
            "x",
            EntryKind::ChangeWindow,
            "2025-05-08T00:00:00Z",
            "2025-05-08T04:00:00Z",
            Vec::new(),
        ))
        .unwrap();
        c.add_tag("x", "weekly").unwrap();
        c.add_tag("x", "weekly").unwrap();
        c.add_tag("x", "ops").unwrap();
        assert_eq!(c.get("x").unwrap().tags, vec!["weekly", "ops"]);
    }

    #[test]
    fn remove_works() {
        let c = DeploymentCalendar::new();
        c.register(entry(
            "x",
            EntryKind::ChangeWindow,
            "2025-05-08T00:00:00Z",
            "2025-05-08T04:00:00Z",
            Vec::new(),
        ))
        .unwrap();
        assert!(c.remove("x").is_some());
        assert!(c.remove("x").is_none());
    }

    #[test]
    fn unknown_entry_errors() {
        let c = DeploymentCalendar::new();
        let err = c.add_tag("nope", "x").unwrap_err();
        assert!(format!("{err}").contains("unknown entry"));
    }

    #[test]
    fn active_at_filters() {
        let c = DeploymentCalendar::new();
        c.register(entry(
            "win",
            EntryKind::ChangeWindow,
            "2025-05-08T00:00:00Z",
            "2025-05-08T04:00:00Z",
            Vec::new(),
        ))
        .unwrap();
        c.register(entry(
            "frz",
            EntryKind::Freeze,
            "2025-05-09T00:00:00Z",
            "2025-05-10T00:00:00Z",
            Vec::new(),
        ))
        .unwrap();
        let a = c.active_at("2025-05-08T02:00:00Z");
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].entry_id, "win");
    }

    #[test]
    fn upcoming_sorts_by_start() {
        let c = DeploymentCalendar::new();
        c.register(entry(
            "b",
            EntryKind::ChangeWindow,
            "2025-05-10T00:00:00Z",
            "2025-05-10T04:00:00Z",
            Vec::new(),
        ))
        .unwrap();
        c.register(entry(
            "a",
            EntryKind::ChangeWindow,
            "2025-05-09T00:00:00Z",
            "2025-05-09T04:00:00Z",
            Vec::new(),
        ))
        .unwrap();
        c.register(entry(
            "past",
            EntryKind::ChangeWindow,
            "2025-04-01T00:00:00Z",
            "2025-04-01T04:00:00Z",
            Vec::new(),
        ))
        .unwrap();
        let up = c.upcoming("2025-05-08T00:00:00Z");
        let ids: Vec<_> = up.iter().map(|e| e.entry_id.clone()).collect();
        assert_eq!(ids, vec!["a", "b"]);
    }

    #[test]
    fn deployable_in_active_window() {
        let c = DeploymentCalendar::new();
        c.register(entry(
            "win",
            EntryKind::ChangeWindow,
            "2025-05-08T00:00:00Z",
            "2025-05-08T04:00:00Z",
            Vec::new(),
        ))
        .unwrap();
        let r = c.is_deployable_at("tenant-a", "billing", "2025-05-08T01:00:00Z");
        assert!(r.allowed);
        assert!(r.active_window.is_some());
        assert!(r.active_freeze.is_none());
    }

    #[test]
    fn freeze_blocks_even_with_window() {
        let c = DeploymentCalendar::new();
        c.register(entry(
            "win",
            EntryKind::ChangeWindow,
            "2025-05-08T00:00:00Z",
            "2025-05-08T04:00:00Z",
            Vec::new(),
        ))
        .unwrap();
        c.register(entry(
            "frz",
            EntryKind::Freeze,
            "2025-05-08T01:00:00Z",
            "2025-05-08T03:00:00Z",
            Vec::new(),
        ))
        .unwrap();
        let r = c.is_deployable_at("tenant-a", "billing", "2025-05-08T02:00:00Z");
        assert!(!r.allowed);
        assert!(r.active_freeze.is_some());
        assert_eq!(r.active_freeze.unwrap().entry_id, "frz");
    }

    #[test]
    fn freeze_scoped_to_specific_services() {
        let c = DeploymentCalendar::new();
        c.register(entry(
            "win",
            EntryKind::ChangeWindow,
            "2025-05-08T00:00:00Z",
            "2025-05-08T04:00:00Z",
            Vec::new(),
        ))
        .unwrap();
        c.register(entry(
            "frz-billing",
            EntryKind::Freeze,
            "2025-05-08T01:00:00Z",
            "2025-05-08T03:00:00Z",
            vec!["billing".into()],
        ))
        .unwrap();
        let billing = c.is_deployable_at("tenant-a", "billing", "2025-05-08T02:00:00Z");
        assert!(!billing.allowed);
        let metrics = c.is_deployable_at("tenant-a", "metrics", "2025-05-08T02:00:00Z");
        assert!(metrics.allowed);
    }

    #[test]
    fn no_window_no_freeze_blocks() {
        let c = DeploymentCalendar::new();
        let r = c.is_deployable_at("tenant-a", "billing", "2025-05-08T02:00:00Z");
        assert!(!r.allowed);
        assert!(r.reason.contains("no active change window"));
    }

    #[test]
    fn maintenance_does_not_authorise_deploy() {
        let c = DeploymentCalendar::new();
        c.register(entry(
            "maint",
            EntryKind::Maintenance,
            "2025-05-08T00:00:00Z",
            "2025-05-08T04:00:00Z",
            Vec::new(),
        ))
        .unwrap();
        let r = c.is_deployable_at("tenant-a", "billing", "2025-05-08T02:00:00Z");
        assert!(!r.allowed);
    }

    #[test]
    fn other_tenant_freeze_does_not_block() {
        let c = DeploymentCalendar::new();
        c.register(entry(
            "win",
            EntryKind::ChangeWindow,
            "2025-05-08T00:00:00Z",
            "2025-05-08T04:00:00Z",
            Vec::new(),
        ))
        .unwrap();
        let mut frz = entry(
            "frz",
            EntryKind::Freeze,
            "2025-05-08T01:00:00Z",
            "2025-05-08T03:00:00Z",
            Vec::new(),
        );
        frz.tenant_id = "tenant-b".into();
        c.register(frz).unwrap();
        let r = c.is_deployable_at("tenant-a", "billing", "2025-05-08T02:00:00Z");
        assert!(r.allowed);
    }

    #[test]
    fn count_tracks() {
        let c = DeploymentCalendar::new();
        assert_eq!(c.count(), 0);
        c.register(entry(
            "x",
            EntryKind::ChangeWindow,
            "2025-05-08T00:00:00Z",
            "2025-05-08T04:00:00Z",
            Vec::new(),
        ))
        .unwrap();
        assert_eq!(c.count(), 1);
    }

    #[test]
    fn entry_serde() {
        let e = entry(
            "x",
            EntryKind::ChangeWindow,
            "2025-05-08T00:00:00Z",
            "2025-05-08T04:00:00Z",
            vec!["billing".into()],
        );
        let j = serde_json::to_string(&e).unwrap();
        let back: CalendarEntry = serde_json::from_str(&j).unwrap();
        assert_eq!(e, back);
    }

    #[test]
    fn check_serde() {
        let c = DeploymentCalendar::new();
        c.register(entry(
            "x",
            EntryKind::ChangeWindow,
            "2025-05-08T00:00:00Z",
            "2025-05-08T04:00:00Z",
            Vec::new(),
        ))
        .unwrap();
        let r = c.is_deployable_at("tenant-a", "billing", "2025-05-08T02:00:00Z");
        let j = serde_json::to_string(&r).unwrap();
        let back: DeployabilityCheck = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn kind_serde() {
        for k in [
            EntryKind::ChangeWindow,
            EntryKind::Freeze,
            EntryKind::Maintenance,
        ] {
            let j = serde_json::to_string(&k).unwrap();
            let back: EntryKind = serde_json::from_str(&j).unwrap();
            assert_eq!(k, back);
        }
    }
}
