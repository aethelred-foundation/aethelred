//! On-call schedule registry — who is responsible at any given moment.
//!
//! Maps to ISO 27001 A.6.1.1 (responsibilities) and SRE best practice. Each
//! schedule is composed of named shifts on a primary/secondary rotation, and
//! the registry can answer "who is on call right now?" given any
//! point-in-time RFC 3339 timestamp.
//!
//! Override entries (overlay shifts) take precedence over the base rotation —
//! useful for vacation hand-offs and incident takeovers without rewriting the
//! schedule.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

// =============================================================================
// ShiftRole
// =============================================================================

/// Role assigned during a shift.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShiftRole {
    /// First responder.
    Primary,
    /// Backup if primary fails to acknowledge.
    Secondary,
    /// Third tier (often manager).
    Tertiary,
    /// Domain specialist on call for escalations.
    Specialist,
}

// =============================================================================
// Shift
// =============================================================================

/// One scheduled shift.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Shift {
    /// Operator user id.
    pub user_id: String,
    /// Display name.
    pub display_name: String,
    /// Role.
    pub role: ShiftRole,
    /// RFC 3339 — start (inclusive).
    pub start_at: String,
    /// RFC 3339 — end (exclusive).
    pub end_at: String,
    /// Free-form notes.
    pub note: Option<String>,
}

impl Shift {
    /// New shift.
    pub fn new(
        user_id: impl Into<String>,
        display_name: impl Into<String>,
        role: ShiftRole,
        start_at: impl Into<String>,
        end_at: impl Into<String>,
    ) -> Self {
        Self {
            user_id: user_id.into(),
            display_name: display_name.into(),
            role,
            start_at: start_at.into(),
            end_at: end_at.into(),
            note: None,
        }
    }

    /// True if `now` falls in `[start_at, end_at)` using lexicographic RFC
    /// 3339 comparison.
    pub fn covers(&self, now: &str) -> bool {
        now >= self.start_at.as_str() && now < self.end_at.as_str()
    }
}

// =============================================================================
// Schedule
// =============================================================================

/// Named schedule: base shifts plus optional overrides.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Schedule {
    /// Schedule id (e.g., "sre-primary", "ml-platform").
    pub schedule_id: String,
    /// Tenant scope.
    pub tenant_id: String,
    /// Description.
    pub description: String,
    /// Base shift rotation (chronological).
    pub shifts: Vec<Shift>,
    /// Override shifts; matched first when computing coverage.
    pub overrides: Vec<Shift>,
    /// Free-form tags.
    pub tags: Vec<String>,
}

impl Schedule {
    /// New empty schedule.
    pub fn new(
        schedule_id: impl Into<String>,
        tenant_id: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            schedule_id: schedule_id.into(),
            tenant_id: tenant_id.into(),
            description: description.into(),
            shifts: Vec::new(),
            overrides: Vec::new(),
            tags: Vec::new(),
        }
    }

    /// All shifts (overrides first) covering `now`, deduped by role.
    /// Override-role wins; base-role kept if no override of the same role
    /// covers `now`.
    pub fn coverage_at(&self, now: &str) -> Vec<Shift> {
        let mut taken_roles = Vec::new();
        let mut out = Vec::new();
        for s in self.overrides.iter().filter(|s| s.covers(now)) {
            taken_roles.push(s.role);
            out.push(s.clone());
        }
        for s in self.shifts.iter().filter(|s| s.covers(now)) {
            if !taken_roles.contains(&s.role) {
                taken_roles.push(s.role);
                out.push(s.clone());
            }
        }
        out
    }

    /// Convenience: who is Primary at `now`?
    pub fn primary_at(&self, now: &str) -> Option<Shift> {
        self.coverage_at(now)
            .into_iter()
            .find(|s| s.role == ShiftRole::Primary)
    }
}

// =============================================================================
// OnCallRegistry
// =============================================================================

/// Thread-safe registry of named schedules.
#[derive(Debug, Default)]
pub struct OnCallRegistry {
    inner: RwLock<HashMap<String, Schedule>>,
}

impl OnCallRegistry {
    /// New empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new schedule. Errors on duplicate id.
    pub fn register(&self, schedule: Schedule) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("on call registry poisoned".into()))?;
        if g.contains_key(&schedule.schedule_id) {
            return Err(SandboxError::Other(format!(
                "schedule already registered: {}",
                schedule.schedule_id
            )));
        }
        g.insert(schedule.schedule_id.clone(), schedule);
        Ok(())
    }

    /// Append a shift to the base rotation.
    pub fn add_shift(&self, schedule_id: &str, shift: Shift) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("on call registry poisoned".into()))?;
        let s = g
            .get_mut(schedule_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown schedule {schedule_id}")))?;
        if shift.start_at >= shift.end_at {
            return Err(SandboxError::Other(format!(
                "shift start {} not before end {}",
                shift.start_at, shift.end_at
            )));
        }
        s.shifts.push(shift);
        Ok(())
    }

    /// Append an override shift.
    pub fn add_override(&self, schedule_id: &str, shift: Shift) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("on call registry poisoned".into()))?;
        let s = g
            .get_mut(schedule_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown schedule {schedule_id}")))?;
        if shift.start_at >= shift.end_at {
            return Err(SandboxError::Other(format!(
                "override start {} not before end {}",
                shift.start_at, shift.end_at
            )));
        }
        s.overrides.push(shift);
        Ok(())
    }

    /// Add a tag (deduplicated).
    pub fn add_tag(&self, schedule_id: &str, tag: impl Into<String>) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("on call registry poisoned".into()))?;
        let s = g
            .get_mut(schedule_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown schedule {schedule_id}")))?;
        let tag = tag.into();
        if !s.tags.contains(&tag) {
            s.tags.push(tag);
        }
        Ok(())
    }

    /// Look up a schedule.
    pub fn get(&self, schedule_id: &str) -> Option<Schedule> {
        let g = self.inner.read().ok()?;
        g.get(schedule_id).cloned()
    }

    /// All schedules.
    pub fn all(&self) -> Vec<Schedule> {
        match self.inner.read() {
            Ok(g) => g.values().cloned().collect(),
            Err(_) => Vec::new(),
        }
    }

    /// All schedules for a tenant.
    pub fn for_tenant(&self, tenant_id: &str) -> Vec<Schedule> {
        self.all()
            .into_iter()
            .filter(|s| s.tenant_id == tenant_id)
            .collect()
    }

    /// Coverage across all schedules at `now`.
    pub fn coverage_at(&self, now: &str) -> Vec<(String, Shift)> {
        let mut out = Vec::new();
        for s in self.all() {
            for sh in s.coverage_at(now) {
                out.push((s.schedule_id.clone(), sh));
            }
        }
        out
    }

    /// Number of registered schedules.
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

    fn sched() -> Schedule {
        Schedule::new("sre", "tenant-a", "SRE primary rotation")
    }

    #[test]
    fn shift_covers_inclusive_start_exclusive_end() {
        let s = Shift::new(
            "alice",
            "Alice",
            ShiftRole::Primary,
            "2025-05-01T00:00:00Z",
            "2025-05-08T00:00:00Z",
        );
        assert!(s.covers("2025-05-01T00:00:00Z"));
        assert!(s.covers("2025-05-04T12:00:00Z"));
        assert!(!s.covers("2025-05-08T00:00:00Z"));
        assert!(!s.covers("2025-04-30T23:59:59Z"));
    }

    #[test]
    fn register_and_get() {
        let r = OnCallRegistry::new();
        r.register(sched()).unwrap();
        assert!(r.get("sre").is_some());
    }

    #[test]
    fn duplicate_register_errors() {
        let r = OnCallRegistry::new();
        r.register(sched()).unwrap();
        let err = r.register(sched()).unwrap_err();
        assert!(format!("{err}").contains("already registered"));
    }

    #[test]
    fn add_shift_validates_range() {
        let r = OnCallRegistry::new();
        r.register(sched()).unwrap();
        let err = r
            .add_shift(
                "sre",
                Shift::new(
                    "a",
                    "A",
                    ShiftRole::Primary,
                    "2025-05-08T00:00:00Z",
                    "2025-05-01T00:00:00Z",
                ),
            )
            .unwrap_err();
        assert!(format!("{err}").contains("not before"));
    }

    #[test]
    fn add_override_validates_range() {
        let r = OnCallRegistry::new();
        r.register(sched()).unwrap();
        let err = r
            .add_override(
                "sre",
                Shift::new(
                    "a",
                    "A",
                    ShiftRole::Primary,
                    "2025-05-08T00:00:00Z",
                    "2025-05-01T00:00:00Z",
                ),
            )
            .unwrap_err();
        assert!(format!("{err}").contains("not before"));
    }

    #[test]
    fn add_tag_dedupes() {
        let r = OnCallRegistry::new();
        r.register(sched()).unwrap();
        r.add_tag("sre", "prod").unwrap();
        r.add_tag("sre", "prod").unwrap();
        r.add_tag("sre", "p1").unwrap();
        assert_eq!(r.get("sre").unwrap().tags, vec!["prod", "p1"]);
    }

    #[test]
    fn coverage_picks_active_shift() {
        let r = OnCallRegistry::new();
        r.register(sched()).unwrap();
        r.add_shift(
            "sre",
            Shift::new(
                "alice",
                "Alice",
                ShiftRole::Primary,
                "2025-05-01T00:00:00Z",
                "2025-05-08T00:00:00Z",
            ),
        )
        .unwrap();
        r.add_shift(
            "sre",
            Shift::new(
                "bob",
                "Bob",
                ShiftRole::Primary,
                "2025-05-08T00:00:00Z",
                "2025-05-15T00:00:00Z",
            ),
        )
        .unwrap();
        let s = r.get("sre").unwrap();
        let p = s.primary_at("2025-05-04T00:00:00Z").unwrap();
        assert_eq!(p.user_id, "alice");
        let p = s.primary_at("2025-05-10T00:00:00Z").unwrap();
        assert_eq!(p.user_id, "bob");
    }

    #[test]
    fn override_wins_over_base() {
        let r = OnCallRegistry::new();
        r.register(sched()).unwrap();
        r.add_shift(
            "sre",
            Shift::new(
                "alice",
                "Alice",
                ShiftRole::Primary,
                "2025-05-01T00:00:00Z",
                "2025-05-08T00:00:00Z",
            ),
        )
        .unwrap();
        r.add_override(
            "sre",
            Shift::new(
                "bob",
                "Bob",
                ShiftRole::Primary,
                "2025-05-04T00:00:00Z",
                "2025-05-05T00:00:00Z",
            ),
        )
        .unwrap();
        let s = r.get("sre").unwrap();
        // outside override window — Alice
        assert_eq!(
            s.primary_at("2025-05-03T00:00:00Z").unwrap().user_id,
            "alice"
        );
        // inside override window — Bob
        assert_eq!(
            s.primary_at("2025-05-04T12:00:00Z").unwrap().user_id,
            "bob"
        );
    }

    #[test]
    fn coverage_includes_secondary_when_primary_overridden() {
        let r = OnCallRegistry::new();
        r.register(sched()).unwrap();
        r.add_shift(
            "sre",
            Shift::new(
                "alice",
                "Alice",
                ShiftRole::Primary,
                "2025-05-01T00:00:00Z",
                "2025-05-08T00:00:00Z",
            ),
        )
        .unwrap();
        r.add_shift(
            "sre",
            Shift::new(
                "carol",
                "Carol",
                ShiftRole::Secondary,
                "2025-05-01T00:00:00Z",
                "2025-05-08T00:00:00Z",
            ),
        )
        .unwrap();
        r.add_override(
            "sre",
            Shift::new(
                "bob",
                "Bob",
                ShiftRole::Primary,
                "2025-05-04T00:00:00Z",
                "2025-05-05T00:00:00Z",
            ),
        )
        .unwrap();
        let s = r.get("sre").unwrap();
        let cov = s.coverage_at("2025-05-04T12:00:00Z");
        let users: Vec<_> = cov.iter().map(|s| s.user_id.clone()).collect();
        assert!(users.contains(&"bob".to_string()));
        assert!(users.contains(&"carol".to_string()));
        assert!(!users.contains(&"alice".to_string()));
    }

    #[test]
    fn coverage_empty_outside_shifts() {
        let r = OnCallRegistry::new();
        r.register(sched()).unwrap();
        r.add_shift(
            "sre",
            Shift::new(
                "alice",
                "Alice",
                ShiftRole::Primary,
                "2025-05-01T00:00:00Z",
                "2025-05-02T00:00:00Z",
            ),
        )
        .unwrap();
        assert!(r
            .get("sre")
            .unwrap()
            .coverage_at("2025-06-01T00:00:00Z")
            .is_empty());
    }

    #[test]
    fn primary_at_returns_none_when_no_primary() {
        let r = OnCallRegistry::new();
        r.register(sched()).unwrap();
        r.add_shift(
            "sre",
            Shift::new(
                "alice",
                "Alice",
                ShiftRole::Secondary,
                "2025-05-01T00:00:00Z",
                "2025-05-02T00:00:00Z",
            ),
        )
        .unwrap();
        assert!(r
            .get("sre")
            .unwrap()
            .primary_at("2025-05-01T12:00:00Z")
            .is_none());
    }

    #[test]
    fn for_tenant_filters() {
        let r = OnCallRegistry::new();
        r.register(sched()).unwrap();
        let mut other = sched();
        other.schedule_id = "data".into();
        other.tenant_id = "tenant-b".into();
        r.register(other).unwrap();
        assert_eq!(r.for_tenant("tenant-a").len(), 1);
        assert_eq!(r.for_tenant("tenant-b").len(), 1);
        assert_eq!(r.for_tenant("nope").len(), 0);
    }

    #[test]
    fn coverage_across_schedules() {
        let r = OnCallRegistry::new();
        r.register(sched()).unwrap();
        let mut other = sched();
        other.schedule_id = "ml".into();
        r.register(other).unwrap();
        r.add_shift(
            "sre",
            Shift::new(
                "alice",
                "Alice",
                ShiftRole::Primary,
                "2025-05-01T00:00:00Z",
                "2025-05-08T00:00:00Z",
            ),
        )
        .unwrap();
        r.add_shift(
            "ml",
            Shift::new(
                "carol",
                "Carol",
                ShiftRole::Primary,
                "2025-05-01T00:00:00Z",
                "2025-05-08T00:00:00Z",
            ),
        )
        .unwrap();
        let cov = r.coverage_at("2025-05-04T00:00:00Z");
        assert_eq!(cov.len(), 2);
    }

    #[test]
    fn count_tracks() {
        let r = OnCallRegistry::new();
        assert_eq!(r.count(), 0);
        r.register(sched()).unwrap();
        assert_eq!(r.count(), 1);
    }

    #[test]
    fn unknown_schedule_errors() {
        let r = OnCallRegistry::new();
        let err = r
            .add_shift(
                "nope",
                Shift::new(
                    "a",
                    "A",
                    ShiftRole::Primary,
                    "2025-05-01T00:00:00Z",
                    "2025-05-02T00:00:00Z",
                ),
            )
            .unwrap_err();
        assert!(format!("{err}").contains("unknown schedule"));
    }

    #[test]
    fn role_serde() {
        for r in [
            ShiftRole::Primary,
            ShiftRole::Secondary,
            ShiftRole::Tertiary,
            ShiftRole::Specialist,
        ] {
            let j = serde_json::to_string(&r).unwrap();
            let back: ShiftRole = serde_json::from_str(&j).unwrap();
            assert_eq!(r, back);
        }
    }

    #[test]
    fn shift_serde() {
        let s = Shift::new(
            "alice",
            "Alice",
            ShiftRole::Primary,
            "2025-05-01T00:00:00Z",
            "2025-05-08T00:00:00Z",
        );
        let j = serde_json::to_string(&s).unwrap();
        let back: Shift = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn schedule_serde() {
        let s = sched();
        let j = serde_json::to_string(&s).unwrap();
        let back: Schedule = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn coverage_dedupes_role_collisions() {
        let r = OnCallRegistry::new();
        r.register(sched()).unwrap();
        // two overlapping primary shifts in the base rotation — first wins
        r.add_shift(
            "sre",
            Shift::new(
                "alice",
                "Alice",
                ShiftRole::Primary,
                "2025-05-01T00:00:00Z",
                "2025-05-08T00:00:00Z",
            ),
        )
        .unwrap();
        r.add_shift(
            "sre",
            Shift::new(
                "ann",
                "Ann",
                ShiftRole::Primary,
                "2025-05-01T00:00:00Z",
                "2025-05-08T00:00:00Z",
            ),
        )
        .unwrap();
        let cov = r.get("sre").unwrap().coverage_at("2025-05-04T00:00:00Z");
        // Only one Primary should appear; first registered wins.
        let primaries: Vec<_> = cov
            .iter()
            .filter(|s| s.role == ShiftRole::Primary)
            .collect();
        assert_eq!(primaries.len(), 1);
        assert_eq!(primaries[0].user_id, "alice");
    }
}
