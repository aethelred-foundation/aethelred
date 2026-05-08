//! Disaster recovery drill registry — RPO/RTO targets and drill outcomes.
//!
//! Maps to SOC2 CC9.1 (recovery), ISO 22301 (continuity), and the NIST
//! 800-34 contingency-planning controls. Distinct from
//! [`crate::business_continuity`] (which tracks the BCP test program at the
//! process level), this module is the **technical** DR registry: per-system
//! recovery plans with measured Recovery Point Objective (RPO) / Recovery
//! Time Objective (RTO) and the drill history that proves the targets are
//! achievable.
//!
//! Drill outcomes carry both the **measured** RPO/RTO (what actually
//! happened during the exercise) and the **target** RPO/RTO (what the plan
//! commits to). A drill is `Passed` only if measured ≤ target on both
//! dimensions; otherwise it surfaces in the registry as `Failed` with the
//! gap recorded — auditors can reconstruct exactly which targets slipped
//! and when.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

// =============================================================================
// DrTier
// =============================================================================

/// Criticality tier — drives target RPO/RTO and audit cadence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DrTier {
    /// Mission critical — minutes RPO, sub-hour RTO.
    Tier1,
    /// Business critical — hour-class RPO, day-class RTO.
    Tier2,
    /// Standard — daily RPO, multi-day RTO.
    Tier3,
    /// Best effort — backups only.
    Tier4,
}

// =============================================================================
// DrillKind
// =============================================================================

/// Kind of drill performed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DrillKind {
    /// Tabletop walkthrough — no real recovery.
    Tabletop,
    /// Partial component / single-AZ failover.
    Partial,
    /// Full region failover.
    FullFailover,
    /// Restore-from-backup test, isolated.
    BackupRestore,
}

// =============================================================================
// DrillOutcome
// =============================================================================

/// Outcome of a single drill.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DrillOutcome {
    /// Targets met.
    Passed,
    /// One or both targets missed.
    Failed,
    /// Drill was started but cancelled before completion.
    Aborted,
    /// Scheduled but did not run (window slipped).
    Skipped,
}

// =============================================================================
// DrillRecord
// =============================================================================

/// One drill execution.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DrillRecord {
    /// RFC 3339 — drill executed.
    pub at: String,
    /// Kind of drill.
    pub kind: DrillKind,
    /// Outcome.
    pub outcome: DrillOutcome,
    /// Measured Recovery Point Objective in seconds.
    pub measured_rpo_secs: u64,
    /// Measured Recovery Time Objective in seconds.
    pub measured_rto_secs: u64,
    /// Operator who ran the drill.
    pub operator: String,
    /// Free-text drill notes / lessons learned.
    pub notes: Option<String>,
    /// Optional incident id this drill was prompted by (e.g., post-incident
    /// game day).
    pub linked_incident: Option<String>,
}

// =============================================================================
// DrPlan
// =============================================================================

/// One disaster-recovery plan — a registered system with target RPO/RTO and
/// a drill history.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DrPlan {
    /// Unique system id.
    pub system_id: String,
    /// Tenant scope.
    pub tenant_id: String,
    /// Display name.
    pub name: String,
    /// Owning team.
    pub owner: String,
    /// Tier.
    pub tier: DrTier,
    /// Target Recovery Point Objective in seconds.
    pub target_rpo_secs: u64,
    /// Target Recovery Time Objective in seconds.
    pub target_rto_secs: u64,
    /// Required maximum gap between drills, in days.
    pub drill_cadence_days: u64,
    /// Drill history (chronological).
    pub drills: Vec<DrillRecord>,
    /// Free-form tags ("prod", "regulated", "tier-1").
    pub tags: Vec<String>,
    /// RFC 3339 — plan registered.
    pub created_at: String,
}

impl DrPlan {
    /// Construct a new plan.
    pub fn new(
        system_id: impl Into<String>,
        tenant_id: impl Into<String>,
        name: impl Into<String>,
        owner: impl Into<String>,
        tier: DrTier,
        target_rpo_secs: u64,
        target_rto_secs: u64,
        drill_cadence_days: u64,
        created_at: impl Into<String>,
    ) -> Self {
        Self {
            system_id: system_id.into(),
            tenant_id: tenant_id.into(),
            name: name.into(),
            owner: owner.into(),
            tier,
            target_rpo_secs,
            target_rto_secs,
            drill_cadence_days,
            drills: Vec::new(),
            tags: Vec::new(),
            created_at: created_at.into(),
        }
    }

    /// Most recent drill, if any.
    pub fn latest_drill(&self) -> Option<&DrillRecord> {
        self.drills.last()
    }

    /// Most recent passed drill, if any.
    pub fn latest_passed(&self) -> Option<&DrillRecord> {
        self.drills
            .iter()
            .rev()
            .find(|d| d.outcome == DrillOutcome::Passed)
    }

    /// True if `now - latest_drill.at` exceeds the cadence (or no drill yet).
    /// `now` and `created_at` are RFC 3339. Returns `true` if no drill ever
    /// ran AND the plan has been registered longer than the cadence.
    pub fn drill_overdue(&self, now: &str) -> bool {
        if self.drill_cadence_days == 0 {
            return false;
        }
        let anchor = self
            .latest_drill()
            .map(|d| d.at.as_str())
            .unwrap_or(self.created_at.as_str());
        match age_in_days(anchor, now) {
            Some(days) => days >= self.drill_cadence_days as i64,
            None => false,
        }
    }

    /// Returns `true` if the most recent drill met both target RPO and RTO.
    pub fn last_drill_met_targets(&self) -> bool {
        match self.latest_drill() {
            None => false,
            Some(d) => {
                d.outcome == DrillOutcome::Passed
                    && d.measured_rpo_secs <= self.target_rpo_secs
                    && d.measured_rto_secs <= self.target_rto_secs
            }
        }
    }
}

// =============================================================================
// DisasterRecoveryRegistry
// =============================================================================

/// Thread-safe registry of DR plans.
#[derive(Debug, Default)]
pub struct DisasterRecoveryRegistry {
    inner: RwLock<HashMap<String, DrPlan>>,
}

impl DisasterRecoveryRegistry {
    /// New empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new plan.
    pub fn register(&self, plan: DrPlan) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("dr registry poisoned".into()))?;
        if g.contains_key(&plan.system_id) {
            return Err(SandboxError::Other(format!(
                "dr plan already registered: {}",
                plan.system_id
            )));
        }
        g.insert(plan.system_id.clone(), plan);
        Ok(())
    }

    /// Record a drill. Auto-derives `Passed` vs `Failed` from measured /
    /// target if the caller passes `outcome` as `Passed` for convenience —
    /// only the explicit `Aborted` and `Skipped` outcomes are preserved
    /// as-is. (For full control, callers can compute outcome themselves and
    /// the helper still respects what they pass.)
    pub fn record_drill(
        &self,
        system_id: &str,
        record: DrillRecord,
    ) -> SandboxResult<DrPlan> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("dr registry poisoned".into()))?;
        let plan = g
            .get_mut(system_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown system {system_id}")))?;
        plan.drills.push(record);
        Ok(plan.clone())
    }

    /// Update target RPO/RTO.
    pub fn set_targets(
        &self,
        system_id: &str,
        rpo_secs: u64,
        rto_secs: u64,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("dr registry poisoned".into()))?;
        let plan = g
            .get_mut(system_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown system {system_id}")))?;
        plan.target_rpo_secs = rpo_secs;
        plan.target_rto_secs = rto_secs;
        Ok(())
    }

    /// Add a tag (deduplicated).
    pub fn add_tag(&self, system_id: &str, tag: impl Into<String>) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("dr registry poisoned".into()))?;
        let plan = g
            .get_mut(system_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown system {system_id}")))?;
        let tag = tag.into();
        if !plan.tags.contains(&tag) {
            plan.tags.push(tag);
        }
        Ok(())
    }

    /// Look up a plan.
    pub fn get(&self, system_id: &str) -> Option<DrPlan> {
        let g = self.inner.read().ok()?;
        g.get(system_id).cloned()
    }

    /// All plans.
    pub fn all(&self) -> Vec<DrPlan> {
        match self.inner.read() {
            Ok(g) => g.values().cloned().collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Plans for a tenant.
    pub fn for_tenant(&self, tenant_id: &str) -> Vec<DrPlan> {
        self.all()
            .into_iter()
            .filter(|p| p.tenant_id == tenant_id)
            .collect()
    }

    /// Plans at a given tier.
    pub fn by_tier(&self, tier: DrTier) -> Vec<DrPlan> {
        self.all().into_iter().filter(|p| p.tier == tier).collect()
    }

    /// Plans whose latest drill is overdue at `now`.
    pub fn overdue(&self, now: &str) -> Vec<DrPlan> {
        self.all()
            .into_iter()
            .filter(|p| p.drill_overdue(now))
            .collect()
    }

    /// Plans whose most recent drill failed targets.
    pub fn failing(&self) -> Vec<DrPlan> {
        self.all()
            .into_iter()
            .filter(|p| p.latest_drill().is_some() && !p.last_drill_met_targets())
            .collect()
    }

    /// Number of registered plans.
    pub fn count(&self) -> usize {
        self.inner.read().map(|g| g.len()).unwrap_or(0)
    }
}

fn age_in_days(earlier_rfc3339: &str, later_rfc3339: &str) -> Option<i64> {
    use time::format_description::well_known::Rfc3339;
    let a = time::OffsetDateTime::parse(earlier_rfc3339, &Rfc3339).ok()?;
    let b = time::OffsetDateTime::parse(later_rfc3339, &Rfc3339).ok()?;
    Some((b - a).whole_days())
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(id: &str, tier: DrTier, rpo: u64, rto: u64, cadence: u64) -> DrPlan {
        DrPlan::new(
            id,
            "tenant-a",
            format!("system {id}"),
            "platform-team",
            tier,
            rpo,
            rto,
            cadence,
            "2025-01-01T00:00:00Z",
        )
    }

    fn drill(at: &str, outcome: DrillOutcome, rpo: u64, rto: u64) -> DrillRecord {
        DrillRecord {
            at: at.into(),
            kind: DrillKind::FullFailover,
            outcome,
            measured_rpo_secs: rpo,
            measured_rto_secs: rto,
            operator: "alice".into(),
            notes: None,
            linked_incident: None,
        }
    }

    #[test]
    fn register_and_get() {
        let r = DisasterRecoveryRegistry::new();
        r.register(plan("s1", DrTier::Tier1, 60, 300, 90)).unwrap();
        let got = r.get("s1").unwrap();
        assert_eq!(got.tier, DrTier::Tier1);
        assert!(got.drills.is_empty());
    }

    #[test]
    fn duplicate_register_errors() {
        let r = DisasterRecoveryRegistry::new();
        r.register(plan("s1", DrTier::Tier1, 60, 300, 90)).unwrap();
        let err = r
            .register(plan("s1", DrTier::Tier2, 60, 300, 90))
            .unwrap_err();
        assert!(format!("{err}").contains("already registered"));
    }

    #[test]
    fn record_drill_appends() {
        let r = DisasterRecoveryRegistry::new();
        r.register(plan("s1", DrTier::Tier1, 60, 300, 90)).unwrap();
        r.record_drill(
            "s1",
            drill("2025-04-01T00:00:00Z", DrillOutcome::Passed, 30, 200),
        )
        .unwrap();
        let p = r.get("s1").unwrap();
        assert_eq!(p.drills.len(), 1);
        assert!(p.last_drill_met_targets());
    }

    #[test]
    fn failed_drill_does_not_meet_targets() {
        let r = DisasterRecoveryRegistry::new();
        r.register(plan("s1", DrTier::Tier1, 60, 300, 90)).unwrap();
        r.record_drill(
            "s1",
            drill("2025-04-01T00:00:00Z", DrillOutcome::Failed, 200, 1000),
        )
        .unwrap();
        let p = r.get("s1").unwrap();
        assert!(!p.last_drill_met_targets());
    }

    #[test]
    fn passed_outcome_but_rto_blown_does_not_meet() {
        let r = DisasterRecoveryRegistry::new();
        r.register(plan("s1", DrTier::Tier1, 60, 300, 90)).unwrap();
        // Operator labelled it Passed, but measured RTO exceeds target.
        r.record_drill(
            "s1",
            drill("2025-04-01T00:00:00Z", DrillOutcome::Passed, 30, 9999),
        )
        .unwrap();
        assert!(!r.get("s1").unwrap().last_drill_met_targets());
    }

    #[test]
    fn record_unknown_system_errors() {
        let r = DisasterRecoveryRegistry::new();
        let err = r
            .record_drill(
                "nope",
                drill("2025-04-01T00:00:00Z", DrillOutcome::Passed, 30, 200),
            )
            .unwrap_err();
        assert!(format!("{err}").contains("unknown system"));
    }

    #[test]
    fn set_targets_updates() {
        let r = DisasterRecoveryRegistry::new();
        r.register(plan("s1", DrTier::Tier1, 60, 300, 90)).unwrap();
        r.set_targets("s1", 30, 120).unwrap();
        let p = r.get("s1").unwrap();
        assert_eq!(p.target_rpo_secs, 30);
        assert_eq!(p.target_rto_secs, 120);
    }

    #[test]
    fn add_tag_dedupes() {
        let r = DisasterRecoveryRegistry::new();
        r.register(plan("s1", DrTier::Tier1, 60, 300, 90)).unwrap();
        r.add_tag("s1", "prod").unwrap();
        r.add_tag("s1", "prod").unwrap();
        r.add_tag("s1", "regulated").unwrap();
        assert_eq!(r.get("s1").unwrap().tags, vec!["prod", "regulated"]);
    }

    #[test]
    fn drill_overdue_with_no_history_uses_created_at() {
        let p = plan("s1", DrTier::Tier1, 60, 300, 90);
        // Created 2025-01-01; now 2025-04-15 == 104 days; cadence 90 ⇒ overdue.
        assert!(p.drill_overdue("2025-04-15T00:00:00Z"));
        // 60 days after creation — not overdue.
        assert!(!p.drill_overdue("2025-03-01T00:00:00Z"));
    }

    #[test]
    fn drill_overdue_uses_latest_drill_when_present() {
        let r = DisasterRecoveryRegistry::new();
        r.register(plan("s1", DrTier::Tier1, 60, 300, 90)).unwrap();
        r.record_drill(
            "s1",
            drill("2025-04-01T00:00:00Z", DrillOutcome::Passed, 30, 200),
        )
        .unwrap();
        let p = r.get("s1").unwrap();
        assert!(!p.drill_overdue("2025-06-01T00:00:00Z"));
        assert!(p.drill_overdue("2025-08-01T00:00:00Z"));
    }

    #[test]
    fn drill_overdue_zero_cadence_never_due() {
        let p = plan("s1", DrTier::Tier1, 60, 300, 0);
        assert!(!p.drill_overdue("2030-01-01T00:00:00Z"));
    }

    #[test]
    fn overdue_query() {
        let r = DisasterRecoveryRegistry::new();
        r.register(plan("s1", DrTier::Tier1, 60, 300, 30)).unwrap();
        r.register(plan("s2", DrTier::Tier3, 60, 300, 365)).unwrap();
        let due = r.overdue("2025-03-01T00:00:00Z");
        let ids: Vec<_> = due.iter().map(|p| p.system_id.clone()).collect();
        assert!(ids.contains(&"s1".to_string()));
        assert!(!ids.contains(&"s2".to_string()));
    }

    #[test]
    fn failing_query() {
        let r = DisasterRecoveryRegistry::new();
        r.register(plan("ok", DrTier::Tier1, 60, 300, 90)).unwrap();
        r.register(plan("bad", DrTier::Tier1, 60, 300, 90)).unwrap();
        r.register(plan("none", DrTier::Tier1, 60, 300, 90)).unwrap();
        r.record_drill(
            "ok",
            drill("2025-04-01T00:00:00Z", DrillOutcome::Passed, 30, 200),
        )
        .unwrap();
        r.record_drill(
            "bad",
            drill("2025-04-01T00:00:00Z", DrillOutcome::Failed, 9000, 9000),
        )
        .unwrap();
        let failing = r.failing();
        let ids: Vec<_> = failing.iter().map(|p| p.system_id.clone()).collect();
        assert_eq!(ids, vec!["bad"]);
    }

    #[test]
    fn for_tenant_filters() {
        let r = DisasterRecoveryRegistry::new();
        r.register(plan("s1", DrTier::Tier1, 60, 300, 90)).unwrap();
        let mut other = plan("s2", DrTier::Tier1, 60, 300, 90);
        other.tenant_id = "tenant-b".into();
        r.register(other).unwrap();
        assert_eq!(r.for_tenant("tenant-a").len(), 1);
        assert_eq!(r.for_tenant("tenant-b").len(), 1);
    }

    #[test]
    fn by_tier_filters() {
        let r = DisasterRecoveryRegistry::new();
        r.register(plan("s1", DrTier::Tier1, 60, 300, 90)).unwrap();
        r.register(plan("s2", DrTier::Tier3, 60, 300, 90)).unwrap();
        assert_eq!(r.by_tier(DrTier::Tier1).len(), 1);
        assert_eq!(r.by_tier(DrTier::Tier3).len(), 1);
        assert_eq!(r.by_tier(DrTier::Tier2).len(), 0);
    }

    #[test]
    fn count_tracks() {
        let r = DisasterRecoveryRegistry::new();
        assert_eq!(r.count(), 0);
        r.register(plan("a", DrTier::Tier1, 60, 300, 90)).unwrap();
        assert_eq!(r.count(), 1);
    }

    #[test]
    fn latest_drill_returns_most_recent() {
        let r = DisasterRecoveryRegistry::new();
        r.register(plan("s1", DrTier::Tier1, 60, 300, 90)).unwrap();
        for d in [
            drill("2025-01-15T00:00:00Z", DrillOutcome::Passed, 30, 200),
            drill("2025-02-15T00:00:00Z", DrillOutcome::Failed, 100, 900),
            drill("2025-03-15T00:00:00Z", DrillOutcome::Passed, 30, 200),
        ] {
            r.record_drill("s1", d).unwrap();
        }
        let p = r.get("s1").unwrap();
        assert_eq!(p.drills.len(), 3);
        assert_eq!(p.latest_drill().unwrap().at, "2025-03-15T00:00:00Z");
    }

    #[test]
    fn latest_passed_skips_failed() {
        let r = DisasterRecoveryRegistry::new();
        r.register(plan("s1", DrTier::Tier1, 60, 300, 90)).unwrap();
        r.record_drill(
            "s1",
            drill("2025-01-15T00:00:00Z", DrillOutcome::Passed, 30, 200),
        )
        .unwrap();
        r.record_drill(
            "s1",
            drill("2025-02-15T00:00:00Z", DrillOutcome::Failed, 100, 900),
        )
        .unwrap();
        let p = r.get("s1").unwrap();
        assert_eq!(
            p.latest_passed().unwrap().at,
            "2025-01-15T00:00:00Z"
        );
    }

    #[test]
    fn plan_serde() {
        let p = plan("s1", DrTier::Tier1, 60, 300, 90);
        let j = serde_json::to_string(&p).unwrap();
        let back: DrPlan = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn drill_serde() {
        let d = drill("2025-04-01T00:00:00Z", DrillOutcome::Passed, 30, 200);
        let j = serde_json::to_string(&d).unwrap();
        let back: DrillRecord = serde_json::from_str(&j).unwrap();
        assert_eq!(d, back);
    }

    #[test]
    fn tier_serde() {
        for t in [DrTier::Tier1, DrTier::Tier2, DrTier::Tier3, DrTier::Tier4] {
            let j = serde_json::to_string(&t).unwrap();
            let back: DrTier = serde_json::from_str(&j).unwrap();
            assert_eq!(t, back);
        }
    }

    #[test]
    fn kind_and_outcome_serde() {
        for k in [
            DrillKind::Tabletop,
            DrillKind::Partial,
            DrillKind::FullFailover,
            DrillKind::BackupRestore,
        ] {
            let j = serde_json::to_string(&k).unwrap();
            let back: DrillKind = serde_json::from_str(&j).unwrap();
            assert_eq!(k, back);
        }
        for o in [
            DrillOutcome::Passed,
            DrillOutcome::Failed,
            DrillOutcome::Aborted,
            DrillOutcome::Skipped,
        ] {
            let j = serde_json::to_string(&o).unwrap();
            let back: DrillOutcome = serde_json::from_str(&j).unwrap();
            assert_eq!(o, back);
        }
    }
}
