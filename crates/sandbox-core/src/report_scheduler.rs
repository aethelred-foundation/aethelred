//! Compliance-report scheduler.
//!
//! Many regulatory regimes require *periodic* compliance reporting (monthly
//! for some banking SAR-style reports, quarterly for SEC, annually for SOC
//! 2). Operators register a schedule per report; this module fires due
//! reports and tracks delivery.
//!
//! It is **not** a cron daemon — it operates on a passive "tick the clock"
//! model that integrates with the protocol's deterministic event loop.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use time::OffsetDateTime;
use uuid::Uuid;

// =============================================================================
// Cadence
// =============================================================================

/// Schedule cadence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Cadence {
    /// Daily.
    Daily,
    /// Weekly.
    Weekly,
    /// Monthly.
    Monthly,
    /// Quarterly.
    Quarterly,
    /// Semi-annual.
    SemiAnnual,
    /// Annual.
    Annual,
}

impl Cadence {
    /// Interval in days.
    pub fn interval_days(self) -> i64 {
        match self {
            Self::Daily => 1,
            Self::Weekly => 7,
            Self::Monthly => 30,
            Self::Quarterly => 91,
            Self::SemiAnnual => 182,
            Self::Annual => 365,
        }
    }
}

// =============================================================================
// ReportSchedule
// =============================================================================

/// Schedule.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReportSchedule {
    /// Stable id.
    pub schedule_id: String,
    /// Display name.
    pub name: String,
    /// Recipients (emails or roles).
    pub recipients: Vec<String>,
    /// Owner.
    pub owner: String,
    /// Cadence.
    pub cadence: Cadence,
    /// RFC 3339 first-due.
    pub first_due_at: String,
    /// Next due (RFC 3339).
    pub next_due_at: String,
    /// Last fired (RFC 3339).
    pub last_fired_at: Option<String>,
    /// `true` if active.
    pub active: bool,
    /// Free-text description.
    pub description: String,
}

impl ReportSchedule {
    /// `true` if the schedule is due as of `now`.
    pub fn is_due(&self, now: OffsetDateTime) -> bool {
        if !self.active {
            return false;
        }
        let next = match OffsetDateTime::parse(
            &self.next_due_at,
            &time::format_description::well_known::Rfc3339,
        ) {
            Ok(t) => t,
            Err(_) => return false,
        };
        now >= next
    }
}

// =============================================================================
// Firing
// =============================================================================

/// One firing record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReportFiring {
    /// Stable id.
    pub firing_id: Uuid,
    /// Schedule id.
    pub schedule_id: String,
    /// RFC 3339 fired at.
    pub fired_at: String,
    /// Delivery status.
    pub status: FiringStatus,
    /// Optional output reference (URL, S3 key, etc.).
    pub output_ref: Option<String>,
    /// Error message if failed.
    pub error: Option<String>,
}

/// Per-firing status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FiringStatus {
    /// Successfully delivered.
    Delivered,
    /// Failed.
    Failed,
    /// Skipped (e.g., paused).
    Skipped,
}

// =============================================================================
// ReportScheduler
// =============================================================================

#[derive(Default)]
struct State {
    schedules: HashMap<String, ReportSchedule>,
    firings: Vec<ReportFiring>,
}

/// Scheduler.
pub struct ReportScheduler {
    state: RwLock<State>,
}

impl Default for ReportScheduler {
    fn default() -> Self {
        Self {
            state: RwLock::new(State::default()),
        }
    }
}

impl std::fmt::Debug for ReportScheduler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReportScheduler")
            .field("schedules", &self.schedule_count())
            .field("firings", &self.firing_count())
            .finish()
    }
}

impl ReportScheduler {
    /// New.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a schedule.
    pub fn register(&self, s: ReportSchedule) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("scheduler poisoned".into()))?;
        if g.schedules.contains_key(&s.schedule_id) {
            return Err(SandboxError::Other(format!(
                "schedule {} already registered",
                s.schedule_id
            )));
        }
        g.schedules.insert(s.schedule_id.clone(), s);
        Ok(())
    }

    /// Pause / resume.
    pub fn set_active(&self, schedule_id: &str, active: bool) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("scheduler poisoned".into()))?;
        let s = g
            .schedules
            .get_mut(schedule_id)
            .ok_or_else(|| SandboxError::Other(format!("schedule {} not found", schedule_id)))?;
        s.active = active;
        Ok(())
    }

    /// Tick: fire all due schedules as of `now`. Returns firing records.
    /// Caller supplies `deliver` to actually deliver each report — returns
    /// `(status, optional_output_ref)`.
    pub fn tick<F>(
        &self,
        now: OffsetDateTime,
        mut deliver: F,
    ) -> SandboxResult<Vec<ReportFiring>>
    where
        F: FnMut(&ReportSchedule) -> (FiringStatus, Option<String>, Option<String>),
    {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("scheduler poisoned".into()))?;
        let due_schedules: Vec<ReportSchedule> = g
            .schedules
            .values()
            .filter(|s| s.is_due(now))
            .cloned()
            .collect();
        let mut firings = Vec::new();
        for s in due_schedules {
            let (status, output_ref, error) = deliver(&s);
            let firing = ReportFiring {
                firing_id: Uuid::now_v7(),
                schedule_id: s.schedule_id.clone(),
                fired_at: now
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_default(),
                status,
                output_ref,
                error,
            };
            g.firings.push(firing.clone());
            // Advance next_due_at.
            if let Some(updated) = g.schedules.get_mut(&s.schedule_id) {
                updated.last_fired_at = Some(firing.fired_at.clone());
                let next = now + time::Duration::days(updated.cadence.interval_days());
                updated.next_due_at = next
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_default();
            }
            firings.push(firing);
        }
        Ok(firings)
    }

    /// All schedules.
    pub fn schedules(&self) -> Vec<ReportSchedule> {
        self.state
            .read()
            .map(|g| g.schedules.values().cloned().collect())
            .unwrap_or_default()
    }
    /// Schedule by id.
    pub fn schedule(&self, id: &str) -> Option<ReportSchedule> {
        self.state.read().ok()?.schedules.get(id).cloned()
    }
    /// All firings.
    pub fn firings(&self) -> Vec<ReportFiring> {
        self.state.read().map(|g| g.firings.clone()).unwrap_or_default()
    }
    /// Firings for a schedule.
    pub fn firings_for(&self, schedule_id: &str) -> Vec<ReportFiring> {
        self.firings()
            .into_iter()
            .filter(|f| f.schedule_id == schedule_id)
            .collect()
    }
    /// Schedule count.
    pub fn schedule_count(&self) -> usize {
        self.state.read().map(|g| g.schedules.len()).unwrap_or(0)
    }
    /// Firing count.
    pub fn firing_count(&self) -> usize {
        self.state.read().map(|g| g.firings.len()).unwrap_or(0)
    }
    /// Schedules due as of `now`.
    pub fn due(&self, now: OffsetDateTime) -> Vec<ReportSchedule> {
        self.schedules().into_iter().filter(|s| s.is_due(now)).collect()
    }
}

// =============================================================================
// ScheduleBuilder
// =============================================================================

/// Builder.
pub struct ScheduleBuilder {
    schedule_id: String,
    name: String,
    cadence: Cadence,
    owner: String,
    recipients: Vec<String>,
    first_due_at: String,
    description: String,
}

impl ScheduleBuilder {
    /// New.
    pub fn new(
        schedule_id: impl Into<String>,
        name: impl Into<String>,
        cadence: Cadence,
        owner: impl Into<String>,
        first_due_at: impl Into<String>,
    ) -> Self {
        Self {
            schedule_id: schedule_id.into(),
            name: name.into(),
            cadence,
            owner: owner.into(),
            recipients: Vec::new(),
            first_due_at: first_due_at.into(),
            description: String::new(),
        }
    }
    /// Recipient.
    pub fn recipient(mut self, r: impl Into<String>) -> Self {
        self.recipients.push(r.into());
        self
    }
    /// Description.
    pub fn description(mut self, s: impl Into<String>) -> Self {
        self.description = s.into();
        self
    }
    /// Build.
    pub fn build(self) -> SandboxResult<ReportSchedule> {
        if self.schedule_id.trim().is_empty() {
            return Err(SandboxError::Other("schedule_id required".into()));
        }
        Ok(ReportSchedule {
            schedule_id: self.schedule_id,
            name: self.name,
            recipients: self.recipients,
            owner: self.owner,
            cadence: self.cadence,
            first_due_at: self.first_due_at.clone(),
            next_due_at: self.first_due_at,
            last_fired_at: None,
            active: true,
            description: self.description,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schedule(due: &str, cad: Cadence) -> ReportSchedule {
        ScheduleBuilder::new(
            "soc2-monthly",
            "SOC 2 monthly evidence pull",
            cad,
            "compliance",
            due,
        )
        .recipient("auditor@bank")
        .build()
        .unwrap()
    }

    #[test]
    fn cadence_interval() {
        assert_eq!(Cadence::Daily.interval_days(), 1);
        assert_eq!(Cadence::Weekly.interval_days(), 7);
        assert_eq!(Cadence::Annual.interval_days(), 365);
    }

    #[test]
    fn schedule_is_due_when_past_next() {
        let s = schedule("2025-01-01T00:00:00Z", Cadence::Monthly);
        let now = OffsetDateTime::parse(
            "2026-06-01T00:00:00Z",
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap();
        assert!(s.is_due(now));
    }

    #[test]
    fn schedule_not_due_when_before() {
        let s = schedule("2030-01-01T00:00:00Z", Cadence::Monthly);
        assert!(!s.is_due(OffsetDateTime::now_utc()));
    }

    #[test]
    fn paused_schedule_not_due() {
        let mut s = schedule("2025-01-01T00:00:00Z", Cadence::Monthly);
        s.active = false;
        assert!(!s.is_due(OffsetDateTime::now_utc()));
    }

    #[test]
    fn register_succeeds() {
        let r = ReportScheduler::new();
        r.register(schedule("2025-01-01T00:00:00Z", Cadence::Monthly))
            .unwrap();
        assert_eq!(r.schedule_count(), 1);
    }

    #[test]
    fn duplicate_register_errors() {
        let r = ReportScheduler::new();
        r.register(schedule("2025-01-01T00:00:00Z", Cadence::Monthly))
            .unwrap();
        assert!(r
            .register(schedule("2025-01-01T00:00:00Z", Cadence::Monthly))
            .is_err());
    }

    #[test]
    fn set_active_pauses() {
        let r = ReportScheduler::new();
        r.register(schedule("2025-01-01T00:00:00Z", Cadence::Monthly))
            .unwrap();
        r.set_active("soc2-monthly", false).unwrap();
        assert!(!r.schedule("soc2-monthly").unwrap().active);
    }

    #[test]
    fn set_active_unknown_errors() {
        let r = ReportScheduler::new();
        assert!(r.set_active("ghost", false).is_err());
    }

    #[test]
    fn tick_fires_due_schedules() {
        let r = ReportScheduler::new();
        r.register(schedule("2025-01-01T00:00:00Z", Cadence::Monthly))
            .unwrap();
        let now = OffsetDateTime::parse(
            "2026-06-01T00:00:00Z",
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap();
        let firings = r
            .tick(now, |_| (FiringStatus::Delivered, Some("s3://x".into()), None))
            .unwrap();
        assert_eq!(firings.len(), 1);
        assert_eq!(firings[0].status, FiringStatus::Delivered);
    }

    #[test]
    fn tick_advances_next_due() {
        let r = ReportScheduler::new();
        r.register(schedule("2025-01-01T00:00:00Z", Cadence::Daily))
            .unwrap();
        let now = OffsetDateTime::parse(
            "2026-06-01T00:00:00Z",
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap();
        r.tick(now, |_| (FiringStatus::Delivered, None, None)).unwrap();
        let s = r.schedule("soc2-monthly").unwrap();
        let next = OffsetDateTime::parse(
            &s.next_due_at,
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap();
        assert_eq!(next, now + time::Duration::days(1));
    }

    #[test]
    fn tick_records_failure() {
        let r = ReportScheduler::new();
        r.register(schedule("2025-01-01T00:00:00Z", Cadence::Monthly))
            .unwrap();
        let now = OffsetDateTime::parse(
            "2026-06-01T00:00:00Z",
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap();
        let firings = r
            .tick(now, |_| (FiringStatus::Failed, None, Some("smtp down".into())))
            .unwrap();
        assert_eq!(firings[0].status, FiringStatus::Failed);
    }

    #[test]
    fn tick_no_due_schedules_no_firings() {
        let r = ReportScheduler::new();
        r.register(schedule("2030-01-01T00:00:00Z", Cadence::Monthly))
            .unwrap();
        let firings = r
            .tick(OffsetDateTime::now_utc(), |_| {
                (FiringStatus::Delivered, None, None)
            })
            .unwrap();
        assert!(firings.is_empty());
    }

    #[test]
    fn paused_schedules_not_fired() {
        let r = ReportScheduler::new();
        r.register(schedule("2025-01-01T00:00:00Z", Cadence::Monthly))
            .unwrap();
        r.set_active("soc2-monthly", false).unwrap();
        let now = OffsetDateTime::parse(
            "2026-06-01T00:00:00Z",
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap();
        let firings = r
            .tick(now, |_| (FiringStatus::Delivered, None, None))
            .unwrap();
        assert!(firings.is_empty());
    }

    #[test]
    fn firings_for_filters_by_schedule() {
        let r = ReportScheduler::new();
        r.register(schedule("2025-01-01T00:00:00Z", Cadence::Monthly))
            .unwrap();
        let now = OffsetDateTime::parse(
            "2026-06-01T00:00:00Z",
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap();
        r.tick(now, |_| (FiringStatus::Delivered, None, None)).unwrap();
        assert_eq!(r.firings_for("soc2-monthly").len(), 1);
        assert!(r.firings_for("ghost").is_empty());
    }

    #[test]
    fn schedule_serde() {
        let s = schedule("2026-01-01T00:00:00Z", Cadence::Quarterly);
        let j = serde_json::to_string(&s).unwrap();
        let p: ReportSchedule = serde_json::from_str(&j).unwrap();
        assert_eq!(p, s);
    }

    #[test]
    fn cadence_serde() {
        for c in [
            Cadence::Daily,
            Cadence::Weekly,
            Cadence::Monthly,
            Cadence::Quarterly,
            Cadence::SemiAnnual,
            Cadence::Annual,
        ] {
            let j = serde_json::to_string(&c).unwrap();
            let p: Cadence = serde_json::from_str(&j).unwrap();
            assert_eq!(c, p);
        }
    }

    #[test]
    fn firing_serde() {
        let f = ReportFiring {
            firing_id: Uuid::now_v7(),
            schedule_id: "x".into(),
            fired_at: "t".into(),
            status: FiringStatus::Delivered,
            output_ref: Some("ref".into()),
            error: None,
        };
        let j = serde_json::to_string(&f).unwrap();
        let p: ReportFiring = serde_json::from_str(&j).unwrap();
        assert_eq!(p, f);
    }

    #[test]
    fn status_serde() {
        for s in [
            FiringStatus::Delivered,
            FiringStatus::Failed,
            FiringStatus::Skipped,
        ] {
            let j = serde_json::to_string(&s).unwrap();
            let p: FiringStatus = serde_json::from_str(&j).unwrap();
            assert_eq!(s, p);
        }
    }

    #[test]
    fn due_lists_only_due() {
        let r = ReportScheduler::new();
        r.register(
            ScheduleBuilder::new("a", "A", Cadence::Daily, "x", "2025-01-01T00:00:00Z")
                .build()
                .unwrap(),
        )
        .unwrap();
        r.register(
            ScheduleBuilder::new("b", "B", Cadence::Daily, "x", "2030-01-01T00:00:00Z")
                .build()
                .unwrap(),
        )
        .unwrap();
        let now = OffsetDateTime::parse(
            "2026-01-01T00:00:00Z",
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap();
        let due = r.due(now);
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].schedule_id, "a");
    }

    #[test]
    fn empty_id_errors() {
        assert!(ScheduleBuilder::new("", "x", Cadence::Daily, "y", "z")
            .build()
            .is_err());
    }

    #[test]
    fn last_fired_recorded() {
        let r = ReportScheduler::new();
        r.register(schedule("2025-01-01T00:00:00Z", Cadence::Daily))
            .unwrap();
        let now = OffsetDateTime::parse(
            "2026-01-01T00:00:00Z",
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap();
        r.tick(now, |_| (FiringStatus::Delivered, None, None)).unwrap();
        let s = r.schedule("soc2-monthly").unwrap();
        assert!(s.last_fired_at.is_some());
    }

    #[test]
    fn many_firings_aggregate() {
        let r = ReportScheduler::new();
        r.register(schedule("2025-01-01T00:00:00Z", Cadence::Daily))
            .unwrap();
        let mut now = OffsetDateTime::parse(
            "2026-01-01T00:00:00Z",
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap();
        for _ in 0..5 {
            r.tick(now, |_| (FiringStatus::Delivered, None, None)).unwrap();
            now = now + time::Duration::days(2);
        }
        assert_eq!(r.firing_count(), 5);
    }
}
