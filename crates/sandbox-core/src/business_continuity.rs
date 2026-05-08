//! Business Continuity Planning (BCP) — RTO/RPO definitions + test log.
//!
//! Regulators (FFIEC, ISO 22301, MAS BCM) require organizations to:
//!
//! - Define **Recovery Time Objective** (RTO — max acceptable downtime).
//! - Define **Recovery Point Objective** (RPO — max acceptable data loss).
//! - Periodically *test* the plan (tabletop, simulation, full failover).
//! - Maintain a tamper-evident log of test outcomes.
//!
//! This module models that evidence trail.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use time::OffsetDateTime;
use uuid::Uuid;

// =============================================================================
// CriticalProcess
// =============================================================================

/// One business-critical process with RTO/RPO targets.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CriticalProcess {
    /// Stable id.
    pub process_id: String,
    /// Process name.
    pub name: String,
    /// Owning team.
    pub owner: String,
    /// RTO in minutes.
    pub rto_minutes: u64,
    /// RPO in minutes.
    pub rpo_minutes: u64,
    /// Free-text description.
    pub description: String,
    /// RFC 3339 last-reviewed.
    pub last_reviewed_at: Option<String>,
}

// =============================================================================
// BcpTestKind
// =============================================================================

/// Kind of BCP test.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BcpTestKind {
    /// Tabletop walk-through, no traffic moved.
    Tabletop,
    /// Simulation — partial traffic switched.
    Simulation,
    /// Full failover.
    FullFailover,
    /// Backup-restore drill.
    RestoreDrill,
}

// =============================================================================
// BcpTestOutcome
// =============================================================================

/// Per-test outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BcpTestOutcome {
    /// Met both RTO and RPO.
    Pass,
    /// Met some but not all targets.
    PartialPass,
    /// Failed to meet targets.
    Fail,
    /// Aborted before completion.
    Aborted,
}

// =============================================================================
// BcpTestRecord
// =============================================================================

/// One BCP test record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BcpTestRecord {
    /// Stable id.
    pub test_id: Uuid,
    /// Process tested.
    pub process_id: String,
    /// Kind.
    pub kind: BcpTestKind,
    /// Outcome.
    pub outcome: BcpTestOutcome,
    /// RFC 3339 conducted at.
    pub conducted_at: String,
    /// Conducted by.
    pub conducted_by: String,
    /// Measured RTO in minutes.
    pub measured_rto_minutes: Option<u64>,
    /// Measured RPO in minutes.
    pub measured_rpo_minutes: Option<u64>,
    /// Notes / findings.
    pub notes: String,
    /// Next-test due date.
    pub next_due: Option<String>,
}

impl BcpTestRecord {
    /// `true` if measured RTO meets target (≤ target).
    pub fn rto_met(&self, target_minutes: u64) -> bool {
        match self.measured_rto_minutes {
            Some(m) => m <= target_minutes,
            None => false,
        }
    }
    /// `true` if measured RPO meets target.
    pub fn rpo_met(&self, target_minutes: u64) -> bool {
        match self.measured_rpo_minutes {
            Some(m) => m <= target_minutes,
            None => false,
        }
    }
}

// =============================================================================
// BcpRegistry
// =============================================================================

#[derive(Default)]
struct State {
    processes: HashMap<String, CriticalProcess>,
    tests: Vec<BcpTestRecord>,
}

/// Registry of processes + tests.
pub struct BcpRegistry {
    state: RwLock<State>,
}

impl Default for BcpRegistry {
    fn default() -> Self {
        Self {
            state: RwLock::new(State::default()),
        }
    }
}

impl std::fmt::Debug for BcpRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BcpRegistry")
            .field("processes", &self.process_count())
            .field("tests", &self.test_count())
            .finish()
    }
}

impl BcpRegistry {
    /// New empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a critical process.
    pub fn register_process(&self, p: CriticalProcess) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("bcp registry poisoned".into()))?;
        if g.processes.contains_key(&p.process_id) {
            return Err(SandboxError::Other(format!(
                "process {} already registered",
                p.process_id
            )));
        }
        g.processes.insert(p.process_id.clone(), p);
        Ok(())
    }

    /// Mark a process as reviewed.
    pub fn mark_reviewed(&self, process_id: &str) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("bcp registry poisoned".into()))?;
        let p = g
            .processes
            .get_mut(process_id)
            .ok_or_else(|| SandboxError::Other(format!("process {} not found", process_id)))?;
        p.last_reviewed_at = Some(
            OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
        );
        Ok(())
    }

    /// Record a test.
    pub fn record_test(&self, r: BcpTestRecord) -> SandboxResult<Uuid> {
        let id = r.test_id;
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("bcp registry poisoned".into()))?;
        if !g.processes.contains_key(&r.process_id) {
            return Err(SandboxError::Other(format!(
                "process {} not registered",
                r.process_id
            )));
        }
        g.tests.push(r);
        Ok(id)
    }

    /// Look up process.
    pub fn process(&self, id: &str) -> Option<CriticalProcess> {
        self.state.read().ok()?.processes.get(id).cloned()
    }

    /// All processes.
    pub fn processes(&self) -> Vec<CriticalProcess> {
        self.state
            .read()
            .map(|g| g.processes.values().cloned().collect())
            .unwrap_or_default()
    }

    /// All tests.
    pub fn tests(&self) -> Vec<BcpTestRecord> {
        self.state.read().map(|g| g.tests.clone()).unwrap_or_default()
    }

    /// Tests for a process.
    pub fn tests_for(&self, process_id: &str) -> Vec<BcpTestRecord> {
        self.tests()
            .into_iter()
            .filter(|t| t.process_id == process_id)
            .collect()
    }

    /// Latest test for a process by `conducted_at`.
    pub fn latest_test(&self, process_id: &str) -> Option<BcpTestRecord> {
        self.tests_for(process_id)
            .into_iter()
            .max_by(|a, b| a.conducted_at.cmp(&b.conducted_at))
    }

    /// Process count.
    pub fn process_count(&self) -> usize {
        self.state.read().map(|g| g.processes.len()).unwrap_or(0)
    }
    /// Test count.
    pub fn test_count(&self) -> usize {
        self.state.read().map(|g| g.tests.len()).unwrap_or(0)
    }

    /// Compliance summary: per-process latest test outcome.
    pub fn compliance_summary(&self) -> Vec<ComplianceRow> {
        let processes = self.processes();
        processes
            .into_iter()
            .map(|p| {
                let latest = self.latest_test(&p.process_id);
                let outcome = latest.as_ref().map(|t| t.outcome);
                let last_at = latest.as_ref().map(|t| t.conducted_at.clone());
                ComplianceRow {
                    process_id: p.process_id,
                    process_name: p.name,
                    rto_minutes: p.rto_minutes,
                    rpo_minutes: p.rpo_minutes,
                    last_test_at: last_at,
                    last_outcome: outcome,
                }
            })
            .collect()
    }
}

/// One row in [`BcpRegistry::compliance_summary`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ComplianceRow {
    /// Process id.
    pub process_id: String,
    /// Process name.
    pub process_name: String,
    /// Target RTO.
    pub rto_minutes: u64,
    /// Target RPO.
    pub rpo_minutes: u64,
    /// Last test time.
    pub last_test_at: Option<String>,
    /// Last test outcome.
    pub last_outcome: Option<BcpTestOutcome>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proc(id: &str, rto: u64, rpo: u64) -> CriticalProcess {
        CriticalProcess {
            process_id: id.into(),
            name: id.into(),
            owner: "ops".into(),
            rto_minutes: rto,
            rpo_minutes: rpo,
            description: "x".into(),
            last_reviewed_at: None,
        }
    }

    fn test_rec(process: &str, outcome: BcpTestOutcome, rto: Option<u64>) -> BcpTestRecord {
        BcpTestRecord {
            test_id: Uuid::now_v7(),
            process_id: process.into(),
            kind: BcpTestKind::Simulation,
            outcome,
            conducted_at: OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
            conducted_by: "team".into(),
            measured_rto_minutes: rto,
            measured_rpo_minutes: Some(5),
            notes: "x".into(),
            next_due: None,
        }
    }

    #[test]
    fn register_process_increments() {
        let r = BcpRegistry::new();
        r.register_process(proc("a", 60, 5)).unwrap();
        assert_eq!(r.process_count(), 1);
    }

    #[test]
    fn duplicate_process_errors() {
        let r = BcpRegistry::new();
        r.register_process(proc("a", 60, 5)).unwrap();
        assert!(r.register_process(proc("a", 60, 5)).is_err());
    }

    #[test]
    fn record_test_after_register() {
        let r = BcpRegistry::new();
        r.register_process(proc("a", 60, 5)).unwrap();
        r.record_test(test_rec("a", BcpTestOutcome::Pass, Some(30)))
            .unwrap();
        assert_eq!(r.test_count(), 1);
    }

    #[test]
    fn record_test_for_unknown_process_errors() {
        let r = BcpRegistry::new();
        assert!(r
            .record_test(test_rec("ghost", BcpTestOutcome::Pass, None))
            .is_err());
    }

    #[test]
    fn tests_for_filters() {
        let r = BcpRegistry::new();
        r.register_process(proc("a", 60, 5)).unwrap();
        r.register_process(proc("b", 60, 5)).unwrap();
        r.record_test(test_rec("a", BcpTestOutcome::Pass, None)).unwrap();
        r.record_test(test_rec("b", BcpTestOutcome::Fail, None)).unwrap();
        assert_eq!(r.tests_for("a").len(), 1);
        assert_eq!(r.tests_for("b").len(), 1);
    }

    #[test]
    fn latest_test_picks_newest() {
        let r = BcpRegistry::new();
        r.register_process(proc("a", 60, 5)).unwrap();
        let mut t1 = test_rec("a", BcpTestOutcome::Pass, Some(30));
        t1.conducted_at = "2026-01-01T00:00:00Z".into();
        let mut t2 = test_rec("a", BcpTestOutcome::Fail, Some(120));
        t2.conducted_at = "2026-06-01T00:00:00Z".into();
        r.record_test(t1).unwrap();
        r.record_test(t2).unwrap();
        let latest = r.latest_test("a").unwrap();
        assert_eq!(latest.outcome, BcpTestOutcome::Fail);
    }

    #[test]
    fn rto_met_evaluates() {
        let t = test_rec("a", BcpTestOutcome::Pass, Some(30));
        assert!(t.rto_met(60));
        assert!(!t.rto_met(20));
    }

    #[test]
    fn rpo_met_evaluates() {
        let t = test_rec("a", BcpTestOutcome::Pass, Some(30));
        assert!(t.rpo_met(10));
        assert!(!t.rpo_met(2));
    }

    #[test]
    fn rto_unset_returns_false() {
        let t = test_rec("a", BcpTestOutcome::Pass, None);
        assert!(!t.rto_met(60));
    }

    #[test]
    fn mark_reviewed_records_timestamp() {
        let r = BcpRegistry::new();
        r.register_process(proc("a", 60, 5)).unwrap();
        r.mark_reviewed("a").unwrap();
        let p = r.process("a").unwrap();
        assert!(p.last_reviewed_at.is_some());
    }

    #[test]
    fn mark_reviewed_unknown_errors() {
        let r = BcpRegistry::new();
        assert!(r.mark_reviewed("ghost").is_err());
    }

    #[test]
    fn compliance_summary_returns_rows() {
        let r = BcpRegistry::new();
        r.register_process(proc("a", 60, 5)).unwrap();
        r.register_process(proc("b", 30, 2)).unwrap();
        r.record_test(test_rec("a", BcpTestOutcome::Pass, Some(45)))
            .unwrap();
        let rows = r.compliance_summary();
        assert_eq!(rows.len(), 2);
        let arow = rows.iter().find(|r| r.process_id == "a").unwrap();
        assert_eq!(arow.last_outcome, Some(BcpTestOutcome::Pass));
    }

    #[test]
    fn compliance_row_no_test() {
        let r = BcpRegistry::new();
        r.register_process(proc("a", 60, 5)).unwrap();
        let rows = r.compliance_summary();
        assert!(rows[0].last_outcome.is_none());
    }

    #[test]
    fn process_serde() {
        let p = proc("a", 60, 5);
        let j = serde_json::to_string(&p).unwrap();
        let q: CriticalProcess = serde_json::from_str(&j).unwrap();
        assert_eq!(p, q);
    }

    #[test]
    fn test_record_serde() {
        let t = test_rec("a", BcpTestOutcome::Pass, Some(30));
        let j = serde_json::to_string(&t).unwrap();
        let p: BcpTestRecord = serde_json::from_str(&j).unwrap();
        assert_eq!(p, t);
    }

    #[test]
    fn outcome_serde() {
        for o in [
            BcpTestOutcome::Pass,
            BcpTestOutcome::PartialPass,
            BcpTestOutcome::Fail,
            BcpTestOutcome::Aborted,
        ] {
            let j = serde_json::to_string(&o).unwrap();
            let p: BcpTestOutcome = serde_json::from_str(&j).unwrap();
            assert_eq!(p, o);
        }
    }

    #[test]
    fn kind_serde() {
        for k in [
            BcpTestKind::Tabletop,
            BcpTestKind::Simulation,
            BcpTestKind::FullFailover,
            BcpTestKind::RestoreDrill,
        ] {
            let j = serde_json::to_string(&k).unwrap();
            let p: BcpTestKind = serde_json::from_str(&j).unwrap();
            assert_eq!(p, k);
        }
    }

    #[test]
    fn many_processes_and_tests() {
        let r = BcpRegistry::new();
        for i in 0..10 {
            r.register_process(proc(&format!("p{i}"), 60, 5)).unwrap();
            r.record_test(test_rec(
                &format!("p{i}"),
                BcpTestOutcome::Pass,
                Some(30),
            ))
            .unwrap();
        }
        assert_eq!(r.process_count(), 10);
        assert_eq!(r.test_count(), 10);
    }

    #[test]
    fn compliance_row_serde() {
        let row = ComplianceRow {
            process_id: "a".into(),
            process_name: "A".into(),
            rto_minutes: 60,
            rpo_minutes: 5,
            last_test_at: Some("2026-01-01T00:00:00Z".into()),
            last_outcome: Some(BcpTestOutcome::Pass),
        };
        let j = serde_json::to_string(&row).unwrap();
        let p: ComplianceRow = serde_json::from_str(&j).unwrap();
        assert_eq!(p, row);
    }

    #[test]
    fn process_lookup_unknown_none() {
        let r = BcpRegistry::new();
        assert!(r.process("ghost").is_none());
    }

    #[test]
    fn processes_returns_all() {
        let r = BcpRegistry::new();
        r.register_process(proc("a", 60, 5)).unwrap();
        r.register_process(proc("b", 60, 5)).unwrap();
        assert_eq!(r.processes().len(), 2);
    }

    #[test]
    fn empty_registry_has_zero_counts() {
        let r = BcpRegistry::new();
        assert_eq!(r.process_count(), 0);
        assert_eq!(r.test_count(), 0);
    }
}
