//! Red-team test log — record adversarial probes against the AI system.
//!
//! EU AI Act Art. 15 (cyber-resilience), NIST AI RMF MANAGE 4.1, and most
//! enterprise AI policies require a register of red-team / adversarial test
//! results. This module is that register.
//!
//! Each [`RedTeamRun`] records:
//! - Attack scenario name + threat model.
//! - Date + tester.
//! - Number of probes.
//! - Findings + severity.
//! - Whether the model behaved safely.
//! - Mitigations recorded for each finding.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use time::OffsetDateTime;
use uuid::Uuid;

// =============================================================================
// AttackCategory
// =============================================================================

/// Standard adversarial attack categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttackCategory {
    /// Prompt injection.
    PromptInjection,
    /// Data poisoning.
    DataPoisoning,
    /// Model extraction.
    ModelExtraction,
    /// Membership inference.
    MembershipInference,
    /// Evasion / adversarial input.
    Evasion,
    /// Privacy / re-identification.
    Privacy,
    /// Bias / fairness.
    Bias,
    /// Toxicity / harmful content.
    Toxicity,
    /// Custom.
    Custom,
}

// =============================================================================
// FindingSeverity
// =============================================================================

/// Per-finding severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedTeamSeverity {
    /// Critical.
    Critical,
    /// High.
    High,
    /// Medium.
    Medium,
    /// Low.
    Low,
    /// Informational.
    Info,
}

// =============================================================================
// RedTeamFinding
// =============================================================================

/// One finding from a run.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RedTeamFinding {
    /// Finding id.
    pub finding_id: Uuid,
    /// Severity.
    pub severity: RedTeamSeverity,
    /// Free-text description.
    pub description: String,
    /// Reproduction steps.
    pub reproduction: String,
    /// Mitigation status (e.g., `"open"`, `"in_progress"`, `"resolved"`).
    pub mitigation_status: String,
    /// Mitigation note.
    pub mitigation_note: Option<String>,
}

impl RedTeamFinding {
    /// New open finding.
    pub fn open(
        severity: RedTeamSeverity,
        description: impl Into<String>,
        reproduction: impl Into<String>,
    ) -> Self {
        Self {
            finding_id: Uuid::now_v7(),
            severity,
            description: description.into(),
            reproduction: reproduction.into(),
            mitigation_status: "open".into(),
            mitigation_note: None,
        }
    }
}

// =============================================================================
// RedTeamRun
// =============================================================================

/// One adversarial test run.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RedTeamRun {
    /// Run id.
    pub run_id: Uuid,
    /// Model under test.
    pub model_id: String,
    /// Attack categories exercised.
    pub categories: Vec<AttackCategory>,
    /// Tester (team or person).
    pub tester: String,
    /// Threat model description.
    pub threat_model: String,
    /// Number of probes attempted.
    pub probes_attempted: u32,
    /// Number of probes that produced unsafe output.
    pub probes_unsafe: u32,
    /// Findings raised.
    pub findings: Vec<RedTeamFinding>,
    /// RFC 3339 conducted at.
    pub conducted_at: String,
    /// Free-text summary.
    pub summary: String,
}

impl RedTeamRun {
    /// Unsafe ratio.
    pub fn unsafe_ratio(&self) -> f64 {
        if self.probes_attempted == 0 {
            return 0.0;
        }
        self.probes_unsafe as f64 / self.probes_attempted as f64
    }

    /// Number of open findings.
    pub fn open_findings(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.mitigation_status != "resolved")
            .count()
    }

    /// Highest severity among open findings.
    pub fn highest_open_severity(&self) -> Option<RedTeamSeverity> {
        self.findings
            .iter()
            .filter(|f| f.mitigation_status != "resolved")
            .map(|f| f.severity)
            .min_by_key(|s| severity_rank(*s))
    }
}

fn severity_rank(s: RedTeamSeverity) -> u8 {
    match s {
        RedTeamSeverity::Critical => 0,
        RedTeamSeverity::High => 1,
        RedTeamSeverity::Medium => 2,
        RedTeamSeverity::Low => 3,
        RedTeamSeverity::Info => 4,
    }
}

// =============================================================================
// RedTeamLog
// =============================================================================

#[derive(Default)]
struct State {
    runs: HashMap<Uuid, RedTeamRun>,
}

/// Append-only log of runs.
pub struct RedTeamLog {
    state: RwLock<State>,
}

impl Default for RedTeamLog {
    fn default() -> Self {
        Self {
            state: RwLock::new(State::default()),
        }
    }
}

impl std::fmt::Debug for RedTeamLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedTeamLog")
            .field("runs", &self.len())
            .finish()
    }
}

impl RedTeamLog {
    /// New empty.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a run.
    pub fn append(&self, run: RedTeamRun) -> SandboxResult<Uuid> {
        let id = run.run_id;
        self.state
            .write()
            .map_err(|_| SandboxError::Other("red team log poisoned".into()))?
            .runs
            .insert(id, run);
        Ok(id)
    }

    /// Append a finding to a run.
    pub fn add_finding(&self, run_id: Uuid, finding: RedTeamFinding) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("red team log poisoned".into()))?;
        let r = g
            .runs
            .get_mut(&run_id)
            .ok_or_else(|| SandboxError::Other(format!("run {} not found", run_id)))?;
        r.findings.push(finding);
        Ok(())
    }

    /// Update a finding's mitigation status.
    pub fn update_mitigation(
        &self,
        run_id: Uuid,
        finding_id: Uuid,
        status: impl Into<String>,
        note: Option<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("red team log poisoned".into()))?;
        let r = g
            .runs
            .get_mut(&run_id)
            .ok_or_else(|| SandboxError::Other(format!("run {} not found", run_id)))?;
        let f = r
            .findings
            .iter_mut()
            .find(|f| f.finding_id == finding_id)
            .ok_or_else(|| SandboxError::Other(format!("finding {} not in run", finding_id)))?;
        f.mitigation_status = status.into();
        f.mitigation_note = note;
        Ok(())
    }

    /// Lookup.
    pub fn get(&self, id: Uuid) -> Option<RedTeamRun> {
        self.state.read().ok()?.runs.get(&id).cloned()
    }
    /// All.
    pub fn all(&self) -> Vec<RedTeamRun> {
        self.state
            .read()
            .map(|g| g.runs.values().cloned().collect())
            .unwrap_or_default()
    }
    /// By model id.
    pub fn for_model(&self, model_id: &str) -> Vec<RedTeamRun> {
        self.all().into_iter().filter(|r| r.model_id == model_id).collect()
    }
    /// By category.
    pub fn for_category(&self, category: AttackCategory) -> Vec<RedTeamRun> {
        self.all()
            .into_iter()
            .filter(|r| r.categories.contains(&category))
            .collect()
    }
    /// Runs with open findings of severity >= `min`.
    pub fn open_high(&self, min: RedTeamSeverity) -> Vec<RedTeamRun> {
        self.all()
            .into_iter()
            .filter(|r| {
                r.findings
                    .iter()
                    .any(|f| f.mitigation_status != "resolved" && severity_rank(f.severity) <= severity_rank(min))
            })
            .collect()
    }
    /// Count.
    pub fn len(&self) -> usize {
        self.state.read().map(|g| g.runs.len()).unwrap_or(0)
    }
    /// Empty?
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// =============================================================================
// Builder
// =============================================================================

/// Builder for [`RedTeamRun`].
pub struct RunBuilder {
    model_id: String,
    categories: Vec<AttackCategory>,
    tester: String,
    threat_model: String,
    probes_attempted: u32,
    probes_unsafe: u32,
    findings: Vec<RedTeamFinding>,
    summary: String,
}

impl RunBuilder {
    /// New builder with required fields.
    pub fn new(
        model_id: impl Into<String>,
        tester: impl Into<String>,
        threat_model: impl Into<String>,
    ) -> Self {
        Self {
            model_id: model_id.into(),
            categories: Vec::new(),
            tester: tester.into(),
            threat_model: threat_model.into(),
            probes_attempted: 0,
            probes_unsafe: 0,
            findings: Vec::new(),
            summary: String::new(),
        }
    }
    /// Add a category.
    pub fn category(mut self, c: AttackCategory) -> Self {
        if !self.categories.contains(&c) {
            self.categories.push(c);
        }
        self
    }
    /// Probes.
    pub fn probes(mut self, attempted: u32, unsafe_count: u32) -> Self {
        self.probes_attempted = attempted;
        self.probes_unsafe = unsafe_count;
        self
    }
    /// Finding.
    pub fn finding(mut self, f: RedTeamFinding) -> Self {
        self.findings.push(f);
        self
    }
    /// Summary.
    pub fn summary(mut self, s: impl Into<String>) -> Self {
        self.summary = s.into();
        self
    }
    /// Build.
    pub fn build(self) -> SandboxResult<RedTeamRun> {
        if self.probes_unsafe > self.probes_attempted {
            return Err(SandboxError::Other(format!(
                "unsafe ({}) > attempted ({})",
                self.probes_unsafe, self.probes_attempted
            )));
        }
        Ok(RedTeamRun {
            run_id: Uuid::now_v7(),
            model_id: self.model_id,
            categories: self.categories,
            tester: self.tester,
            threat_model: self.threat_model,
            probes_attempted: self.probes_attempted,
            probes_unsafe: self.probes_unsafe,
            findings: self.findings,
            conducted_at: OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
            summary: self.summary,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run() -> RedTeamRun {
        RunBuilder::new("gpt-x", "redteam", "sql-injection")
            .category(AttackCategory::PromptInjection)
            .probes(100, 5)
            .finding(RedTeamFinding::open(
                RedTeamSeverity::High,
                "leaked secret",
                "send 'ignore...'",
            ))
            .summary("ok")
            .build()
            .unwrap()
    }

    #[test]
    fn build_creates_run() {
        let r = run();
        assert_eq!(r.probes_attempted, 100);
        assert_eq!(r.probes_unsafe, 5);
    }

    #[test]
    fn build_unsafe_gt_attempted_errors() {
        let b = RunBuilder::new("x", "y", "z").probes(10, 100);
        assert!(b.build().is_err());
    }

    #[test]
    fn unsafe_ratio_correct() {
        let r = run();
        assert!((r.unsafe_ratio() - 0.05).abs() < 1e-9);
    }

    #[test]
    fn unsafe_ratio_zero_when_no_probes() {
        let r = RunBuilder::new("x", "y", "z").build().unwrap();
        assert_eq!(r.unsafe_ratio(), 0.0);
    }

    #[test]
    fn open_findings_count() {
        let r = run();
        assert_eq!(r.open_findings(), 1);
    }

    #[test]
    fn highest_open_severity() {
        let r = run();
        assert_eq!(r.highest_open_severity(), Some(RedTeamSeverity::High));
    }

    #[test]
    fn log_append_and_get() {
        let l = RedTeamLog::new();
        let id = l.append(run()).unwrap();
        assert!(l.get(id).is_some());
    }

    #[test]
    fn add_finding_appends() {
        let l = RedTeamLog::new();
        let id = l.append(run()).unwrap();
        l.add_finding(
            id,
            RedTeamFinding::open(RedTeamSeverity::Medium, "x", "y"),
        )
        .unwrap();
        assert_eq!(l.get(id).unwrap().findings.len(), 2);
    }

    #[test]
    fn add_finding_unknown_errors() {
        let l = RedTeamLog::new();
        let f = RedTeamFinding::open(RedTeamSeverity::Low, "x", "y");
        assert!(l.add_finding(Uuid::now_v7(), f).is_err());
    }

    #[test]
    fn update_mitigation_changes_status() {
        let l = RedTeamLog::new();
        let id = l.append(run()).unwrap();
        let r = l.get(id).unwrap();
        let fid = r.findings[0].finding_id;
        l.update_mitigation(id, fid, "resolved", Some("patched".into()))
            .unwrap();
        let updated = l.get(id).unwrap();
        assert_eq!(updated.findings[0].mitigation_status, "resolved");
        assert_eq!(updated.open_findings(), 0);
    }

    #[test]
    fn update_unknown_finding_errors() {
        let l = RedTeamLog::new();
        let id = l.append(run()).unwrap();
        assert!(l
            .update_mitigation(id, Uuid::now_v7(), "resolved", None)
            .is_err());
    }

    #[test]
    fn for_model_filters() {
        let l = RedTeamLog::new();
        l.append(run()).unwrap();
        l.append(
            RunBuilder::new("gpt-y", "x", "y")
                .build()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(l.for_model("gpt-x").len(), 1);
        assert_eq!(l.for_model("gpt-y").len(), 1);
    }

    #[test]
    fn for_category_filters() {
        let l = RedTeamLog::new();
        l.append(run()).unwrap();
        let r2 = RunBuilder::new("gpt-y", "x", "y")
            .category(AttackCategory::Evasion)
            .build()
            .unwrap();
        l.append(r2).unwrap();
        assert_eq!(l.for_category(AttackCategory::PromptInjection).len(), 1);
        assert_eq!(l.for_category(AttackCategory::Evasion).len(), 1);
    }

    #[test]
    fn open_high_filters_by_severity() {
        let l = RedTeamLog::new();
        l.append(run()).unwrap();
        // Ours has High open.
        assert_eq!(l.open_high(RedTeamSeverity::High).len(), 1);
        // Critical-only filter shouldn't include High.
        assert_eq!(l.open_high(RedTeamSeverity::Critical).len(), 0);
    }

    #[test]
    fn category_dedupes() {
        let r = RunBuilder::new("x", "y", "z")
            .category(AttackCategory::PromptInjection)
            .category(AttackCategory::PromptInjection)
            .build()
            .unwrap();
        assert_eq!(r.categories.len(), 1);
    }

    #[test]
    fn finding_serde() {
        let f = RedTeamFinding::open(RedTeamSeverity::Critical, "x", "y");
        let j = serde_json::to_string(&f).unwrap();
        let p: RedTeamFinding = serde_json::from_str(&j).unwrap();
        assert_eq!(p, f);
    }

    #[test]
    fn run_serde() {
        let r = run();
        let j = serde_json::to_string(&r).unwrap();
        let p: RedTeamRun = serde_json::from_str(&j).unwrap();
        assert_eq!(p, r);
    }

    #[test]
    fn category_serde() {
        for c in [
            AttackCategory::PromptInjection,
            AttackCategory::DataPoisoning,
            AttackCategory::ModelExtraction,
            AttackCategory::MembershipInference,
            AttackCategory::Evasion,
            AttackCategory::Privacy,
            AttackCategory::Bias,
            AttackCategory::Toxicity,
            AttackCategory::Custom,
        ] {
            let j = serde_json::to_string(&c).unwrap();
            let p: AttackCategory = serde_json::from_str(&j).unwrap();
            assert_eq!(p, c);
        }
    }

    #[test]
    fn severity_serde() {
        for s in [
            RedTeamSeverity::Critical,
            RedTeamSeverity::High,
            RedTeamSeverity::Medium,
            RedTeamSeverity::Low,
            RedTeamSeverity::Info,
        ] {
            let j = serde_json::to_string(&s).unwrap();
            let p: RedTeamSeverity = serde_json::from_str(&j).unwrap();
            assert_eq!(p, s);
        }
    }

    #[test]
    fn log_count_tracks() {
        let l = RedTeamLog::new();
        assert!(l.is_empty());
        l.append(run()).unwrap();
        assert_eq!(l.len(), 1);
    }
}
