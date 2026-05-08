//! Control test register — evidence-of-operation for compliance controls.
//!
//! Distinct from [`crate::compliance_dashboard`] (snapshot of current
//! compliance posture) and [`crate::compliance_report`] (point-in-time
//! report bundle), this is the **operational test history**: every
//! quarter (or whatever the test cadence is), every in-scope control is
//! tested, the result is recorded, and exceptions are tracked through
//! to remediation.
//!
//! Maps to SOC 2 (where Type II reports require 6-12 months of
//! operational testing evidence), ISO 27001 A.18.2 (independent review
//! of information security), PCI-DSS 12.x (compliance management), and
//! NIST 800-53 CA-7 (continuous monitoring).
//!
//! ## Test outcome
//!
//! Each [`ControlTest`] records `Passed | Failed | Exception | NotApplicable`.
//! Failed/Exception tests open remediation timelines; the registry exposes
//! `failed_open()` so compliance can dashboard the backlog.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

// =============================================================================
// TestOutcome
// =============================================================================

/// Outcome of a single control test.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TestOutcome {
    /// Control operated effectively.
    Passed,
    /// Control failed.
    Failed,
    /// Control had an exception (an isolated breakdown, with documented
    /// compensating actions).
    Exception,
    /// Control wasn't applicable for this test period.
    NotApplicable,
}

impl TestOutcome {
    /// True if a remediation is needed.
    pub fn requires_remediation(self) -> bool {
        matches!(self, Self::Failed | Self::Exception)
    }
}

// =============================================================================
// TestMethod
// =============================================================================

/// How the test was performed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TestMethod {
    /// Inspected documentation / config.
    Inspection,
    /// Observed the control in operation.
    Observation,
    /// Re-performed the control (independent recomputation).
    Reperformance,
    /// Inquired of personnel.
    Inquiry,
    /// Automated continuous monitoring.
    Automated,
}

// =============================================================================
// RemediationStatus
// =============================================================================

/// Status of remediation for a Failed / Exception test.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemediationStatus {
    /// Remediation work hasn't started.
    NotStarted,
    /// Remediation in progress.
    InProgress,
    /// Remediation complete; awaiting re-test.
    Implemented,
    /// Re-test verified the remediation.
    Verified,
}

impl RemediationStatus {
    /// True if the remediation is fully closed.
    pub fn is_closed(self) -> bool {
        matches!(self, Self::Verified)
    }
}

// =============================================================================
// ControlTest
// =============================================================================

/// One control test instance.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ControlTest {
    /// Unique test id.
    pub test_id: String,
    /// Tenant scope.
    pub tenant_id: String,
    /// Control id (matches [`crate::compliance_report::ControlRef`] or
    /// internal control catalog).
    pub control_id: String,
    /// Optional framework label ("SOC2 CC6.1", "ISO 27001 A.9.2.1").
    pub framework: Option<String>,
    /// Test period label ("Q1-2025", "2025-04").
    pub period: String,
    /// Method used.
    pub method: TestMethod,
    /// Outcome.
    pub outcome: TestOutcome,
    /// Tester / auditor.
    pub tester: String,
    /// RFC 3339 — when test was performed.
    pub tested_at: String,
    /// Free-text test description / what was inspected.
    pub description: String,
    /// Free-text findings / evidence summary.
    pub findings: Option<String>,
    /// Sample size if a sampling test (0 = full population / not applicable).
    pub sample_size: u64,
    /// Remediation status (only meaningful when outcome requires_remediation).
    pub remediation: RemediationStatus,
    /// RFC 3339 — when remediation was verified.
    pub remediation_verified_at: Option<String>,
    /// Free-text remediation notes.
    pub remediation_notes: Option<String>,
    /// Free-form tags.
    pub tags: Vec<String>,
}

impl ControlTest {
    /// Construct a new test record.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        test_id: impl Into<String>,
        tenant_id: impl Into<String>,
        control_id: impl Into<String>,
        period: impl Into<String>,
        method: TestMethod,
        outcome: TestOutcome,
        tester: impl Into<String>,
        tested_at: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            test_id: test_id.into(),
            tenant_id: tenant_id.into(),
            control_id: control_id.into(),
            framework: None,
            period: period.into(),
            method,
            outcome,
            tester: tester.into(),
            tested_at: tested_at.into(),
            description: description.into(),
            findings: None,
            sample_size: 0,
            // Failed/Exception default to NotStarted; everything else stays
            // NotStarted but is irrelevant.
            remediation: RemediationStatus::NotStarted,
            remediation_verified_at: None,
            remediation_notes: None,
            tags: Vec::new(),
        }
    }

    /// True if this test has unresolved remediation.
    pub fn is_open(&self) -> bool {
        self.outcome.requires_remediation() && !self.remediation.is_closed()
    }
}

// =============================================================================
// ControlTestRegister
// =============================================================================

/// Thread-safe register of control tests.
#[derive(Debug, Default)]
pub struct ControlTestRegister {
    inner: RwLock<HashMap<String, ControlTest>>,
}

impl ControlTestRegister {
    /// New empty register.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new test.
    pub fn register(&self, test: ControlTest) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("control test register poisoned".into()))?;
        if g.contains_key(&test.test_id) {
            return Err(SandboxError::Other(format!(
                "test already registered: {}",
                test.test_id
            )));
        }
        g.insert(test.test_id.clone(), test);
        Ok(())
    }

    /// Set framework label.
    pub fn set_framework(
        &self,
        test_id: &str,
        framework: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("control test register poisoned".into()))?;
        let t = g
            .get_mut(test_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown test {test_id}")))?;
        t.framework = Some(framework.into());
        Ok(())
    }

    /// Set findings text.
    pub fn set_findings(
        &self,
        test_id: &str,
        findings: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("control test register poisoned".into()))?;
        let t = g
            .get_mut(test_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown test {test_id}")))?;
        t.findings = Some(findings.into());
        Ok(())
    }

    /// Set sample size.
    pub fn set_sample_size(&self, test_id: &str, n: u64) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("control test register poisoned".into()))?;
        let t = g
            .get_mut(test_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown test {test_id}")))?;
        t.sample_size = n;
        Ok(())
    }

    /// Update remediation status. If transitioning to `Verified`, records
    /// `remediation_verified_at`. Errors if the test outcome doesn't
    /// require remediation.
    pub fn set_remediation(
        &self,
        test_id: &str,
        status: RemediationStatus,
        at: impl Into<String>,
        notes: Option<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("control test register poisoned".into()))?;
        let t = g
            .get_mut(test_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown test {test_id}")))?;
        if !t.outcome.requires_remediation() {
            return Err(SandboxError::Other(format!(
                "test {test_id} outcome {:?} does not require remediation",
                t.outcome
            )));
        }
        t.remediation = status;
        if status == RemediationStatus::Verified {
            t.remediation_verified_at = Some(at.into());
        }
        if let Some(n) = notes {
            t.remediation_notes = Some(n);
        }
        Ok(())
    }

    /// Add a tag (deduplicated).
    pub fn add_tag(&self, test_id: &str, tag: impl Into<String>) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("control test register poisoned".into()))?;
        let t = g
            .get_mut(test_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown test {test_id}")))?;
        let tag = tag.into();
        if !t.tags.contains(&tag) {
            t.tags.push(tag);
        }
        Ok(())
    }

    /// Look up.
    pub fn get(&self, test_id: &str) -> Option<ControlTest> {
        let g = self.inner.read().ok()?;
        g.get(test_id).cloned()
    }

    /// All tests.
    pub fn all(&self) -> Vec<ControlTest> {
        match self.inner.read() {
            Ok(g) => g.values().cloned().collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Tests for a tenant.
    pub fn for_tenant(&self, tenant_id: &str) -> Vec<ControlTest> {
        self.all()
            .into_iter()
            .filter(|t| t.tenant_id == tenant_id)
            .collect()
    }

    /// Tests for a control id.
    pub fn for_control(&self, control_id: &str) -> Vec<ControlTest> {
        self.all()
            .into_iter()
            .filter(|t| t.control_id == control_id)
            .collect()
    }

    /// Tests for a period.
    pub fn for_period(&self, period: &str) -> Vec<ControlTest> {
        self.all()
            .into_iter()
            .filter(|t| t.period == period)
            .collect()
    }

    /// Tests by outcome.
    pub fn by_outcome(&self, outcome: TestOutcome) -> Vec<ControlTest> {
        self.all()
            .into_iter()
            .filter(|t| t.outcome == outcome)
            .collect()
    }

    /// Tests with unresolved remediation (Failed / Exception that haven't
    /// been verified).
    pub fn open_remediations(&self) -> Vec<ControlTest> {
        self.all().into_iter().filter(|t| t.is_open()).collect()
    }

    /// Aggregate stats for a test period across all controls.
    pub fn period_summary(&self, period: &str) -> PeriodSummary {
        let tests = self.for_period(period);
        let total = tests.len();
        let mut passed = 0;
        let mut failed = 0;
        let mut exception = 0;
        let mut not_applicable = 0;
        for t in &tests {
            match t.outcome {
                TestOutcome::Passed => passed += 1,
                TestOutcome::Failed => failed += 1,
                TestOutcome::Exception => exception += 1,
                TestOutcome::NotApplicable => not_applicable += 1,
            }
        }
        let open = tests.iter().filter(|t| t.is_open()).count();
        PeriodSummary {
            period: period.to_string(),
            total,
            passed,
            failed,
            exception,
            not_applicable,
            open_remediations: open,
        }
    }

    /// Count.
    pub fn count(&self) -> usize {
        self.inner.read().map(|g| g.len()).unwrap_or(0)
    }
}

// =============================================================================
// PeriodSummary
// =============================================================================

/// Aggregate snapshot of one test period.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PeriodSummary {
    /// Period label.
    pub period: String,
    /// Total tests.
    pub total: usize,
    /// Passed count.
    pub passed: usize,
    /// Failed count.
    pub failed: usize,
    /// Exception count.
    pub exception: usize,
    /// Not-applicable count.
    pub not_applicable: usize,
    /// Tests with open remediations.
    pub open_remediations: usize,
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn t(id: &str, outcome: TestOutcome) -> ControlTest {
        ControlTest::new(
            id,
            "global",
            "CC6.1",
            "Q1-2025",
            TestMethod::Inspection,
            outcome,
            "auditor",
            "2025-04-01T00:00:00Z",
            "inspect access review evidence",
        )
    }

    #[test]
    fn register_and_get() {
        let r = ControlTestRegister::new();
        r.register(t("t1", TestOutcome::Passed)).unwrap();
        assert!(r.get("t1").is_some());
    }

    #[test]
    fn duplicate_register_errors() {
        let r = ControlTestRegister::new();
        r.register(t("t1", TestOutcome::Passed)).unwrap();
        let err = r.register(t("t1", TestOutcome::Passed)).unwrap_err();
        assert!(format!("{err}").contains("already registered"));
    }

    #[test]
    fn set_framework_findings_sample() {
        let r = ControlTestRegister::new();
        r.register(t("t1", TestOutcome::Passed)).unwrap();
        r.set_framework("t1", "SOC2 CC6.1").unwrap();
        r.set_findings("t1", "all 25 sampled records had documented review")
            .unwrap();
        r.set_sample_size("t1", 25).unwrap();
        let g = r.get("t1").unwrap();
        assert_eq!(g.framework.as_deref(), Some("SOC2 CC6.1"));
        assert!(g.findings.is_some());
        assert_eq!(g.sample_size, 25);
    }

    #[test]
    fn set_remediation_only_when_required() {
        let r = ControlTestRegister::new();
        r.register(t("t1", TestOutcome::Passed)).unwrap();
        let err = r
            .set_remediation(
                "t1",
                RemediationStatus::InProgress,
                "2025-05-01T00:00:00Z",
                None,
            )
            .unwrap_err();
        assert!(format!("{err}").contains("does not require remediation"));
    }

    #[test]
    fn set_remediation_records_verified_timestamp() {
        let r = ControlTestRegister::new();
        r.register(t("t1", TestOutcome::Failed)).unwrap();
        r.set_remediation(
            "t1",
            RemediationStatus::InProgress,
            "2025-05-02T00:00:00Z",
            Some("control redesign in flight".into()),
        )
        .unwrap();
        // Not verified yet → remediation_verified_at stays None.
        assert!(r.get("t1").unwrap().remediation_verified_at.is_none());
        r.set_remediation(
            "t1",
            RemediationStatus::Verified,
            "2025-06-01T00:00:00Z",
            None,
        )
        .unwrap();
        assert_eq!(
            r.get("t1").unwrap().remediation_verified_at.as_deref(),
            Some("2025-06-01T00:00:00Z")
        );
    }

    #[test]
    fn add_tag_dedupes() {
        let r = ControlTestRegister::new();
        r.register(t("t1", TestOutcome::Passed)).unwrap();
        r.add_tag("t1", "regulatory").unwrap();
        r.add_tag("t1", "regulatory").unwrap();
        r.add_tag("t1", "high-priority").unwrap();
        assert_eq!(
            r.get("t1").unwrap().tags,
            vec!["regulatory", "high-priority"]
        );
    }

    #[test]
    fn unknown_test_errors() {
        let r = ControlTestRegister::new();
        let err = r.set_findings("nope", "x").unwrap_err();
        assert!(format!("{err}").contains("unknown test"));
    }

    #[test]
    fn for_tenant_filters() {
        let r = ControlTestRegister::new();
        r.register(t("t1", TestOutcome::Passed)).unwrap();
        let mut other = t("t2", TestOutcome::Passed);
        other.tenant_id = "tenant-b".into();
        r.register(other).unwrap();
        assert_eq!(r.for_tenant("global").len(), 1);
        assert_eq!(r.for_tenant("tenant-b").len(), 1);
    }

    #[test]
    fn for_control_for_period_filters() {
        let r = ControlTestRegister::new();
        r.register(t("t1", TestOutcome::Passed)).unwrap();
        let mut other = t("t2", TestOutcome::Passed);
        other.control_id = "CC7.2".into();
        other.period = "Q2-2025".into();
        r.register(other).unwrap();
        assert_eq!(r.for_control("CC6.1").len(), 1);
        assert_eq!(r.for_control("CC7.2").len(), 1);
        assert_eq!(r.for_period("Q1-2025").len(), 1);
        assert_eq!(r.for_period("Q2-2025").len(), 1);
    }

    #[test]
    fn by_outcome_filters() {
        let r = ControlTestRegister::new();
        r.register(t("t1", TestOutcome::Passed)).unwrap();
        r.register(t("t2", TestOutcome::Failed)).unwrap();
        r.register(t("t3", TestOutcome::Exception)).unwrap();
        r.register(t("t4", TestOutcome::NotApplicable)).unwrap();
        assert_eq!(r.by_outcome(TestOutcome::Passed).len(), 1);
        assert_eq!(r.by_outcome(TestOutcome::Failed).len(), 1);
        assert_eq!(r.by_outcome(TestOutcome::Exception).len(), 1);
        assert_eq!(r.by_outcome(TestOutcome::NotApplicable).len(), 1);
    }

    #[test]
    fn open_remediations_filters() {
        let r = ControlTestRegister::new();
        r.register(t("ok", TestOutcome::Passed)).unwrap();
        r.register(t("fail", TestOutcome::Failed)).unwrap();
        r.register(t("verified", TestOutcome::Failed)).unwrap();
        r.set_remediation(
            "verified",
            RemediationStatus::Verified,
            "2025-06-01T00:00:00Z",
            None,
        )
        .unwrap();
        let open = r.open_remediations();
        let ids: Vec<_> = open.iter().map(|t| t.test_id.clone()).collect();
        assert_eq!(ids, vec!["fail"]);
    }

    #[test]
    fn period_summary_counts() {
        let r = ControlTestRegister::new();
        r.register(t("t1", TestOutcome::Passed)).unwrap();
        r.register(t("t2", TestOutcome::Passed)).unwrap();
        r.register(t("t3", TestOutcome::Failed)).unwrap();
        r.register(t("t4", TestOutcome::Exception)).unwrap();
        r.register(t("t5", TestOutcome::NotApplicable)).unwrap();
        let s = r.period_summary("Q1-2025");
        assert_eq!(s.total, 5);
        assert_eq!(s.passed, 2);
        assert_eq!(s.failed, 1);
        assert_eq!(s.exception, 1);
        assert_eq!(s.not_applicable, 1);
        assert_eq!(s.open_remediations, 2);
    }

    #[test]
    fn period_summary_excludes_other_periods() {
        let r = ControlTestRegister::new();
        r.register(t("t1", TestOutcome::Passed)).unwrap();
        let mut other = t("t2", TestOutcome::Passed);
        other.period = "Q2-2025".into();
        r.register(other).unwrap();
        let s = r.period_summary("Q1-2025");
        assert_eq!(s.total, 1);
    }

    #[test]
    fn outcome_helpers() {
        assert!(TestOutcome::Failed.requires_remediation());
        assert!(TestOutcome::Exception.requires_remediation());
        assert!(!TestOutcome::Passed.requires_remediation());
        assert!(!TestOutcome::NotApplicable.requires_remediation());
    }

    #[test]
    fn remediation_helpers() {
        assert!(RemediationStatus::Verified.is_closed());
        for s in [
            RemediationStatus::NotStarted,
            RemediationStatus::InProgress,
            RemediationStatus::Implemented,
        ] {
            assert!(!s.is_closed());
        }
    }

    #[test]
    fn is_open_only_when_failure_and_unverified() {
        let mut t1 = t("t1", TestOutcome::Failed);
        assert!(t1.is_open());
        t1.remediation = RemediationStatus::Verified;
        assert!(!t1.is_open());
        let pass = t("t2", TestOutcome::Passed);
        assert!(!pass.is_open());
    }

    #[test]
    fn count_tracks() {
        let r = ControlTestRegister::new();
        assert_eq!(r.count(), 0);
        r.register(t("t1", TestOutcome::Passed)).unwrap();
        assert_eq!(r.count(), 1);
    }

    #[test]
    fn test_serde() {
        let x = t("t1", TestOutcome::Passed);
        let j = serde_json::to_string(&x).unwrap();
        let back: ControlTest = serde_json::from_str(&j).unwrap();
        assert_eq!(x, back);
    }

    #[test]
    fn period_summary_serde() {
        let r = ControlTestRegister::new();
        r.register(t("t1", TestOutcome::Passed)).unwrap();
        let s = r.period_summary("Q1-2025");
        let j = serde_json::to_string(&s).unwrap();
        let back: PeriodSummary = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn enums_serde() {
        for o in [
            TestOutcome::Passed,
            TestOutcome::Failed,
            TestOutcome::Exception,
            TestOutcome::NotApplicable,
        ] {
            assert_eq!(
                o,
                serde_json::from_str::<TestOutcome>(&serde_json::to_string(&o).unwrap()).unwrap()
            );
        }
        for m in [
            TestMethod::Inspection,
            TestMethod::Observation,
            TestMethod::Reperformance,
            TestMethod::Inquiry,
            TestMethod::Automated,
        ] {
            assert_eq!(
                m,
                serde_json::from_str::<TestMethod>(&serde_json::to_string(&m).unwrap()).unwrap()
            );
        }
        for s in [
            RemediationStatus::NotStarted,
            RemediationStatus::InProgress,
            RemediationStatus::Implemented,
            RemediationStatus::Verified,
        ] {
            assert_eq!(
                s,
                serde_json::from_str::<RemediationStatus>(&serde_json::to_string(&s).unwrap())
                    .unwrap()
            );
        }
    }
}
