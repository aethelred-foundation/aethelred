//! Pre-employment / pre-engagement background check register.
//!
//! Maps to **SOC 2 CC1.4** (commitment to integrity and ethical values),
//! **ISO 27001 A.7.1.1** (screening), **NIST 800-53 PS-3** (personnel
//! screening), and the FCRA / GDPR requirements that govern third-party
//! background screening services. Every employee, contractor, and
//! sensitive role-holder must complete a documented background check
//! prior to access being granted.
//!
//! ## Lifecycle
//!
//! `Initiated → Consent → InProgress → (Cleared | Adverse | Inconclusive | Withdrawn)`
//!
//! - `Initiated`: HR opened the request.
//! - `Consent`: subject consent received (FCRA / GDPR mandatory before
//!   external check vendor is engaged).
//! - `InProgress`: vendor running checks.
//! - `Cleared` / `Adverse` / `Inconclusive`: terminal verdicts.
//! - `Withdrawn`: subject withdrew consent or HR cancelled before vendor
//!   completed.
//!
//! Distinct from [`crate::identity_lifecycle`] (joiner workflow tasks)
//! and [`crate::access_certification`] (periodic re-review). This is the
//! **pre-engagement** evidence that auditors examine on day one.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

// =============================================================================
// CheckType
// =============================================================================

/// Category of background check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckType {
    /// Criminal history.
    Criminal,
    /// Employment history verification.
    Employment,
    /// Education verification.
    Education,
    /// Credit / financial history (sensitive roles only).
    Credit,
    /// Identity verification.
    Identity,
    /// Drug screening.
    DrugScreen,
    /// Government sanctions / watchlist (OFAC, PEP).
    Sanctions,
    /// Professional licensure verification.
    Licensure,
    /// Reference checks.
    References,
    /// Right-to-work / immigration (E-Verify, BRP).
    RightToWork,
}

impl CheckType {
    /// True if this check requires explicit subject consent before
    /// engagement (FCRA / GDPR essentially all of them).
    pub fn requires_consent(self) -> bool {
        true
    }
}

// =============================================================================
// CheckResult
// =============================================================================

/// Per-check result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckResult {
    /// Not yet completed.
    Pending,
    /// Returned clean.
    Cleared,
    /// Returned adverse finding.
    Adverse,
    /// Returned but inconclusive (could not verify).
    Inconclusive,
    /// Skipped — not applicable for this role.
    NotApplicable,
}

impl CheckResult {
    /// True if no further work expected.
    pub fn is_resolved(self) -> bool {
        !matches!(self, Self::Pending)
    }
}

// =============================================================================
// CheckLine
// =============================================================================

/// One individual check line within a screening.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CheckLine {
    /// Stable id within the screening.
    pub line_id: String,
    /// Type.
    pub check_type: CheckType,
    /// Result.
    pub result: CheckResult,
    /// Optional summary (cleared / adverse details — sensitive, kept brief).
    pub summary: Option<String>,
    /// RFC 3339 — when the result was recorded.
    pub completed_at: Option<String>,
}

impl CheckLine {
    /// New `Pending` line.
    pub fn new(line_id: impl Into<String>, check_type: CheckType) -> Self {
        Self {
            line_id: line_id.into(),
            check_type,
            result: CheckResult::Pending,
            summary: None,
            completed_at: None,
        }
    }
}

// =============================================================================
// ScreeningStage
// =============================================================================

/// Lifecycle stage of the screening.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScreeningStage {
    /// HR opened the request; no consent yet.
    Initiated,
    /// Subject consented; ready to send to vendor.
    Consent,
    /// Vendor running checks.
    InProgress,
    /// All checks cleared.
    Cleared,
    /// One or more checks adverse.
    Adverse,
    /// All checks resolved but at least one Inconclusive (and no Adverse).
    Inconclusive,
    /// Subject withdrew consent or HR cancelled.
    Withdrawn,
}

impl ScreeningStage {
    /// True if no further state changes expected.
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Cleared | Self::Adverse | Self::Inconclusive | Self::Withdrawn
        )
    }

    /// True if onboarding may proceed.
    pub fn permits_onboarding(self) -> bool {
        matches!(self, Self::Cleared)
    }
}

// =============================================================================
// BackgroundCheckRecord
// =============================================================================

/// One full background-check screening for a subject.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackgroundCheckRecord {
    /// Unique screening id (e.g., "BGC-2025-007").
    pub screening_id: String,
    /// Tenant scope.
    pub tenant_id: String,
    /// Subject id (employee / contractor id).
    pub subject_id: String,
    /// Subject display name.
    pub subject_name: String,
    /// Role / position the screening is for.
    pub role: String,
    /// Vendor performing the check ("checkr", "sterling", "first-advantage").
    pub vendor: String,
    /// HR sponsor.
    pub sponsor: String,
    /// Screening stage.
    pub stage: ScreeningStage,
    /// Individual check lines.
    pub lines: Vec<CheckLine>,
    /// RFC 3339 — when consent was recorded (if any).
    pub consent_at: Option<String>,
    /// RFC 3339 — when initiated.
    pub initiated_at: String,
    /// RFC 3339 — when completed (terminal).
    pub completed_at: Option<String>,
    /// Optional final reasoned outcome.
    pub final_summary: Option<String>,
    /// Free-form tags.
    pub tags: Vec<String>,
}

impl BackgroundCheckRecord {
    /// New `Initiated` screening.
    pub fn new(
        screening_id: impl Into<String>,
        tenant_id: impl Into<String>,
        subject_id: impl Into<String>,
        subject_name: impl Into<String>,
        role: impl Into<String>,
        vendor: impl Into<String>,
        sponsor: impl Into<String>,
        initiated_at: impl Into<String>,
    ) -> Self {
        Self {
            screening_id: screening_id.into(),
            tenant_id: tenant_id.into(),
            subject_id: subject_id.into(),
            subject_name: subject_name.into(),
            role: role.into(),
            vendor: vendor.into(),
            sponsor: sponsor.into(),
            stage: ScreeningStage::Initiated,
            lines: Vec::new(),
            consent_at: None,
            initiated_at: initiated_at.into(),
            completed_at: None,
            final_summary: None,
            tags: Vec::new(),
        }
    }

    /// Number of unresolved lines.
    pub fn pending_line_count(&self) -> usize {
        self.lines.iter().filter(|l| !l.result.is_resolved()).count()
    }

    /// Number of adverse lines.
    pub fn adverse_line_count(&self) -> usize {
        self.lines
            .iter()
            .filter(|l| matches!(l.result, CheckResult::Adverse))
            .count()
    }

    /// Number of inconclusive lines.
    pub fn inconclusive_line_count(&self) -> usize {
        self.lines
            .iter()
            .filter(|l| matches!(l.result, CheckResult::Inconclusive))
            .count()
    }
}

// =============================================================================
// Lifecycle transition table
// =============================================================================

fn legal_transition(from: ScreeningStage, to: ScreeningStage) -> bool {
    use ScreeningStage::*;
    matches!(
        (from, to),
        (Initiated, Consent)
            | (Initiated, Withdrawn)
            | (Consent, InProgress)
            | (Consent, Withdrawn)
            | (InProgress, Cleared)
            | (InProgress, Adverse)
            | (InProgress, Inconclusive)
            | (InProgress, Withdrawn)
    )
}

// =============================================================================
// BackgroundCheckRegister
// =============================================================================

/// Thread-safe register of background checks.
#[derive(Debug, Default)]
pub struct BackgroundCheckRegister {
    inner: RwLock<HashMap<String, BackgroundCheckRecord>>,
}

impl BackgroundCheckRegister {
    /// New empty register.
    pub fn new() -> Self {
        Self::default()
    }

    /// Initiate a new screening.
    pub fn initiate(&self, record: BackgroundCheckRecord) -> SandboxResult<()> {
        if !matches!(record.stage, ScreeningStage::Initiated) {
            return Err(SandboxError::Other(format!(
                "screening must start Initiated, got {:?}",
                record.stage
            )));
        }
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("background check register poisoned".into()))?;
        if g.contains_key(&record.screening_id) {
            return Err(SandboxError::Other(format!(
                "screening already initiated: {}",
                record.screening_id
            )));
        }
        g.insert(record.screening_id.clone(), record);
        Ok(())
    }

    /// Add a check line. Allowed in Initiated or Consent stages.
    pub fn add_line(&self, screening_id: &str, line: CheckLine) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("background check register poisoned".into()))?;
        let r = g
            .get_mut(screening_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown screening {screening_id}")))?;
        if !matches!(r.stage, ScreeningStage::Initiated | ScreeningStage::Consent) {
            return Err(SandboxError::Other(format!(
                "cannot add line to {screening_id}: stage is {:?}",
                r.stage
            )));
        }
        if r.lines.iter().any(|l| l.line_id == line.line_id) {
            return Err(SandboxError::Other(format!(
                "line already present: {}",
                line.line_id
            )));
        }
        r.lines.push(line);
        Ok(())
    }

    /// Record subject consent (transitions Initiated → Consent).
    pub fn record_consent(
        &self,
        screening_id: &str,
        at: impl Into<String>,
    ) -> SandboxResult<BackgroundCheckRecord> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("background check register poisoned".into()))?;
        let r = g
            .get_mut(screening_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown screening {screening_id}")))?;
        if !legal_transition(r.stage, ScreeningStage::Consent) {
            return Err(SandboxError::Other(format!(
                "illegal transition {:?} -> Consent",
                r.stage
            )));
        }
        let when = at.into();
        r.stage = ScreeningStage::Consent;
        r.consent_at = Some(when);
        Ok(r.clone())
    }

    /// Move screening to InProgress (Consent → InProgress).
    pub fn start(
        &self,
        screening_id: &str,
        at: impl Into<String>,
    ) -> SandboxResult<BackgroundCheckRecord> {
        let _ = at;
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("background check register poisoned".into()))?;
        let r = g
            .get_mut(screening_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown screening {screening_id}")))?;
        if !legal_transition(r.stage, ScreeningStage::InProgress) {
            return Err(SandboxError::Other(format!(
                "illegal transition {:?} -> InProgress",
                r.stage
            )));
        }
        if r.lines.is_empty() {
            return Err(SandboxError::Other(format!(
                "cannot start {screening_id}: no check lines"
            )));
        }
        r.stage = ScreeningStage::InProgress;
        Ok(r.clone())
    }

    /// Record a per-line result. Screening must be InProgress.
    pub fn record_line_result(
        &self,
        screening_id: &str,
        line_id: &str,
        result: CheckResult,
        at: impl Into<String>,
        summary: Option<String>,
    ) -> SandboxResult<()> {
        if matches!(result, CheckResult::Pending) {
            return Err(SandboxError::Other(
                "cannot record result Pending".into(),
            ));
        }
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("background check register poisoned".into()))?;
        let r = g
            .get_mut(screening_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown screening {screening_id}")))?;
        if !matches!(r.stage, ScreeningStage::InProgress) {
            return Err(SandboxError::Other(format!(
                "cannot record on {screening_id}: stage is {:?}",
                r.stage
            )));
        }
        let l = r
            .lines
            .iter_mut()
            .find(|l| l.line_id == line_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown line {line_id}")))?;
        l.result = result;
        l.completed_at = Some(at.into());
        if let Some(s) = summary {
            l.summary = Some(s);
        }
        Ok(())
    }

    /// Finalise the screening. Auto-derives the terminal stage from line
    /// results: if any Adverse → `Adverse`; else if any Inconclusive →
    /// `Inconclusive`; else (all Cleared or NotApplicable) → `Cleared`.
    /// All lines must be resolved.
    pub fn finalise(
        &self,
        screening_id: &str,
        at: impl Into<String>,
        final_summary: Option<String>,
    ) -> SandboxResult<BackgroundCheckRecord> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("background check register poisoned".into()))?;
        let r = g
            .get_mut(screening_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown screening {screening_id}")))?;
        if !matches!(r.stage, ScreeningStage::InProgress) {
            return Err(SandboxError::Other(format!(
                "cannot finalise {screening_id}: stage is {:?}",
                r.stage
            )));
        }
        if r.pending_line_count() > 0 {
            return Err(SandboxError::Other(format!(
                "cannot finalise {screening_id}: {} lines unresolved",
                r.pending_line_count()
            )));
        }
        let new_stage = if r.adverse_line_count() > 0 {
            ScreeningStage::Adverse
        } else if r.inconclusive_line_count() > 0 {
            ScreeningStage::Inconclusive
        } else {
            ScreeningStage::Cleared
        };
        let when = at.into();
        r.stage = new_stage;
        r.completed_at = Some(when);
        if let Some(s) = final_summary {
            r.final_summary = Some(s);
        }
        Ok(r.clone())
    }

    /// Withdraw a screening (subject revokes consent or HR cancels).
    /// Allowed from any non-terminal stage.
    pub fn withdraw(
        &self,
        screening_id: &str,
        at: impl Into<String>,
        reason: impl Into<String>,
    ) -> SandboxResult<BackgroundCheckRecord> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("background check register poisoned".into()))?;
        let r = g
            .get_mut(screening_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown screening {screening_id}")))?;
        if !legal_transition(r.stage, ScreeningStage::Withdrawn) {
            return Err(SandboxError::Other(format!(
                "illegal transition {:?} -> Withdrawn",
                r.stage
            )));
        }
        let when = at.into();
        r.stage = ScreeningStage::Withdrawn;
        r.completed_at = Some(when);
        r.final_summary = Some(reason.into());
        Ok(r.clone())
    }

    /// Add a tag (deduplicated).
    pub fn add_tag(&self, screening_id: &str, tag: impl Into<String>) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("background check register poisoned".into()))?;
        let r = g
            .get_mut(screening_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown screening {screening_id}")))?;
        let tag = tag.into();
        if !r.tags.contains(&tag) {
            r.tags.push(tag);
        }
        Ok(())
    }

    /// Look up.
    pub fn get(&self, screening_id: &str) -> Option<BackgroundCheckRecord> {
        let g = self.inner.read().ok()?;
        g.get(screening_id).cloned()
    }

    /// All screenings.
    pub fn all(&self) -> Vec<BackgroundCheckRecord> {
        match self.inner.read() {
            Ok(g) => g.values().cloned().collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Screenings for a tenant.
    pub fn for_tenant(&self, tenant_id: &str) -> Vec<BackgroundCheckRecord> {
        self.all()
            .into_iter()
            .filter(|r| r.tenant_id == tenant_id)
            .collect()
    }

    /// Screenings for a subject.
    pub fn for_subject(&self, subject_id: &str) -> Vec<BackgroundCheckRecord> {
        self.all()
            .into_iter()
            .filter(|r| r.subject_id == subject_id)
            .collect()
    }

    /// Screenings at a stage.
    pub fn by_stage(&self, stage: ScreeningStage) -> Vec<BackgroundCheckRecord> {
        self.all().into_iter().filter(|r| r.stage == stage).collect()
    }

    /// Open screenings (non-terminal).
    pub fn open(&self) -> Vec<BackgroundCheckRecord> {
        self.all()
            .into_iter()
            .filter(|r| !r.stage.is_terminal())
            .collect()
    }

    /// Adverse screenings.
    pub fn adverse(&self) -> Vec<BackgroundCheckRecord> {
        self.by_stage(ScreeningStage::Adverse)
    }

    /// Latest cleared screening for a subject.
    pub fn latest_cleared_for_subject(
        &self,
        subject_id: &str,
    ) -> Option<BackgroundCheckRecord> {
        let mut cleared: Vec<BackgroundCheckRecord> = self
            .for_subject(subject_id)
            .into_iter()
            .filter(|r| matches!(r.stage, ScreeningStage::Cleared))
            .collect();
        cleared.sort_by(|a, b| {
            a.completed_at
                .as_deref()
                .unwrap_or("")
                .cmp(b.completed_at.as_deref().unwrap_or(""))
        });
        cleared.pop()
    }

    /// Number of registered screenings.
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

    fn rec(id: &str, subject: &str) -> BackgroundCheckRecord {
        BackgroundCheckRecord::new(
            id,
            "tenant-a",
            subject,
            format!("Subject {subject}"),
            "Engineer",
            "Checkr",
            "hr-team",
            "2025-04-01T00:00:00Z",
        )
    }

    fn line(id: &str, t: CheckType) -> CheckLine {
        CheckLine::new(id, t)
    }

    #[test]
    fn initiate_and_get() {
        let r = BackgroundCheckRegister::new();
        r.initiate(rec("s1", "alice")).unwrap();
        let g = r.get("s1").unwrap();
        assert_eq!(g.stage, ScreeningStage::Initiated);
    }

    #[test]
    fn duplicate_initiate_errors() {
        let r = BackgroundCheckRegister::new();
        r.initiate(rec("s1", "alice")).unwrap();
        let err = r.initiate(rec("s1", "alice")).unwrap_err();
        assert!(format!("{err}").contains("already initiated"));
    }

    #[test]
    fn must_start_initiated() {
        let mut s = rec("s1", "alice");
        s.stage = ScreeningStage::InProgress;
        let r = BackgroundCheckRegister::new();
        let err = r.initiate(s).unwrap_err();
        assert!(format!("{err}").contains("must start Initiated"));
    }

    #[test]
    fn legal_transitions() {
        use ScreeningStage::*;
        assert!(legal_transition(Initiated, Consent));
        assert!(legal_transition(Initiated, Withdrawn));
        assert!(legal_transition(Consent, InProgress));
        assert!(legal_transition(Consent, Withdrawn));
        assert!(legal_transition(InProgress, Cleared));
        assert!(legal_transition(InProgress, Adverse));
        assert!(legal_transition(InProgress, Inconclusive));
        assert!(legal_transition(InProgress, Withdrawn));
        // illegal
        assert!(!legal_transition(Initiated, InProgress));
        assert!(!legal_transition(Cleared, InProgress));
        assert!(!legal_transition(Withdrawn, Cleared));
    }

    #[test]
    fn happy_path_cleared() {
        let r = BackgroundCheckRegister::new();
        r.initiate(rec("s1", "alice")).unwrap();
        r.add_line("s1", line("l1", CheckType::Criminal)).unwrap();
        r.add_line("s1", line("l2", CheckType::Identity)).unwrap();
        r.record_consent("s1", "2025-04-02T00:00:00Z").unwrap();
        r.start("s1", "2025-04-03T00:00:00Z").unwrap();
        r.record_line_result(
            "s1",
            "l1",
            CheckResult::Cleared,
            "2025-04-15T00:00:00Z",
            None,
        )
        .unwrap();
        r.record_line_result(
            "s1",
            "l2",
            CheckResult::Cleared,
            "2025-04-15T00:00:00Z",
            None,
        )
        .unwrap();
        let s = r.finalise("s1", "2025-04-16T00:00:00Z", None).unwrap();
        assert_eq!(s.stage, ScreeningStage::Cleared);
        assert!(s.stage.permits_onboarding());
        assert!(s.stage.is_terminal());
        assert_eq!(s.consent_at.as_deref(), Some("2025-04-02T00:00:00Z"));
        assert_eq!(s.completed_at.as_deref(), Some("2025-04-16T00:00:00Z"));
    }

    #[test]
    fn finalise_adverse_when_any_line_adverse() {
        let r = BackgroundCheckRegister::new();
        r.initiate(rec("s1", "alice")).unwrap();
        r.add_line("s1", line("l1", CheckType::Criminal)).unwrap();
        r.add_line("s1", line("l2", CheckType::Identity)).unwrap();
        r.record_consent("s1", "2025-04-02T00:00:00Z").unwrap();
        r.start("s1", "2025-04-03T00:00:00Z").unwrap();
        r.record_line_result(
            "s1",
            "l1",
            CheckResult::Adverse,
            "2025-04-15T00:00:00Z",
            Some("conviction within 7 years".into()),
        )
        .unwrap();
        r.record_line_result(
            "s1",
            "l2",
            CheckResult::Cleared,
            "2025-04-15T00:00:00Z",
            None,
        )
        .unwrap();
        let s = r.finalise("s1", "2025-04-16T00:00:00Z", None).unwrap();
        assert_eq!(s.stage, ScreeningStage::Adverse);
        assert!(!s.stage.permits_onboarding());
    }

    #[test]
    fn finalise_inconclusive_when_no_adverse_but_inconclusive() {
        let r = BackgroundCheckRegister::new();
        r.initiate(rec("s1", "alice")).unwrap();
        r.add_line("s1", line("l1", CheckType::Education)).unwrap();
        r.add_line("s1", line("l2", CheckType::Identity)).unwrap();
        r.record_consent("s1", "2025-04-02T00:00:00Z").unwrap();
        r.start("s1", "2025-04-03T00:00:00Z").unwrap();
        r.record_line_result(
            "s1",
            "l1",
            CheckResult::Inconclusive,
            "2025-04-15T00:00:00Z",
            None,
        )
        .unwrap();
        r.record_line_result(
            "s1",
            "l2",
            CheckResult::Cleared,
            "2025-04-15T00:00:00Z",
            None,
        )
        .unwrap();
        let s = r.finalise("s1", "2025-04-16T00:00:00Z", None).unwrap();
        assert_eq!(s.stage, ScreeningStage::Inconclusive);
    }

    #[test]
    fn finalise_cleared_when_only_cleared_or_n_a() {
        let r = BackgroundCheckRegister::new();
        r.initiate(rec("s1", "alice")).unwrap();
        r.add_line("s1", line("l1", CheckType::Criminal)).unwrap();
        r.add_line("s1", line("l2", CheckType::Credit)).unwrap();
        r.record_consent("s1", "2025-04-02T00:00:00Z").unwrap();
        r.start("s1", "2025-04-03T00:00:00Z").unwrap();
        r.record_line_result(
            "s1",
            "l1",
            CheckResult::Cleared,
            "2025-04-15T00:00:00Z",
            None,
        )
        .unwrap();
        r.record_line_result(
            "s1",
            "l2",
            CheckResult::NotApplicable,
            "2025-04-15T00:00:00Z",
            None,
        )
        .unwrap();
        let s = r.finalise("s1", "2025-04-16T00:00:00Z", None).unwrap();
        assert_eq!(s.stage, ScreeningStage::Cleared);
    }

    #[test]
    fn finalise_rejects_pending_lines() {
        let r = BackgroundCheckRegister::new();
        r.initiate(rec("s1", "alice")).unwrap();
        r.add_line("s1", line("l1", CheckType::Identity)).unwrap();
        r.record_consent("s1", "2025-04-02T00:00:00Z").unwrap();
        r.start("s1", "2025-04-03T00:00:00Z").unwrap();
        let err = r.finalise("s1", "2025-04-16T00:00:00Z", None).unwrap_err();
        assert!(format!("{err}").contains("lines unresolved"));
    }

    #[test]
    fn record_line_result_pending_errors() {
        let r = BackgroundCheckRegister::new();
        r.initiate(rec("s1", "alice")).unwrap();
        r.add_line("s1", line("l1", CheckType::Identity)).unwrap();
        r.record_consent("s1", "2025-04-02T00:00:00Z").unwrap();
        r.start("s1", "2025-04-03T00:00:00Z").unwrap();
        let err = r
            .record_line_result(
                "s1",
                "l1",
                CheckResult::Pending,
                "2025-04-15T00:00:00Z",
                None,
            )
            .unwrap_err();
        assert!(format!("{err}").contains("Pending"));
    }

    #[test]
    fn record_line_result_unknown_line_errors() {
        let r = BackgroundCheckRegister::new();
        r.initiate(rec("s1", "alice")).unwrap();
        r.add_line("s1", line("l1", CheckType::Identity)).unwrap();
        r.record_consent("s1", "2025-04-02T00:00:00Z").unwrap();
        r.start("s1", "2025-04-03T00:00:00Z").unwrap();
        let err = r
            .record_line_result(
                "s1",
                "nope",
                CheckResult::Cleared,
                "2025-04-15T00:00:00Z",
                None,
            )
            .unwrap_err();
        assert!(format!("{err}").contains("unknown line"));
    }

    #[test]
    fn record_line_result_when_not_in_progress_errors() {
        let r = BackgroundCheckRegister::new();
        r.initiate(rec("s1", "alice")).unwrap();
        r.add_line("s1", line("l1", CheckType::Identity)).unwrap();
        let err = r
            .record_line_result(
                "s1",
                "l1",
                CheckResult::Cleared,
                "2025-04-15T00:00:00Z",
                None,
            )
            .unwrap_err();
        assert!(format!("{err}").contains("cannot record"));
    }

    #[test]
    fn start_requires_lines() {
        let r = BackgroundCheckRegister::new();
        r.initiate(rec("s1", "alice")).unwrap();
        r.record_consent("s1", "2025-04-02T00:00:00Z").unwrap();
        let err = r.start("s1", "2025-04-03T00:00:00Z").unwrap_err();
        assert!(format!("{err}").contains("no check lines"));
    }

    #[test]
    fn add_line_after_in_progress_errors() {
        let r = BackgroundCheckRegister::new();
        r.initiate(rec("s1", "alice")).unwrap();
        r.add_line("s1", line("l1", CheckType::Identity)).unwrap();
        r.record_consent("s1", "2025-04-02T00:00:00Z").unwrap();
        r.start("s1", "2025-04-03T00:00:00Z").unwrap();
        let err = r
            .add_line("s1", line("l2", CheckType::Criminal))
            .unwrap_err();
        assert!(format!("{err}").contains("cannot add line"));
    }

    #[test]
    fn add_line_dedupes() {
        let r = BackgroundCheckRegister::new();
        r.initiate(rec("s1", "alice")).unwrap();
        r.add_line("s1", line("l1", CheckType::Identity)).unwrap();
        let err = r.add_line("s1", line("l1", CheckType::Criminal)).unwrap_err();
        assert!(format!("{err}").contains("already present"));
    }

    #[test]
    fn withdraw_from_initiated() {
        let r = BackgroundCheckRegister::new();
        r.initiate(rec("s1", "alice")).unwrap();
        let s = r
            .withdraw("s1", "2025-04-05T00:00:00Z", "candidate declined offer")
            .unwrap();
        assert_eq!(s.stage, ScreeningStage::Withdrawn);
        assert_eq!(s.final_summary.as_deref(), Some("candidate declined offer"));
    }

    #[test]
    fn withdraw_from_consent() {
        let r = BackgroundCheckRegister::new();
        r.initiate(rec("s1", "alice")).unwrap();
        r.record_consent("s1", "2025-04-02T00:00:00Z").unwrap();
        let s = r.withdraw("s1", "2025-04-05T00:00:00Z", "withdraw").unwrap();
        assert_eq!(s.stage, ScreeningStage::Withdrawn);
    }

    #[test]
    fn withdraw_from_in_progress() {
        let r = BackgroundCheckRegister::new();
        r.initiate(rec("s1", "alice")).unwrap();
        r.add_line("s1", line("l1", CheckType::Identity)).unwrap();
        r.record_consent("s1", "2025-04-02T00:00:00Z").unwrap();
        r.start("s1", "2025-04-03T00:00:00Z").unwrap();
        let s = r.withdraw("s1", "2025-04-10T00:00:00Z", "withdraw").unwrap();
        assert_eq!(s.stage, ScreeningStage::Withdrawn);
    }

    #[test]
    fn withdraw_terminal_errors() {
        let r = BackgroundCheckRegister::new();
        r.initiate(rec("s1", "alice")).unwrap();
        r.withdraw("s1", "2025-04-05T00:00:00Z", "x").unwrap();
        let err = r.withdraw("s1", "2025-04-06T00:00:00Z", "y").unwrap_err();
        assert!(format!("{err}").contains("illegal transition"));
    }

    #[test]
    fn add_tag_dedupes() {
        let r = BackgroundCheckRegister::new();
        r.initiate(rec("s1", "alice")).unwrap();
        r.add_tag("s1", "regulated").unwrap();
        r.add_tag("s1", "regulated").unwrap();
        r.add_tag("s1", "exec").unwrap();
        assert_eq!(r.get("s1").unwrap().tags, vec!["regulated", "exec"]);
    }

    #[test]
    fn unknown_screening_errors() {
        let r = BackgroundCheckRegister::new();
        let err = r
            .record_consent("nope", "2025-04-02T00:00:00Z")
            .unwrap_err();
        assert!(format!("{err}").contains("unknown screening"));
    }

    #[test]
    fn for_tenant_for_subject_filters() {
        let r = BackgroundCheckRegister::new();
        r.initiate(rec("s1", "alice")).unwrap();
        let mut other = rec("s2", "bob");
        other.tenant_id = "tenant-b".into();
        r.initiate(other).unwrap();
        assert_eq!(r.for_tenant("tenant-a").len(), 1);
        assert_eq!(r.for_tenant("tenant-b").len(), 1);
        assert_eq!(r.for_subject("alice").len(), 1);
        assert_eq!(r.for_subject("bob").len(), 1);
    }

    #[test]
    fn open_filter() {
        let r = BackgroundCheckRegister::new();
        r.initiate(rec("s1", "alice")).unwrap();
        r.initiate(rec("s2", "bob")).unwrap();
        r.withdraw("s2", "2025-04-05T00:00:00Z", "x").unwrap();
        let open = r.open();
        assert_eq!(open.len(), 1);
        assert_eq!(open[0].screening_id, "s1");
    }

    #[test]
    fn adverse_filter() {
        let r = BackgroundCheckRegister::new();
        r.initiate(rec("s1", "alice")).unwrap();
        r.add_line("s1", line("l1", CheckType::Criminal)).unwrap();
        r.record_consent("s1", "2025-04-02T00:00:00Z").unwrap();
        r.start("s1", "2025-04-03T00:00:00Z").unwrap();
        r.record_line_result(
            "s1",
            "l1",
            CheckResult::Adverse,
            "2025-04-15T00:00:00Z",
            None,
        )
        .unwrap();
        r.finalise("s1", "2025-04-16T00:00:00Z", None).unwrap();
        let adv = r.adverse();
        assert_eq!(adv.len(), 1);
        assert_eq!(adv[0].screening_id, "s1");
    }

    #[test]
    fn latest_cleared_for_subject() {
        let r = BackgroundCheckRegister::new();
        // Older cleared screening
        r.initiate(rec("s1", "alice")).unwrap();
        r.add_line("s1", line("l1", CheckType::Identity)).unwrap();
        r.record_consent("s1", "2024-01-02T00:00:00Z").unwrap();
        r.start("s1", "2024-01-03T00:00:00Z").unwrap();
        r.record_line_result(
            "s1",
            "l1",
            CheckResult::Cleared,
            "2024-01-15T00:00:00Z",
            None,
        )
        .unwrap();
        r.finalise("s1", "2024-01-16T00:00:00Z", None).unwrap();
        // Newer cleared screening
        r.initiate(rec("s2", "alice")).unwrap();
        r.add_line("s2", line("l1", CheckType::Identity)).unwrap();
        r.record_consent("s2", "2025-04-02T00:00:00Z").unwrap();
        r.start("s2", "2025-04-03T00:00:00Z").unwrap();
        r.record_line_result(
            "s2",
            "l1",
            CheckResult::Cleared,
            "2025-04-15T00:00:00Z",
            None,
        )
        .unwrap();
        r.finalise("s2", "2025-04-16T00:00:00Z", None).unwrap();
        let latest = r.latest_cleared_for_subject("alice").unwrap();
        assert_eq!(latest.screening_id, "s2");
    }

    #[test]
    fn check_result_resolved_helpers() {
        assert!(CheckResult::Cleared.is_resolved());
        assert!(CheckResult::Adverse.is_resolved());
        assert!(CheckResult::Inconclusive.is_resolved());
        assert!(CheckResult::NotApplicable.is_resolved());
        assert!(!CheckResult::Pending.is_resolved());
    }

    #[test]
    fn stage_helpers() {
        assert!(ScreeningStage::Cleared.permits_onboarding());
        assert!(!ScreeningStage::Adverse.permits_onboarding());
        assert!(!ScreeningStage::Inconclusive.permits_onboarding());
        assert!(!ScreeningStage::Withdrawn.permits_onboarding());
        for s in [
            ScreeningStage::Cleared,
            ScreeningStage::Adverse,
            ScreeningStage::Inconclusive,
            ScreeningStage::Withdrawn,
        ] {
            assert!(s.is_terminal());
        }
        for s in [
            ScreeningStage::Initiated,
            ScreeningStage::Consent,
            ScreeningStage::InProgress,
        ] {
            assert!(!s.is_terminal());
        }
    }

    #[test]
    fn count_tracks() {
        let r = BackgroundCheckRegister::new();
        assert_eq!(r.count(), 0);
        r.initiate(rec("s1", "alice")).unwrap();
        assert_eq!(r.count(), 1);
    }

    #[test]
    fn record_serde() {
        let r = rec("s1", "alice");
        let j = serde_json::to_string(&r).unwrap();
        let back: BackgroundCheckRecord = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn enums_serde() {
        for t in [
            CheckType::Criminal,
            CheckType::Employment,
            CheckType::Education,
            CheckType::Credit,
            CheckType::Identity,
            CheckType::DrugScreen,
            CheckType::Sanctions,
            CheckType::Licensure,
            CheckType::References,
            CheckType::RightToWork,
        ] {
            assert_eq!(
                t,
                serde_json::from_str::<CheckType>(&serde_json::to_string(&t).unwrap()).unwrap()
            );
        }
        for r in [
            CheckResult::Pending,
            CheckResult::Cleared,
            CheckResult::Adverse,
            CheckResult::Inconclusive,
            CheckResult::NotApplicable,
        ] {
            assert_eq!(
                r,
                serde_json::from_str::<CheckResult>(&serde_json::to_string(&r).unwrap()).unwrap()
            );
        }
        for s in [
            ScreeningStage::Initiated,
            ScreeningStage::Consent,
            ScreeningStage::InProgress,
            ScreeningStage::Cleared,
            ScreeningStage::Adverse,
            ScreeningStage::Inconclusive,
            ScreeningStage::Withdrawn,
        ] {
            assert_eq!(
                s,
                serde_json::from_str::<ScreeningStage>(&serde_json::to_string(&s).unwrap())
                    .unwrap()
            );
        }
    }
}
