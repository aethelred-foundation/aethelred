//! External audit finding tracker.
//!
//! Distinct from [`crate::control_test_register`] (internal control
//! testing) and [`crate::compliance_report`] (point-in-time bundle), this
//! is the **external auditor finding registry**: when SOC 2, ISO 27001,
//! PCI-QSA, internal-audit, or regulator examination produces a finding,
//! the controller logs it here and tracks it through to verified
//! remediation.
//!
//! Maps to SOC 2 Type II (qualified opinions and management responses),
//! ISO 27001 9.2 (internal audit), and SOX §404 (auditor remediation
//! tracking).
//!
//! ## Lifecycle
//!
//! `Open → AcceptedByMgmt → Remediating → Remediated → Verified | Closed`
//!
//! Findings can also be `Disputed` (controller challenges the finding) or
//! `Withdrawn` (auditor retracts).

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

// =============================================================================
// FindingSeverity
// =============================================================================

/// Severity / disposition of the finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingSeverity {
    /// Significant deficiency / material weakness — qualified opinion.
    Critical,
    /// High — must remediate before next audit window.
    High,
    /// Moderate / process improvement.
    Moderate,
    /// Low / observation.
    Low,
    /// Informational / best-practice suggestion.
    Informational,
}

impl FindingSeverity {
    /// Numeric rank (higher = worse).
    pub fn rank(self) -> u8 {
        match self {
            Self::Critical => 5,
            Self::High => 4,
            Self::Moderate => 3,
            Self::Low => 2,
            Self::Informational => 1,
        }
    }

    /// True if a regulator notification may be required.
    pub fn is_material(self) -> bool {
        matches!(self, Self::Critical | Self::High)
    }
}

// =============================================================================
// FindingStage
// =============================================================================

/// Lifecycle stage of the finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingStage {
    /// Reported by auditor; controller hasn't responded yet.
    Open,
    /// Management has accepted the finding and committed to remediation.
    AcceptedByMgmt,
    /// Remediation work in progress.
    Remediating,
    /// Remediation work complete; awaiting auditor re-test.
    Remediated,
    /// Re-test verified the remediation.
    Verified,
    /// Closed without remediation (e.g., risk accepted, control retired).
    Closed,
    /// Controller disputes the finding.
    Disputed,
    /// Auditor withdrew the finding.
    Withdrawn,
}

impl FindingStage {
    /// True if no further action is expected.
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Verified | Self::Closed | Self::Withdrawn
        )
    }
}

// =============================================================================
// AuditSource
// =============================================================================

/// Where the finding came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditSource {
    /// SOC 2 audit.
    Soc2,
    /// ISO 27001 audit.
    Iso27001,
    /// PCI-DSS audit (QSA).
    PciQsa,
    /// HIPAA audit.
    Hipaa,
    /// SOX (financial controls).
    Sox,
    /// Internal audit.
    Internal,
    /// Regulator examination.
    Regulator,
    /// Customer-initiated audit (vendor-risk DDQ).
    CustomerAudit,
    /// Penetration test.
    PenTest,
}

// =============================================================================
// FindingEvent
// =============================================================================

/// One event on the finding timeline.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FindingEvent {
    /// RFC 3339.
    pub at: String,
    /// Author.
    pub actor: String,
    /// Stage applied.
    pub stage: FindingStage,
    /// Free-text note.
    pub note: String,
}

// =============================================================================
// AuditFinding
// =============================================================================

/// One external audit finding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuditFinding {
    /// Unique id (e.g., "FIND-SOC2-2025-007").
    pub finding_id: String,
    /// Tenant scope.
    pub tenant_id: String,
    /// Display title.
    pub title: String,
    /// Long-form description.
    pub description: String,
    /// Source.
    pub source: AuditSource,
    /// Audit period or report id ("SOC2 2025 Type II").
    pub audit_reference: String,
    /// Auditor / firm.
    pub auditor: String,
    /// Severity.
    pub severity: FindingSeverity,
    /// Linked control id (if any).
    pub control_id: Option<String>,
    /// Linked enterprise risk id (if any).
    pub linked_risk_id: Option<String>,
    /// Owning team.
    pub owner: String,
    /// Current lifecycle stage.
    pub stage: FindingStage,
    /// RFC 3339 — first reported by auditor.
    pub reported_at: String,
    /// RFC 3339 — committed remediation deadline.
    pub remediation_due_at: Option<String>,
    /// RFC 3339 — closed (any terminal stage).
    pub closed_at: Option<String>,
    /// Free-text management response.
    pub management_response: Option<String>,
    /// Free-text remediation summary at closure.
    pub remediation_summary: Option<String>,
    /// Event log.
    pub events: Vec<FindingEvent>,
    /// Free-form tags.
    pub tags: Vec<String>,
}

impl AuditFinding {
    /// New `Open` finding.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        finding_id: impl Into<String>,
        tenant_id: impl Into<String>,
        title: impl Into<String>,
        description: impl Into<String>,
        source: AuditSource,
        audit_reference: impl Into<String>,
        auditor: impl Into<String>,
        severity: FindingSeverity,
        owner: impl Into<String>,
        reported_at: impl Into<String>,
    ) -> Self {
        Self {
            finding_id: finding_id.into(),
            tenant_id: tenant_id.into(),
            title: title.into(),
            description: description.into(),
            source,
            audit_reference: audit_reference.into(),
            auditor: auditor.into(),
            severity,
            control_id: None,
            linked_risk_id: None,
            owner: owner.into(),
            stage: FindingStage::Open,
            reported_at: reported_at.into(),
            remediation_due_at: None,
            closed_at: None,
            management_response: None,
            remediation_summary: None,
            events: Vec::new(),
            tags: Vec::new(),
        }
    }

    /// True if the finding is past its remediation due date and not closed.
    pub fn is_overdue(&self, now: &str) -> bool {
        if self.stage.is_terminal() {
            return false;
        }
        match self.remediation_due_at.as_deref() {
            Some(due) => now >= due,
            None => false,
        }
    }
}

// =============================================================================
// Lifecycle transition table
// =============================================================================

fn legal_transition(from: FindingStage, to: FindingStage) -> bool {
    use FindingStage::*;
    match (from, to) {
        (Open, AcceptedByMgmt)
        | (Open, Disputed)
        | (Open, Withdrawn)
        | (Open, Closed)
        | (AcceptedByMgmt, Remediating)
        | (AcceptedByMgmt, Closed)
        | (AcceptedByMgmt, Disputed)
        | (Remediating, Remediated)
        | (Remediating, Closed)
        | (Remediated, Verified)
        | (Remediated, Remediating) // re-tested and failed
        | (Disputed, AcceptedByMgmt)
        | (Disputed, Withdrawn)
        | (Disputed, Closed) => true,
        _ => false,
    }
}

// =============================================================================
// AuditFindingTracker
// =============================================================================

/// Thread-safe tracker for external audit findings.
#[derive(Debug, Default)]
pub struct AuditFindingTracker {
    inner: RwLock<HashMap<String, AuditFinding>>,
}

impl AuditFindingTracker {
    /// New empty tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new finding.
    pub fn register(&self, finding: AuditFinding) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("audit finding tracker poisoned".into()))?;
        if g.contains_key(&finding.finding_id) {
            return Err(SandboxError::Other(format!(
                "finding already registered: {}",
                finding.finding_id
            )));
        }
        g.insert(finding.finding_id.clone(), finding);
        Ok(())
    }

    /// Apply a stage transition.
    pub fn transition(
        &self,
        finding_id: &str,
        new_stage: FindingStage,
        actor: impl Into<String>,
        note: impl Into<String>,
        at: impl Into<String>,
    ) -> SandboxResult<AuditFinding> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("audit finding tracker poisoned".into()))?;
        let f = g
            .get_mut(finding_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown finding {finding_id}")))?;
        if !legal_transition(f.stage, new_stage) {
            return Err(SandboxError::Other(format!(
                "illegal transition {:?} -> {:?}",
                f.stage, new_stage
            )));
        }
        let when = at.into();
        let actor = actor.into();
        let note = note.into();
        f.stage = new_stage;
        f.events.push(FindingEvent {
            at: when.clone(),
            actor,
            stage: new_stage,
            note,
        });
        if new_stage.is_terminal() {
            f.closed_at = Some(when);
        }
        Ok(f.clone())
    }

    /// Set the remediation due date.
    pub fn set_remediation_due(
        &self,
        finding_id: &str,
        due_at: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("audit finding tracker poisoned".into()))?;
        let f = g
            .get_mut(finding_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown finding {finding_id}")))?;
        f.remediation_due_at = Some(due_at.into());
        Ok(())
    }

    /// Set the linked control id.
    pub fn set_control(
        &self,
        finding_id: &str,
        control_id: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("audit finding tracker poisoned".into()))?;
        let f = g
            .get_mut(finding_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown finding {finding_id}")))?;
        f.control_id = Some(control_id.into());
        Ok(())
    }

    /// Set the linked enterprise risk id.
    pub fn set_linked_risk(
        &self,
        finding_id: &str,
        risk_id: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("audit finding tracker poisoned".into()))?;
        let f = g
            .get_mut(finding_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown finding {finding_id}")))?;
        f.linked_risk_id = Some(risk_id.into());
        Ok(())
    }

    /// Set management response.
    pub fn set_management_response(
        &self,
        finding_id: &str,
        response: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("audit finding tracker poisoned".into()))?;
        let f = g
            .get_mut(finding_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown finding {finding_id}")))?;
        f.management_response = Some(response.into());
        Ok(())
    }

    /// Set remediation summary at closure.
    pub fn set_remediation_summary(
        &self,
        finding_id: &str,
        summary: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("audit finding tracker poisoned".into()))?;
        let f = g
            .get_mut(finding_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown finding {finding_id}")))?;
        f.remediation_summary = Some(summary.into());
        Ok(())
    }

    /// Add a tag (deduplicated).
    pub fn add_tag(&self, finding_id: &str, tag: impl Into<String>) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("audit finding tracker poisoned".into()))?;
        let f = g
            .get_mut(finding_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown finding {finding_id}")))?;
        let tag = tag.into();
        if !f.tags.contains(&tag) {
            f.tags.push(tag);
        }
        Ok(())
    }

    /// Look up.
    pub fn get(&self, finding_id: &str) -> Option<AuditFinding> {
        let g = self.inner.read().ok()?;
        g.get(finding_id).cloned()
    }

    /// All findings.
    pub fn all(&self) -> Vec<AuditFinding> {
        match self.inner.read() {
            Ok(g) => g.values().cloned().collect(),
            Err(_) => Vec::new(),
        }
    }

    /// For tenant.
    pub fn for_tenant(&self, tenant_id: &str) -> Vec<AuditFinding> {
        self.all()
            .into_iter()
            .filter(|f| f.tenant_id == tenant_id)
            .collect()
    }

    /// By source.
    pub fn by_source(&self, source: AuditSource) -> Vec<AuditFinding> {
        self.all().into_iter().filter(|f| f.source == source).collect()
    }

    /// By severity.
    pub fn by_severity(&self, severity: FindingSeverity) -> Vec<AuditFinding> {
        self.all()
            .into_iter()
            .filter(|f| f.severity == severity)
            .collect()
    }

    /// At a stage.
    pub fn by_stage(&self, stage: FindingStage) -> Vec<AuditFinding> {
        self.all().into_iter().filter(|f| f.stage == stage).collect()
    }

    /// Open findings (any non-terminal stage).
    pub fn open(&self) -> Vec<AuditFinding> {
        self.all()
            .into_iter()
            .filter(|f| !f.stage.is_terminal())
            .collect()
    }

    /// Findings overdue at `now`.
    pub fn overdue(&self, now: &str) -> Vec<AuditFinding> {
        self.all().into_iter().filter(|f| f.is_overdue(now)).collect()
    }

    /// Findings of material severity (Critical or High) that aren't yet
    /// closed.
    pub fn material_open(&self) -> Vec<AuditFinding> {
        self.all()
            .into_iter()
            .filter(|f| f.severity.is_material() && !f.stage.is_terminal())
            .collect()
    }

    /// Count.
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

    fn finding(id: &str, sev: FindingSeverity) -> AuditFinding {
        AuditFinding::new(
            id,
            "global",
            format!("title-{id}"),
            "description",
            AuditSource::Soc2,
            "SOC2 2025",
            "BigFour LLP",
            sev,
            "ciso",
            "2025-04-01T00:00:00Z",
        )
    }

    #[test]
    fn register_and_get() {
        let t = AuditFindingTracker::new();
        t.register(finding("f1", FindingSeverity::High)).unwrap();
        let f = t.get("f1").unwrap();
        assert_eq!(f.stage, FindingStage::Open);
        assert_eq!(f.severity, FindingSeverity::High);
    }

    #[test]
    fn duplicate_register_errors() {
        let t = AuditFindingTracker::new();
        t.register(finding("f1", FindingSeverity::High)).unwrap();
        let err = t.register(finding("f1", FindingSeverity::High)).unwrap_err();
        assert!(format!("{err}").contains("already registered"));
    }

    #[test]
    fn legal_transitions_table() {
        use FindingStage::*;
        assert!(legal_transition(Open, AcceptedByMgmt));
        assert!(legal_transition(Open, Disputed));
        assert!(legal_transition(Open, Withdrawn));
        assert!(legal_transition(AcceptedByMgmt, Remediating));
        assert!(legal_transition(Remediating, Remediated));
        assert!(legal_transition(Remediated, Verified));
        assert!(legal_transition(Remediated, Remediating)); // re-test failed
        assert!(legal_transition(Disputed, AcceptedByMgmt));
        assert!(legal_transition(Disputed, Withdrawn));
        // illegal
        assert!(!legal_transition(Open, Verified));
        assert!(!legal_transition(Verified, Open));
        assert!(!legal_transition(Withdrawn, Remediating));
    }

    #[test]
    fn happy_path_lifecycle() {
        let t = AuditFindingTracker::new();
        t.register(finding("f1", FindingSeverity::High)).unwrap();
        t.transition(
            "f1",
            FindingStage::AcceptedByMgmt,
            "ciso",
            "we accept",
            "2025-04-15T00:00:00Z",
        )
        .unwrap();
        t.transition(
            "f1",
            FindingStage::Remediating,
            "team",
            "patch in flight",
            "2025-04-20T00:00:00Z",
        )
        .unwrap();
        t.transition(
            "f1",
            FindingStage::Remediated,
            "team",
            "patch deployed",
            "2025-05-15T00:00:00Z",
        )
        .unwrap();
        let f = t
            .transition(
                "f1",
                FindingStage::Verified,
                "auditor",
                "re-test passed",
                "2025-06-01T00:00:00Z",
            )
            .unwrap();
        assert_eq!(f.stage, FindingStage::Verified);
        assert!(f.stage.is_terminal());
        assert_eq!(f.closed_at.as_deref(), Some("2025-06-01T00:00:00Z"));
        assert_eq!(f.events.len(), 4);
    }

    #[test]
    fn dispute_path() {
        let t = AuditFindingTracker::new();
        t.register(finding("f1", FindingSeverity::High)).unwrap();
        t.transition(
            "f1",
            FindingStage::Disputed,
            "ciso",
            "control was operating",
            "2025-04-15T00:00:00Z",
        )
        .unwrap();
        t.transition(
            "f1",
            FindingStage::Withdrawn,
            "auditor",
            "agreed",
            "2025-04-20T00:00:00Z",
        )
        .unwrap();
        let f = t.get("f1").unwrap();
        assert_eq!(f.stage, FindingStage::Withdrawn);
    }

    #[test]
    fn remediated_can_loop_back_to_remediating() {
        let t = AuditFindingTracker::new();
        t.register(finding("f1", FindingSeverity::High)).unwrap();
        t.transition(
            "f1",
            FindingStage::AcceptedByMgmt,
            "x",
            "n",
            "2025-04-15T00:00:00Z",
        )
        .unwrap();
        t.transition(
            "f1",
            FindingStage::Remediating,
            "x",
            "n",
            "2025-04-20T00:00:00Z",
        )
        .unwrap();
        t.transition(
            "f1",
            FindingStage::Remediated,
            "x",
            "n",
            "2025-05-15T00:00:00Z",
        )
        .unwrap();
        // Re-test failed → back to Remediating
        let f = t
            .transition(
                "f1",
                FindingStage::Remediating,
                "auditor",
                "re-test failed",
                "2025-06-01T00:00:00Z",
            )
            .unwrap();
        assert_eq!(f.stage, FindingStage::Remediating);
    }

    #[test]
    fn illegal_transition_errors() {
        let t = AuditFindingTracker::new();
        t.register(finding("f1", FindingSeverity::High)).unwrap();
        let err = t
            .transition(
                "f1",
                FindingStage::Verified,
                "x",
                "skip",
                "2025-04-15T00:00:00Z",
            )
            .unwrap_err();
        assert!(format!("{err}").contains("illegal transition"));
    }

    #[test]
    fn set_remediation_due_and_overdue() {
        let t = AuditFindingTracker::new();
        t.register(finding("f1", FindingSeverity::High)).unwrap();
        t.set_remediation_due("f1", "2025-05-01T00:00:00Z").unwrap();
        // Open + past due → overdue
        let overdue = t.overdue("2025-06-01T00:00:00Z");
        assert_eq!(overdue.len(), 1);
        // Move to terminal
        t.transition(
            "f1",
            FindingStage::Withdrawn,
            "auditor",
            "n",
            "2025-05-15T00:00:00Z",
        )
        .unwrap();
        assert_eq!(t.overdue("2025-06-01T00:00:00Z").len(), 0);
    }

    #[test]
    fn set_control_set_risk_set_responses() {
        let t = AuditFindingTracker::new();
        t.register(finding("f1", FindingSeverity::High)).unwrap();
        t.set_control("f1", "CC6.1").unwrap();
        t.set_linked_risk("f1", "RISK-2025-007").unwrap();
        t.set_management_response("f1", "We are remediating by Q3.")
            .unwrap();
        t.set_remediation_summary("f1", "Deployed automated user access reviews.")
            .unwrap();
        let f = t.get("f1").unwrap();
        assert_eq!(f.control_id.as_deref(), Some("CC6.1"));
        assert_eq!(f.linked_risk_id.as_deref(), Some("RISK-2025-007"));
        assert!(f.management_response.is_some());
        assert!(f.remediation_summary.is_some());
    }

    #[test]
    fn add_tag_dedupes() {
        let t = AuditFindingTracker::new();
        t.register(finding("f1", FindingSeverity::High)).unwrap();
        t.add_tag("f1", "soc2").unwrap();
        t.add_tag("f1", "soc2").unwrap();
        t.add_tag("f1", "p0").unwrap();
        assert_eq!(t.get("f1").unwrap().tags, vec!["soc2", "p0"]);
    }

    #[test]
    fn unknown_finding_errors() {
        let t = AuditFindingTracker::new();
        let err = t.set_control("nope", "x").unwrap_err();
        assert!(format!("{err}").contains("unknown finding"));
    }

    #[test]
    fn for_tenant_filters() {
        let t = AuditFindingTracker::new();
        t.register(finding("f1", FindingSeverity::High)).unwrap();
        let mut other = finding("f2", FindingSeverity::High);
        other.tenant_id = "tenant-b".into();
        t.register(other).unwrap();
        assert_eq!(t.for_tenant("global").len(), 1);
        assert_eq!(t.for_tenant("tenant-b").len(), 1);
    }

    #[test]
    fn by_source_severity_stage_filters() {
        let t = AuditFindingTracker::new();
        t.register(finding("f1", FindingSeverity::Critical)).unwrap();
        let mut iso = finding("f2", FindingSeverity::Moderate);
        iso.source = AuditSource::Iso27001;
        t.register(iso).unwrap();
        assert_eq!(t.by_source(AuditSource::Soc2).len(), 1);
        assert_eq!(t.by_source(AuditSource::Iso27001).len(), 1);
        assert_eq!(t.by_severity(FindingSeverity::Critical).len(), 1);
        assert_eq!(t.by_severity(FindingSeverity::Moderate).len(), 1);
        assert_eq!(t.by_stage(FindingStage::Open).len(), 2);
    }

    #[test]
    fn open_filters() {
        let t = AuditFindingTracker::new();
        t.register(finding("f1", FindingSeverity::High)).unwrap();
        t.register(finding("f2", FindingSeverity::High)).unwrap();
        t.transition(
            "f2",
            FindingStage::Withdrawn,
            "x",
            "n",
            "2025-04-15T00:00:00Z",
        )
        .unwrap();
        let open = t.open();
        let ids: Vec<_> = open.iter().map(|f| f.finding_id.clone()).collect();
        assert_eq!(ids, vec!["f1"]);
    }

    #[test]
    fn material_open_filters() {
        let t = AuditFindingTracker::new();
        t.register(finding("crit", FindingSeverity::Critical)).unwrap();
        t.register(finding("high", FindingSeverity::High)).unwrap();
        t.register(finding("low", FindingSeverity::Low)).unwrap();
        t.transition(
            "high",
            FindingStage::Withdrawn,
            "x",
            "n",
            "2025-04-15T00:00:00Z",
        )
        .unwrap();
        let m = t.material_open();
        let ids: Vec<_> = m.iter().map(|f| f.finding_id.clone()).collect();
        assert_eq!(ids, vec!["crit"]);
    }

    #[test]
    fn severity_helpers() {
        assert!(FindingSeverity::Critical.is_material());
        assert!(FindingSeverity::High.is_material());
        assert!(!FindingSeverity::Moderate.is_material());
        assert!(FindingSeverity::Critical.rank() > FindingSeverity::High.rank());
        assert!(FindingSeverity::High.rank() > FindingSeverity::Moderate.rank());
    }

    #[test]
    fn stage_terminal_helpers() {
        for s in [
            FindingStage::Verified,
            FindingStage::Closed,
            FindingStage::Withdrawn,
        ] {
            assert!(s.is_terminal());
        }
        for s in [
            FindingStage::Open,
            FindingStage::AcceptedByMgmt,
            FindingStage::Remediating,
            FindingStage::Remediated,
            FindingStage::Disputed,
        ] {
            assert!(!s.is_terminal());
        }
    }

    #[test]
    fn count_tracks() {
        let t = AuditFindingTracker::new();
        assert_eq!(t.count(), 0);
        t.register(finding("f1", FindingSeverity::High)).unwrap();
        assert_eq!(t.count(), 1);
    }

    #[test]
    fn finding_serde() {
        let f = finding("f1", FindingSeverity::High);
        let j = serde_json::to_string(&f).unwrap();
        let back: AuditFinding = serde_json::from_str(&j).unwrap();
        assert_eq!(f, back);
    }

    #[test]
    fn enums_serde() {
        for s in [
            FindingStage::Open,
            FindingStage::AcceptedByMgmt,
            FindingStage::Remediating,
            FindingStage::Remediated,
            FindingStage::Verified,
            FindingStage::Closed,
            FindingStage::Disputed,
            FindingStage::Withdrawn,
        ] {
            assert_eq!(
                s,
                serde_json::from_str::<FindingStage>(&serde_json::to_string(&s).unwrap()).unwrap()
            );
        }
        for sev in [
            FindingSeverity::Critical,
            FindingSeverity::High,
            FindingSeverity::Moderate,
            FindingSeverity::Low,
            FindingSeverity::Informational,
        ] {
            assert_eq!(
                sev,
                serde_json::from_str::<FindingSeverity>(&serde_json::to_string(&sev).unwrap())
                    .unwrap()
            );
        }
        for src in [
            AuditSource::Soc2,
            AuditSource::Iso27001,
            AuditSource::PciQsa,
            AuditSource::Hipaa,
            AuditSource::Sox,
            AuditSource::Internal,
            AuditSource::Regulator,
            AuditSource::CustomerAudit,
            AuditSource::PenTest,
        ] {
            assert_eq!(
                src,
                serde_json::from_str::<AuditSource>(&serde_json::to_string(&src).unwrap()).unwrap()
            );
        }
    }
}
