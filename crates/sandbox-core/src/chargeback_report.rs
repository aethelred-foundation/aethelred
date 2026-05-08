//! Chargeback report register — invoice-style reports per cost-center.
//!
//! Distinct from [`crate::cost_attribution`] (which records the
//! per-entry allocation) and [`crate::billing_meter`] (which generates
//! customer-facing invoices), this module is the **internal chargeback
//! report**: monthly statements rendered to each cost-center showing
//! what was allocated to them, broken out by source.
//!
//! Maps to FinOps Foundation "Run a Showback / Chargeback" capability
//! and SOX §404 inter-company chargeback evidence.
//!
//! ## Lifecycle
//!
//! `Draft → Issued → Disputed | Settled`
//!
//! Draft reports can be edited; issued reports are immutable except for
//! the `Disputed → Settled` transition (with a documented adjustment).

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

// =============================================================================
// ReportStage
// =============================================================================

/// Lifecycle stage of a chargeback report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportStage {
    /// Drafted; lines are mutable.
    Draft,
    /// Issued to recipient; immutable.
    Issued,
    /// Recipient disputed the report.
    Disputed,
    /// Settled (paid or otherwise resolved).
    Settled,
}

impl ReportStage {
    /// True if no further state changes expected.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Settled)
    }

    /// True if the report is still mutable.
    pub fn is_mutable(self) -> bool {
        matches!(self, Self::Draft)
    }
}

// =============================================================================
// LineItem
// =============================================================================

/// One line on a chargeback report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LineItem {
    /// Stable id within the report.
    pub line_id: String,
    /// Source label ("aws-ec2", "openai-gpt4", "shared-monitoring").
    pub source: String,
    /// Description.
    pub description: String,
    /// Quantity (units depend on source — GPU-hours, requests, GB).
    pub quantity: u64,
    /// Unit name ("gpu-hour", "request", "gb-month").
    pub unit: String,
    /// Amount in micro-units (1 USD = 1_000_000).
    pub amount_micro: i64,
    /// Optional reference back to a [`crate::cost_attribution`] entry id.
    pub cost_entry_ref: Option<String>,
}

impl LineItem {
    /// Construct a new line item.
    pub fn new(
        line_id: impl Into<String>,
        source: impl Into<String>,
        description: impl Into<String>,
        quantity: u64,
        unit: impl Into<String>,
        amount_micro: i64,
    ) -> Self {
        Self {
            line_id: line_id.into(),
            source: source.into(),
            description: description.into(),
            quantity,
            unit: unit.into(),
            amount_micro,
            cost_entry_ref: None,
        }
    }
}

// =============================================================================
// Adjustment
// =============================================================================

/// Adjustment applied during dispute resolution.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Adjustment {
    /// RFC 3339.
    pub at: String,
    /// Operator who applied the adjustment.
    pub actor: String,
    /// Amount in micro-units (negative = credit to recipient).
    pub amount_micro: i64,
    /// Reason.
    pub reason: String,
}

// =============================================================================
// ChargebackReport
// =============================================================================

/// One chargeback report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChargebackReport {
    /// Unique id (e.g., "CB-2025-04-PLATFORM").
    pub report_id: String,
    /// Tenant scope.
    pub tenant_id: String,
    /// Issuing cost-center / service.
    pub issuer: String,
    /// Recipient cost-center.
    pub recipient: String,
    /// Period label ("2025-04").
    pub period: String,
    /// Currency.
    pub currency: String,
    /// Lines.
    pub lines: Vec<LineItem>,
    /// Adjustments (post-issue).
    pub adjustments: Vec<Adjustment>,
    /// Lifecycle stage.
    pub stage: ReportStage,
    /// RFC 3339 — drafted.
    pub drafted_at: String,
    /// RFC 3339 — issued.
    pub issued_at: Option<String>,
    /// RFC 3339 — settled.
    pub settled_at: Option<String>,
    /// Free-text dispute reason (if disputed).
    pub dispute_reason: Option<String>,
    /// Free-form tags.
    pub tags: Vec<String>,
}

impl ChargebackReport {
    /// New `Draft` report.
    pub fn new(
        report_id: impl Into<String>,
        tenant_id: impl Into<String>,
        issuer: impl Into<String>,
        recipient: impl Into<String>,
        period: impl Into<String>,
        currency: impl Into<String>,
        drafted_at: impl Into<String>,
    ) -> Self {
        Self {
            report_id: report_id.into(),
            tenant_id: tenant_id.into(),
            issuer: issuer.into(),
            recipient: recipient.into(),
            period: period.into(),
            currency: currency.into(),
            lines: Vec::new(),
            adjustments: Vec::new(),
            stage: ReportStage::Draft,
            drafted_at: drafted_at.into(),
            issued_at: None,
            settled_at: None,
            dispute_reason: None,
            tags: Vec::new(),
        }
    }

    /// Sum of line amounts.
    pub fn line_total_micro(&self) -> i64 {
        self.lines.iter().map(|l| l.amount_micro).sum()
    }

    /// Sum of adjustments.
    pub fn adjustment_total_micro(&self) -> i64 {
        self.adjustments.iter().map(|a| a.amount_micro).sum()
    }

    /// Net amount due (lines + adjustments).
    pub fn net_total_micro(&self) -> i64 {
        self.line_total_micro()
            .saturating_add(self.adjustment_total_micro())
    }
}

// =============================================================================
// Lifecycle transition table
// =============================================================================

fn legal_transition(from: ReportStage, to: ReportStage) -> bool {
    use ReportStage::*;
    matches!(
        (from, to),
        (Draft, Issued)
            | (Issued, Disputed)
            | (Issued, Settled)
            | (Disputed, Settled)
    )
}

// =============================================================================
// ChargebackRegister
// =============================================================================

/// Thread-safe register of chargeback reports.
#[derive(Debug, Default)]
pub struct ChargebackRegister {
    inner: RwLock<HashMap<String, ChargebackReport>>,
}

impl ChargebackRegister {
    /// New empty register.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new draft report.
    pub fn register(&self, report: ChargebackReport) -> SandboxResult<()> {
        if !matches!(report.stage, ReportStage::Draft) {
            return Err(SandboxError::Other(format!(
                "report must start Draft, got {:?}",
                report.stage
            )));
        }
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("chargeback register poisoned".into()))?;
        if g.contains_key(&report.report_id) {
            return Err(SandboxError::Other(format!(
                "report already registered: {}",
                report.report_id
            )));
        }
        g.insert(report.report_id.clone(), report);
        Ok(())
    }

    /// Add a line item to a Draft report.
    pub fn add_line(&self, report_id: &str, line: LineItem) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("chargeback register poisoned".into()))?;
        let r = g
            .get_mut(report_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown report {report_id}")))?;
        if !r.stage.is_mutable() {
            return Err(SandboxError::Other(format!(
                "cannot add line to {report_id}: stage is {:?}",
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

    /// Issue the report (Draft → Issued). Errors if no lines.
    pub fn issue(
        &self,
        report_id: &str,
        at: impl Into<String>,
    ) -> SandboxResult<ChargebackReport> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("chargeback register poisoned".into()))?;
        let r = g
            .get_mut(report_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown report {report_id}")))?;
        if r.lines.is_empty() {
            return Err(SandboxError::Other(format!(
                "cannot issue {report_id}: no lines"
            )));
        }
        if !legal_transition(r.stage, ReportStage::Issued) {
            return Err(SandboxError::Other(format!(
                "illegal transition {:?} -> Issued",
                r.stage
            )));
        }
        r.stage = ReportStage::Issued;
        r.issued_at = Some(at.into());
        Ok(r.clone())
    }

    /// Mark a report Disputed (from Issued).
    pub fn dispute(
        &self,
        report_id: &str,
        reason: impl Into<String>,
    ) -> SandboxResult<ChargebackReport> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("chargeback register poisoned".into()))?;
        let r = g
            .get_mut(report_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown report {report_id}")))?;
        if !legal_transition(r.stage, ReportStage::Disputed) {
            return Err(SandboxError::Other(format!(
                "illegal transition {:?} -> Disputed",
                r.stage
            )));
        }
        r.stage = ReportStage::Disputed;
        r.dispute_reason = Some(reason.into());
        Ok(r.clone())
    }

    /// Apply an adjustment (only valid on Issued or Disputed reports).
    pub fn add_adjustment(
        &self,
        report_id: &str,
        adjustment: Adjustment,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("chargeback register poisoned".into()))?;
        let r = g
            .get_mut(report_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown report {report_id}")))?;
        if !matches!(r.stage, ReportStage::Issued | ReportStage::Disputed) {
            return Err(SandboxError::Other(format!(
                "cannot adjust {report_id}: stage is {:?}",
                r.stage
            )));
        }
        r.adjustments.push(adjustment);
        Ok(())
    }

    /// Settle a report (from Issued or Disputed).
    pub fn settle(
        &self,
        report_id: &str,
        at: impl Into<String>,
    ) -> SandboxResult<ChargebackReport> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("chargeback register poisoned".into()))?;
        let r = g
            .get_mut(report_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown report {report_id}")))?;
        if !legal_transition(r.stage, ReportStage::Settled) {
            return Err(SandboxError::Other(format!(
                "illegal transition {:?} -> Settled",
                r.stage
            )));
        }
        r.stage = ReportStage::Settled;
        r.settled_at = Some(at.into());
        Ok(r.clone())
    }

    /// Add a tag (deduplicated).
    pub fn add_tag(&self, report_id: &str, tag: impl Into<String>) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("chargeback register poisoned".into()))?;
        let r = g
            .get_mut(report_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown report {report_id}")))?;
        let tag = tag.into();
        if !r.tags.contains(&tag) {
            r.tags.push(tag);
        }
        Ok(())
    }

    /// Look up.
    pub fn get(&self, report_id: &str) -> Option<ChargebackReport> {
        let g = self.inner.read().ok()?;
        g.get(report_id).cloned()
    }

    /// All reports.
    pub fn all(&self) -> Vec<ChargebackReport> {
        match self.inner.read() {
            Ok(g) => g.values().cloned().collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Reports for a tenant.
    pub fn for_tenant(&self, tenant_id: &str) -> Vec<ChargebackReport> {
        self.all()
            .into_iter()
            .filter(|r| r.tenant_id == tenant_id)
            .collect()
    }

    /// Reports for a recipient.
    pub fn for_recipient(&self, recipient: &str) -> Vec<ChargebackReport> {
        self.all()
            .into_iter()
            .filter(|r| r.recipient == recipient)
            .collect()
    }

    /// Reports for an issuer.
    pub fn for_issuer(&self, issuer: &str) -> Vec<ChargebackReport> {
        self.all()
            .into_iter()
            .filter(|r| r.issuer == issuer)
            .collect()
    }

    /// Reports at a stage.
    pub fn by_stage(&self, stage: ReportStage) -> Vec<ChargebackReport> {
        self.all().into_iter().filter(|r| r.stage == stage).collect()
    }

    /// Reports for a period.
    pub fn for_period(&self, period: &str) -> Vec<ChargebackReport> {
        self.all()
            .into_iter()
            .filter(|r| r.period == period)
            .collect()
    }

    /// Sum of net totals across all reports for a recipient.
    pub fn recipient_total_micro(&self, recipient: &str) -> i64 {
        self.for_recipient(recipient)
            .iter()
            .map(|r| r.net_total_micro())
            .sum()
    }

    /// Number of reports.
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

    fn report(id: &str, recipient: &str) -> ChargebackReport {
        ChargebackReport::new(
            id,
            "tenant-a",
            "platform-team",
            recipient,
            "2025-04",
            "USD",
            "2025-05-01T00:00:00Z",
        )
    }

    fn line(id: &str, amount: i64) -> LineItem {
        LineItem::new(id, "aws-ec2", format!("desc-{id}"), 100, "hour", amount)
    }

    fn adj(amount: i64, reason: &str) -> Adjustment {
        Adjustment {
            at: "2025-05-15T00:00:00Z".into(),
            actor: "finance".into(),
            amount_micro: amount,
            reason: reason.into(),
        }
    }

    #[test]
    fn register_and_get() {
        let r = ChargebackRegister::new();
        r.register(report("c1", "data-team")).unwrap();
        assert!(r.get("c1").is_some());
    }

    #[test]
    fn duplicate_register_errors() {
        let r = ChargebackRegister::new();
        r.register(report("c1", "data-team")).unwrap();
        let err = r.register(report("c1", "data-team")).unwrap_err();
        assert!(format!("{err}").contains("already registered"));
    }

    #[test]
    fn must_start_draft() {
        let mut r = report("c1", "data-team");
        r.stage = ReportStage::Issued;
        let reg = ChargebackRegister::new();
        let err = reg.register(r).unwrap_err();
        assert!(format!("{err}").contains("must start Draft"));
    }

    #[test]
    fn add_line_to_draft() {
        let r = ChargebackRegister::new();
        r.register(report("c1", "data-team")).unwrap();
        r.add_line("c1", line("l1", 1_000_000)).unwrap();
        r.add_line("c1", line("l2", 500_000)).unwrap();
        let rep = r.get("c1").unwrap();
        assert_eq!(rep.lines.len(), 2);
        assert_eq!(rep.line_total_micro(), 1_500_000);
    }

    #[test]
    fn add_line_dedupes_id() {
        let r = ChargebackRegister::new();
        r.register(report("c1", "data-team")).unwrap();
        r.add_line("c1", line("l1", 1_000_000)).unwrap();
        let err = r.add_line("c1", line("l1", 999)).unwrap_err();
        assert!(format!("{err}").contains("already present"));
    }

    #[test]
    fn add_line_after_issued_errors() {
        let r = ChargebackRegister::new();
        r.register(report("c1", "data-team")).unwrap();
        r.add_line("c1", line("l1", 1_000_000)).unwrap();
        r.issue("c1", "2025-05-10T00:00:00Z").unwrap();
        let err = r.add_line("c1", line("l2", 500_000)).unwrap_err();
        assert!(format!("{err}").contains("cannot add line"));
    }

    #[test]
    fn issue_requires_lines() {
        let r = ChargebackRegister::new();
        r.register(report("c1", "data-team")).unwrap();
        let err = r.issue("c1", "2025-05-10T00:00:00Z").unwrap_err();
        assert!(format!("{err}").contains("no lines"));
    }

    #[test]
    fn legal_transitions() {
        use ReportStage::*;
        assert!(legal_transition(Draft, Issued));
        assert!(legal_transition(Issued, Disputed));
        assert!(legal_transition(Issued, Settled));
        assert!(legal_transition(Disputed, Settled));
        assert!(!legal_transition(Draft, Settled));
        assert!(!legal_transition(Settled, Disputed));
        assert!(!legal_transition(Disputed, Issued));
    }

    #[test]
    fn happy_path_lifecycle() {
        let r = ChargebackRegister::new();
        r.register(report("c1", "data-team")).unwrap();
        r.add_line("c1", line("l1", 1_000_000)).unwrap();
        r.issue("c1", "2025-05-10T00:00:00Z").unwrap();
        let rep = r.settle("c1", "2025-05-25T00:00:00Z").unwrap();
        assert_eq!(rep.stage, ReportStage::Settled);
        assert_eq!(rep.settled_at.as_deref(), Some("2025-05-25T00:00:00Z"));
        assert!(rep.stage.is_terminal());
    }

    #[test]
    fn dispute_then_settle() {
        let r = ChargebackRegister::new();
        r.register(report("c1", "data-team")).unwrap();
        r.add_line("c1", line("l1", 1_000_000)).unwrap();
        r.issue("c1", "2025-05-10T00:00:00Z").unwrap();
        r.dispute("c1", "double-charged for shared infra").unwrap();
        r.add_adjustment("c1", adj(-200_000, "shared-infra credit")).unwrap();
        let rep = r.settle("c1", "2025-05-25T00:00:00Z").unwrap();
        assert_eq!(rep.stage, ReportStage::Settled);
        assert_eq!(rep.dispute_reason.as_deref(), Some("double-charged for shared infra"));
        assert_eq!(rep.adjustment_total_micro(), -200_000);
        assert_eq!(rep.net_total_micro(), 800_000);
    }

    #[test]
    fn add_adjustment_only_post_issue() {
        let r = ChargebackRegister::new();
        r.register(report("c1", "data-team")).unwrap();
        // Draft → adjust errors
        let err = r.add_adjustment("c1", adj(-100, "x")).unwrap_err();
        assert!(format!("{err}").contains("cannot adjust"));
    }

    #[test]
    fn illegal_transitions_error() {
        let r = ChargebackRegister::new();
        r.register(report("c1", "data-team")).unwrap();
        // Cannot dispute a Draft
        let err = r.dispute("c1", "no").unwrap_err();
        assert!(format!("{err}").contains("illegal transition"));
        // Cannot settle a Draft
        let err = r.settle("c1", "2025-05-25T00:00:00Z").unwrap_err();
        assert!(format!("{err}").contains("illegal transition"));
    }

    #[test]
    fn add_tag_dedupes() {
        let r = ChargebackRegister::new();
        r.register(report("c1", "data-team")).unwrap();
        r.add_tag("c1", "monthly").unwrap();
        r.add_tag("c1", "monthly").unwrap();
        r.add_tag("c1", "shared-infra").unwrap();
        assert_eq!(r.get("c1").unwrap().tags, vec!["monthly", "shared-infra"]);
    }

    #[test]
    fn unknown_report_errors() {
        let r = ChargebackRegister::new();
        let err = r.add_line("nope", line("l1", 1_000)).unwrap_err();
        assert!(format!("{err}").contains("unknown report"));
    }

    #[test]
    fn for_tenant_recipient_issuer_period_filters() {
        let r = ChargebackRegister::new();
        r.register(report("c1", "data-team")).unwrap();
        let mut other = report("c2", "ml-team");
        other.tenant_id = "tenant-b".into();
        other.issuer = "infra-team".into();
        other.period = "2025-05".into();
        r.register(other).unwrap();
        assert_eq!(r.for_tenant("tenant-a").len(), 1);
        assert_eq!(r.for_tenant("tenant-b").len(), 1);
        assert_eq!(r.for_recipient("data-team").len(), 1);
        assert_eq!(r.for_recipient("ml-team").len(), 1);
        assert_eq!(r.for_issuer("platform-team").len(), 1);
        assert_eq!(r.for_issuer("infra-team").len(), 1);
        assert_eq!(r.for_period("2025-04").len(), 1);
        assert_eq!(r.for_period("2025-05").len(), 1);
    }

    #[test]
    fn by_stage_filters() {
        let r = ChargebackRegister::new();
        r.register(report("a", "x")).unwrap();
        r.register(report("b", "x")).unwrap();
        r.add_line("b", line("l1", 1_000_000)).unwrap();
        r.issue("b", "2025-05-10T00:00:00Z").unwrap();
        assert_eq!(r.by_stage(ReportStage::Draft).len(), 1);
        assert_eq!(r.by_stage(ReportStage::Issued).len(), 1);
    }

    #[test]
    fn recipient_total_aggregates() {
        let r = ChargebackRegister::new();
        r.register(report("c1", "data-team")).unwrap();
        r.add_line("c1", line("l1", 1_000_000)).unwrap();
        r.register(report("c2", "data-team")).unwrap();
        r.add_line("c2", line("l1", 500_000)).unwrap();
        r.register(report("c3", "ml-team")).unwrap();
        r.add_line("c3", line("l1", 300_000)).unwrap();
        assert_eq!(r.recipient_total_micro("data-team"), 1_500_000);
        assert_eq!(r.recipient_total_micro("ml-team"), 300_000);
        assert_eq!(r.recipient_total_micro("nobody"), 0);
    }

    #[test]
    fn line_total_zero_when_empty() {
        let r = report("c1", "x");
        assert_eq!(r.line_total_micro(), 0);
    }

    #[test]
    fn stage_helpers() {
        assert!(ReportStage::Settled.is_terminal());
        assert!(!ReportStage::Issued.is_terminal());
        assert!(ReportStage::Draft.is_mutable());
        assert!(!ReportStage::Issued.is_mutable());
    }

    #[test]
    fn count_tracks() {
        let r = ChargebackRegister::new();
        assert_eq!(r.count(), 0);
        r.register(report("c1", "x")).unwrap();
        assert_eq!(r.count(), 1);
    }

    #[test]
    fn report_serde() {
        let r = report("c1", "x");
        let j = serde_json::to_string(&r).unwrap();
        let back: ChargebackReport = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn line_adjustment_serde() {
        let l = line("l1", 1_000);
        assert_eq!(
            l,
            serde_json::from_str::<LineItem>(&serde_json::to_string(&l).unwrap()).unwrap()
        );
        let a = adj(-100, "credit");
        assert_eq!(
            a,
            serde_json::from_str::<Adjustment>(&serde_json::to_string(&a).unwrap()).unwrap()
        );
    }

    #[test]
    fn stage_serde() {
        for s in [
            ReportStage::Draft,
            ReportStage::Issued,
            ReportStage::Disputed,
            ReportStage::Settled,
        ] {
            assert_eq!(
                s,
                serde_json::from_str::<ReportStage>(&serde_json::to_string(&s).unwrap()).unwrap()
            );
        }
    }
}
