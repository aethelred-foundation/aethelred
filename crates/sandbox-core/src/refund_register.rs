//! Refund / service-credit register.
//!
//! Composes [`crate::sla_contract`] credit evaluations and [`crate::billing_meter`]
//! invoices into customer-facing refund records. Supports full refunds, service
//! credits applied to the next invoice, and explicit goodwill credits.
//!
//! Every refund has a structured cause + ledger of approvals.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use time::OffsetDateTime;
use uuid::Uuid;

// =============================================================================
// RefundKind
// =============================================================================

/// Refund kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefundKind {
    /// SLA breach service credit.
    SlaCredit,
    /// Cash refund / chargeback.
    CashRefund,
    /// Goodwill / customer-success credit.
    Goodwill,
    /// Billing error correction.
    BillingError,
}

// =============================================================================
// RefundStatus
// =============================================================================

/// Refund lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefundStatus {
    /// Pending approval.
    Pending,
    /// Approved.
    Approved,
    /// Applied to next invoice (service credit).
    Applied,
    /// Cash refund processed.
    Settled,
    /// Rejected.
    Rejected,
}

// =============================================================================
// Approval
// =============================================================================

/// One approval action.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RefundApproval {
    /// Approver.
    pub approver: String,
    /// `true` for approve, `false` for reject.
    pub approved: bool,
    /// Free-text reason.
    pub reason: Option<String>,
    /// RFC 3339 at.
    pub at: String,
}

// =============================================================================
// RefundRecord
// =============================================================================

/// One refund record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RefundRecord {
    /// Stable id.
    pub refund_id: Uuid,
    /// Customer-facing id (e.g. `"REF-2026-0001"`).
    pub display_id: String,
    /// Tenant.
    pub tenant_id: String,
    /// Refund kind.
    pub kind: RefundKind,
    /// Amount in micro-currency-units.
    pub micro_amount: i64,
    /// Currency.
    pub currency: String,
    /// Linked SLA evaluation id (if SlaCredit).
    pub sla_evaluation_id: Option<Uuid>,
    /// Linked invoice id (if BillingError).
    pub invoice_id: Option<Uuid>,
    /// Free-text reason.
    pub reason: String,
    /// Created by.
    pub created_by: String,
    /// Approvals.
    pub approvals: Vec<RefundApproval>,
    /// Status.
    pub status: RefundStatus,
    /// RFC 3339 created.
    pub created_at: String,
    /// RFC 3339 last-updated.
    pub last_updated_at: String,
}

impl RefundRecord {
    /// `true` if any approver rejected.
    pub fn has_rejection(&self) -> bool {
        self.approvals.iter().any(|a| !a.approved)
    }
    /// Number of approvals.
    pub fn approval_count(&self) -> usize {
        self.approvals.iter().filter(|a| a.approved).count()
    }
}

// =============================================================================
// RefundRegister
// =============================================================================

#[derive(Default)]
struct State {
    refunds: HashMap<Uuid, RefundRecord>,
    by_display: HashMap<String, Uuid>,
    /// Next display-number sequence per year prefix.
    seq: HashMap<String, u32>,
}

/// Register.
pub struct RefundRegister {
    state: RwLock<State>,
}

impl Default for RefundRegister {
    fn default() -> Self {
        Self {
            state: RwLock::new(State::default()),
        }
    }
}

impl std::fmt::Debug for RefundRegister {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RefundRegister")
            .field("refunds", &self.len())
            .finish()
    }
}

impl RefundRegister {
    /// New empty.
    pub fn new() -> Self {
        Self::default()
    }

    /// Open a new refund. Auto-assigns a `REF-YYYY-NNNN` display id.
    pub fn open(
        &self,
        tenant_id: impl Into<String>,
        kind: RefundKind,
        micro_amount: i64,
        currency: impl Into<String>,
        reason: impl Into<String>,
        created_by: impl Into<String>,
    ) -> SandboxResult<RefundRecord> {
        if micro_amount <= 0 {
            return Err(SandboxError::Other("micro_amount must be > 0".into()));
        }
        let now = OffsetDateTime::now_utc();
        let year = now.year();
        let prefix = format!("REF-{}", year);
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("refund register poisoned".into()))?;
        let seq = g.seq.entry(prefix.clone()).or_insert(0);
        *seq += 1;
        let display_id = format!("{}-{:04}", prefix, *seq);
        let now_str = now
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        let r = RefundRecord {
            refund_id: Uuid::now_v7(),
            display_id: display_id.clone(),
            tenant_id: tenant_id.into(),
            kind,
            micro_amount,
            currency: currency.into(),
            sla_evaluation_id: None,
            invoice_id: None,
            reason: reason.into(),
            created_by: created_by.into(),
            approvals: Vec::new(),
            status: RefundStatus::Pending,
            created_at: now_str.clone(),
            last_updated_at: now_str,
        };
        g.by_display.insert(display_id, r.refund_id);
        g.refunds.insert(r.refund_id, r.clone());
        Ok(r)
    }

    /// Link to an SLA evaluation.
    pub fn link_sla(&self, refund_id: Uuid, eval_id: Uuid) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("refund register poisoned".into()))?;
        let r = g
            .refunds
            .get_mut(&refund_id)
            .ok_or_else(|| SandboxError::Other(format!("refund {} not found", refund_id)))?;
        r.sla_evaluation_id = Some(eval_id);
        Ok(())
    }

    /// Link to an invoice.
    pub fn link_invoice(&self, refund_id: Uuid, invoice_id: Uuid) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("refund register poisoned".into()))?;
        let r = g
            .refunds
            .get_mut(&refund_id)
            .ok_or_else(|| SandboxError::Other(format!("refund {} not found", refund_id)))?;
        r.invoice_id = Some(invoice_id);
        Ok(())
    }

    /// Add an approval / rejection.
    pub fn record_decision(
        &self,
        refund_id: Uuid,
        approver: impl Into<String>,
        approved: bool,
        reason: Option<String>,
    ) -> SandboxResult<()> {
        let approver = approver.into();
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("refund register poisoned".into()))?;
        let r = g
            .refunds
            .get_mut(&refund_id)
            .ok_or_else(|| SandboxError::Other(format!("refund {} not found", refund_id)))?;
        if r.status != RefundStatus::Pending {
            return Err(SandboxError::Other(format!(
                "cannot decide on refund in state {:?}",
                r.status
            )));
        }
        let now = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        r.approvals.push(RefundApproval {
            approver,
            approved,
            reason,
            at: now.clone(),
        });
        r.last_updated_at = now;
        if !approved {
            r.status = RefundStatus::Rejected;
        }
        Ok(())
    }

    /// Mark an approved refund as applied to next invoice.
    pub fn mark_applied(&self, refund_id: Uuid) -> SandboxResult<()> {
        self.transition(refund_id, RefundStatus::Applied)
    }

    /// Mark as settled (cash refund processed).
    pub fn mark_settled(&self, refund_id: Uuid) -> SandboxResult<()> {
        self.transition(refund_id, RefundStatus::Settled)
    }

    /// Move from Pending → Approved if at least N approvals.
    pub fn finalize_approval(
        &self,
        refund_id: Uuid,
        required_approvals: u32,
    ) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("refund register poisoned".into()))?;
        let r = g
            .refunds
            .get_mut(&refund_id)
            .ok_or_else(|| SandboxError::Other(format!("refund {} not found", refund_id)))?;
        if r.has_rejection() {
            return Err(SandboxError::Other("refund has rejection — cannot approve".into()));
        }
        if (r.approval_count() as u32) < required_approvals {
            return Err(SandboxError::Other(format!(
                "need {} approvals, have {}",
                required_approvals,
                r.approval_count()
            )));
        }
        r.status = RefundStatus::Approved;
        Ok(())
    }

    fn transition(&self, refund_id: Uuid, target: RefundStatus) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("refund register poisoned".into()))?;
        let r = g
            .refunds
            .get_mut(&refund_id)
            .ok_or_else(|| SandboxError::Other(format!("refund {} not found", refund_id)))?;
        if r.status != RefundStatus::Approved {
            return Err(SandboxError::Other(format!(
                "cannot transition refund in state {:?}",
                r.status
            )));
        }
        r.status = target;
        r.last_updated_at = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        Ok(())
    }

    /// Lookup by id.
    pub fn get(&self, id: Uuid) -> Option<RefundRecord> {
        self.state.read().ok()?.refunds.get(&id).cloned()
    }
    /// Lookup by display id.
    pub fn by_display_id(&self, display: &str) -> Option<RefundRecord> {
        let g = self.state.read().ok()?;
        let id = g.by_display.get(display)?;
        g.refunds.get(id).cloned()
    }
    /// All.
    pub fn all(&self) -> Vec<RefundRecord> {
        self.state
            .read()
            .map(|g| g.refunds.values().cloned().collect())
            .unwrap_or_default()
    }
    /// Refunds for a tenant.
    pub fn for_tenant(&self, tenant: &str) -> Vec<RefundRecord> {
        self.all().into_iter().filter(|r| r.tenant_id == tenant).collect()
    }
    /// Refunds in a status.
    pub fn by_status(&self, s: RefundStatus) -> Vec<RefundRecord> {
        self.all().into_iter().filter(|r| r.status == s).collect()
    }
    /// Total approved amount for a tenant + currency (micro-units).
    pub fn approved_total_micro(&self, tenant: &str, currency: &str) -> i64 {
        self.for_tenant(tenant)
            .into_iter()
            .filter(|r| {
                r.currency == currency
                    && (r.status == RefundStatus::Approved
                        || r.status == RefundStatus::Applied
                        || r.status == RefundStatus::Settled)
            })
            .map(|r| r.micro_amount)
            .sum()
    }
    /// Count.
    pub fn len(&self) -> usize {
        self.state.read().map(|g| g.refunds.len()).unwrap_or(0)
    }
    /// Empty?
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_one(r: &RefundRegister) -> RefundRecord {
        r.open(
            "FAB",
            RefundKind::SlaCredit,
            500_000,
            "USD",
            "Q2 SLA breach",
            "ops",
        )
        .unwrap()
    }

    #[test]
    fn open_creates_record() {
        let r = RefundRegister::new();
        let rec = open_one(&r);
        assert_eq!(rec.status, RefundStatus::Pending);
        assert_eq!(rec.kind, RefundKind::SlaCredit);
        assert!(rec.display_id.starts_with("REF-"));
    }

    #[test]
    fn open_zero_amount_errors() {
        let r = RefundRegister::new();
        assert!(r
            .open("FAB", RefundKind::SlaCredit, 0, "USD", "x", "ops")
            .is_err());
    }

    #[test]
    fn display_id_increments() {
        let r = RefundRegister::new();
        let r1 = open_one(&r);
        let r2 = open_one(&r);
        assert_ne!(r1.display_id, r2.display_id);
    }

    #[test]
    fn link_sla() {
        let r = RefundRegister::new();
        let rec = open_one(&r);
        let eid = Uuid::now_v7();
        r.link_sla(rec.refund_id, eid).unwrap();
        assert_eq!(r.get(rec.refund_id).unwrap().sla_evaluation_id, Some(eid));
    }

    #[test]
    fn link_invoice() {
        let r = RefundRegister::new();
        let rec = open_one(&r);
        let inv = Uuid::now_v7();
        r.link_invoice(rec.refund_id, inv).unwrap();
        assert_eq!(r.get(rec.refund_id).unwrap().invoice_id, Some(inv));
    }

    #[test]
    fn record_decision_appends() {
        let r = RefundRegister::new();
        let rec = open_one(&r);
        r.record_decision(rec.refund_id, "vp-finance", true, None).unwrap();
        assert_eq!(r.get(rec.refund_id).unwrap().approval_count(), 1);
    }

    #[test]
    fn record_rejection_sets_status() {
        let r = RefundRegister::new();
        let rec = open_one(&r);
        r.record_decision(rec.refund_id, "vp-finance", false, Some("policy".into()))
            .unwrap();
        assert_eq!(r.get(rec.refund_id).unwrap().status, RefundStatus::Rejected);
    }

    #[test]
    fn finalize_approval_succeeds_with_quorum() {
        let r = RefundRegister::new();
        let rec = open_one(&r);
        r.record_decision(rec.refund_id, "a", true, None).unwrap();
        r.record_decision(rec.refund_id, "b", true, None).unwrap();
        r.finalize_approval(rec.refund_id, 2).unwrap();
        assert_eq!(r.get(rec.refund_id).unwrap().status, RefundStatus::Approved);
    }

    #[test]
    fn finalize_below_quorum_errors() {
        let r = RefundRegister::new();
        let rec = open_one(&r);
        r.record_decision(rec.refund_id, "a", true, None).unwrap();
        assert!(r.finalize_approval(rec.refund_id, 2).is_err());
    }

    #[test]
    fn finalize_with_rejection_errors() {
        let r = RefundRegister::new();
        let rec = open_one(&r);
        // First an approval, then a rejection.
        r.record_decision(rec.refund_id, "a", true, None).unwrap();
        // After rejection, status is Rejected — record_decision is blocked
        // for non-Pending. So we need to not record a rejection at all.
        // Instead test rejection-only flow.
        let other = open_one(&r);
        r.record_decision(other.refund_id, "a", false, None).unwrap();
        assert!(r.finalize_approval(other.refund_id, 1).is_err());
    }

    #[test]
    fn mark_applied_after_approval() {
        let r = RefundRegister::new();
        let rec = open_one(&r);
        r.record_decision(rec.refund_id, "a", true, None).unwrap();
        r.finalize_approval(rec.refund_id, 1).unwrap();
        r.mark_applied(rec.refund_id).unwrap();
        assert_eq!(r.get(rec.refund_id).unwrap().status, RefundStatus::Applied);
    }

    #[test]
    fn mark_settled_after_approval() {
        let r = RefundRegister::new();
        let rec = open_one(&r);
        r.record_decision(rec.refund_id, "a", true, None).unwrap();
        r.finalize_approval(rec.refund_id, 1).unwrap();
        r.mark_settled(rec.refund_id).unwrap();
        assert_eq!(r.get(rec.refund_id).unwrap().status, RefundStatus::Settled);
    }

    #[test]
    fn cannot_apply_unapproved() {
        let r = RefundRegister::new();
        let rec = open_one(&r);
        assert!(r.mark_applied(rec.refund_id).is_err());
    }

    #[test]
    fn cannot_record_after_rejection() {
        let r = RefundRegister::new();
        let rec = open_one(&r);
        r.record_decision(rec.refund_id, "a", false, None).unwrap();
        // Now in Rejected state — second decision should error.
        assert!(r.record_decision(rec.refund_id, "b", true, None).is_err());
    }

    #[test]
    fn approved_total_micro_sums_relevant() {
        let r = RefundRegister::new();
        let r1 = r
            .open("FAB", RefundKind::SlaCredit, 100_000, "USD", "x", "ops")
            .unwrap();
        r.record_decision(r1.refund_id, "a", true, None).unwrap();
        r.finalize_approval(r1.refund_id, 1).unwrap();
        let r2 = r
            .open("FAB", RefundKind::Goodwill, 50_000, "USD", "y", "ops")
            .unwrap();
        r.record_decision(r2.refund_id, "a", true, None).unwrap();
        r.finalize_approval(r2.refund_id, 1).unwrap();
        r.mark_settled(r2.refund_id).unwrap();
        // Both should sum.
        assert_eq!(r.approved_total_micro("FAB", "USD"), 150_000);
    }

    #[test]
    fn for_tenant_filters() {
        let r = RefundRegister::new();
        open_one(&r);
        r.open("ENBD", RefundKind::Goodwill, 100, "USD", "x", "ops").unwrap();
        assert_eq!(r.for_tenant("FAB").len(), 1);
        assert_eq!(r.for_tenant("ENBD").len(), 1);
    }

    #[test]
    fn by_status_filters() {
        let r = RefundRegister::new();
        let rec = open_one(&r);
        r.record_decision(rec.refund_id, "a", false, None).unwrap();
        assert_eq!(r.by_status(RefundStatus::Rejected).len(), 1);
        assert_eq!(r.by_status(RefundStatus::Pending).len(), 0);
    }

    #[test]
    fn by_display_id_lookup() {
        let r = RefundRegister::new();
        let rec = open_one(&r);
        let found = r.by_display_id(&rec.display_id).unwrap();
        assert_eq!(found.refund_id, rec.refund_id);
    }

    #[test]
    fn record_serde() {
        let r = RefundRegister::new();
        let rec = open_one(&r);
        let j = serde_json::to_string(&rec).unwrap();
        let p: RefundRecord = serde_json::from_str(&j).unwrap();
        assert_eq!(p, rec);
    }

    #[test]
    fn approval_serde() {
        let a = RefundApproval {
            approver: "x".into(),
            approved: true,
            reason: None,
            at: "t".into(),
        };
        let j = serde_json::to_string(&a).unwrap();
        let p: RefundApproval = serde_json::from_str(&j).unwrap();
        assert_eq!(p, a);
    }

    #[test]
    fn kind_serde() {
        for k in [
            RefundKind::SlaCredit,
            RefundKind::CashRefund,
            RefundKind::Goodwill,
            RefundKind::BillingError,
        ] {
            let j = serde_json::to_string(&k).unwrap();
            let p: RefundKind = serde_json::from_str(&j).unwrap();
            assert_eq!(p, k);
        }
    }

    #[test]
    fn status_serde() {
        for s in [
            RefundStatus::Pending,
            RefundStatus::Approved,
            RefundStatus::Applied,
            RefundStatus::Settled,
            RefundStatus::Rejected,
        ] {
            let j = serde_json::to_string(&s).unwrap();
            let p: RefundStatus = serde_json::from_str(&j).unwrap();
            assert_eq!(p, s);
        }
    }

    #[test]
    fn registry_count_tracks() {
        let r = RefundRegister::new();
        assert!(r.is_empty());
        open_one(&r);
        assert_eq!(r.len(), 1);
    }
}
