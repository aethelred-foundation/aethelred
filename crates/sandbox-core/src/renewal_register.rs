//! Customer subscription / contract renewal register.
//!
//! Distinct from [`crate::sla_contract`] (SLA terms + credit evaluation),
//! [`crate::billing_meter`] (usage metering), and [`crate::refund_register`]
//! (refund processing), this is the **renewal pipeline** — the
//! register that customer success / sales teams pull on to track when
//! every customer contract is up for renewal, what the proposed terms
//! are, and the eventual outcome (renewed / churned / downgraded /
//! upsold).
//!
//! Maps to canonical SaaS GTM systems (Salesforce, HubSpot, Gong) and
//! gross-/net-retention KPIs that feed board reporting.
//!
//! ## Lifecycle
//!
//! `Upcoming → InNegotiation → (Renewed | Churned | Expired)`
//!
//! `Renewed` may include `Upsell`, `Flat`, or `Downgrade` size deltas.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

// =============================================================================
// RenewalStage
// =============================================================================

/// Lifecycle stage of a renewal opportunity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RenewalStage {
    /// Detected by the system; not yet engaged.
    Upcoming,
    /// CSM / AE engaged; terms being negotiated.
    InNegotiation,
    /// Customer renewed.
    Renewed,
    /// Customer chose not to renew (churn).
    Churned,
    /// Contract expired without action (silent churn).
    Expired,
}

impl RenewalStage {
    /// True if no further state changes expected.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Renewed | Self::Churned | Self::Expired)
    }

    /// True if revenue was retained.
    pub fn is_retained(self) -> bool {
        matches!(self, Self::Renewed)
    }
}

// =============================================================================
// SizeDelta
// =============================================================================

/// Size of the renewal relative to prior contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SizeDelta {
    /// Renewed at higher ARR (upsell).
    Upsell,
    /// Renewed at same ARR.
    Flat,
    /// Renewed at lower ARR (downgrade / contraction).
    Downgrade,
}

// =============================================================================
// HealthSignal
// =============================================================================

/// Coarse-grained health signal feeding into renewal-risk scoring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthSignal {
    /// Healthy / on-track.
    Green,
    /// Yellow flag — needs attention.
    Yellow,
    /// Red flag — at risk.
    Red,
}

impl HealthSignal {
    /// Numeric rank (lower = better).
    pub fn rank(self) -> u8 {
        match self {
            Self::Green => 0,
            Self::Yellow => 1,
            Self::Red => 2,
        }
    }
}

// =============================================================================
// RenewalEvent
// =============================================================================

/// One event on the renewal timeline.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RenewalEvent {
    /// RFC 3339.
    pub at: String,
    /// Actor.
    pub actor: String,
    /// Stage applied.
    pub stage: RenewalStage,
    /// Free-text note.
    pub note: String,
}

// =============================================================================
// RenewalOpportunity
// =============================================================================

/// One renewal opportunity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RenewalOpportunity {
    /// Unique id.
    pub renewal_id: String,
    /// Tenant scope.
    pub tenant_id: String,
    /// Customer id.
    pub customer_id: String,
    /// Customer display name.
    pub customer_name: String,
    /// Linked contract id from [`crate::sla_contract`] (if any).
    pub contract_id: Option<String>,
    /// Account owner / CSM.
    pub owner: String,
    /// Stage.
    pub stage: RenewalStage,
    /// Health signal.
    pub health: HealthSignal,
    /// Current contract end (RFC 3339).
    pub current_end_at: String,
    /// Target renewal start (RFC 3339).
    pub target_start_at: String,
    /// Current ARR in micro-units (1 USD = 1_000_000).
    pub current_arr_micro: i64,
    /// Proposed renewal ARR.
    pub proposed_arr_micro: i64,
    /// Settled (final) renewal ARR — set on `Renewed`.
    pub settled_arr_micro: Option<i64>,
    /// Size delta — set on `Renewed`.
    pub size_delta: Option<SizeDelta>,
    /// Free-text rationale (engagement notes, churn reason).
    pub rationale: Option<String>,
    /// RFC 3339 — first detected.
    pub detected_at: String,
    /// RFC 3339 — closed.
    pub closed_at: Option<String>,
    /// Event log.
    pub events: Vec<RenewalEvent>,
    /// Free-form tags.
    pub tags: Vec<String>,
}

impl RenewalOpportunity {
    /// New `Upcoming` opportunity.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        renewal_id: impl Into<String>,
        tenant_id: impl Into<String>,
        customer_id: impl Into<String>,
        customer_name: impl Into<String>,
        owner: impl Into<String>,
        current_end_at: impl Into<String>,
        target_start_at: impl Into<String>,
        current_arr_micro: i64,
        detected_at: impl Into<String>,
    ) -> Self {
        let current_arr = current_arr_micro;
        Self {
            renewal_id: renewal_id.into(),
            tenant_id: tenant_id.into(),
            customer_id: customer_id.into(),
            customer_name: customer_name.into(),
            contract_id: None,
            owner: owner.into(),
            stage: RenewalStage::Upcoming,
            health: HealthSignal::Green,
            current_end_at: current_end_at.into(),
            target_start_at: target_start_at.into(),
            current_arr_micro: current_arr,
            // Default proposed = current (flat).
            proposed_arr_micro: current_arr,
            settled_arr_micro: None,
            size_delta: None,
            rationale: None,
            detected_at: detected_at.into(),
            closed_at: None,
            events: Vec::new(),
            tags: Vec::new(),
        }
    }

    /// True if `now >= current_end_at` and the opportunity is still open.
    pub fn is_overdue(&self, now: &str) -> bool {
        if self.stage.is_terminal() {
            return false;
        }
        now >= self.current_end_at.as_str()
    }

    /// Net retention basis-points: settled / current * 10_000. Returns
    /// `None` if not yet settled or current is zero.
    pub fn net_retention_basis_points(&self) -> Option<i64> {
        if self.current_arr_micro <= 0 {
            return None;
        }
        let settled = self.settled_arr_micro?;
        Some((settled as i128 * 10_000 / self.current_arr_micro as i128) as i64)
    }
}

// =============================================================================
// Lifecycle transition table
// =============================================================================

fn legal_transition(from: RenewalStage, to: RenewalStage) -> bool {
    use RenewalStage::*;
    matches!(
        (from, to),
        (Upcoming, InNegotiation)
            | (Upcoming, Churned)
            | (Upcoming, Expired)
            | (InNegotiation, Renewed)
            | (InNegotiation, Churned)
            | (InNegotiation, Expired)
            | (InNegotiation, Upcoming) // re-detect early
    )
}

// =============================================================================
// RenewalRegister
// =============================================================================

/// Thread-safe register of renewal opportunities.
#[derive(Debug, Default)]
pub struct RenewalRegister {
    inner: RwLock<HashMap<String, RenewalOpportunity>>,
}

impl RenewalRegister {
    /// New empty register.
    pub fn new() -> Self {
        Self::default()
    }

    /// Detect a new renewal opportunity.
    pub fn detect(&self, opp: RenewalOpportunity) -> SandboxResult<()> {
        if !matches!(opp.stage, RenewalStage::Upcoming) {
            return Err(SandboxError::Other(format!(
                "opportunity must start Upcoming, got {:?}",
                opp.stage
            )));
        }
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("renewal register poisoned".into()))?;
        if g.contains_key(&opp.renewal_id) {
            return Err(SandboxError::Other(format!(
                "renewal already detected: {}",
                opp.renewal_id
            )));
        }
        g.insert(opp.renewal_id.clone(), opp);
        Ok(())
    }

    /// Move into negotiation.
    pub fn engage(
        &self,
        renewal_id: &str,
        actor: impl Into<String>,
        at: impl Into<String>,
        note: impl Into<String>,
    ) -> SandboxResult<RenewalOpportunity> {
        self.simple_transition(renewal_id, RenewalStage::InNegotiation, actor, at, note)
    }

    /// Set proposed ARR (during negotiation).
    pub fn set_proposed_arr(
        &self,
        renewal_id: &str,
        proposed_arr_micro: i64,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("renewal register poisoned".into()))?;
        let r = g
            .get_mut(renewal_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown renewal {renewal_id}")))?;
        if r.stage.is_terminal() {
            return Err(SandboxError::Other(format!(
                "cannot set proposed on {renewal_id}: stage is {:?}",
                r.stage
            )));
        }
        r.proposed_arr_micro = proposed_arr_micro;
        Ok(())
    }

    /// Set health signal.
    pub fn set_health(&self, renewal_id: &str, health: HealthSignal) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("renewal register poisoned".into()))?;
        let r = g
            .get_mut(renewal_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown renewal {renewal_id}")))?;
        r.health = health;
        Ok(())
    }

    /// Mark Renewed with a settled ARR. Auto-derives `size_delta` from
    /// `current_arr` vs `settled_arr`.
    pub fn renewed(
        &self,
        renewal_id: &str,
        actor: impl Into<String>,
        at: impl Into<String>,
        settled_arr_micro: i64,
        rationale: impl Into<String>,
    ) -> SandboxResult<RenewalOpportunity> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("renewal register poisoned".into()))?;
        let r = g
            .get_mut(renewal_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown renewal {renewal_id}")))?;
        if !legal_transition(r.stage, RenewalStage::Renewed) {
            return Err(SandboxError::Other(format!(
                "illegal transition {:?} -> Renewed",
                r.stage
            )));
        }
        let when = at.into();
        let actor = actor.into();
        let rationale = rationale.into();
        r.stage = RenewalStage::Renewed;
        r.settled_arr_micro = Some(settled_arr_micro);
        r.size_delta = Some(if settled_arr_micro > r.current_arr_micro {
            SizeDelta::Upsell
        } else if settled_arr_micro < r.current_arr_micro {
            SizeDelta::Downgrade
        } else {
            SizeDelta::Flat
        });
        r.rationale = Some(rationale.clone());
        r.closed_at = Some(when.clone());
        r.events.push(RenewalEvent {
            at: when,
            actor,
            stage: RenewalStage::Renewed,
            note: rationale,
        });
        Ok(r.clone())
    }

    /// Mark Churned.
    pub fn churned(
        &self,
        renewal_id: &str,
        actor: impl Into<String>,
        at: impl Into<String>,
        rationale: impl Into<String>,
    ) -> SandboxResult<RenewalOpportunity> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("renewal register poisoned".into()))?;
        let r = g
            .get_mut(renewal_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown renewal {renewal_id}")))?;
        if !legal_transition(r.stage, RenewalStage::Churned) {
            return Err(SandboxError::Other(format!(
                "illegal transition {:?} -> Churned",
                r.stage
            )));
        }
        let when = at.into();
        let actor = actor.into();
        let rationale = rationale.into();
        r.stage = RenewalStage::Churned;
        r.rationale = Some(rationale.clone());
        r.closed_at = Some(when.clone());
        r.events.push(RenewalEvent {
            at: when,
            actor,
            stage: RenewalStage::Churned,
            note: rationale,
        });
        Ok(r.clone())
    }

    /// Mark Expired.
    pub fn expired(
        &self,
        renewal_id: &str,
        at: impl Into<String>,
    ) -> SandboxResult<RenewalOpportunity> {
        self.simple_transition(
            renewal_id,
            RenewalStage::Expired,
            "system",
            at,
            "contract expired without renewal",
        )
    }

    fn simple_transition(
        &self,
        renewal_id: &str,
        new_stage: RenewalStage,
        actor: impl Into<String>,
        at: impl Into<String>,
        note: impl Into<String>,
    ) -> SandboxResult<RenewalOpportunity> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("renewal register poisoned".into()))?;
        let r = g
            .get_mut(renewal_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown renewal {renewal_id}")))?;
        if !legal_transition(r.stage, new_stage) {
            return Err(SandboxError::Other(format!(
                "illegal transition {:?} -> {:?}",
                r.stage, new_stage
            )));
        }
        let when = at.into();
        let note = note.into();
        r.stage = new_stage;
        if new_stage.is_terminal() {
            r.closed_at = Some(when.clone());
            r.rationale = Some(note.clone());
        }
        r.events.push(RenewalEvent {
            at: when,
            actor: actor.into(),
            stage: new_stage,
            note,
        });
        Ok(r.clone())
    }

    /// Link to a contract id.
    pub fn link_contract(
        &self,
        renewal_id: &str,
        contract_id: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("renewal register poisoned".into()))?;
        let r = g
            .get_mut(renewal_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown renewal {renewal_id}")))?;
        r.contract_id = Some(contract_id.into());
        Ok(())
    }

    /// Add a tag (deduplicated).
    pub fn add_tag(&self, renewal_id: &str, tag: impl Into<String>) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("renewal register poisoned".into()))?;
        let r = g
            .get_mut(renewal_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown renewal {renewal_id}")))?;
        let tag = tag.into();
        if !r.tags.contains(&tag) {
            r.tags.push(tag);
        }
        Ok(())
    }

    /// Look up.
    pub fn get(&self, renewal_id: &str) -> Option<RenewalOpportunity> {
        let g = self.inner.read().ok()?;
        g.get(renewal_id).cloned()
    }

    /// All opportunities.
    pub fn all(&self) -> Vec<RenewalOpportunity> {
        match self.inner.read() {
            Ok(g) => g.values().cloned().collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Opportunities for a tenant.
    pub fn for_tenant(&self, tenant_id: &str) -> Vec<RenewalOpportunity> {
        self.all()
            .into_iter()
            .filter(|r| r.tenant_id == tenant_id)
            .collect()
    }

    /// Opportunities for a customer.
    pub fn for_customer(&self, customer_id: &str) -> Vec<RenewalOpportunity> {
        self.all()
            .into_iter()
            .filter(|r| r.customer_id == customer_id)
            .collect()
    }

    /// Opportunities by stage.
    pub fn by_stage(&self, stage: RenewalStage) -> Vec<RenewalOpportunity> {
        self.all().into_iter().filter(|r| r.stage == stage).collect()
    }

    /// Open opportunities (non-terminal).
    pub fn open(&self) -> Vec<RenewalOpportunity> {
        self.all()
            .into_iter()
            .filter(|r| !r.stage.is_terminal())
            .collect()
    }

    /// At-risk opportunities (Yellow or Red, non-terminal).
    pub fn at_risk(&self) -> Vec<RenewalOpportunity> {
        self.all()
            .into_iter()
            .filter(|r| !r.stage.is_terminal() && r.health.rank() > 0)
            .collect()
    }

    /// Open opportunities past their current_end_at at `now`.
    pub fn overdue(&self, now: &str) -> Vec<RenewalOpportunity> {
        self.all()
            .into_iter()
            .filter(|r| r.is_overdue(now))
            .collect()
    }

    /// Total ARR retained from `Renewed` opportunities (sum of settled).
    pub fn total_retained_arr_micro(&self) -> i64 {
        self.all()
            .iter()
            .filter(|r| matches!(r.stage, RenewalStage::Renewed))
            .filter_map(|r| r.settled_arr_micro)
            .sum()
    }

    /// Total ARR lost from `Churned` and `Expired` (sum of current_arr).
    pub fn total_lost_arr_micro(&self) -> i64 {
        self.all()
            .iter()
            .filter(|r| matches!(r.stage, RenewalStage::Churned | RenewalStage::Expired))
            .map(|r| r.current_arr_micro)
            .sum()
    }

    /// Net Revenue Retention basis points across all *closed* opportunities:
    /// `sum(settled retained) / sum(current ARR of all closed) * 10_000`.
    /// Lost opportunities contribute 0 to numerator. Returns `None` if no
    /// closed opportunities have positive current_arr.
    pub fn nrr_basis_points(&self) -> Option<i64> {
        let closed: Vec<RenewalOpportunity> = self
            .all()
            .into_iter()
            .filter(|r| r.stage.is_terminal())
            .collect();
        let denom: i128 = closed
            .iter()
            .map(|r| r.current_arr_micro as i128)
            .filter(|v| *v > 0)
            .sum();
        if denom == 0 {
            return None;
        }
        let numer: i128 = closed
            .iter()
            .filter(|r| matches!(r.stage, RenewalStage::Renewed))
            .filter_map(|r| r.settled_arr_micro)
            .map(|s| s as i128)
            .sum();
        Some((numer * 10_000 / denom) as i64)
    }

    /// Number of opportunities.
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

    fn opp(id: &str, customer: &str, current_arr: i64) -> RenewalOpportunity {
        RenewalOpportunity::new(
            id,
            "tenant-a",
            customer,
            format!("Customer {customer}"),
            "csm-bob",
            "2025-12-31T00:00:00Z",
            "2026-01-01T00:00:00Z",
            current_arr,
            "2025-09-01T00:00:00Z",
        )
    }

    #[test]
    fn detect_and_get() {
        let r = RenewalRegister::new();
        r.detect(opp("r1", "alice", 1_000_000)).unwrap();
        let g = r.get("r1").unwrap();
        assert_eq!(g.stage, RenewalStage::Upcoming);
        // Default proposed = current
        assert_eq!(g.proposed_arr_micro, 1_000_000);
    }

    #[test]
    fn duplicate_detect_errors() {
        let r = RenewalRegister::new();
        r.detect(opp("r1", "alice", 1_000_000)).unwrap();
        let err = r.detect(opp("r1", "alice", 1_000_000)).unwrap_err();
        assert!(format!("{err}").contains("already detected"));
    }

    #[test]
    fn must_start_upcoming() {
        let mut o = opp("r1", "alice", 1_000_000);
        o.stage = RenewalStage::InNegotiation;
        let r = RenewalRegister::new();
        let err = r.detect(o).unwrap_err();
        assert!(format!("{err}").contains("must start Upcoming"));
    }

    #[test]
    fn legal_transitions() {
        use RenewalStage::*;
        assert!(legal_transition(Upcoming, InNegotiation));
        assert!(legal_transition(Upcoming, Churned));
        assert!(legal_transition(Upcoming, Expired));
        assert!(legal_transition(InNegotiation, Renewed));
        assert!(legal_transition(InNegotiation, Churned));
        assert!(legal_transition(InNegotiation, Upcoming));
        // illegal
        assert!(!legal_transition(Upcoming, Renewed));
        assert!(!legal_transition(Renewed, InNegotiation));
        assert!(!legal_transition(Churned, Renewed));
    }

    #[test]
    fn happy_path_upsell() {
        let r = RenewalRegister::new();
        r.detect(opp("r1", "alice", 1_000_000)).unwrap();
        r.engage("r1", "csm-bob", "2025-09-15T00:00:00Z", "outreach started")
            .unwrap();
        r.set_proposed_arr("r1", 1_500_000).unwrap();
        let g = r
            .renewed(
                "r1",
                "csm-bob",
                "2025-12-15T00:00:00Z",
                1_400_000,
                "negotiated mid-tier upsell",
            )
            .unwrap();
        assert_eq!(g.stage, RenewalStage::Renewed);
        assert_eq!(g.settled_arr_micro, Some(1_400_000));
        assert_eq!(g.size_delta, Some(SizeDelta::Upsell));
        assert!(g.stage.is_retained());
    }

    #[test]
    fn flat_renewal() {
        let r = RenewalRegister::new();
        r.detect(opp("r1", "alice", 1_000_000)).unwrap();
        r.engage("r1", "csm-bob", "2025-09-15T00:00:00Z", "n").unwrap();
        let g = r
            .renewed("r1", "csm-bob", "2025-12-15T00:00:00Z", 1_000_000, "flat")
            .unwrap();
        assert_eq!(g.size_delta, Some(SizeDelta::Flat));
    }

    #[test]
    fn downgrade_renewal() {
        let r = RenewalRegister::new();
        r.detect(opp("r1", "alice", 1_000_000)).unwrap();
        r.engage("r1", "csm-bob", "2025-09-15T00:00:00Z", "n").unwrap();
        let g = r
            .renewed("r1", "csm-bob", "2025-12-15T00:00:00Z", 700_000, "contraction")
            .unwrap();
        assert_eq!(g.size_delta, Some(SizeDelta::Downgrade));
    }

    #[test]
    fn churned_path() {
        let r = RenewalRegister::new();
        r.detect(opp("r1", "alice", 1_000_000)).unwrap();
        r.engage("r1", "csm-bob", "2025-09-15T00:00:00Z", "n").unwrap();
        let g = r
            .churned(
                "r1",
                "csm-bob",
                "2025-12-15T00:00:00Z",
                "moved to competitor",
            )
            .unwrap();
        assert_eq!(g.stage, RenewalStage::Churned);
        assert!(g.stage.is_terminal());
        assert!(!g.stage.is_retained());
    }

    #[test]
    fn expired_path() {
        let r = RenewalRegister::new();
        r.detect(opp("r1", "alice", 1_000_000)).unwrap();
        let g = r.expired("r1", "2026-01-01T00:00:00Z").unwrap();
        assert_eq!(g.stage, RenewalStage::Expired);
    }

    #[test]
    fn illegal_transitions_error() {
        let r = RenewalRegister::new();
        r.detect(opp("r1", "alice", 1_000_000)).unwrap();
        let err = r
            .renewed(
                "r1",
                "csm-bob",
                "2025-12-15T00:00:00Z",
                1_000_000,
                "skipped negotiation",
            )
            .unwrap_err();
        assert!(format!("{err}").contains("illegal transition"));
    }

    #[test]
    fn set_proposed_arr_after_terminal_errors() {
        let r = RenewalRegister::new();
        r.detect(opp("r1", "alice", 1_000_000)).unwrap();
        r.expired("r1", "2026-01-01T00:00:00Z").unwrap();
        let err = r.set_proposed_arr("r1", 2_000_000).unwrap_err();
        assert!(format!("{err}").contains("cannot set proposed"));
    }

    #[test]
    fn set_health_works_at_any_stage() {
        let r = RenewalRegister::new();
        r.detect(opp("r1", "alice", 1_000_000)).unwrap();
        r.set_health("r1", HealthSignal::Red).unwrap();
        assert_eq!(r.get("r1").unwrap().health, HealthSignal::Red);
        // Even after closed (allowed for retrospective tagging).
        r.engage("r1", "x", "2025-09-15T00:00:00Z", "n").unwrap();
        r.churned("r1", "x", "2025-12-15T00:00:00Z", "n").unwrap();
        r.set_health("r1", HealthSignal::Yellow).unwrap();
    }

    #[test]
    fn link_contract_set_tag() {
        let r = RenewalRegister::new();
        r.detect(opp("r1", "alice", 1_000_000)).unwrap();
        r.link_contract("r1", "CTR-007").unwrap();
        r.add_tag("r1", "enterprise").unwrap();
        r.add_tag("r1", "enterprise").unwrap();
        let g = r.get("r1").unwrap();
        assert_eq!(g.contract_id.as_deref(), Some("CTR-007"));
        assert_eq!(g.tags, vec!["enterprise"]);
    }

    #[test]
    fn unknown_renewal_errors() {
        let r = RenewalRegister::new();
        let err = r.set_proposed_arr("nope", 1_000).unwrap_err();
        assert!(format!("{err}").contains("unknown renewal"));
    }

    #[test]
    fn for_tenant_customer_filters() {
        let r = RenewalRegister::new();
        r.detect(opp("r1", "alice", 1_000_000)).unwrap();
        let mut other = opp("r2", "bob", 500_000);
        other.tenant_id = "tenant-b".into();
        r.detect(other).unwrap();
        assert_eq!(r.for_tenant("tenant-a").len(), 1);
        assert_eq!(r.for_tenant("tenant-b").len(), 1);
        assert_eq!(r.for_customer("alice").len(), 1);
        assert_eq!(r.for_customer("bob").len(), 1);
    }

    #[test]
    fn by_stage_open_filters() {
        let r = RenewalRegister::new();
        r.detect(opp("r1", "alice", 1_000_000)).unwrap();
        r.detect(opp("r2", "bob", 500_000)).unwrap();
        r.expired("r2", "2026-01-01T00:00:00Z").unwrap();
        assert_eq!(r.by_stage(RenewalStage::Upcoming).len(), 1);
        assert_eq!(r.by_stage(RenewalStage::Expired).len(), 1);
        assert_eq!(r.open().len(), 1);
    }

    #[test]
    fn at_risk_filter() {
        let r = RenewalRegister::new();
        r.detect(opp("r1", "alice", 1_000_000)).unwrap();
        r.detect(opp("r2", "bob", 500_000)).unwrap();
        r.detect(opp("r3", "carol", 750_000)).unwrap();
        r.set_health("r1", HealthSignal::Green).unwrap();
        r.set_health("r2", HealthSignal::Yellow).unwrap();
        r.set_health("r3", HealthSignal::Red).unwrap();
        let at = r.at_risk();
        let ids: Vec<_> = at.iter().map(|r| r.renewal_id.clone()).collect();
        assert!(ids.contains(&"r2".to_string()));
        assert!(ids.contains(&"r3".to_string()));
        assert!(!ids.contains(&"r1".to_string()));
    }

    #[test]
    fn overdue_filter() {
        let r = RenewalRegister::new();
        r.detect(opp("r1", "alice", 1_000_000)).unwrap();
        // current_end_at = 2025-12-31; ask 2026-01-15 → overdue
        assert_eq!(r.overdue("2026-01-15T00:00:00Z").len(), 1);
        r.expired("r1", "2026-01-01T00:00:00Z").unwrap();
        assert_eq!(r.overdue("2026-01-15T00:00:00Z").len(), 0);
    }

    #[test]
    fn total_retained_lost_arr() {
        let r = RenewalRegister::new();
        r.detect(opp("r1", "alice", 1_000_000)).unwrap();
        r.detect(opp("r2", "bob", 500_000)).unwrap();
        r.detect(opp("r3", "carol", 750_000)).unwrap();
        r.engage("r1", "x", "2025-09-15T00:00:00Z", "n").unwrap();
        r.renewed("r1", "x", "2025-12-15T00:00:00Z", 1_200_000, "n").unwrap();
        r.churned("r2", "x", "2025-12-15T00:00:00Z", "n").unwrap();
        r.expired("r3", "2026-01-01T00:00:00Z").unwrap();
        assert_eq!(r.total_retained_arr_micro(), 1_200_000);
        assert_eq!(r.total_lost_arr_micro(), 500_000 + 750_000);
    }

    #[test]
    fn nrr_basis_points_calculation() {
        let r = RenewalRegister::new();
        // 3 closed opportunities:
        // r1: current 1M, settled 1.2M (Renewed)
        // r2: current 500k, churned (settled 0)
        // r3: current 1M, settled 1M (flat)
        // numer = 1.2M + 1M = 2.2M; denom = 2.5M; ratio = 0.88 → 8800 bp
        r.detect(opp("r1", "alice", 1_000_000)).unwrap();
        r.detect(opp("r2", "bob", 500_000)).unwrap();
        r.detect(opp("r3", "carol", 1_000_000)).unwrap();
        r.engage("r1", "x", "2025-09-15T00:00:00Z", "n").unwrap();
        r.engage("r3", "x", "2025-09-15T00:00:00Z", "n").unwrap();
        r.renewed("r1", "x", "2025-12-15T00:00:00Z", 1_200_000, "n").unwrap();
        r.churned("r2", "x", "2025-12-15T00:00:00Z", "n").unwrap();
        r.renewed("r3", "x", "2025-12-15T00:00:00Z", 1_000_000, "n").unwrap();
        assert_eq!(r.nrr_basis_points(), Some(8800));
    }

    #[test]
    fn nrr_basis_points_no_closed_returns_none() {
        let r = RenewalRegister::new();
        r.detect(opp("r1", "alice", 1_000_000)).unwrap();
        assert_eq!(r.nrr_basis_points(), None);
    }

    #[test]
    fn net_retention_basis_points_per_opportunity() {
        let r = RenewalRegister::new();
        r.detect(opp("r1", "alice", 1_000_000)).unwrap();
        r.engage("r1", "x", "2025-09-15T00:00:00Z", "n").unwrap();
        r.renewed("r1", "x", "2025-12-15T00:00:00Z", 1_500_000, "upsell")
            .unwrap();
        let g = r.get("r1").unwrap();
        assert_eq!(g.net_retention_basis_points(), Some(15_000));
    }

    #[test]
    fn stage_helpers() {
        for s in [
            RenewalStage::Renewed,
            RenewalStage::Churned,
            RenewalStage::Expired,
        ] {
            assert!(s.is_terminal());
        }
        assert!(RenewalStage::Renewed.is_retained());
        assert!(!RenewalStage::Churned.is_retained());
        assert!(!RenewalStage::Expired.is_retained());
        assert!(!RenewalStage::Upcoming.is_terminal());
    }

    #[test]
    fn count_tracks() {
        let r = RenewalRegister::new();
        assert_eq!(r.count(), 0);
        r.detect(opp("r1", "alice", 1_000_000)).unwrap();
        assert_eq!(r.count(), 1);
    }

    #[test]
    fn opportunity_serde() {
        let o = opp("r1", "alice", 1_000_000);
        let j = serde_json::to_string(&o).unwrap();
        let back: RenewalOpportunity = serde_json::from_str(&j).unwrap();
        assert_eq!(o, back);
    }

    #[test]
    fn enums_serde() {
        for s in [
            RenewalStage::Upcoming,
            RenewalStage::InNegotiation,
            RenewalStage::Renewed,
            RenewalStage::Churned,
            RenewalStage::Expired,
        ] {
            assert_eq!(
                s,
                serde_json::from_str::<RenewalStage>(&serde_json::to_string(&s).unwrap()).unwrap()
            );
        }
        for d in [SizeDelta::Upsell, SizeDelta::Flat, SizeDelta::Downgrade] {
            assert_eq!(
                d,
                serde_json::from_str::<SizeDelta>(&serde_json::to_string(&d).unwrap()).unwrap()
            );
        }
        for h in [HealthSignal::Green, HealthSignal::Yellow, HealthSignal::Red] {
            assert_eq!(
                h,
                serde_json::from_str::<HealthSignal>(&serde_json::to_string(&h).unwrap()).unwrap()
            );
        }
    }
}
