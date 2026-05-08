//! Cost attribution — allocate observed cost back to tenants / teams /
//! projects.
//!
//! Distinct from [`crate::billing_meter`] (which records *usage* events)
//! and [`crate::llm_cost_meter`] (which prices LLM calls), this module is
//! the **allocation layer** that splits the actual cloud / vendor bill
//! across owners. Maps to FinOps Foundation "Allocation" capability and
//! financial-control evidence under SOX §404.
//!
//! ## Allocation methods
//!
//! - **`DirectAttribution`** — entire cost goes to one owner (the
//!   straightforward case where a resource is dedicated).
//! - **`EvenSplit`** — divide equally across all listed owners.
//! - **`UsageProrate`** — divide proportionally by `weight` provided per
//!   owner (e.g., requests-per-tenant, GPU-hours-per-team).
//! - **`Custom`** — caller supplies the per-owner amounts directly. Useful
//!   for hand-corrected allocations.
//!
//! Costs are tracked in **micro-units** (1 USD = 1_000_000 micro-units) to
//! avoid float drift. Allocation results are rounded so that the sum of
//! per-owner amounts always equals the input total.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

// =============================================================================
// AllocationMethod
// =============================================================================

/// Method for splitting cost across owners.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum AllocationMethod {
    /// Whole cost goes to one owner.
    DirectAttribution {
        /// Owner identifier.
        owner: String,
    },
    /// Divide evenly across `owners`.
    EvenSplit {
        /// Owners.
        owners: Vec<String>,
    },
    /// Prorate by per-owner weight (e.g., requests, GPU-seconds).
    UsageProrate {
        /// (owner, weight) pairs. Weights are u64 to avoid float drift.
        weights: Vec<(String, u64)>,
    },
    /// Caller supplies the per-owner amount directly.
    Custom {
        /// (owner, micro-units) pairs.
        amounts: Vec<(String, i64)>,
    },
}

// =============================================================================
// Allocation
// =============================================================================

/// One per-owner allocated amount in micro-units (1 USD = 1_000_000).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Allocation {
    /// Owner id.
    pub owner: String,
    /// Allocated amount in micro-units.
    pub amount_micro: i64,
}

// =============================================================================
// CostEntry
// =============================================================================

/// One cost entry to be allocated.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CostEntry {
    /// Unique id.
    pub entry_id: String,
    /// Tenant scope (top-level tenant; allocation may further fan out).
    pub tenant_id: String,
    /// Cost source (e.g., "aws-ec2", "openai-gpt4", "data-egress").
    pub source: String,
    /// Period label ("2025-04", "Q1-2025").
    pub period: String,
    /// Total cost in micro-units (always non-negative; refunds use Custom).
    pub total_micro: i64,
    /// Currency ISO 4217 ("USD", "EUR").
    pub currency: String,
    /// Allocation method.
    pub method: AllocationMethod,
    /// Per-owner allocations (computed at registration time).
    pub allocations: Vec<Allocation>,
    /// Optional source reference (invoice line, billing meter export id).
    pub reference: Option<String>,
    /// RFC 3339 — when the cost was incurred.
    pub incurred_at: String,
    /// RFC 3339 — when this allocation was recorded.
    pub allocated_at: String,
    /// Free-form tags.
    pub tags: Vec<String>,
}

// =============================================================================
// Allocation algorithm
// =============================================================================

fn allocate(total: i64, method: &AllocationMethod) -> SandboxResult<Vec<Allocation>> {
    match method {
        AllocationMethod::DirectAttribution { owner } => {
            if owner.is_empty() {
                return Err(SandboxError::Other(
                    "DirectAttribution requires non-empty owner".into(),
                ));
            }
            Ok(vec![Allocation {
                owner: owner.clone(),
                amount_micro: total,
            }])
        }
        AllocationMethod::EvenSplit { owners } => {
            if owners.is_empty() {
                return Err(SandboxError::Other(
                    "EvenSplit requires at least one owner".into(),
                ));
            }
            let n = owners.len() as i64;
            let base = total / n;
            let remainder = total - base * n;
            let mut out = Vec::with_capacity(owners.len());
            for (i, o) in owners.iter().enumerate() {
                let extra = if (i as i64) < remainder.abs() {
                    if remainder >= 0 {
                        1
                    } else {
                        -1
                    }
                } else {
                    0
                };
                out.push(Allocation {
                    owner: o.clone(),
                    amount_micro: base + extra,
                });
            }
            Ok(out)
        }
        AllocationMethod::UsageProrate { weights } => {
            if weights.is_empty() {
                return Err(SandboxError::Other(
                    "UsageProrate requires at least one weight".into(),
                ));
            }
            let sum: u128 = weights.iter().map(|(_, w)| *w as u128).sum();
            if sum == 0 {
                return Err(SandboxError::Other(
                    "UsageProrate weights sum to zero".into(),
                ));
            }
            let total_abs = total.unsigned_abs() as u128;
            let sign: i64 = if total < 0 { -1 } else { 1 };
            let mut allocated: i64 = 0;
            let mut out: Vec<Allocation> = Vec::with_capacity(weights.len());
            for (i, (owner, w)) in weights.iter().enumerate() {
                let amount = if i + 1 == weights.len() {
                    // Last gets the remainder so the sum matches exactly.
                    sign * (total_abs as i64 - allocated)
                } else {
                    let portion = (total_abs * (*w as u128)) / sum;
                    let portion_i = portion as i64;
                    allocated += portion_i;
                    sign * portion_i
                };
                out.push(Allocation {
                    owner: owner.clone(),
                    amount_micro: amount,
                });
            }
            Ok(out)
        }
        AllocationMethod::Custom { amounts } => {
            if amounts.is_empty() {
                return Err(SandboxError::Other(
                    "Custom allocation requires at least one entry".into(),
                ));
            }
            let sum: i64 = amounts.iter().map(|(_, a)| *a).sum();
            if sum != total {
                return Err(SandboxError::Other(format!(
                    "Custom amounts sum {sum} does not match total {total}"
                )));
            }
            Ok(amounts
                .iter()
                .map(|(owner, amount)| Allocation {
                    owner: owner.clone(),
                    amount_micro: *amount,
                })
                .collect())
        }
    }
}

// =============================================================================
// CostAttributionRegistry
// =============================================================================

/// Thread-safe cost-attribution registry.
#[derive(Debug, Default)]
pub struct CostAttributionRegistry {
    inner: RwLock<HashMap<String, CostEntry>>,
}

impl CostAttributionRegistry {
    /// New empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Allocate and register a new cost entry.
    pub fn allocate_and_register(
        &self,
        entry_id: impl Into<String>,
        tenant_id: impl Into<String>,
        source: impl Into<String>,
        period: impl Into<String>,
        total_micro: i64,
        currency: impl Into<String>,
        method: AllocationMethod,
        incurred_at: impl Into<String>,
        allocated_at: impl Into<String>,
    ) -> SandboxResult<CostEntry> {
        let entry_id = entry_id.into();
        let allocations = allocate(total_micro, &method)?;
        let entry = CostEntry {
            entry_id: entry_id.clone(),
            tenant_id: tenant_id.into(),
            source: source.into(),
            period: period.into(),
            total_micro,
            currency: currency.into(),
            method,
            allocations,
            reference: None,
            incurred_at: incurred_at.into(),
            allocated_at: allocated_at.into(),
            tags: Vec::new(),
        };
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("cost attribution registry poisoned".into()))?;
        if g.contains_key(&entry_id) {
            return Err(SandboxError::Other(format!(
                "cost entry already registered: {entry_id}"
            )));
        }
        g.insert(entry_id, entry.clone());
        Ok(entry)
    }

    /// Set the source reference.
    pub fn set_reference(
        &self,
        entry_id: &str,
        reference: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("cost attribution registry poisoned".into()))?;
        let e = g
            .get_mut(entry_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown entry {entry_id}")))?;
        e.reference = Some(reference.into());
        Ok(())
    }

    /// Add a tag (deduplicated).
    pub fn add_tag(&self, entry_id: &str, tag: impl Into<String>) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("cost attribution registry poisoned".into()))?;
        let e = g
            .get_mut(entry_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown entry {entry_id}")))?;
        let tag = tag.into();
        if !e.tags.contains(&tag) {
            e.tags.push(tag);
        }
        Ok(())
    }

    /// Look up.
    pub fn get(&self, entry_id: &str) -> Option<CostEntry> {
        let g = self.inner.read().ok()?;
        g.get(entry_id).cloned()
    }

    /// All entries.
    pub fn all(&self) -> Vec<CostEntry> {
        match self.inner.read() {
            Ok(g) => g.values().cloned().collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Entries for a tenant.
    pub fn for_tenant(&self, tenant_id: &str) -> Vec<CostEntry> {
        self.all()
            .into_iter()
            .filter(|e| e.tenant_id == tenant_id)
            .collect()
    }

    /// Entries for a period.
    pub fn for_period(&self, period: &str) -> Vec<CostEntry> {
        self.all()
            .into_iter()
            .filter(|e| e.period == period)
            .collect()
    }

    /// Entries for a source.
    pub fn for_source(&self, source: &str) -> Vec<CostEntry> {
        self.all()
            .into_iter()
            .filter(|e| e.source == source)
            .collect()
    }

    /// Total allocated to an owner across all entries (in micro-units).
    pub fn total_for_owner(&self, owner: &str) -> i64 {
        self.all()
            .iter()
            .flat_map(|e| e.allocations.iter())
            .filter(|a| a.owner == owner)
            .map(|a| a.amount_micro)
            .sum()
    }

    /// Total allocated to an owner for a period.
    pub fn total_for_owner_period(&self, owner: &str, period: &str) -> i64 {
        self.for_period(period)
            .iter()
            .flat_map(|e| e.allocations.iter())
            .filter(|a| a.owner == owner)
            .map(|a| a.amount_micro)
            .sum()
    }

    /// Sum of all costs for a tenant in a period.
    pub fn tenant_period_total(&self, tenant_id: &str, period: &str) -> i64 {
        self.for_period(period)
            .into_iter()
            .filter(|e| e.tenant_id == tenant_id)
            .map(|e| e.total_micro)
            .sum()
    }

    /// Number of registered entries.
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

    fn even(owners: &[&str]) -> AllocationMethod {
        AllocationMethod::EvenSplit {
            owners: owners.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn weighted(pairs: &[(&str, u64)]) -> AllocationMethod {
        AllocationMethod::UsageProrate {
            weights: pairs.iter().map(|(s, w)| (s.to_string(), *w)).collect(),
        }
    }

    fn custom(pairs: &[(&str, i64)]) -> AllocationMethod {
        AllocationMethod::Custom {
            amounts: pairs.iter().map(|(s, a)| (s.to_string(), *a)).collect(),
        }
    }

    fn direct(owner: &str) -> AllocationMethod {
        AllocationMethod::DirectAttribution {
            owner: owner.into(),
        }
    }

    #[test]
    fn direct_attribution_allocates_total_to_owner() {
        let allocs = allocate(1_000_000, &direct("alice")).unwrap();
        assert_eq!(allocs.len(), 1);
        assert_eq!(allocs[0].owner, "alice");
        assert_eq!(allocs[0].amount_micro, 1_000_000);
    }

    #[test]
    fn direct_attribution_empty_owner_errors() {
        let err = allocate(1_000_000, &direct("")).unwrap_err();
        assert!(format!("{err}").contains("non-empty owner"));
    }

    #[test]
    fn even_split_divides_equally() {
        let allocs = allocate(1_000_000, &even(&["a", "b", "c", "d"])).unwrap();
        assert_eq!(allocs.len(), 4);
        for a in &allocs {
            assert_eq!(a.amount_micro, 250_000);
        }
        // Sum equals total.
        assert_eq!(allocs.iter().map(|a| a.amount_micro).sum::<i64>(), 1_000_000);
    }

    #[test]
    fn even_split_handles_remainder() {
        // 100 / 3 = 33 with 1 remainder; first owner gets 34, others 33.
        let allocs = allocate(100, &even(&["a", "b", "c"])).unwrap();
        assert_eq!(allocs.iter().map(|a| a.amount_micro).sum::<i64>(), 100);
        assert_eq!(allocs[0].amount_micro, 34);
        assert_eq!(allocs[1].amount_micro, 33);
        assert_eq!(allocs[2].amount_micro, 33);
    }

    #[test]
    fn even_split_empty_errors() {
        let err = allocate(1_000_000, &even(&[])).unwrap_err();
        assert!(format!("{err}").contains("at least one owner"));
    }

    #[test]
    fn usage_prorate_distributes_by_weight() {
        // 1000 split 70/30
        let allocs = allocate(
            1_000,
            &weighted(&[("a", 70), ("b", 30)]),
        )
        .unwrap();
        assert_eq!(allocs.iter().map(|a| a.amount_micro).sum::<i64>(), 1_000);
        // a gets 700, b gets the rest (300).
        assert_eq!(allocs[0].amount_micro, 700);
        assert_eq!(allocs[1].amount_micro, 300);
    }

    #[test]
    fn usage_prorate_handles_uneven_division() {
        // 100 across (1,1,1) — first two get 33, last gets 34 (the remainder).
        let allocs = allocate(
            100,
            &weighted(&[("a", 1), ("b", 1), ("c", 1)]),
        )
        .unwrap();
        assert_eq!(allocs.iter().map(|a| a.amount_micro).sum::<i64>(), 100);
    }

    #[test]
    fn usage_prorate_zero_weights_errors() {
        let err = allocate(1_000, &weighted(&[("a", 0), ("b", 0)])).unwrap_err();
        assert!(format!("{err}").contains("sum to zero"));
    }

    #[test]
    fn usage_prorate_empty_errors() {
        let err = allocate(1_000, &weighted(&[])).unwrap_err();
        assert!(format!("{err}").contains("at least one weight"));
    }

    #[test]
    fn custom_validates_sum() {
        let ok = allocate(1_000, &custom(&[("a", 600), ("b", 400)])).unwrap();
        assert_eq!(ok.iter().map(|a| a.amount_micro).sum::<i64>(), 1_000);

        let err = allocate(1_000, &custom(&[("a", 500), ("b", 400)])).unwrap_err();
        assert!(format!("{err}").contains("does not match total"));
    }

    #[test]
    fn custom_empty_errors() {
        let err = allocate(1_000, &custom(&[])).unwrap_err();
        assert!(format!("{err}").contains("at least one entry"));
    }

    #[test]
    fn negative_total_for_refunds() {
        // Refund modeled as negative total.
        let allocs = allocate(-1_000, &direct("alice")).unwrap();
        assert_eq!(allocs[0].amount_micro, -1_000);
        let allocs = allocate(-1_000, &custom(&[("a", -600), ("b", -400)])).unwrap();
        assert_eq!(allocs.iter().map(|a| a.amount_micro).sum::<i64>(), -1_000);
    }

    #[test]
    fn register_and_get() {
        let r = CostAttributionRegistry::new();
        let e = r
            .allocate_and_register(
                "e1",
                "tenant-a",
                "aws-ec2",
                "2025-04",
                1_000_000,
                "USD",
                direct("alice"),
                "2025-04-30T00:00:00Z",
                "2025-05-01T00:00:00Z",
            )
            .unwrap();
        assert_eq!(e.allocations.len(), 1);
        assert!(r.get("e1").is_some());
    }

    #[test]
    fn duplicate_register_errors() {
        let r = CostAttributionRegistry::new();
        r.allocate_and_register(
            "e1",
            "tenant-a",
            "aws-ec2",
            "2025-04",
            1_000_000,
            "USD",
            direct("alice"),
            "2025-04-30T00:00:00Z",
            "2025-05-01T00:00:00Z",
        )
        .unwrap();
        let err = r
            .allocate_and_register(
                "e1",
                "tenant-a",
                "aws-ec2",
                "2025-04",
                500_000,
                "USD",
                direct("alice"),
                "2025-04-30T00:00:00Z",
                "2025-05-01T00:00:00Z",
            )
            .unwrap_err();
        assert!(format!("{err}").contains("already registered"));
    }

    #[test]
    fn invalid_method_errors_at_register() {
        let r = CostAttributionRegistry::new();
        let err = r
            .allocate_and_register(
                "e1",
                "tenant-a",
                "x",
                "2025-04",
                1_000,
                "USD",
                even(&[]),
                "2025-04-30T00:00:00Z",
                "2025-05-01T00:00:00Z",
            )
            .unwrap_err();
        assert!(format!("{err}").contains("at least one owner"));
    }

    #[test]
    fn set_reference_set_tag() {
        let r = CostAttributionRegistry::new();
        r.allocate_and_register(
            "e1",
            "tenant-a",
            "x",
            "2025-04",
            1_000,
            "USD",
            direct("alice"),
            "2025-04-30T00:00:00Z",
            "2025-05-01T00:00:00Z",
        )
        .unwrap();
        r.set_reference("e1", "INV-2025-001").unwrap();
        r.add_tag("e1", "engineering").unwrap();
        r.add_tag("e1", "engineering").unwrap();
        r.add_tag("e1", "prod").unwrap();
        let e = r.get("e1").unwrap();
        assert_eq!(e.reference.as_deref(), Some("INV-2025-001"));
        assert_eq!(e.tags, vec!["engineering", "prod"]);
    }

    #[test]
    fn unknown_entry_errors() {
        let r = CostAttributionRegistry::new();
        let err = r.set_reference("nope", "x").unwrap_err();
        assert!(format!("{err}").contains("unknown entry"));
    }

    #[test]
    fn for_tenant_for_period_for_source_filters() {
        let r = CostAttributionRegistry::new();
        r.allocate_and_register(
            "e1",
            "tenant-a",
            "aws-ec2",
            "2025-04",
            1_000,
            "USD",
            direct("alice"),
            "2025-04-30T00:00:00Z",
            "2025-05-01T00:00:00Z",
        )
        .unwrap();
        r.allocate_and_register(
            "e2",
            "tenant-b",
            "openai",
            "2025-04",
            500,
            "USD",
            direct("bob"),
            "2025-04-30T00:00:00Z",
            "2025-05-01T00:00:00Z",
        )
        .unwrap();
        r.allocate_and_register(
            "e3",
            "tenant-a",
            "aws-ec2",
            "2025-05",
            2_000,
            "USD",
            direct("alice"),
            "2025-05-30T00:00:00Z",
            "2025-06-01T00:00:00Z",
        )
        .unwrap();
        assert_eq!(r.for_tenant("tenant-a").len(), 2);
        assert_eq!(r.for_tenant("tenant-b").len(), 1);
        assert_eq!(r.for_period("2025-04").len(), 2);
        assert_eq!(r.for_period("2025-05").len(), 1);
        assert_eq!(r.for_source("aws-ec2").len(), 2);
        assert_eq!(r.for_source("openai").len(), 1);
    }

    #[test]
    fn total_for_owner_aggregates() {
        let r = CostAttributionRegistry::new();
        r.allocate_and_register(
            "e1",
            "tenant-a",
            "x",
            "2025-04",
            1_000,
            "USD",
            direct("alice"),
            "2025-04-30T00:00:00Z",
            "2025-05-01T00:00:00Z",
        )
        .unwrap();
        r.allocate_and_register(
            "e2",
            "tenant-a",
            "y",
            "2025-04",
            500,
            "USD",
            even(&["alice", "bob"]),
            "2025-04-30T00:00:00Z",
            "2025-05-01T00:00:00Z",
        )
        .unwrap();
        // Alice gets 1000 from e1 + 250 from e2.
        assert_eq!(r.total_for_owner("alice"), 1_250);
        assert_eq!(r.total_for_owner("bob"), 250);
        assert_eq!(r.total_for_owner("nobody"), 0);
    }

    #[test]
    fn total_for_owner_period_filters() {
        let r = CostAttributionRegistry::new();
        r.allocate_and_register(
            "e1",
            "tenant-a",
            "x",
            "2025-04",
            1_000,
            "USD",
            direct("alice"),
            "2025-04-30T00:00:00Z",
            "2025-05-01T00:00:00Z",
        )
        .unwrap();
        r.allocate_and_register(
            "e2",
            "tenant-a",
            "x",
            "2025-05",
            500,
            "USD",
            direct("alice"),
            "2025-05-30T00:00:00Z",
            "2025-06-01T00:00:00Z",
        )
        .unwrap();
        assert_eq!(r.total_for_owner_period("alice", "2025-04"), 1_000);
        assert_eq!(r.total_for_owner_period("alice", "2025-05"), 500);
    }

    #[test]
    fn tenant_period_total() {
        let r = CostAttributionRegistry::new();
        r.allocate_and_register(
            "e1",
            "tenant-a",
            "x",
            "2025-04",
            1_000,
            "USD",
            direct("alice"),
            "2025-04-30T00:00:00Z",
            "2025-05-01T00:00:00Z",
        )
        .unwrap();
        r.allocate_and_register(
            "e2",
            "tenant-a",
            "y",
            "2025-04",
            500,
            "USD",
            direct("alice"),
            "2025-04-30T00:00:00Z",
            "2025-05-01T00:00:00Z",
        )
        .unwrap();
        assert_eq!(r.tenant_period_total("tenant-a", "2025-04"), 1_500);
    }

    #[test]
    fn count_tracks() {
        let r = CostAttributionRegistry::new();
        assert_eq!(r.count(), 0);
        r.allocate_and_register(
            "e1",
            "tenant-a",
            "x",
            "2025-04",
            1_000,
            "USD",
            direct("alice"),
            "2025-04-30T00:00:00Z",
            "2025-05-01T00:00:00Z",
        )
        .unwrap();
        assert_eq!(r.count(), 1);
    }

    #[test]
    fn entry_serde() {
        let r = CostAttributionRegistry::new();
        let e = r
            .allocate_and_register(
                "e1",
                "tenant-a",
                "aws-ec2",
                "2025-04",
                1_000_000,
                "USD",
                direct("alice"),
                "2025-04-30T00:00:00Z",
                "2025-05-01T00:00:00Z",
            )
            .unwrap();
        let j = serde_json::to_string(&e).unwrap();
        let back: CostEntry = serde_json::from_str(&j).unwrap();
        assert_eq!(e, back);
    }

    #[test]
    fn allocation_method_serde() {
        for m in [
            direct("alice"),
            even(&["a", "b"]),
            weighted(&[("a", 1), ("b", 2)]),
            custom(&[("a", 100), ("b", 200)]),
        ] {
            let j = serde_json::to_string(&m).unwrap();
            let back: AllocationMethod = serde_json::from_str(&j).unwrap();
            assert_eq!(m, back);
        }
    }
}
