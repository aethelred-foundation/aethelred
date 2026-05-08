//! Segregation-of-duties (SoD) violation detector and register.
//!
//! Maps to **SOX §404** (financial-reporting controls), **SOC 2 CC6.1**
//! (logical access), **NIST 800-53 AC-5** (separation of duties), and PCI
//! 6.4. The principle is simple: nobody should hold combinations of
//! entitlements that would allow them to commit a fraud or material error
//! single-handedly. A classic example: the same person who creates a
//! vendor record cannot also approve payments to that vendor.
//!
//! ## Two halves
//!
//! - **[`SodRule`]**: a declared conflict between two (or more) entitlements
//!   under a named conflict policy.
//! - **[`SodViolation`]**: a detected instance where a single principal
//!   holds at least one entitlement from each side of a rule.
//!
//! `evaluate(principal, holdings)` is the synchronous decision point —
//! given a list of entitlements held by a principal, return all violated
//! rules. Detected violations are also persisted to the registry for audit.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::RwLock;

// =============================================================================
// ConflictKind
// =============================================================================

/// Type of conflict the rule guards against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictKind {
    /// Financial conflict (create + approve, vendor + payment).
    Financial,
    /// Operational conflict (request + fulfil, change + verify).
    Operational,
    /// Privacy conflict (data access + data deletion / oversight).
    Privacy,
    /// Compliance conflict (control owner + control tester).
    Compliance,
    /// Security conflict (privileged access + log management).
    Security,
}

// =============================================================================
// ViolationStatus
// =============================================================================

/// Lifecycle status of a detected violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViolationStatus {
    /// Detected; needs review.
    Open,
    /// Reviewer accepted with documented compensating control.
    AcceptedWithCompensation,
    /// Subject's access has been adjusted; violation cleared.
    Remediated,
    /// Reviewer determined this was a false positive.
    FalsePositive,
}

impl ViolationStatus {
    /// True if no further action is expected.
    pub fn is_terminal(self) -> bool {
        !matches!(self, Self::Open)
    }
}

// =============================================================================
// SodRule
// =============================================================================

/// Declared SoD conflict policy.
///
/// A principal violates the rule if they hold at least one entitlement
/// from `left` AND at least one entitlement from `right`. Either side may
/// be a single entitlement or a set of equivalents.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SodRule {
    /// Stable rule id (e.g., "SOD-FIN-001").
    pub rule_id: String,
    /// Tenant scope.
    pub tenant_id: String,
    /// Display name.
    pub name: String,
    /// Long-form description / rationale.
    pub description: String,
    /// Kind of conflict.
    pub kind: ConflictKind,
    /// Left side entitlements (any one is sufficient).
    pub left: Vec<String>,
    /// Right side entitlements (any one is sufficient).
    pub right: Vec<String>,
    /// True if rule is currently active.
    pub enabled: bool,
    /// Free-form tags.
    pub tags: Vec<String>,
}

impl SodRule {
    /// Construct a new active rule.
    pub fn new(
        rule_id: impl Into<String>,
        tenant_id: impl Into<String>,
        name: impl Into<String>,
        description: impl Into<String>,
        kind: ConflictKind,
        left: Vec<String>,
        right: Vec<String>,
    ) -> Self {
        Self {
            rule_id: rule_id.into(),
            tenant_id: tenant_id.into(),
            name: name.into(),
            description: description.into(),
            kind,
            left,
            right,
            enabled: true,
            tags: Vec::new(),
        }
    }

    /// True if the rule is well-formed (both sides non-empty).
    pub fn is_well_formed(&self) -> bool {
        !self.left.is_empty() && !self.right.is_empty()
    }

    /// Return the (left_match, right_match) pair if `holdings` triggers the
    /// rule; `None` otherwise. Disabled rules never trigger.
    pub fn check(&self, holdings: &[String]) -> Option<(String, String)> {
        if !self.enabled {
            return None;
        }
        let lh = self.left.iter().find(|e| holdings.iter().any(|h| h == *e))?;
        let rh = self
            .right
            .iter()
            .find(|e| holdings.iter().any(|h| h == *e))?;
        Some((lh.clone(), rh.clone()))
    }
}

// =============================================================================
// SodViolation
// =============================================================================

/// One detected violation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SodViolation {
    /// Unique id within the registry.
    pub violation_id: String,
    /// Tenant scope (mirrors the rule's tenant).
    pub tenant_id: String,
    /// Rule that fired.
    pub rule_id: String,
    /// Principal holding the conflicting entitlements.
    pub principal: String,
    /// Specific left-side entitlement that matched.
    pub left_match: String,
    /// Specific right-side entitlement that matched.
    pub right_match: String,
    /// Status.
    pub status: ViolationStatus,
    /// RFC 3339 — first detected.
    pub detected_at: String,
    /// RFC 3339 — closed (terminal status).
    pub closed_at: Option<String>,
    /// Reviewer who acted.
    pub reviewer: Option<String>,
    /// Free-text justification / compensating control description.
    pub note: Option<String>,
    /// Free-form tags.
    pub tags: Vec<String>,
}

impl SodViolation {
    /// Construct a new `Open` violation.
    pub fn new(
        violation_id: impl Into<String>,
        tenant_id: impl Into<String>,
        rule_id: impl Into<String>,
        principal: impl Into<String>,
        left_match: impl Into<String>,
        right_match: impl Into<String>,
        detected_at: impl Into<String>,
    ) -> Self {
        Self {
            violation_id: violation_id.into(),
            tenant_id: tenant_id.into(),
            rule_id: rule_id.into(),
            principal: principal.into(),
            left_match: left_match.into(),
            right_match: right_match.into(),
            status: ViolationStatus::Open,
            detected_at: detected_at.into(),
            closed_at: None,
            reviewer: None,
            note: None,
            tags: Vec::new(),
        }
    }
}

// =============================================================================
// SegregationOfDutiesRegistry
// =============================================================================

/// Thread-safe SoD policy + violation registry.
#[derive(Debug, Default)]
pub struct SegregationOfDutiesRegistry {
    rules: RwLock<HashMap<String, SodRule>>,
    violations: RwLock<HashMap<String, SodViolation>>,
}

impl SegregationOfDutiesRegistry {
    /// New empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new SoD rule.
    pub fn register_rule(&self, rule: SodRule) -> SandboxResult<()> {
        if !rule.is_well_formed() {
            return Err(SandboxError::Other(format!(
                "rule {} is not well-formed (both sides must be non-empty)",
                rule.rule_id
            )));
        }
        let mut g = self
            .rules
            .write()
            .map_err(|_| SandboxError::Other("sod registry poisoned".into()))?;
        if g.contains_key(&rule.rule_id) {
            return Err(SandboxError::Other(format!(
                "rule already registered: {}",
                rule.rule_id
            )));
        }
        g.insert(rule.rule_id.clone(), rule);
        Ok(())
    }

    /// Enable / disable a rule.
    pub fn set_rule_enabled(&self, rule_id: &str, enabled: bool) -> SandboxResult<()> {
        let mut g = self
            .rules
            .write()
            .map_err(|_| SandboxError::Other("sod registry poisoned".into()))?;
        let r = g
            .get_mut(rule_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown rule {rule_id}")))?;
        r.enabled = enabled;
        Ok(())
    }

    /// Add a tag to a rule (deduplicated).
    pub fn add_rule_tag(&self, rule_id: &str, tag: impl Into<String>) -> SandboxResult<()> {
        let mut g = self
            .rules
            .write()
            .map_err(|_| SandboxError::Other("sod registry poisoned".into()))?;
        let r = g
            .get_mut(rule_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown rule {rule_id}")))?;
        let tag = tag.into();
        if !r.tags.contains(&tag) {
            r.tags.push(tag);
        }
        Ok(())
    }

    /// Look up a rule.
    pub fn get_rule(&self, rule_id: &str) -> Option<SodRule> {
        let g = self.rules.read().ok()?;
        g.get(rule_id).cloned()
    }

    /// All rules.
    pub fn all_rules(&self) -> Vec<SodRule> {
        match self.rules.read() {
            Ok(g) => g.values().cloned().collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Active (enabled) rules.
    pub fn active_rules(&self) -> Vec<SodRule> {
        self.all_rules().into_iter().filter(|r| r.enabled).collect()
    }

    /// Active rules for a tenant.
    pub fn rules_for_tenant(&self, tenant_id: &str) -> Vec<SodRule> {
        self.all_rules()
            .into_iter()
            .filter(|r| r.tenant_id == tenant_id)
            .collect()
    }

    /// Evaluate a principal's holdings against active rules in the
    /// principal's tenant. Returns the set of fired rules with their
    /// (left, right) match. Caller can then call `record_violation()` to
    /// persist. The pure evaluation is exposed so callers can do dry-runs
    /// without polluting the violation registry.
    pub fn evaluate(
        &self,
        tenant_id: &str,
        principal: &str,
        holdings: &[String],
    ) -> Vec<EvaluationHit> {
        let _ = principal; // signature for symmetry / future use
        let mut out = Vec::new();
        let dedup: HashSet<&String> = holdings.iter().collect();
        let holdings_v: Vec<String> = dedup.into_iter().cloned().collect();
        for r in self.rules_for_tenant(tenant_id) {
            if let Some((l, rt)) = r.check(&holdings_v) {
                out.push(EvaluationHit {
                    rule_id: r.rule_id.clone(),
                    left_match: l,
                    right_match: rt,
                });
            }
        }
        out
    }

    /// Record a detected violation.
    pub fn record_violation(&self, v: SodViolation) -> SandboxResult<()> {
        let mut g = self
            .violations
            .write()
            .map_err(|_| SandboxError::Other("sod registry poisoned".into()))?;
        if g.contains_key(&v.violation_id) {
            return Err(SandboxError::Other(format!(
                "violation already registered: {}",
                v.violation_id
            )));
        }
        g.insert(v.violation_id.clone(), v);
        Ok(())
    }

    /// Update violation status. `Open` cannot be re-set once moved off.
    pub fn set_violation_status(
        &self,
        violation_id: &str,
        status: ViolationStatus,
        reviewer: impl Into<String>,
        note: Option<String>,
        at: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .violations
            .write()
            .map_err(|_| SandboxError::Other("sod registry poisoned".into()))?;
        let v = g
            .get_mut(violation_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown violation {violation_id}")))?;
        if matches!(status, ViolationStatus::Open) {
            return Err(SandboxError::Other(format!(
                "cannot reset {violation_id} to Open"
            )));
        }
        if v.status.is_terminal() {
            return Err(SandboxError::Other(format!(
                "violation {violation_id} already terminal: {:?}",
                v.status
            )));
        }
        v.status = status;
        v.reviewer = Some(reviewer.into());
        if let Some(n) = note {
            v.note = Some(n);
        }
        v.closed_at = Some(at.into());
        Ok(())
    }

    /// Add a tag to a violation (deduplicated).
    pub fn add_violation_tag(
        &self,
        violation_id: &str,
        tag: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .violations
            .write()
            .map_err(|_| SandboxError::Other("sod registry poisoned".into()))?;
        let v = g
            .get_mut(violation_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown violation {violation_id}")))?;
        let tag = tag.into();
        if !v.tags.contains(&tag) {
            v.tags.push(tag);
        }
        Ok(())
    }

    /// Look up a violation.
    pub fn get_violation(&self, violation_id: &str) -> Option<SodViolation> {
        let g = self.violations.read().ok()?;
        g.get(violation_id).cloned()
    }

    /// All violations.
    pub fn all_violations(&self) -> Vec<SodViolation> {
        match self.violations.read() {
            Ok(g) => g.values().cloned().collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Open violations.
    pub fn open_violations(&self) -> Vec<SodViolation> {
        self.all_violations()
            .into_iter()
            .filter(|v| matches!(v.status, ViolationStatus::Open))
            .collect()
    }

    /// Violations for a principal.
    pub fn for_principal(&self, principal: &str) -> Vec<SodViolation> {
        self.all_violations()
            .into_iter()
            .filter(|v| v.principal == principal)
            .collect()
    }

    /// Violations for a tenant.
    pub fn for_tenant(&self, tenant_id: &str) -> Vec<SodViolation> {
        self.all_violations()
            .into_iter()
            .filter(|v| v.tenant_id == tenant_id)
            .collect()
    }

    /// Counts.
    pub fn rule_count(&self) -> usize {
        self.rules.read().map(|g| g.len()).unwrap_or(0)
    }

    /// Counts.
    pub fn violation_count(&self) -> usize {
        self.violations.read().map(|g| g.len()).unwrap_or(0)
    }
}

// =============================================================================
// EvaluationHit
// =============================================================================

/// Outcome of one rule firing on a principal's holdings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EvaluationHit {
    /// Rule that fired.
    pub rule_id: String,
    /// Left side entitlement matched.
    pub left_match: String,
    /// Right side entitlement matched.
    pub right_match: String,
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(id: &str, left: Vec<&str>, right: Vec<&str>) -> SodRule {
        SodRule::new(
            id,
            "tenant-a",
            format!("name-{id}"),
            "rationale",
            ConflictKind::Financial,
            left.into_iter().map(String::from).collect(),
            right.into_iter().map(String::from).collect(),
        )
    }

    fn h(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    fn vio(id: &str) -> SodViolation {
        SodViolation::new(
            id,
            "tenant-a",
            "SOD-1",
            "alice",
            "vendor.create",
            "payment.approve",
            "2025-05-01T00:00:00Z",
        )
    }

    #[test]
    fn register_well_formed_rule() {
        let r = SegregationOfDutiesRegistry::new();
        r.register_rule(rule("SOD-1", vec!["a"], vec!["b"])).unwrap();
        assert!(r.get_rule("SOD-1").is_some());
    }

    #[test]
    fn register_malformed_errors() {
        let r = SegregationOfDutiesRegistry::new();
        let err = r
            .register_rule(rule("SOD-1", vec![], vec!["b"]))
            .unwrap_err();
        assert!(format!("{err}").contains("not well-formed"));
        let err = r
            .register_rule(rule("SOD-2", vec!["a"], vec![]))
            .unwrap_err();
        assert!(format!("{err}").contains("not well-formed"));
    }

    #[test]
    fn duplicate_rule_errors() {
        let r = SegregationOfDutiesRegistry::new();
        r.register_rule(rule("SOD-1", vec!["a"], vec!["b"])).unwrap();
        let err = r
            .register_rule(rule("SOD-1", vec!["a"], vec!["c"]))
            .unwrap_err();
        assert!(format!("{err}").contains("already registered"));
    }

    #[test]
    fn check_fires_on_both_sides() {
        let rl = rule("SOD-1", vec!["a"], vec!["b"]);
        let hit = rl.check(&h(&["a", "b"]));
        assert!(hit.is_some());
        assert_eq!(hit.unwrap(), ("a".into(), "b".into()));
    }

    #[test]
    fn check_no_fire_with_only_one_side() {
        let rl = rule("SOD-1", vec!["a"], vec!["b"]);
        assert!(rl.check(&h(&["a"])).is_none());
        assert!(rl.check(&h(&["b"])).is_none());
        assert!(rl.check(&h(&[])).is_none());
    }

    #[test]
    fn check_disabled_does_not_fire() {
        let mut rl = rule("SOD-1", vec!["a"], vec!["b"]);
        rl.enabled = false;
        assert!(rl.check(&h(&["a", "b"])).is_none());
    }

    #[test]
    fn check_picks_first_match_on_each_side() {
        let rl = rule("SOD-1", vec!["a", "x"], vec!["b", "y"]);
        let hit = rl.check(&h(&["x", "y"])).unwrap();
        assert_eq!(hit, ("x".into(), "y".into()));
    }

    #[test]
    fn evaluate_returns_all_fired_rules() {
        let r = SegregationOfDutiesRegistry::new();
        r.register_rule(rule("SOD-1", vec!["a"], vec!["b"])).unwrap();
        r.register_rule(rule("SOD-2", vec!["c"], vec!["d"])).unwrap();
        r.register_rule(rule("SOD-3", vec!["e"], vec!["f"])).unwrap();
        let hits = r.evaluate("tenant-a", "alice", &h(&["a", "b", "c", "d"]));
        let ids: Vec<_> = hits.iter().map(|h| h.rule_id.clone()).collect();
        assert!(ids.contains(&"SOD-1".to_string()));
        assert!(ids.contains(&"SOD-2".to_string()));
        assert!(!ids.contains(&"SOD-3".to_string()));
    }

    #[test]
    fn evaluate_filters_by_tenant() {
        let r = SegregationOfDutiesRegistry::new();
        r.register_rule(rule("SOD-1", vec!["a"], vec!["b"])).unwrap();
        let mut other = rule("SOD-2", vec!["a"], vec!["b"]);
        other.tenant_id = "tenant-b".into();
        r.register_rule(other).unwrap();
        let hits = r.evaluate("tenant-a", "alice", &h(&["a", "b"]));
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule_id, "SOD-1");
    }

    #[test]
    fn evaluate_skips_disabled() {
        let r = SegregationOfDutiesRegistry::new();
        r.register_rule(rule("SOD-1", vec!["a"], vec!["b"])).unwrap();
        r.set_rule_enabled("SOD-1", false).unwrap();
        let hits = r.evaluate("tenant-a", "alice", &h(&["a", "b"]));
        assert!(hits.is_empty());
    }

    #[test]
    fn evaluate_dedupes_holdings() {
        let r = SegregationOfDutiesRegistry::new();
        r.register_rule(rule("SOD-1", vec!["a"], vec!["b"])).unwrap();
        let hits = r.evaluate("tenant-a", "alice", &h(&["a", "a", "b", "b"]));
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn record_violation_unique_id() {
        let r = SegregationOfDutiesRegistry::new();
        r.record_violation(vio("v1")).unwrap();
        let err = r.record_violation(vio("v1")).unwrap_err();
        assert!(format!("{err}").contains("already registered"));
    }

    #[test]
    fn set_violation_status_lifecycle() {
        let r = SegregationOfDutiesRegistry::new();
        r.record_violation(vio("v1")).unwrap();
        r.set_violation_status(
            "v1",
            ViolationStatus::AcceptedWithCompensation,
            "ciso",
            Some("CFO sign-off attached".into()),
            "2025-05-15T00:00:00Z",
        )
        .unwrap();
        let v = r.get_violation("v1").unwrap();
        assert_eq!(v.status, ViolationStatus::AcceptedWithCompensation);
        assert_eq!(v.reviewer.as_deref(), Some("ciso"));
        assert!(v.note.is_some());
        assert_eq!(v.closed_at.as_deref(), Some("2025-05-15T00:00:00Z"));
    }

    #[test]
    fn cannot_reset_to_open() {
        let r = SegregationOfDutiesRegistry::new();
        r.record_violation(vio("v1")).unwrap();
        let err = r
            .set_violation_status(
                "v1",
                ViolationStatus::Open,
                "x",
                None,
                "2025-05-15T00:00:00Z",
            )
            .unwrap_err();
        assert!(format!("{err}").contains("cannot reset"));
    }

    #[test]
    fn cannot_double_terminate() {
        let r = SegregationOfDutiesRegistry::new();
        r.record_violation(vio("v1")).unwrap();
        r.set_violation_status(
            "v1",
            ViolationStatus::Remediated,
            "x",
            None,
            "2025-05-15T00:00:00Z",
        )
        .unwrap();
        let err = r
            .set_violation_status(
                "v1",
                ViolationStatus::FalsePositive,
                "x",
                None,
                "2025-05-16T00:00:00Z",
            )
            .unwrap_err();
        assert!(format!("{err}").contains("already terminal"));
    }

    #[test]
    fn open_violations_filter() {
        let r = SegregationOfDutiesRegistry::new();
        r.record_violation(vio("v1")).unwrap();
        r.record_violation(vio("v2")).unwrap();
        r.set_violation_status(
            "v2",
            ViolationStatus::Remediated,
            "x",
            None,
            "2025-05-15T00:00:00Z",
        )
        .unwrap();
        let open = r.open_violations();
        let ids: Vec<_> = open.iter().map(|v| v.violation_id.clone()).collect();
        assert_eq!(ids, vec!["v1"]);
    }

    #[test]
    fn for_principal_for_tenant_filters() {
        let r = SegregationOfDutiesRegistry::new();
        r.record_violation(vio("v1")).unwrap();
        let mut other = vio("v2");
        other.principal = "bob".into();
        other.tenant_id = "tenant-b".into();
        r.record_violation(other).unwrap();
        assert_eq!(r.for_principal("alice").len(), 1);
        assert_eq!(r.for_principal("bob").len(), 1);
        assert_eq!(r.for_tenant("tenant-a").len(), 1);
        assert_eq!(r.for_tenant("tenant-b").len(), 1);
    }

    #[test]
    fn add_tags_dedupe() {
        let r = SegregationOfDutiesRegistry::new();
        r.register_rule(rule("SOD-1", vec!["a"], vec!["b"])).unwrap();
        r.record_violation(vio("v1")).unwrap();
        r.add_rule_tag("SOD-1", "sox").unwrap();
        r.add_rule_tag("SOD-1", "sox").unwrap();
        r.add_violation_tag("v1", "p0").unwrap();
        r.add_violation_tag("v1", "p0").unwrap();
        assert_eq!(r.get_rule("SOD-1").unwrap().tags, vec!["sox"]);
        assert_eq!(r.get_violation("v1").unwrap().tags, vec!["p0"]);
    }

    #[test]
    fn unknown_rule_violation_errors() {
        let r = SegregationOfDutiesRegistry::new();
        let err = r.set_rule_enabled("nope", false).unwrap_err();
        assert!(format!("{err}").contains("unknown rule"));
        let err = r
            .set_violation_status(
                "nope",
                ViolationStatus::Remediated,
                "x",
                None,
                "2025-05-15T00:00:00Z",
            )
            .unwrap_err();
        assert!(format!("{err}").contains("unknown violation"));
    }

    #[test]
    fn active_and_tenant_filter() {
        let r = SegregationOfDutiesRegistry::new();
        r.register_rule(rule("SOD-1", vec!["a"], vec!["b"])).unwrap();
        r.register_rule(rule("SOD-2", vec!["c"], vec!["d"])).unwrap();
        r.set_rule_enabled("SOD-2", false).unwrap();
        assert_eq!(r.active_rules().len(), 1);
        assert_eq!(r.rules_for_tenant("tenant-a").len(), 2);
    }

    #[test]
    fn counts() {
        let r = SegregationOfDutiesRegistry::new();
        assert_eq!(r.rule_count(), 0);
        assert_eq!(r.violation_count(), 0);
        r.register_rule(rule("SOD-1", vec!["a"], vec!["b"])).unwrap();
        r.record_violation(vio("v1")).unwrap();
        assert_eq!(r.rule_count(), 1);
        assert_eq!(r.violation_count(), 1);
    }

    #[test]
    fn status_helpers() {
        assert!(ViolationStatus::AcceptedWithCompensation.is_terminal());
        assert!(ViolationStatus::Remediated.is_terminal());
        assert!(ViolationStatus::FalsePositive.is_terminal());
        assert!(!ViolationStatus::Open.is_terminal());
    }

    #[test]
    fn rule_serde() {
        let r = rule("SOD-1", vec!["a"], vec!["b"]);
        let j = serde_json::to_string(&r).unwrap();
        let back: SodRule = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn violation_serde() {
        let v = vio("v1");
        let j = serde_json::to_string(&v).unwrap();
        let back: SodViolation = serde_json::from_str(&j).unwrap();
        assert_eq!(v, back);
    }

    #[test]
    fn hit_serde() {
        let h = EvaluationHit {
            rule_id: "x".into(),
            left_match: "a".into(),
            right_match: "b".into(),
        };
        let j = serde_json::to_string(&h).unwrap();
        let back: EvaluationHit = serde_json::from_str(&j).unwrap();
        assert_eq!(h, back);
    }

    #[test]
    fn enums_serde() {
        for k in [
            ConflictKind::Financial,
            ConflictKind::Operational,
            ConflictKind::Privacy,
            ConflictKind::Compliance,
            ConflictKind::Security,
        ] {
            assert_eq!(
                k,
                serde_json::from_str::<ConflictKind>(&serde_json::to_string(&k).unwrap()).unwrap()
            );
        }
        for s in [
            ViolationStatus::Open,
            ViolationStatus::AcceptedWithCompensation,
            ViolationStatus::Remediated,
            ViolationStatus::FalsePositive,
        ] {
            assert_eq!(
                s,
                serde_json::from_str::<ViolationStatus>(&serde_json::to_string(&s).unwrap())
                    .unwrap()
            );
        }
    }
}
