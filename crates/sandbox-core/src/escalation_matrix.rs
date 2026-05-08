//! Escalation matrix — structured escalation routing for incidents.
//!
//! Distinct from [`crate::on_call_schedule`] (who is on-call by clock) and
//! [`crate::alert_router`] (per-channel routing rules), this module is the
//! **per-incident escalation tree**: when severity X happens to service Y,
//! who gets paged first, who gets escalated to after N minutes without
//! ack, and at what tier does the executive bridge open?
//!
//! Maps to ITIL incident-management escalation, NIST 800-53 IR-6
//! (incident reporting), and SOC2 CC7.4. The matrix is keyed by
//! `(severity, service_id)`, returns an ordered list of escalation
//! steps, and exposes `next_step(now, last_ack_at)` so an alert pipeline
//! can poll for the next escalation deterministically.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

// =============================================================================
// Severity
// =============================================================================

/// Incident severity. Free-form labels keep this composable with existing
/// severity vocabularies; the registry sorts by this string verbatim.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Severity(pub String);

impl Severity {
    /// Construct from any string (`sev1`, `p0`, `critical`, ...).
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
}

// =============================================================================
// EscalationTier
// =============================================================================

/// Tier of escalation reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscalationTier {
    /// Primary on-call.
    Primary,
    /// Secondary on-call.
    Secondary,
    /// Engineering manager.
    Manager,
    /// Director / VP.
    Director,
    /// Executive bridge.
    Executive,
}

impl EscalationTier {
    /// Numeric ordering for sort.
    pub fn order(self) -> u8 {
        match self {
            Self::Primary => 1,
            Self::Secondary => 2,
            Self::Manager => 3,
            Self::Director => 4,
            Self::Executive => 5,
        }
    }
}

// =============================================================================
// EscalationStep
// =============================================================================

/// One step in the escalation chain.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EscalationStep {
    /// Tier.
    pub tier: EscalationTier,
    /// Target — could be a user_id, schedule_id, or paging-target spec.
    pub target: String,
    /// Channel ("page", "phone", "slack", "email", "exec_bridge").
    pub channel: String,
    /// Seconds without ack before escalating to the *next* step.
    pub timeout_secs: u64,
    /// Optional free-text note.
    pub note: Option<String>,
}

// =============================================================================
// EscalationPolicy
// =============================================================================

/// Per-(severity, service) escalation policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EscalationPolicy {
    /// Tenant scope.
    pub tenant_id: String,
    /// Incident severity that triggers this policy.
    pub severity: Severity,
    /// Service id this policy applies to ("" = tenant-wide default).
    pub service_id: String,
    /// Display name.
    pub name: String,
    /// Steps in escalation order — must be sorted by tier.order ascending.
    pub steps: Vec<EscalationStep>,
    /// Free-form tags.
    pub tags: Vec<String>,
}

impl EscalationPolicy {
    /// Construct an empty policy.
    pub fn new(
        tenant_id: impl Into<String>,
        severity: Severity,
        service_id: impl Into<String>,
        name: impl Into<String>,
    ) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            severity,
            service_id: service_id.into(),
            name: name.into(),
            steps: Vec::new(),
            tags: Vec::new(),
        }
    }

    /// Composite key.
    pub fn key(&self) -> (String, String, String) {
        (
            self.tenant_id.clone(),
            self.severity.0.clone(),
            self.service_id.clone(),
        )
    }
}

// =============================================================================
// NextStep
// =============================================================================

/// Outcome of asking "what is the next escalation step?"
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NextStep {
    /// True if a step is required now.
    pub required: bool,
    /// Index into the policy's `steps` Vec.
    pub step_index: Option<usize>,
    /// The step itself, if any.
    pub step: Option<EscalationStep>,
    /// Free-text reason / status.
    pub reason: String,
}

// =============================================================================
// EscalationMatrix
// =============================================================================

/// Thread-safe registry of escalation policies.
#[derive(Debug, Default)]
pub struct EscalationMatrix {
    inner: RwLock<HashMap<(String, String, String), EscalationPolicy>>,
}

impl EscalationMatrix {
    /// New empty matrix.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new policy.
    pub fn register(&self, policy: EscalationPolicy) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("escalation matrix poisoned".into()))?;
        let key = policy.key();
        if g.contains_key(&key) {
            return Err(SandboxError::Other(format!(
                "escalation policy already registered: {}/{}/{}",
                key.0, key.1, key.2
            )));
        }
        g.insert(key, policy);
        Ok(())
    }

    /// Append a step to a policy. The step's tier must be strictly greater
    /// than the previous step's tier (or first step).
    pub fn add_step(
        &self,
        tenant_id: &str,
        severity: &Severity,
        service_id: &str,
        step: EscalationStep,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("escalation matrix poisoned".into()))?;
        let key = (
            tenant_id.to_string(),
            severity.0.clone(),
            service_id.to_string(),
        );
        let p = g
            .get_mut(&key)
            .ok_or_else(|| SandboxError::Other(format!("unknown policy {}/{}/{}", key.0, key.1, key.2)))?;
        if let Some(last) = p.steps.last() {
            if step.tier.order() <= last.tier.order() {
                return Err(SandboxError::Other(format!(
                    "step tier {:?} not greater than previous {:?}",
                    step.tier, last.tier
                )));
            }
        }
        p.steps.push(step);
        Ok(())
    }

    /// Add a tag (deduplicated).
    pub fn add_tag(
        &self,
        tenant_id: &str,
        severity: &Severity,
        service_id: &str,
        tag: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("escalation matrix poisoned".into()))?;
        let key = (
            tenant_id.to_string(),
            severity.0.clone(),
            service_id.to_string(),
        );
        let p = g
            .get_mut(&key)
            .ok_or_else(|| SandboxError::Other(format!("unknown policy {}/{}/{}", key.0, key.1, key.2)))?;
        let tag = tag.into();
        if !p.tags.contains(&tag) {
            p.tags.push(tag);
        }
        Ok(())
    }

    /// Look up a specific policy.
    pub fn get(
        &self,
        tenant_id: &str,
        severity: &Severity,
        service_id: &str,
    ) -> Option<EscalationPolicy> {
        let g = self.inner.read().ok()?;
        g.get(&(
            tenant_id.to_string(),
            severity.0.clone(),
            service_id.to_string(),
        ))
        .cloned()
    }

    /// Resolve a policy: prefer service-specific, fall back to tenant-wide
    /// (`service_id == ""`).
    pub fn resolve(
        &self,
        tenant_id: &str,
        severity: &Severity,
        service_id: &str,
    ) -> Option<EscalationPolicy> {
        if let Some(p) = self.get(tenant_id, severity, service_id) {
            return Some(p);
        }
        self.get(tenant_id, severity, "")
    }

    /// Compute the next escalation step. `incident_started` is the RFC 3339
    /// timestamp when the incident was first declared. `last_ack_at` is
    /// the most recent ack from any responder (or `None` if not acked).
    /// `now` is the current time.
    ///
    /// Returns the step that should fire next:
    ///
    /// - If `last_ack_at` is set, no further escalation is required.
    /// - Otherwise, the index = number of timeouts elapsed since
    ///   `incident_started`. Each step's `timeout_secs` field controls the
    ///   delay until escalation to the *next* tier.
    pub fn next_step(
        &self,
        tenant_id: &str,
        severity: &Severity,
        service_id: &str,
        incident_started: &str,
        last_ack_at: Option<&str>,
        now: &str,
    ) -> NextStep {
        let policy = match self.resolve(tenant_id, severity, service_id) {
            Some(p) => p,
            None => {
                return NextStep {
                    required: false,
                    step_index: None,
                    step: None,
                    reason: format!(
                        "no policy for {tenant_id}/{}/{service_id}",
                        severity.0
                    ),
                }
            }
        };
        if policy.steps.is_empty() {
            return NextStep {
                required: false,
                step_index: None,
                step: None,
                reason: "policy has no steps".into(),
            };
        }
        if last_ack_at.is_some() {
            return NextStep {
                required: false,
                step_index: None,
                step: None,
                reason: "incident is acked".into(),
            };
        }
        let elapsed = match elapsed_seconds(incident_started, now) {
            Some(e) if e >= 0 => e as u64,
            _ => 0,
        };
        // Determine which step we should be on. We sum step timeouts: the
        // 0-th step fires immediately at activation; the 1-th fires after
        // step[0].timeout_secs without ack; the 2-th fires after
        // step[0]+step[1] without ack; etc.
        let mut acc: u64 = 0;
        let mut idx = 0usize;
        for (i, s) in policy.steps.iter().enumerate() {
            if elapsed < acc {
                idx = i.saturating_sub(1);
                break;
            }
            idx = i;
            // The step itself fires at `acc`; the *next* fires at acc + s.timeout_secs.
            acc = acc.saturating_add(s.timeout_secs);
        }
        // Cap at last step.
        if idx >= policy.steps.len() {
            idx = policy.steps.len() - 1;
        }
        let step = policy.steps[idx].clone();
        NextStep {
            required: true,
            step_index: Some(idx),
            step: Some(step),
            reason: format!(
                "elapsed {elapsed}s since incident; on tier index {idx}"
            ),
        }
    }

    /// All policies.
    pub fn all(&self) -> Vec<EscalationPolicy> {
        match self.inner.read() {
            Ok(g) => g.values().cloned().collect(),
            Err(_) => Vec::new(),
        }
    }

    /// All policies for a tenant.
    pub fn for_tenant(&self, tenant_id: &str) -> Vec<EscalationPolicy> {
        self.all()
            .into_iter()
            .filter(|p| p.tenant_id == tenant_id)
            .collect()
    }

    /// Number of registered policies.
    pub fn count(&self) -> usize {
        self.inner.read().map(|g| g.len()).unwrap_or(0)
    }
}

fn elapsed_seconds(earlier: &str, later: &str) -> Option<i64> {
    use time::format_description::well_known::Rfc3339;
    let a = time::OffsetDateTime::parse(earlier, &Rfc3339).ok()?;
    let b = time::OffsetDateTime::parse(later, &Rfc3339).ok()?;
    Some((b - a).whole_seconds())
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn sev(s: &str) -> Severity {
        Severity::new(s)
    }

    fn step(tier: EscalationTier, target: &str, timeout: u64) -> EscalationStep {
        EscalationStep {
            tier,
            target: target.into(),
            channel: "page".into(),
            timeout_secs: timeout,
            note: None,
        }
    }

    fn policy() -> EscalationPolicy {
        EscalationPolicy::new("tenant-a", sev("sev1"), "billing", "billing sev1")
    }

    #[test]
    fn register_and_get() {
        let m = EscalationMatrix::new();
        m.register(policy()).unwrap();
        assert!(m.get("tenant-a", &sev("sev1"), "billing").is_some());
    }

    #[test]
    fn duplicate_register_errors() {
        let m = EscalationMatrix::new();
        m.register(policy()).unwrap();
        let err = m.register(policy()).unwrap_err();
        assert!(format!("{err}").contains("already registered"));
    }

    #[test]
    fn add_step_enforces_ascending_tier() {
        let m = EscalationMatrix::new();
        m.register(policy()).unwrap();
        m.add_step(
            "tenant-a",
            &sev("sev1"),
            "billing",
            step(EscalationTier::Primary, "schedule:sre", 300),
        )
        .unwrap();
        m.add_step(
            "tenant-a",
            &sev("sev1"),
            "billing",
            step(EscalationTier::Secondary, "schedule:sre-secondary", 600),
        )
        .unwrap();
        let err = m
            .add_step(
                "tenant-a",
                &sev("sev1"),
                "billing",
                step(EscalationTier::Primary, "schedule:sre", 300),
            )
            .unwrap_err();
        assert!(format!("{err}").contains("not greater than"));
    }

    #[test]
    fn add_step_unknown_policy_errors() {
        let m = EscalationMatrix::new();
        let err = m
            .add_step(
                "tenant-a",
                &sev("sev1"),
                "billing",
                step(EscalationTier::Primary, "x", 60),
            )
            .unwrap_err();
        assert!(format!("{err}").contains("unknown policy"));
    }

    #[test]
    fn add_tag_dedupes() {
        let m = EscalationMatrix::new();
        m.register(policy()).unwrap();
        m.add_tag("tenant-a", &sev("sev1"), "billing", "p0").unwrap();
        m.add_tag("tenant-a", &sev("sev1"), "billing", "p0").unwrap();
        m.add_tag("tenant-a", &sev("sev1"), "billing", "regulated")
            .unwrap();
        assert_eq!(
            m.get("tenant-a", &sev("sev1"), "billing").unwrap().tags,
            vec!["p0", "regulated"]
        );
    }

    #[test]
    fn resolve_falls_back_to_tenant_wide() {
        let m = EscalationMatrix::new();
        // Tenant-wide default (service_id = "")
        let mut def = EscalationPolicy::new("tenant-a", sev("sev2"), "", "default sev2");
        def.steps.push(step(EscalationTier::Primary, "default", 300));
        m.register(def).unwrap();
        let r = m.resolve("tenant-a", &sev("sev2"), "any-service");
        assert!(r.is_some());
        assert_eq!(r.unwrap().service_id, "");
    }

    #[test]
    fn resolve_prefers_specific_over_default() {
        let m = EscalationMatrix::new();
        let mut def = EscalationPolicy::new("tenant-a", sev("sev2"), "", "default");
        def.steps
            .push(step(EscalationTier::Primary, "default-target", 300));
        let mut svc = EscalationPolicy::new("tenant-a", sev("sev2"), "billing", "billing");
        svc.steps
            .push(step(EscalationTier::Primary, "billing-target", 300));
        m.register(def).unwrap();
        m.register(svc).unwrap();
        let r = m.resolve("tenant-a", &sev("sev2"), "billing").unwrap();
        assert_eq!(r.steps[0].target, "billing-target");
    }

    #[test]
    fn next_step_no_policy_not_required() {
        let m = EscalationMatrix::new();
        let r = m.next_step(
            "tenant-a",
            &sev("sev1"),
            "billing",
            "2025-05-08T00:00:00Z",
            None,
            "2025-05-08T00:01:00Z",
        );
        assert!(!r.required);
        assert!(r.reason.contains("no policy"));
    }

    #[test]
    fn next_step_acked_not_required() {
        let m = EscalationMatrix::new();
        m.register(policy()).unwrap();
        m.add_step(
            "tenant-a",
            &sev("sev1"),
            "billing",
            step(EscalationTier::Primary, "x", 300),
        )
        .unwrap();
        let r = m.next_step(
            "tenant-a",
            &sev("sev1"),
            "billing",
            "2025-05-08T00:00:00Z",
            Some("2025-05-08T00:00:30Z"),
            "2025-05-08T00:10:00Z",
        );
        assert!(!r.required);
        assert!(r.reason.contains("acked"));
    }

    #[test]
    fn next_step_t0_returns_first() {
        let m = EscalationMatrix::new();
        m.register(policy()).unwrap();
        m.add_step(
            "tenant-a",
            &sev("sev1"),
            "billing",
            step(EscalationTier::Primary, "primary", 300),
        )
        .unwrap();
        m.add_step(
            "tenant-a",
            &sev("sev1"),
            "billing",
            step(EscalationTier::Secondary, "secondary", 600),
        )
        .unwrap();
        let r = m.next_step(
            "tenant-a",
            &sev("sev1"),
            "billing",
            "2025-05-08T00:00:00Z",
            None,
            "2025-05-08T00:00:00Z",
        );
        assert!(r.required);
        assert_eq!(r.step_index, Some(0));
        assert_eq!(r.step.unwrap().target, "primary");
    }

    #[test]
    fn next_step_after_first_timeout_returns_second() {
        let m = EscalationMatrix::new();
        m.register(policy()).unwrap();
        m.add_step(
            "tenant-a",
            &sev("sev1"),
            "billing",
            step(EscalationTier::Primary, "primary", 300),
        )
        .unwrap();
        m.add_step(
            "tenant-a",
            &sev("sev1"),
            "billing",
            step(EscalationTier::Secondary, "secondary", 600),
        )
        .unwrap();
        // 6 minutes after start (>5 min primary timeout) → step 1 (secondary)
        let r = m.next_step(
            "tenant-a",
            &sev("sev1"),
            "billing",
            "2025-05-08T00:00:00Z",
            None,
            "2025-05-08T00:06:00Z",
        );
        assert!(r.required);
        assert_eq!(r.step_index, Some(1));
        assert_eq!(r.step.unwrap().target, "secondary");
    }

    #[test]
    fn next_step_caps_at_last_step() {
        let m = EscalationMatrix::new();
        m.register(policy()).unwrap();
        m.add_step(
            "tenant-a",
            &sev("sev1"),
            "billing",
            step(EscalationTier::Primary, "primary", 60),
        )
        .unwrap();
        m.add_step(
            "tenant-a",
            &sev("sev1"),
            "billing",
            step(EscalationTier::Executive, "exec", 60),
        )
        .unwrap();
        // 1 hour after start, well past all timeouts
        let r = m.next_step(
            "tenant-a",
            &sev("sev1"),
            "billing",
            "2025-05-08T00:00:00Z",
            None,
            "2025-05-08T01:00:00Z",
        );
        assert!(r.required);
        assert_eq!(r.step_index, Some(1));
        assert_eq!(r.step.unwrap().target, "exec");
    }

    #[test]
    fn next_step_empty_policy_not_required() {
        let m = EscalationMatrix::new();
        m.register(policy()).unwrap();
        let r = m.next_step(
            "tenant-a",
            &sev("sev1"),
            "billing",
            "2025-05-08T00:00:00Z",
            None,
            "2025-05-08T00:01:00Z",
        );
        assert!(!r.required);
        assert!(r.reason.contains("no steps"));
    }

    #[test]
    fn for_tenant_filters() {
        let m = EscalationMatrix::new();
        m.register(policy()).unwrap();
        let other = EscalationPolicy::new("tenant-b", sev("sev1"), "billing", "x");
        m.register(other).unwrap();
        assert_eq!(m.for_tenant("tenant-a").len(), 1);
        assert_eq!(m.for_tenant("tenant-b").len(), 1);
    }

    #[test]
    fn count_tracks() {
        let m = EscalationMatrix::new();
        assert_eq!(m.count(), 0);
        m.register(policy()).unwrap();
        assert_eq!(m.count(), 1);
    }

    #[test]
    fn tier_order_is_total_ordered() {
        assert!(EscalationTier::Primary.order() < EscalationTier::Secondary.order());
        assert!(EscalationTier::Secondary.order() < EscalationTier::Manager.order());
        assert!(EscalationTier::Manager.order() < EscalationTier::Director.order());
        assert!(EscalationTier::Director.order() < EscalationTier::Executive.order());
    }

    #[test]
    fn policy_serde() {
        let p = policy();
        let j = serde_json::to_string(&p).unwrap();
        let back: EscalationPolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn step_serde() {
        let s = step(EscalationTier::Primary, "x", 300);
        let j = serde_json::to_string(&s).unwrap();
        let back: EscalationStep = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn enums_serde() {
        for t in [
            EscalationTier::Primary,
            EscalationTier::Secondary,
            EscalationTier::Manager,
            EscalationTier::Director,
            EscalationTier::Executive,
        ] {
            assert_eq!(
                t,
                serde_json::from_str::<EscalationTier>(&serde_json::to_string(&t).unwrap())
                    .unwrap()
            );
        }
        let s = sev("sev1");
        assert_eq!(
            s,
            serde_json::from_str::<Severity>(&serde_json::to_string(&s).unwrap()).unwrap()
        );
    }

    #[test]
    fn next_step_serde() {
        let m = EscalationMatrix::new();
        m.register(policy()).unwrap();
        m.add_step(
            "tenant-a",
            &sev("sev1"),
            "billing",
            step(EscalationTier::Primary, "x", 300),
        )
        .unwrap();
        let n = m.next_step(
            "tenant-a",
            &sev("sev1"),
            "billing",
            "2025-05-08T00:00:00Z",
            None,
            "2025-05-08T00:00:00Z",
        );
        let j = serde_json::to_string(&n).unwrap();
        let back: NextStep = serde_json::from_str(&j).unwrap();
        assert_eq!(n, back);
    }
}
