//! Chaos engineering — deterministic fault injection.
//!
//! Production-grade systems must work even when components fail. This module
//! provides a *contract-based* fault injector: tests register failure modes
//! they want to drill (signer death, storage corruption, network partition),
//! then exercise the system. Every injected fault produces a typed event the
//! caller can inspect.
//!
//! ## Design properties
//!
//! - **Deterministic.** All probabilistic choices use a seeded LCG so the
//!   same seed reproduces the same failure pattern. Required for incident
//!   replay.
//! - **Scoped.** Faults are tagged by [`FaultCategory`] so a chaos plan can
//!   enable e.g. signer faults without touching storage faults.
//! - **Observable.** Every triggered fault produces a [`InjectedFault`]
//!   record stored in the harness for later assertion.
//!
//! ## Typical usage
//!
//! ```ignore
//! let harness = ChaosHarness::with_seed(1234);
//! harness.add_rule(FaultRule {
//!     category: FaultCategory::Signer,
//!     probability: 0.1,                 // 10% of attempts fail
//!     until_attempt: Some(50),          // disabled after 50 attempts
//! });
//! for _ in 0..100 {
//!     match harness.maybe_inject(FaultCategory::Signer) {
//!         FaultDecision::Inject(reason) => /* simulate signer crash */,
//!         FaultDecision::Continue => /* normal path */,
//!     }
//! }
//! let events = harness.events();
//! assert!(events.iter().any(|e| e.category == FaultCategory::Signer));
//! ```

use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use time::OffsetDateTime;

// =============================================================================
// FaultCategory
// =============================================================================

/// Categories of failures we can inject.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FaultCategory {
    /// The seal-signing path (HSM unavailable, signature corruption).
    Signer,
    /// Storage layer (write failures, snapshot corruption).
    Storage,
    /// Network (timeouts, connection drops).
    Network,
    /// TEE attestation (verifier failure, expired certs).
    Tee,
    /// zkML proof verifier (verifier crash).
    Zkml,
    /// External anchor service (chain-level rejection).
    Anchor,
    /// Connector / data-source.
    Connector,
    /// Custom — see [`FaultRule::tag`].
    Custom,
}

// =============================================================================
// FaultRule
// =============================================================================

/// One injection rule.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FaultRule {
    /// Category to match.
    pub category: FaultCategory,
    /// Probability `[0.0, 1.0]` of triggering on each `maybe_inject`.
    pub probability: f64,
    /// Optional cap on number of attempts before the rule auto-disables.
    pub until_attempt: Option<u64>,
    /// Optional human label stored on injected events.
    pub tag: Option<String>,
    /// Optional reason text recorded on the event.
    pub reason: Option<String>,
}

impl FaultRule {
    /// New rule with category and probability; no cap, no tag.
    pub fn new(category: FaultCategory, probability: f64) -> Self {
        Self {
            category,
            probability,
            until_attempt: None,
            tag: None,
            reason: None,
        }
    }

    /// Builder: tag.
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tag = Some(tag.into());
        self
    }

    /// Builder: reason.
    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }

    /// Builder: cap.
    pub fn with_until_attempt(mut self, n: u64) -> Self {
        self.until_attempt = Some(n);
        self
    }
}

// =============================================================================
// FaultDecision
// =============================================================================

/// Result of consulting the harness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FaultDecision {
    /// No fault — caller proceeds normally.
    Continue,
    /// Fault — caller should simulate failure of the supplied kind.
    Inject(String),
}

// =============================================================================
// InjectedFault — observation record
// =============================================================================

/// Record produced by [`ChaosHarness::maybe_inject`] when a fault triggers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InjectedFault {
    /// Sequence number (1-indexed).
    pub sequence: u64,
    /// RFC 3339 timestamp.
    pub at: String,
    /// Category triggered.
    pub category: FaultCategory,
    /// Tag from the rule, if any.
    pub tag: Option<String>,
    /// Reason from the rule.
    pub reason: Option<String>,
    /// Attempt counter at the time of injection.
    pub attempt: u64,
}

// =============================================================================
// ChaosHarness
// =============================================================================

#[derive(Debug)]
struct HarnessState {
    rules: Vec<FaultRule>,
    seed: u64,
    rng_state: u64,
    events: Vec<InjectedFault>,
    // Per-category attempt counters.
    attempts: std::collections::HashMap<FaultCategory, u64>,
    enabled: bool,
}

/// Deterministic fault-injection harness.
#[derive(Debug)]
pub struct ChaosHarness {
    inner: Mutex<HarnessState>,
}

impl Default for ChaosHarness {
    fn default() -> Self {
        Self::with_seed(0xDEADBEEFCAFEBABE)
    }
}

impl ChaosHarness {
    /// New harness with the given seed (deterministic).
    pub fn with_seed(seed: u64) -> Self {
        Self {
            inner: Mutex::new(HarnessState {
                rules: Vec::new(),
                seed,
                rng_state: seed,
                events: Vec::new(),
                attempts: Default::default(),
                enabled: true,
            }),
        }
    }

    /// Register a rule. Multiple rules per category are additive: each
    /// `maybe_inject` consults *all* rules for that category and triggers if
    /// *any* fires.
    pub fn add_rule(&self, rule: FaultRule) {
        if let Ok(mut g) = self.inner.lock() {
            g.rules.push(rule);
        }
    }

    /// Disable injection (does not clear rules).
    pub fn disable(&self) {
        if let Ok(mut g) = self.inner.lock() {
            g.enabled = false;
        }
    }

    /// Re-enable injection.
    pub fn enable(&self) {
        if let Ok(mut g) = self.inner.lock() {
            g.enabled = true;
        }
    }

    /// `true` if injection is currently enabled.
    pub fn enabled(&self) -> bool {
        self.inner.lock().map(|g| g.enabled).unwrap_or(false)
    }

    /// Consult all rules for `category` and return a decision.
    pub fn maybe_inject(&self, category: FaultCategory) -> FaultDecision {
        let mut g = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return FaultDecision::Continue,
        };
        if !g.enabled {
            return FaultDecision::Continue;
        }
        let attempt = {
            let n = g.attempts.entry(category).or_insert(0);
            *n += 1;
            *n
        };
        // Iterate by index to avoid borrow conflicts with rng.
        let mut decision = FaultDecision::Continue;
        for i in 0..g.rules.len() {
            let rule = g.rules[i].clone();
            if rule.category != category {
                continue;
            }
            if let Some(cap) = rule.until_attempt {
                if attempt > cap {
                    continue;
                }
            }
            // Sample from LCG.
            let r = next_uniform(&mut g.rng_state);
            if r < rule.probability {
                let seq = (g.events.len() as u64) + 1;
                let at = OffsetDateTime::now_utc()
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_default();
                let event = InjectedFault {
                    sequence: seq,
                    at,
                    category,
                    tag: rule.tag.clone(),
                    reason: rule.reason.clone(),
                    attempt,
                };
                g.events.push(event);
                let label = rule
                    .tag
                    .clone()
                    .unwrap_or_else(|| category_label(category).to_string());
                decision = FaultDecision::Inject(label);
                break;
            }
        }
        decision
    }

    /// Snapshot of all injected fault events.
    pub fn events(&self) -> Vec<InjectedFault> {
        self.inner.lock().map(|g| g.events.clone()).unwrap_or_default()
    }

    /// Number of injected faults.
    pub fn event_count(&self) -> usize {
        self.inner.lock().map(|g| g.events.len()).unwrap_or(0)
    }

    /// Filter events by category.
    pub fn events_for(&self, category: FaultCategory) -> Vec<InjectedFault> {
        self.events().into_iter().filter(|e| e.category == category).collect()
    }

    /// Reset to a fresh state — keep rules but clear events and re-seed.
    pub fn reset(&self) {
        if let Ok(mut g) = self.inner.lock() {
            g.events.clear();
            g.attempts.clear();
            g.rng_state = g.seed;
        }
    }

    /// Total `maybe_inject` calls per category.
    pub fn attempts(&self, category: FaultCategory) -> u64 {
        self.inner
            .lock()
            .map(|g| g.attempts.get(&category).copied().unwrap_or(0))
            .unwrap_or(0)
    }

    /// Number of rules registered.
    pub fn rule_count(&self) -> usize {
        self.inner.lock().map(|g| g.rules.len()).unwrap_or(0)
    }
}

fn next_uniform(state: &mut u64) -> f64 {
    // LCG: Numerical Recipes constants.
    *state = state
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    // Take top 53 bits → divide for uniform [0, 1).
    let v = *state >> 11;
    (v as f64) / ((1u64 << 53) as f64)
}

fn category_label(c: FaultCategory) -> &'static str {
    match c {
        FaultCategory::Signer => "signer",
        FaultCategory::Storage => "storage",
        FaultCategory::Network => "network",
        FaultCategory::Tee => "tee",
        FaultCategory::Zkml => "zkml",
        FaultCategory::Anchor => "anchor",
        FaultCategory::Connector => "connector",
        FaultCategory::Custom => "custom",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_rules_means_no_injection() {
        let h = ChaosHarness::with_seed(1);
        for _ in 0..100 {
            assert_eq!(h.maybe_inject(FaultCategory::Signer), FaultDecision::Continue);
        }
        assert_eq!(h.event_count(), 0);
    }

    #[test]
    fn probability_one_always_injects() {
        let h = ChaosHarness::with_seed(1);
        h.add_rule(FaultRule::new(FaultCategory::Signer, 1.0));
        for _ in 0..10 {
            match h.maybe_inject(FaultCategory::Signer) {
                FaultDecision::Inject(_) => {}
                _ => panic!("expected inject"),
            }
        }
        assert_eq!(h.event_count(), 10);
    }

    #[test]
    fn probability_zero_never_injects() {
        let h = ChaosHarness::with_seed(1);
        h.add_rule(FaultRule::new(FaultCategory::Signer, 0.0));
        for _ in 0..1000 {
            assert_eq!(h.maybe_inject(FaultCategory::Signer), FaultDecision::Continue);
        }
    }

    #[test]
    fn category_isolation() {
        let h = ChaosHarness::with_seed(1);
        h.add_rule(FaultRule::new(FaultCategory::Signer, 1.0));
        for _ in 0..5 {
            assert_eq!(h.maybe_inject(FaultCategory::Storage), FaultDecision::Continue);
        }
        assert_eq!(h.event_count(), 0);
    }

    #[test]
    fn deterministic_with_same_seed() {
        let h1 = ChaosHarness::with_seed(42);
        let h2 = ChaosHarness::with_seed(42);
        h1.add_rule(FaultRule::new(FaultCategory::Storage, 0.3));
        h2.add_rule(FaultRule::new(FaultCategory::Storage, 0.3));
        let mut a = Vec::new();
        let mut b = Vec::new();
        for _ in 0..100 {
            a.push(matches!(h1.maybe_inject(FaultCategory::Storage), FaultDecision::Inject(_)));
            b.push(matches!(h2.maybe_inject(FaultCategory::Storage), FaultDecision::Inject(_)));
        }
        assert_eq!(a, b);
    }

    #[test]
    fn different_seeds_diverge() {
        let h1 = ChaosHarness::with_seed(1);
        let h2 = ChaosHarness::with_seed(2);
        h1.add_rule(FaultRule::new(FaultCategory::Storage, 0.5));
        h2.add_rule(FaultRule::new(FaultCategory::Storage, 0.5));
        let mut a = Vec::new();
        let mut b = Vec::new();
        for _ in 0..500 {
            a.push(matches!(h1.maybe_inject(FaultCategory::Storage), FaultDecision::Inject(_)));
            b.push(matches!(h2.maybe_inject(FaultCategory::Storage), FaultDecision::Inject(_)));
        }
        assert_ne!(a, b, "different seeds must give different patterns");
    }

    #[test]
    fn until_attempt_caps_rule() {
        let h = ChaosHarness::with_seed(1);
        h.add_rule(
            FaultRule::new(FaultCategory::Signer, 1.0)
                .with_until_attempt(3),
        );
        for _ in 0..10 {
            h.maybe_inject(FaultCategory::Signer);
        }
        assert_eq!(h.event_count(), 3, "rule auto-disabled after 3 attempts");
    }

    #[test]
    fn disable_blocks_all_injection() {
        let h = ChaosHarness::with_seed(1);
        h.add_rule(FaultRule::new(FaultCategory::Signer, 1.0));
        h.disable();
        for _ in 0..10 {
            assert_eq!(h.maybe_inject(FaultCategory::Signer), FaultDecision::Continue);
        }
    }

    #[test]
    fn enable_after_disable() {
        let h = ChaosHarness::with_seed(1);
        h.add_rule(FaultRule::new(FaultCategory::Signer, 1.0));
        h.disable();
        h.enable();
        assert!(h.enabled());
        assert!(matches!(
            h.maybe_inject(FaultCategory::Signer),
            FaultDecision::Inject(_)
        ));
    }

    #[test]
    fn reset_clears_events_and_reseeds() {
        let h = ChaosHarness::with_seed(7);
        h.add_rule(FaultRule::new(FaultCategory::Storage, 0.4));
        for _ in 0..50 {
            h.maybe_inject(FaultCategory::Storage);
        }
        let pre = h.event_count();
        h.reset();
        assert_eq!(h.event_count(), 0);
        assert_eq!(h.attempts(FaultCategory::Storage), 0);
        // After reset, identical sequence emerges.
        for _ in 0..50 {
            h.maybe_inject(FaultCategory::Storage);
        }
        assert_eq!(h.event_count(), pre);
    }

    #[test]
    fn events_for_filters_by_category() {
        let h = ChaosHarness::with_seed(1);
        h.add_rule(FaultRule::new(FaultCategory::Signer, 1.0));
        h.add_rule(FaultRule::new(FaultCategory::Storage, 1.0));
        h.maybe_inject(FaultCategory::Signer);
        h.maybe_inject(FaultCategory::Storage);
        h.maybe_inject(FaultCategory::Storage);
        assert_eq!(h.events_for(FaultCategory::Signer).len(), 1);
        assert_eq!(h.events_for(FaultCategory::Storage).len(), 2);
    }

    #[test]
    fn injected_event_has_metadata() {
        let h = ChaosHarness::with_seed(1);
        h.add_rule(
            FaultRule::new(FaultCategory::Network, 1.0)
                .with_tag("packet-loss")
                .with_reason("ToR switch flap"),
        );
        h.maybe_inject(FaultCategory::Network);
        let e = &h.events()[0];
        assert_eq!(e.category, FaultCategory::Network);
        assert_eq!(e.tag.as_deref(), Some("packet-loss"));
        assert_eq!(e.reason.as_deref(), Some("ToR switch flap"));
    }

    #[test]
    fn multiple_rules_one_category_any_can_fire() {
        let h = ChaosHarness::with_seed(1);
        h.add_rule(FaultRule::new(FaultCategory::Signer, 0.0));
        h.add_rule(FaultRule::new(FaultCategory::Signer, 1.0));
        // Second rule (probability 1.0) should fire.
        assert!(matches!(
            h.maybe_inject(FaultCategory::Signer),
            FaultDecision::Inject(_)
        ));
    }

    #[test]
    fn attempt_counter_increments_per_category() {
        let h = ChaosHarness::with_seed(1);
        h.maybe_inject(FaultCategory::Signer);
        h.maybe_inject(FaultCategory::Signer);
        h.maybe_inject(FaultCategory::Storage);
        assert_eq!(h.attempts(FaultCategory::Signer), 2);
        assert_eq!(h.attempts(FaultCategory::Storage), 1);
    }

    #[test]
    fn rule_count_tracks_added() {
        let h = ChaosHarness::with_seed(1);
        assert_eq!(h.rule_count(), 0);
        h.add_rule(FaultRule::new(FaultCategory::Signer, 0.1));
        h.add_rule(FaultRule::new(FaultCategory::Storage, 0.1));
        assert_eq!(h.rule_count(), 2);
    }

    #[test]
    fn fault_rule_serde_round_trip() {
        let r = FaultRule::new(FaultCategory::Tee, 0.5)
            .with_tag("attest-fail")
            .with_until_attempt(20)
            .with_reason("expired cert");
        let j = serde_json::to_string(&r).unwrap();
        let p: FaultRule = serde_json::from_str(&j).unwrap();
        assert_eq!(p, r);
    }

    #[test]
    fn injected_fault_serde_round_trip() {
        let h = ChaosHarness::with_seed(1);
        h.add_rule(FaultRule::new(FaultCategory::Signer, 1.0));
        h.maybe_inject(FaultCategory::Signer);
        let e = &h.events()[0];
        let j = serde_json::to_string(e).unwrap();
        let p: InjectedFault = serde_json::from_str(&j).unwrap();
        assert_eq!(&p, e);
    }

    #[test]
    fn fault_category_serde_lower_case() {
        let s = serde_json::to_string(&FaultCategory::Signer).unwrap();
        assert_eq!(s, "\"signer\"");
    }

    #[test]
    fn lcg_uniform_in_unit_interval() {
        let mut s = 1u64;
        for _ in 0..1000 {
            let v = next_uniform(&mut s);
            assert!((0.0..1.0).contains(&v));
        }
    }

    #[test]
    fn category_label_stable() {
        assert_eq!(category_label(FaultCategory::Signer), "signer");
        assert_eq!(category_label(FaultCategory::Custom), "custom");
    }

    #[test]
    fn event_sequence_is_monotonic() {
        let h = ChaosHarness::with_seed(1);
        h.add_rule(FaultRule::new(FaultCategory::Storage, 1.0));
        for _ in 0..5 {
            h.maybe_inject(FaultCategory::Storage);
        }
        let events = h.events();
        for (i, e) in events.iter().enumerate() {
            assert_eq!(e.sequence, (i + 1) as u64);
        }
    }
}
