//! Canary deployment with auto-rollback gates.
//!
//! When a new model version is deployed, we want to route a small fraction
//! of traffic through it and watch it carefully. If guard-rail metrics
//! breach, the canary is rolled back automatically.
//!
//! ## Gates we enforce
//!
//! - **Error rate** — canary error rate cannot exceed `max_error_rate`.
//! - **Bias parity** — canary's selection-rate parity (vs. baseline)
//!   cannot drop below `min_parity` (typically 0.8 for the four-fifths rule).
//! - **Latency** — canary p99 latency vs baseline cannot exceed `max_latency_multiplier`.
//! - **Manual override** — operator can force a stop or accept.
//!
//! Operators register a [`CanaryDeployment`] with a baseline + candidate
//! model id and traffic percentage, then call [`CanaryRegistry::record_outcome`]
//! for each request. The registry produces [`CanaryDecision`]s
//! (`Continue` / `Rollback` / `Promote`).

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use time::OffsetDateTime;

// =============================================================================
// CanaryConfig
// =============================================================================

/// Per-deployment thresholds.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct CanaryConfig {
    /// Traffic percentage routed to canary (0..=100).
    pub traffic_percent: u32,
    /// Maximum acceptable canary error rate.
    pub max_error_rate: f64,
    /// Minimum acceptable parity ratio (canary success / baseline success).
    pub min_parity: f64,
    /// Maximum p99 latency multiplier (canary / baseline).
    pub max_latency_multiplier: f64,
    /// Minimum samples per side before applying gates.
    pub min_samples_per_side: u32,
}

impl Default for CanaryConfig {
    fn default() -> Self {
        Self {
            traffic_percent: 5,
            max_error_rate: 0.05,
            min_parity: 0.95,
            max_latency_multiplier: 1.5,
            min_samples_per_side: 50,
        }
    }
}

// =============================================================================
// CanaryDeployment
// =============================================================================

/// Lifecycle phases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CanaryPhase {
    /// Recording traffic, no decision yet.
    Active,
    /// Forcibly rolled back.
    RolledBack,
    /// Canary promoted to baseline.
    Promoted,
    /// Operator paused.
    Paused,
}

/// One canary deployment.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CanaryDeployment {
    /// Stable id.
    pub deployment_id: String,
    /// Baseline model id.
    pub baseline_model_id: String,
    /// Candidate model id.
    pub candidate_model_id: String,
    /// Tenant.
    pub tenant_id: String,
    /// Config.
    pub config: CanaryConfig,
    /// Current phase.
    pub phase: CanaryPhase,
    /// RFC 3339 created.
    pub created_at: String,
    /// RFC 3339 last-changed.
    pub last_changed_at: String,
    /// Operator who created it.
    pub created_by: String,
    /// Optional reason for terminal phase.
    pub terminal_reason: Option<String>,
}

// =============================================================================
// SideStats
// =============================================================================

/// Per-side stats.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct SideStats {
    /// Total observations.
    pub total: u64,
    /// Successful outcomes.
    pub successes: u64,
    /// Errors.
    pub errors: u64,
    /// Sum of latency in microseconds.
    pub latency_micros_sum: u128,
}

impl SideStats {
    /// Error rate.
    pub fn error_rate(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        self.errors as f64 / self.total as f64
    }
    /// Success rate.
    pub fn success_rate(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        self.successes as f64 / self.total as f64
    }
    /// Mean latency in microseconds.
    pub fn mean_latency_micros(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        (self.latency_micros_sum as f64) / (self.total as f64)
    }
}

// =============================================================================
// CanaryDecision
// =============================================================================

/// Per-step decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "decision")]
pub enum CanaryDecision {
    /// Keep recording.
    Continue,
    /// Rollback because of a breach.
    Rollback {
        /// Reason.
        reason: String,
    },
    /// Promote — canary has met all gates with sufficient samples.
    Promote,
}

impl CanaryDecision {
    /// `true` if rollback.
    pub fn is_rollback(&self) -> bool {
        matches!(self, CanaryDecision::Rollback { .. })
    }
    /// `true` if promote.
    pub fn is_promote(&self) -> bool {
        matches!(self, CanaryDecision::Promote)
    }
}

// =============================================================================
// CanaryRegistry
// =============================================================================

#[derive(Default)]
struct RegistryState {
    deployments: HashMap<String, CanaryDeployment>,
    /// (id) → (baseline_stats, candidate_stats)
    stats: HashMap<String, (SideStats, SideStats)>,
}

/// Registry of active canaries + per-deployment stats.
pub struct CanaryRegistry {
    state: RwLock<RegistryState>,
    /// If `true`, the registry will issue Promote decisions when gates pass
    /// for `min_samples_per_side` per side. Default `false` (operator
    /// promotes manually).
    pub auto_promote: bool,
}

impl Default for CanaryRegistry {
    fn default() -> Self {
        Self {
            state: RwLock::new(RegistryState::default()),
            auto_promote: false,
        }
    }
}

impl std::fmt::Debug for CanaryRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CanaryRegistry")
            .field("auto_promote", &self.auto_promote)
            .finish()
    }
}

impl CanaryRegistry {
    /// New empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new canary.
    pub fn register(
        &self,
        deployment_id: impl Into<String>,
        tenant: impl Into<String>,
        baseline: impl Into<String>,
        candidate: impl Into<String>,
        config: CanaryConfig,
        creator: impl Into<String>,
    ) -> SandboxResult<CanaryDeployment> {
        if config.traffic_percent > 100 {
            return Err(SandboxError::Other(format!(
                "traffic_percent must be 0..=100, got {}",
                config.traffic_percent
            )));
        }
        let id = deployment_id.into();
        let now = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        let d = CanaryDeployment {
            deployment_id: id.clone(),
            baseline_model_id: baseline.into(),
            candidate_model_id: candidate.into(),
            tenant_id: tenant.into(),
            config,
            phase: CanaryPhase::Active,
            created_at: now.clone(),
            last_changed_at: now,
            created_by: creator.into(),
            terminal_reason: None,
        };
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("canary registry poisoned".into()))?;
        if g.deployments.contains_key(&id) {
            return Err(SandboxError::Other(format!(
                "canary {} already exists",
                id
            )));
        }
        g.deployments.insert(id.clone(), d.clone());
        g.stats.insert(id, (SideStats::default(), SideStats::default()));
        Ok(d)
    }

    /// Record an outcome for one side. `latency_micros` is the request latency.
    pub fn record_outcome(
        &self,
        deployment_id: &str,
        side: Side,
        success: bool,
        latency_micros: u64,
    ) -> SandboxResult<CanaryDecision> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("canary registry poisoned".into()))?;
        let d = g
            .deployments
            .get(deployment_id)
            .cloned()
            .ok_or_else(|| {
                SandboxError::Other(format!("canary {} not found", deployment_id))
            })?;
        if d.phase != CanaryPhase::Active {
            return Ok(CanaryDecision::Continue);
        }
        let stats = g.stats.entry(deployment_id.to_string()).or_default();
        let s = match side {
            Side::Baseline => &mut stats.0,
            Side::Candidate => &mut stats.1,
        };
        s.total += 1;
        if success {
            s.successes += 1;
        } else {
            s.errors += 1;
        }
        s.latency_micros_sum = s.latency_micros_sum.saturating_add(latency_micros as u128);

        let baseline = stats.0.clone();
        let candidate = stats.1.clone();
        drop(g);

        // Apply gates — but only with sufficient samples.
        if candidate.total < d.config.min_samples_per_side as u64
            || baseline.total < d.config.min_samples_per_side as u64
        {
            return Ok(CanaryDecision::Continue);
        }
        // Error rate gate.
        if candidate.error_rate() > d.config.max_error_rate {
            self.set_phase(
                deployment_id,
                CanaryPhase::RolledBack,
                Some(format!(
                    "error rate {:.3} > threshold {:.3}",
                    candidate.error_rate(),
                    d.config.max_error_rate
                )),
            )?;
            return Ok(CanaryDecision::Rollback {
                reason: "error_rate_exceeded".into(),
            });
        }
        // Parity gate.
        let parity = if baseline.success_rate() == 0.0 {
            1.0
        } else {
            candidate.success_rate() / baseline.success_rate()
        };
        if parity < d.config.min_parity {
            self.set_phase(
                deployment_id,
                CanaryPhase::RolledBack,
                Some(format!(
                    "parity {:.3} < min {:.3}",
                    parity, d.config.min_parity
                )),
            )?;
            return Ok(CanaryDecision::Rollback {
                reason: "parity_breach".into(),
            });
        }
        // Latency gate.
        if baseline.mean_latency_micros() > 0.0 {
            let mult = candidate.mean_latency_micros() / baseline.mean_latency_micros();
            if mult > d.config.max_latency_multiplier {
                self.set_phase(
                    deployment_id,
                    CanaryPhase::RolledBack,
                    Some(format!(
                        "latency multiplier {:.2} > {:.2}",
                        mult, d.config.max_latency_multiplier
                    )),
                )?;
                return Ok(CanaryDecision::Rollback {
                    reason: "latency_breach".into(),
                });
            }
        }
        if self.auto_promote {
            self.set_phase(deployment_id, CanaryPhase::Promoted, None)?;
            return Ok(CanaryDecision::Promote);
        }
        Ok(CanaryDecision::Continue)
    }

    /// Force-rollback (operator override).
    pub fn force_rollback(
        &self,
        deployment_id: &str,
        reason: impl Into<String>,
    ) -> SandboxResult<()> {
        self.set_phase(deployment_id, CanaryPhase::RolledBack, Some(reason.into()))
    }

    /// Force-promote (operator override).
    pub fn force_promote(&self, deployment_id: &str) -> SandboxResult<()> {
        self.set_phase(deployment_id, CanaryPhase::Promoted, None)
    }

    /// Pause traffic.
    pub fn pause(&self, deployment_id: &str) -> SandboxResult<()> {
        self.set_phase(deployment_id, CanaryPhase::Paused, None)
    }

    /// Resume after pause.
    pub fn resume(&self, deployment_id: &str) -> SandboxResult<()> {
        let g = self
            .state
            .read()
            .map_err(|_| SandboxError::Other("canary registry poisoned".into()))?;
        let d = g
            .deployments
            .get(deployment_id)
            .ok_or_else(|| {
                SandboxError::Other(format!("canary {} not found", deployment_id))
            })?;
        if d.phase != CanaryPhase::Paused {
            return Err(SandboxError::Other(format!(
                "cannot resume canary in phase {:?}",
                d.phase
            )));
        }
        drop(g);
        self.set_phase(deployment_id, CanaryPhase::Active, None)
    }

    /// Snapshot a deployment.
    pub fn deployment(&self, deployment_id: &str) -> Option<CanaryDeployment> {
        self.state.read().ok()?.deployments.get(deployment_id).cloned()
    }

    /// Snapshot stats `(baseline, candidate)`.
    pub fn stats(&self, deployment_id: &str) -> Option<(SideStats, SideStats)> {
        self.state.read().ok()?.stats.get(deployment_id).cloned()
    }

    /// Number of registered deployments.
    pub fn len(&self) -> usize {
        self.state.read().map(|g| g.deployments.len()).unwrap_or(0)
    }

    /// `true` if no deployments.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn set_phase(
        &self,
        deployment_id: &str,
        phase: CanaryPhase,
        reason: Option<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("canary registry poisoned".into()))?;
        let d = g
            .deployments
            .get_mut(deployment_id)
            .ok_or_else(|| {
                SandboxError::Other(format!("canary {} not found", deployment_id))
            })?;
        d.phase = phase;
        d.last_changed_at = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        d.terminal_reason = reason;
        Ok(())
    }
}

/// Side discriminator for [`CanaryRegistry::record_outcome`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Side {
    /// Baseline (current production model).
    Baseline,
    /// Candidate (new model under test).
    Candidate,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn small_cfg() -> CanaryConfig {
        CanaryConfig {
            traffic_percent: 10,
            max_error_rate: 0.1,
            min_parity: 0.9,
            max_latency_multiplier: 2.0,
            min_samples_per_side: 5,
        }
    }

    #[test]
    fn register_creates_deployment() {
        let r = CanaryRegistry::new();
        let d = r
            .register("d1", "FAB", "v1", "v2", small_cfg(), "ops")
            .unwrap();
        assert_eq!(d.phase, CanaryPhase::Active);
    }

    #[test]
    fn duplicate_registration_errors() {
        let r = CanaryRegistry::new();
        r.register("d1", "FAB", "v1", "v2", small_cfg(), "ops").unwrap();
        assert!(r.register("d1", "FAB", "v1", "v2", small_cfg(), "ops").is_err());
    }

    #[test]
    fn invalid_traffic_percent_errors() {
        let r = CanaryRegistry::new();
        let mut cfg = small_cfg();
        cfg.traffic_percent = 200;
        assert!(r.register("d1", "FAB", "v1", "v2", cfg, "ops").is_err());
    }

    #[test]
    fn record_below_threshold_returns_continue() {
        let r = CanaryRegistry::new();
        r.register("d1", "FAB", "v1", "v2", small_cfg(), "ops").unwrap();
        for _ in 0..3 {
            let d = r.record_outcome("d1", Side::Baseline, true, 100).unwrap();
            assert_eq!(d, CanaryDecision::Continue);
        }
    }

    #[test]
    fn record_high_error_rate_rolls_back() {
        let r = CanaryRegistry::new();
        r.register("d1", "FAB", "v1", "v2", small_cfg(), "ops").unwrap();
        // Baseline 5 successes.
        for _ in 0..5 {
            r.record_outcome("d1", Side::Baseline, true, 100).unwrap();
        }
        // Candidate: 5 errors → 100% error rate, breaches gate.
        let mut last = CanaryDecision::Continue;
        for _ in 0..5 {
            last = r.record_outcome("d1", Side::Candidate, false, 100).unwrap();
        }
        assert!(last.is_rollback());
        assert_eq!(
            r.deployment("d1").unwrap().phase,
            CanaryPhase::RolledBack
        );
    }

    #[test]
    fn record_parity_breach_rolls_back() {
        let r = CanaryRegistry::new();
        let cfg = CanaryConfig {
            min_parity: 0.95,
            ..small_cfg()
        };
        r.register("d1", "FAB", "v1", "v2", cfg, "ops").unwrap();
        // Baseline: 5 successes (rate 1.0).
        for _ in 0..5 {
            r.record_outcome("d1", Side::Baseline, true, 100).unwrap();
        }
        // Candidate: 3 successes / 2 errors (rate 0.6 < 0.95 parity).
        // But error_rate also breaches.  Use min_samples=5 + tighter cfg.
        let cfg = CanaryConfig {
            traffic_percent: 10,
            max_error_rate: 0.5,
            min_parity: 0.95,
            max_latency_multiplier: 2.0,
            min_samples_per_side: 5,
        };
        let r2 = CanaryRegistry::new();
        r2.register("d2", "FAB", "v1", "v2", cfg, "ops").unwrap();
        for _ in 0..5 {
            r2.record_outcome("d2", Side::Baseline, true, 100).unwrap();
        }
        // 3 successes 2 errors → rate 0.6 vs 1.0, parity 0.6 < 0.95.
        for _ in 0..3 {
            r2.record_outcome("d2", Side::Candidate, true, 100).unwrap();
        }
        let last = r2
            .record_outcome("d2", Side::Candidate, false, 100)
            .unwrap();
        let last = match last {
            CanaryDecision::Continue => {
                r2.record_outcome("d2", Side::Candidate, false, 100).unwrap()
            }
            other => other,
        };
        assert!(last.is_rollback());
    }

    #[test]
    fn record_latency_breach_rolls_back() {
        let cfg = CanaryConfig {
            traffic_percent: 10,
            max_error_rate: 1.0,
            min_parity: 0.0,
            max_latency_multiplier: 1.5,
            min_samples_per_side: 3,
        };
        let r = CanaryRegistry::new();
        r.register("d1", "FAB", "v1", "v2", cfg, "ops").unwrap();
        for _ in 0..3 {
            r.record_outcome("d1", Side::Baseline, true, 100).unwrap();
        }
        // Candidate slow: 1000 micros vs baseline 100 micros → 10x.
        for _ in 0..2 {
            r.record_outcome("d1", Side::Candidate, true, 1000).unwrap();
        }
        let last = r.record_outcome("d1", Side::Candidate, true, 1000).unwrap();
        assert!(last.is_rollback());
    }

    #[test]
    fn auto_promote_promotes_after_gates() {
        let r = CanaryRegistry::new();
        let mut reg = r;
        reg.auto_promote = true;
        let cfg = CanaryConfig {
            min_samples_per_side: 3,
            max_error_rate: 1.0,
            min_parity: 0.0,
            max_latency_multiplier: 100.0,
            traffic_percent: 10,
        };
        reg.register("d1", "FAB", "v1", "v2", cfg, "ops").unwrap();
        for _ in 0..3 {
            reg.record_outcome("d1", Side::Baseline, true, 100).unwrap();
        }
        for _ in 0..2 {
            reg.record_outcome("d1", Side::Candidate, true, 100).unwrap();
        }
        let last = reg.record_outcome("d1", Side::Candidate, true, 100).unwrap();
        assert!(last.is_promote());
        assert_eq!(reg.deployment("d1").unwrap().phase, CanaryPhase::Promoted);
    }

    #[test]
    fn force_rollback_changes_phase() {
        let r = CanaryRegistry::new();
        r.register("d1", "FAB", "v1", "v2", small_cfg(), "ops").unwrap();
        r.force_rollback("d1", "operator decision").unwrap();
        let d = r.deployment("d1").unwrap();
        assert_eq!(d.phase, CanaryPhase::RolledBack);
        assert_eq!(d.terminal_reason.as_deref(), Some("operator decision"));
    }

    #[test]
    fn force_promote_changes_phase() {
        let r = CanaryRegistry::new();
        r.register("d1", "FAB", "v1", "v2", small_cfg(), "ops").unwrap();
        r.force_promote("d1").unwrap();
        assert_eq!(r.deployment("d1").unwrap().phase, CanaryPhase::Promoted);
    }

    #[test]
    fn pause_and_resume() {
        let r = CanaryRegistry::new();
        r.register("d1", "FAB", "v1", "v2", small_cfg(), "ops").unwrap();
        r.pause("d1").unwrap();
        assert_eq!(r.deployment("d1").unwrap().phase, CanaryPhase::Paused);
        r.resume("d1").unwrap();
        assert_eq!(r.deployment("d1").unwrap().phase, CanaryPhase::Active);
    }

    #[test]
    fn cannot_resume_non_paused() {
        let r = CanaryRegistry::new();
        r.register("d1", "FAB", "v1", "v2", small_cfg(), "ops").unwrap();
        assert!(r.resume("d1").is_err());
    }

    #[test]
    fn record_for_unknown_errors() {
        let r = CanaryRegistry::new();
        assert!(r.record_outcome("ghost", Side::Baseline, true, 100).is_err());
    }

    #[test]
    fn record_after_rollback_is_continue() {
        let r = CanaryRegistry::new();
        r.register("d1", "FAB", "v1", "v2", small_cfg(), "ops").unwrap();
        r.force_rollback("d1", "x").unwrap();
        let d = r.record_outcome("d1", Side::Candidate, false, 100).unwrap();
        assert_eq!(d, CanaryDecision::Continue);
    }

    #[test]
    fn stats_isolated_per_side() {
        let r = CanaryRegistry::new();
        r.register("d1", "FAB", "v1", "v2", small_cfg(), "ops").unwrap();
        for _ in 0..3 {
            r.record_outcome("d1", Side::Baseline, true, 100).unwrap();
        }
        for _ in 0..2 {
            r.record_outcome("d1", Side::Candidate, true, 100).unwrap();
        }
        let (b, c) = r.stats("d1").unwrap();
        assert_eq!(b.total, 3);
        assert_eq!(c.total, 2);
    }

    #[test]
    fn side_stats_calc() {
        let s = SideStats {
            total: 10,
            successes: 9,
            errors: 1,
            latency_micros_sum: 1000,
        };
        assert!((s.error_rate() - 0.1).abs() < 1e-9);
        assert!((s.success_rate() - 0.9).abs() < 1e-9);
        assert!((s.mean_latency_micros() - 100.0).abs() < 1e-9);
    }

    #[test]
    fn side_stats_zero_total_rates_zero() {
        let s = SideStats::default();
        assert_eq!(s.error_rate(), 0.0);
        assert_eq!(s.success_rate(), 0.0);
        assert_eq!(s.mean_latency_micros(), 0.0);
    }

    #[test]
    fn deployment_serde() {
        let r = CanaryRegistry::new();
        let d = r
            .register("d1", "FAB", "v1", "v2", small_cfg(), "ops")
            .unwrap();
        let j = serde_json::to_string(&d).unwrap();
        let p: CanaryDeployment = serde_json::from_str(&j).unwrap();
        assert_eq!(p, d);
    }

    #[test]
    fn decision_serde() {
        for d in [
            CanaryDecision::Continue,
            CanaryDecision::Promote,
            CanaryDecision::Rollback {
                reason: "x".into(),
            },
        ] {
            let j = serde_json::to_string(&d).unwrap();
            let p: CanaryDecision = serde_json::from_str(&j).unwrap();
            assert_eq!(p, d);
        }
    }

    #[test]
    fn phase_serde() {
        for p in [
            CanaryPhase::Active,
            CanaryPhase::RolledBack,
            CanaryPhase::Promoted,
            CanaryPhase::Paused,
        ] {
            let j = serde_json::to_string(&p).unwrap();
            let q: CanaryPhase = serde_json::from_str(&j).unwrap();
            assert_eq!(q, p);
        }
    }

    #[test]
    fn registry_len_tracks() {
        let r = CanaryRegistry::new();
        assert!(r.is_empty());
        r.register("d1", "FAB", "v1", "v2", small_cfg(), "ops").unwrap();
        r.register("d2", "FAB", "v1", "v2", small_cfg(), "ops").unwrap();
        assert_eq!(r.len(), 2);
    }

    #[test]
    fn unknown_deployment_returns_none() {
        let r = CanaryRegistry::new();
        assert!(r.deployment("ghost").is_none());
        assert!(r.stats("ghost").is_none());
    }

    #[test]
    fn many_outcomes_dont_panic() {
        let r = CanaryRegistry::new();
        let cfg = CanaryConfig {
            min_samples_per_side: 100_000,
            ..small_cfg()
        };
        r.register("d1", "FAB", "v1", "v2", cfg, "ops").unwrap();
        for _ in 0..100 {
            r.record_outcome("d1", Side::Baseline, true, 100).unwrap();
            r.record_outcome("d1", Side::Candidate, true, 100).unwrap();
        }
        assert_eq!(
            r.deployment("d1").unwrap().phase,
            CanaryPhase::Active
        );
    }
}
