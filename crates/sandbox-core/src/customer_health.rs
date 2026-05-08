//! Per-tenant customer-health score.
//!
//! Composes signals from multiple modules into a single score the CS team
//! tracks: active usage, error rate, login frequency, support-ticket
//! volume, NPS, and product-feature adoption.
//!
//! Each input has a configurable weight; the output is a normalized score
//! in `[0.0, 100.0]` plus a [`HealthLevel`] band.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use time::OffsetDateTime;

// =============================================================================
// HealthLevel
// =============================================================================

/// Banded category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthLevel {
    /// Healthy — green.
    Healthy,
    /// At risk — yellow.
    AtRisk,
    /// Churn risk — orange.
    ChurnRisk,
    /// Critical — red.
    Critical,
}

impl HealthLevel {
    /// From numeric score.
    pub fn from_score(score: f64) -> Self {
        if score >= 80.0 {
            HealthLevel::Healthy
        } else if score >= 60.0 {
            HealthLevel::AtRisk
        } else if score >= 40.0 {
            HealthLevel::ChurnRisk
        } else {
            HealthLevel::Critical
        }
    }
}

// =============================================================================
// SignalKind
// =============================================================================

/// Per-signal kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalKind {
    /// Active usage (days/month).
    UsageDays,
    /// Error rate (lower is better).
    ErrorRate,
    /// Login frequency.
    LoginFrequency,
    /// Open support tickets (lower is better).
    OpenTickets,
    /// NPS score.
    Nps,
    /// Feature adoption (count of features used).
    FeatureAdoption,
    /// Custom.
    Custom,
}

// =============================================================================
// SignalDefinition
// =============================================================================

/// One configurable signal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SignalDefinition {
    /// Kind.
    pub kind: SignalKind,
    /// Weight in `[0.0, 1.0]`.
    pub weight: f64,
    /// `true` if higher value = healthier (default), `false` if inverted.
    pub higher_is_better: bool,
    /// Min value (clamped lower).
    pub min: f64,
    /// Max value (clamped upper).
    pub max: f64,
}

impl SignalDefinition {
    /// Convert raw value into 0..=100.
    pub fn normalize(&self, raw: f64) -> f64 {
        let clamped = raw.clamp(self.min, self.max);
        if (self.max - self.min).abs() < 1e-12 {
            return 0.0;
        }
        let normalized = (clamped - self.min) / (self.max - self.min) * 100.0;
        if self.higher_is_better {
            normalized
        } else {
            100.0 - normalized
        }
    }
}

// =============================================================================
// HealthSnapshot
// =============================================================================

/// Per-tenant snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HealthSnapshot {
    /// Tenant.
    pub tenant_id: String,
    /// Score.
    pub score: f64,
    /// Level.
    pub level: HealthLevel,
    /// RFC 3339 generated.
    pub generated_at: String,
    /// Per-signal contributions (for tooltip / debug).
    pub contributions: HashMap<SignalKind, f64>,
}

// =============================================================================
// CustomerHealthRegistry
// =============================================================================

#[derive(Default)]
struct State {
    /// Per-signal kind → definition.
    signals: HashMap<SignalKind, SignalDefinition>,
    /// `(tenant, kind)` → most recent raw value.
    values: HashMap<(String, SignalKind), f64>,
}

/// Registry.
pub struct CustomerHealthRegistry {
    state: RwLock<State>,
}

impl Default for CustomerHealthRegistry {
    fn default() -> Self {
        Self {
            state: RwLock::new(State::default()),
        }
    }
}

impl std::fmt::Debug for CustomerHealthRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CustomerHealthRegistry")
            .field("signals", &self.signal_count())
            .finish()
    }
}

impl CustomerHealthRegistry {
    /// New empty.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a signal.
    pub fn register_signal(&self, def: SignalDefinition) -> SandboxResult<()> {
        if !(def.weight >= 0.0 && def.weight <= 1.0) {
            return Err(SandboxError::Other(format!(
                "weight must be in [0,1], got {}",
                def.weight
            )));
        }
        if def.max <= def.min {
            return Err(SandboxError::Other("max must be > min".into()));
        }
        self.state
            .write()
            .map_err(|_| SandboxError::Other("health registry poisoned".into()))?
            .signals
            .insert(def.kind, def);
        Ok(())
    }

    /// Update a signal's value for a tenant.
    pub fn update(
        &self,
        tenant: impl Into<String>,
        kind: SignalKind,
        value: f64,
    ) -> SandboxResult<()> {
        self.state
            .write()
            .map_err(|_| SandboxError::Other("health registry poisoned".into()))?
            .values
            .insert((tenant.into(), kind), value);
        Ok(())
    }

    /// Compute snapshot.
    pub fn snapshot(&self, tenant: &str) -> HealthSnapshot {
        let g = match self.state.read() {
            Ok(g) => g,
            Err(_) => {
                return HealthSnapshot {
                    tenant_id: tenant.to_string(),
                    score: 0.0,
                    level: HealthLevel::Critical,
                    generated_at: String::new(),
                    contributions: HashMap::new(),
                }
            }
        };
        let mut contributions: HashMap<SignalKind, f64> = HashMap::new();
        let mut weighted_sum = 0.0;
        let mut weight_sum = 0.0;
        for (kind, def) in &g.signals {
            let v = g
                .values
                .get(&(tenant.to_string(), *kind))
                .copied()
                .unwrap_or(def.min);
            let n = def.normalize(v);
            contributions.insert(*kind, n);
            weighted_sum += n * def.weight;
            weight_sum += def.weight;
        }
        let score = if weight_sum > 0.0 {
            weighted_sum / weight_sum
        } else {
            0.0
        };
        let level = HealthLevel::from_score(score);
        HealthSnapshot {
            tenant_id: tenant.to_string(),
            score,
            level,
            generated_at: OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
            contributions,
        }
    }

    /// Snapshots for a list of tenants.
    pub fn snapshots(&self, tenants: &[String]) -> Vec<HealthSnapshot> {
        tenants.iter().map(|t| self.snapshot(t)).collect()
    }

    /// Tenants in a band.
    pub fn tenants_in_band(
        &self,
        tenants: &[String],
        level: HealthLevel,
    ) -> Vec<HealthSnapshot> {
        self.snapshots(tenants)
            .into_iter()
            .filter(|s| s.level == level)
            .collect()
    }

    /// Number of registered signals.
    pub fn signal_count(&self) -> usize {
        self.state.read().map(|g| g.signals.len()).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signals(r: &CustomerHealthRegistry) {
        r.register_signal(SignalDefinition {
            kind: SignalKind::UsageDays,
            weight: 0.5,
            higher_is_better: true,
            min: 0.0,
            max: 30.0,
        })
        .unwrap();
        r.register_signal(SignalDefinition {
            kind: SignalKind::ErrorRate,
            weight: 0.3,
            higher_is_better: false,
            min: 0.0,
            max: 0.1,
        })
        .unwrap();
        r.register_signal(SignalDefinition {
            kind: SignalKind::Nps,
            weight: 0.2,
            higher_is_better: true,
            min: -100.0,
            max: 100.0,
        })
        .unwrap();
    }

    #[test]
    fn level_from_score() {
        assert_eq!(HealthLevel::from_score(95.0), HealthLevel::Healthy);
        assert_eq!(HealthLevel::from_score(70.0), HealthLevel::AtRisk);
        assert_eq!(HealthLevel::from_score(50.0), HealthLevel::ChurnRisk);
        assert_eq!(HealthLevel::from_score(20.0), HealthLevel::Critical);
    }

    #[test]
    fn normalize_higher_better() {
        let s = SignalDefinition {
            kind: SignalKind::UsageDays,
            weight: 1.0,
            higher_is_better: true,
            min: 0.0,
            max: 30.0,
        };
        assert!((s.normalize(15.0) - 50.0).abs() < 1e-9);
        assert!((s.normalize(0.0) - 0.0).abs() < 1e-9);
        assert!((s.normalize(30.0) - 100.0).abs() < 1e-9);
    }

    #[test]
    fn normalize_lower_better() {
        let s = SignalDefinition {
            kind: SignalKind::ErrorRate,
            weight: 1.0,
            higher_is_better: false,
            min: 0.0,
            max: 0.1,
        };
        assert!((s.normalize(0.0) - 100.0).abs() < 1e-9);
        assert!((s.normalize(0.1) - 0.0).abs() < 1e-9);
    }

    #[test]
    fn normalize_clamps() {
        let s = SignalDefinition {
            kind: SignalKind::UsageDays,
            weight: 1.0,
            higher_is_better: true,
            min: 0.0,
            max: 30.0,
        };
        assert!((s.normalize(60.0) - 100.0).abs() < 1e-9);
        assert!((s.normalize(-10.0) - 0.0).abs() < 1e-9);
    }

    #[test]
    fn register_invalid_weight_errors() {
        let r = CustomerHealthRegistry::new();
        let s = SignalDefinition {
            kind: SignalKind::UsageDays,
            weight: 1.5,
            higher_is_better: true,
            min: 0.0,
            max: 30.0,
        };
        assert!(r.register_signal(s).is_err());
    }

    #[test]
    fn register_max_le_min_errors() {
        let r = CustomerHealthRegistry::new();
        let s = SignalDefinition {
            kind: SignalKind::UsageDays,
            weight: 0.5,
            higher_is_better: true,
            min: 100.0,
            max: 50.0,
        };
        assert!(r.register_signal(s).is_err());
    }

    #[test]
    fn snapshot_with_no_data_at_min() {
        let r = CustomerHealthRegistry::new();
        signals(&r);
        let s = r.snapshot("FAB");
        // All values default to min → low score.
        assert!(s.score < 50.0);
    }

    #[test]
    fn snapshot_with_max_data_high() {
        let r = CustomerHealthRegistry::new();
        signals(&r);
        r.update("FAB", SignalKind::UsageDays, 30.0).unwrap();
        r.update("FAB", SignalKind::ErrorRate, 0.0).unwrap();
        r.update("FAB", SignalKind::Nps, 100.0).unwrap();
        let s = r.snapshot("FAB");
        assert!(s.score > 90.0);
        assert_eq!(s.level, HealthLevel::Healthy);
    }

    #[test]
    fn snapshot_per_tenant_isolated() {
        let r = CustomerHealthRegistry::new();
        signals(&r);
        r.update("FAB", SignalKind::UsageDays, 30.0).unwrap();
        // ENBD never updated.
        let fab = r.snapshot("FAB");
        let enbd = r.snapshot("ENBD");
        assert!(fab.score > enbd.score);
    }

    #[test]
    fn snapshot_contributions_recorded() {
        let r = CustomerHealthRegistry::new();
        signals(&r);
        r.update("FAB", SignalKind::UsageDays, 15.0).unwrap();
        let s = r.snapshot("FAB");
        assert!(s.contributions.contains_key(&SignalKind::UsageDays));
    }

    #[test]
    fn tenants_in_band_filters() {
        let r = CustomerHealthRegistry::new();
        signals(&r);
        r.update("FAB", SignalKind::UsageDays, 30.0).unwrap();
        r.update("FAB", SignalKind::ErrorRate, 0.0).unwrap();
        r.update("FAB", SignalKind::Nps, 100.0).unwrap();
        let tenants = vec!["FAB".into(), "ENBD".into()];
        let healthy = r.tenants_in_band(&tenants, HealthLevel::Healthy);
        assert_eq!(healthy.len(), 1);
        assert_eq!(healthy[0].tenant_id, "FAB");
    }

    #[test]
    fn signal_count_tracks() {
        let r = CustomerHealthRegistry::new();
        assert_eq!(r.signal_count(), 0);
        signals(&r);
        assert_eq!(r.signal_count(), 3);
    }

    #[test]
    fn definition_serde() {
        let s = SignalDefinition {
            kind: SignalKind::UsageDays,
            weight: 0.5,
            higher_is_better: true,
            min: 0.0,
            max: 30.0,
        };
        let j = serde_json::to_string(&s).unwrap();
        let p: SignalDefinition = serde_json::from_str(&j).unwrap();
        assert_eq!(p, s);
    }

    #[test]
    fn snapshot_serde() {
        let r = CustomerHealthRegistry::new();
        signals(&r);
        let s = r.snapshot("FAB");
        let j = serde_json::to_string(&s).unwrap();
        let p: HealthSnapshot = serde_json::from_str(&j).unwrap();
        assert_eq!(p, s);
    }

    #[test]
    fn level_serde() {
        for l in [
            HealthLevel::Healthy,
            HealthLevel::AtRisk,
            HealthLevel::ChurnRisk,
            HealthLevel::Critical,
        ] {
            let j = serde_json::to_string(&l).unwrap();
            let p: HealthLevel = serde_json::from_str(&j).unwrap();
            assert_eq!(p, l);
        }
    }

    #[test]
    fn signal_kind_serde() {
        for k in [
            SignalKind::UsageDays,
            SignalKind::ErrorRate,
            SignalKind::LoginFrequency,
            SignalKind::OpenTickets,
            SignalKind::Nps,
            SignalKind::FeatureAdoption,
            SignalKind::Custom,
        ] {
            let j = serde_json::to_string(&k).unwrap();
            let p: SignalKind = serde_json::from_str(&j).unwrap();
            assert_eq!(p, k);
        }
    }

    #[test]
    fn no_signals_zero_score() {
        let r = CustomerHealthRegistry::new();
        let s = r.snapshot("FAB");
        assert_eq!(s.score, 0.0);
        assert_eq!(s.level, HealthLevel::Critical);
    }

    #[test]
    fn snapshots_returns_per_tenant() {
        let r = CustomerHealthRegistry::new();
        signals(&r);
        let tenants = vec!["a".into(), "b".into(), "c".into()];
        let snaps = r.snapshots(&tenants);
        assert_eq!(snaps.len(), 3);
    }

    #[test]
    fn weight_zero_ignored() {
        let r = CustomerHealthRegistry::new();
        r.register_signal(SignalDefinition {
            kind: SignalKind::UsageDays,
            weight: 0.0,
            higher_is_better: true,
            min: 0.0,
            max: 30.0,
        })
        .unwrap();
        // No effect on score if no other signals — score = 0.
        let s = r.snapshot("FAB");
        assert_eq!(s.score, 0.0);
    }

    #[test]
    fn boundary_at_60_at_risk() {
        // 60.0 is exactly the AtRisk lower bound.
        assert_eq!(HealthLevel::from_score(60.0), HealthLevel::AtRisk);
    }

    #[test]
    fn boundary_at_80_healthy() {
        assert_eq!(HealthLevel::from_score(80.0), HealthLevel::Healthy);
    }

    #[test]
    fn signal_definition_min_eq_max_normalize_zero() {
        let s = SignalDefinition {
            kind: SignalKind::UsageDays,
            weight: 1.0,
            higher_is_better: true,
            min: 5.0,
            max: 5.000_000_000_001,
        };
        assert!(s.normalize(5.0).is_finite());
    }
}
