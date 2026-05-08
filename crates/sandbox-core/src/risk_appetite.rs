//! Risk Appetite Statement — quantified org-level risk tolerance.
//!
//! ISO 31000, COSO ERM, and basically every regulator requires a board-
//! approved Risk Appetite Statement (RAS) declaring what risks the
//! organization will and will not take, expressed quantitatively where
//! possible. This module captures:
//!
//! - **Risk dimensions** — Operational, Compliance, Cybersecurity,
//!   Financial, Reputational, Strategic, Model Risk.
//! - **Per-dimension quantitative limit** with metric + threshold.
//! - **Current measurement** vs limit → produces a [`RiskPosition`]
//!   (`Within` / `Approaching` / `Breach`).
//!
//! Operators record measurements over time; the registry computes positions
//! and surfaces breaches automatically.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use time::OffsetDateTime;

// =============================================================================
// RiskDimension
// =============================================================================

/// Top-level risk dimension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskDimension {
    /// Operational.
    Operational,
    /// Compliance.
    Compliance,
    /// Cybersecurity.
    Cybersecurity,
    /// Financial.
    Financial,
    /// Reputational.
    Reputational,
    /// Strategic.
    Strategic,
    /// Model risk.
    Model,
}

// =============================================================================
// RiskPosition
// =============================================================================

/// Position vs declared appetite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskPosition {
    /// Comfortably within.
    Within,
    /// Approaching limit (≥ 80% of threshold).
    Approaching,
    /// Above limit.
    Breach,
}

// =============================================================================
// Limit
// =============================================================================

/// One quantitative limit for a dimension.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Limit {
    /// Dimension.
    pub dimension: RiskDimension,
    /// Free-text description of the metric (e.g., "Critical incidents per quarter").
    pub metric: String,
    /// Threshold value.
    pub threshold: f64,
    /// Higher-is-worse (`true`) or lower-is-worse (`false`).
    pub higher_is_worse: bool,
    /// Free-text rationale.
    pub rationale: String,
}

impl Limit {
    /// Classify a `current` value vs the threshold.
    pub fn classify(&self, current: f64) -> RiskPosition {
        if self.higher_is_worse {
            if current > self.threshold {
                RiskPosition::Breach
            } else if current >= self.threshold * 0.8 {
                RiskPosition::Approaching
            } else {
                RiskPosition::Within
            }
        } else {
            // Lower-is-worse: current below threshold = breach.
            if current < self.threshold {
                RiskPosition::Breach
            } else if current <= self.threshold * 1.2 {
                RiskPosition::Approaching
            } else {
                RiskPosition::Within
            }
        }
    }
}

// =============================================================================
// Measurement
// =============================================================================

/// One measurement of a dimension's metric.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Measurement {
    /// Dimension.
    pub dimension: RiskDimension,
    /// Measured value.
    pub value: f64,
    /// RFC 3339 measured at.
    pub measured_at: String,
    /// Optional reporter.
    pub reporter: Option<String>,
}

// =============================================================================
// AppetiteSnapshot
// =============================================================================

/// One row in [`RiskAppetiteRegistry::snapshot`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AppetiteSnapshot {
    /// Dimension.
    pub dimension: RiskDimension,
    /// Limit metric.
    pub metric: String,
    /// Threshold.
    pub threshold: f64,
    /// Last measured value (if any).
    pub current: Option<f64>,
    /// Position.
    pub position: RiskPosition,
}

// =============================================================================
// RiskAppetiteRegistry
// =============================================================================

#[derive(Default)]
struct State {
    limits: HashMap<RiskDimension, Limit>,
    measurements: HashMap<RiskDimension, Vec<Measurement>>,
}

/// Registry of limits + measurements.
pub struct RiskAppetiteRegistry {
    state: RwLock<State>,
}

impl Default for RiskAppetiteRegistry {
    fn default() -> Self {
        Self {
            state: RwLock::new(State::default()),
        }
    }
}

impl std::fmt::Debug for RiskAppetiteRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RiskAppetiteRegistry")
            .field("limits", &self.limit_count())
            .finish()
    }
}

impl RiskAppetiteRegistry {
    /// New empty.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the limit for a dimension (replaces existing).
    pub fn set_limit(&self, l: Limit) -> SandboxResult<()> {
        self.state
            .write()
            .map_err(|_| SandboxError::Other("appetite registry poisoned".into()))?
            .limits
            .insert(l.dimension, l);
        Ok(())
    }

    /// Record a measurement.
    pub fn record(&self, m: Measurement) -> SandboxResult<()> {
        self.state
            .write()
            .map_err(|_| SandboxError::Other("appetite registry poisoned".into()))?
            .measurements
            .entry(m.dimension)
            .or_default()
            .push(m);
        Ok(())
    }

    /// Convenience: record a value now.
    pub fn record_value(
        &self,
        dim: RiskDimension,
        value: f64,
        reporter: Option<String>,
    ) -> SandboxResult<()> {
        self.record(Measurement {
            dimension: dim,
            value,
            measured_at: OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
            reporter,
        })
    }

    /// Limit count.
    pub fn limit_count(&self) -> usize {
        self.state.read().map(|g| g.limits.len()).unwrap_or(0)
    }

    /// Look up the latest measurement for a dimension. Insertion order is
    /// preserved so the last appended measurement is "latest" — even when
    /// multiple records share the same RFC 3339 second.
    pub fn latest_measurement(&self, dim: RiskDimension) -> Option<Measurement> {
        self.state
            .read()
            .ok()?
            .measurements
            .get(&dim)?
            .last()
            .cloned()
    }

    /// Position for a dimension.
    pub fn position(&self, dim: RiskDimension) -> Option<RiskPosition> {
        let g = self.state.read().ok()?;
        let l = g.limits.get(&dim)?;
        let m = g.measurements.get(&dim).and_then(|v| v.last())?;
        Some(l.classify(m.value))
    }

    /// Whole-org snapshot.
    pub fn snapshot(&self) -> Vec<AppetiteSnapshot> {
        let g = match self.state.read() {
            Ok(g) => g,
            Err(_) => return Vec::new(),
        };
        let mut out = Vec::new();
        for (dim, l) in &g.limits {
            let latest = g.measurements.get(dim).and_then(|v| v.last());
            let current = latest.map(|m| m.value);
            let position = match latest {
                Some(m) => l.classify(m.value),
                None => RiskPosition::Within,
            };
            out.push(AppetiteSnapshot {
                dimension: *dim,
                metric: l.metric.clone(),
                threshold: l.threshold,
                current,
                position,
            });
        }
        out.sort_by(|a, b| (a.dimension as u32).cmp(&(b.dimension as u32)));
        out
    }

    /// Count of dimensions currently in `Breach`.
    pub fn breach_count(&self) -> usize {
        self.snapshot()
            .into_iter()
            .filter(|r| r.position == RiskPosition::Breach)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limit(dim: RiskDimension, threshold: f64, higher_is_worse: bool) -> Limit {
        Limit {
            dimension: dim,
            metric: "metric".into(),
            threshold,
            higher_is_worse,
            rationale: "x".into(),
        }
    }

    #[test]
    fn limit_classifies_within() {
        let l = limit(RiskDimension::Operational, 10.0, true);
        assert_eq!(l.classify(5.0), RiskPosition::Within);
    }

    #[test]
    fn limit_classifies_approaching() {
        let l = limit(RiskDimension::Operational, 10.0, true);
        assert_eq!(l.classify(8.5), RiskPosition::Approaching);
    }

    #[test]
    fn limit_classifies_breach() {
        let l = limit(RiskDimension::Operational, 10.0, true);
        assert_eq!(l.classify(15.0), RiskPosition::Breach);
    }

    #[test]
    fn lower_is_worse_below_threshold_is_breach() {
        let l = limit(RiskDimension::Operational, 0.99, false);
        assert_eq!(l.classify(0.95), RiskPosition::Breach);
    }

    #[test]
    fn lower_is_worse_above_threshold_within() {
        let l = limit(RiskDimension::Operational, 0.99, false);
        assert_eq!(l.classify(2.0), RiskPosition::Within);
    }

    #[test]
    fn set_limit_replaces() {
        let r = RiskAppetiteRegistry::new();
        r.set_limit(limit(RiskDimension::Compliance, 1.0, true)).unwrap();
        r.set_limit(limit(RiskDimension::Compliance, 5.0, true)).unwrap();
        assert_eq!(r.limit_count(), 1);
    }

    #[test]
    fn position_returns_none_without_limit() {
        let r = RiskAppetiteRegistry::new();
        r.record_value(RiskDimension::Compliance, 1.0, None).unwrap();
        assert!(r.position(RiskDimension::Compliance).is_none());
    }

    #[test]
    fn position_returns_none_without_measurement() {
        let r = RiskAppetiteRegistry::new();
        r.set_limit(limit(RiskDimension::Compliance, 1.0, true)).unwrap();
        assert!(r.position(RiskDimension::Compliance).is_none());
    }

    #[test]
    fn position_returns_some_when_both_set() {
        let r = RiskAppetiteRegistry::new();
        r.set_limit(limit(RiskDimension::Compliance, 5.0, true)).unwrap();
        r.record_value(RiskDimension::Compliance, 2.0, None).unwrap();
        assert_eq!(r.position(RiskDimension::Compliance), Some(RiskPosition::Within));
    }

    #[test]
    fn breach_count_reflects_breaches() {
        let r = RiskAppetiteRegistry::new();
        r.set_limit(limit(RiskDimension::Compliance, 1.0, true)).unwrap();
        r.set_limit(limit(RiskDimension::Cybersecurity, 1.0, true))
            .unwrap();
        r.record_value(RiskDimension::Compliance, 5.0, None).unwrap();
        r.record_value(RiskDimension::Cybersecurity, 0.0, None).unwrap();
        assert_eq!(r.breach_count(), 1);
    }

    #[test]
    fn snapshot_lists_all_limits() {
        let r = RiskAppetiteRegistry::new();
        r.set_limit(limit(RiskDimension::Compliance, 1.0, true)).unwrap();
        r.set_limit(limit(RiskDimension::Operational, 1.0, true)).unwrap();
        let s = r.snapshot();
        assert_eq!(s.len(), 2);
    }

    #[test]
    fn snapshot_position_default_within_without_measurement() {
        let r = RiskAppetiteRegistry::new();
        r.set_limit(limit(RiskDimension::Compliance, 1.0, true)).unwrap();
        let s = r.snapshot();
        assert_eq!(s[0].position, RiskPosition::Within);
        assert!(s[0].current.is_none());
    }

    #[test]
    fn latest_measurement_picks_newest() {
        let r = RiskAppetiteRegistry::new();
        r.record(Measurement {
            dimension: RiskDimension::Operational,
            value: 1.0,
            measured_at: "2026-01-01T00:00:00Z".into(),
            reporter: None,
        })
        .unwrap();
        r.record(Measurement {
            dimension: RiskDimension::Operational,
            value: 2.0,
            measured_at: "2026-06-01T00:00:00Z".into(),
            reporter: None,
        })
        .unwrap();
        let m = r.latest_measurement(RiskDimension::Operational).unwrap();
        assert_eq!(m.value, 2.0);
    }

    #[test]
    fn latest_measurement_unknown_none() {
        let r = RiskAppetiteRegistry::new();
        assert!(r.latest_measurement(RiskDimension::Operational).is_none());
    }

    #[test]
    fn risk_dimension_serde() {
        for d in [
            RiskDimension::Operational,
            RiskDimension::Compliance,
            RiskDimension::Cybersecurity,
            RiskDimension::Financial,
            RiskDimension::Reputational,
            RiskDimension::Strategic,
            RiskDimension::Model,
        ] {
            let j = serde_json::to_string(&d).unwrap();
            let p: RiskDimension = serde_json::from_str(&j).unwrap();
            assert_eq!(p, d);
        }
    }

    #[test]
    fn position_serde() {
        for p in [
            RiskPosition::Within,
            RiskPosition::Approaching,
            RiskPosition::Breach,
        ] {
            let j = serde_json::to_string(&p).unwrap();
            let q: RiskPosition = serde_json::from_str(&j).unwrap();
            assert_eq!(p, q);
        }
    }

    #[test]
    fn limit_serde() {
        let l = limit(RiskDimension::Operational, 10.0, true);
        let j = serde_json::to_string(&l).unwrap();
        let p: Limit = serde_json::from_str(&j).unwrap();
        assert_eq!(p, l);
    }

    #[test]
    fn measurement_serde() {
        let m = Measurement {
            dimension: RiskDimension::Operational,
            value: 1.0,
            measured_at: "2026-01-01T00:00:00Z".into(),
            reporter: Some("ciso".into()),
        };
        let j = serde_json::to_string(&m).unwrap();
        let p: Measurement = serde_json::from_str(&j).unwrap();
        assert_eq!(p, m);
    }

    #[test]
    fn snapshot_serde() {
        let r = RiskAppetiteRegistry::new();
        r.set_limit(limit(RiskDimension::Compliance, 1.0, true)).unwrap();
        let s = r.snapshot();
        let j = serde_json::to_string(&s).unwrap();
        let p: Vec<AppetiteSnapshot> = serde_json::from_str(&j).unwrap();
        assert_eq!(p, s);
    }

    #[test]
    fn record_many_per_dimension() {
        let r = RiskAppetiteRegistry::new();
        for i in 0..50 {
            r.record_value(
                RiskDimension::Operational,
                i as f64,
                Some(format!("r{i}")),
            )
            .unwrap();
        }
        let m = r.latest_measurement(RiskDimension::Operational).unwrap();
        assert_eq!(m.value, 49.0);
    }

    #[test]
    fn breach_count_zero_when_no_limits() {
        let r = RiskAppetiteRegistry::new();
        assert_eq!(r.breach_count(), 0);
    }

    #[test]
    fn approaching_at_eighty_percent() {
        let l = limit(RiskDimension::Operational, 100.0, true);
        assert_eq!(l.classify(80.0), RiskPosition::Approaching);
    }

    #[test]
    fn approaching_lower_at_one_twenty_percent() {
        let l = limit(RiskDimension::Operational, 100.0, false);
        assert_eq!(l.classify(110.0), RiskPosition::Approaching);
    }
}
