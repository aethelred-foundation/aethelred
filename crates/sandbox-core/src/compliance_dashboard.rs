//! Compliance dashboard — aggregate KPI snapshot.
//!
//! Operators want a single view that says "where do we stand right now?":
//!
//! - Open compliance findings.
//! - SLO error-budget burn.
//! - Overdue model revalidations.
//! - Overdue vendor reassessments.
//! - Active risk-appetite breaches.
//! - Days to next certification expiry.
//! - Open postmortem actions.
//!
//! This module **does not own** any of those data sources — it composes
//! them into a single [`ComplianceSnapshot`] for export to dashboards.

use serde::{Deserialize, Serialize};
use std::sync::RwLock;
use time::OffsetDateTime;

// =============================================================================
// KpiSeverity
// =============================================================================

/// Color of a KPI tile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KpiSeverity {
    /// Green — healthy.
    Green,
    /// Amber — warning.
    Amber,
    /// Red — alert.
    Red,
}

impl Default for KpiSeverity {
    fn default() -> Self {
        Self::Green
    }
}

// =============================================================================
// Kpi
// =============================================================================

/// One KPI tile.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Kpi {
    /// Stable id.
    pub id: String,
    /// Display label.
    pub label: String,
    /// Numeric value (e.g. count, ratio).
    pub value: f64,
    /// Unit suffix (e.g. `"%"`, `"days"`, `""`).
    pub unit: String,
    /// Severity.
    pub severity: KpiSeverity,
    /// Free-text context for hover.
    pub note: Option<String>,
}

impl Kpi {
    /// Convenience.
    pub fn green(id: impl Into<String>, label: impl Into<String>, value: f64) -> Self {
        Self {
            id: id.into(),
            label: label.into(),
            value,
            unit: String::new(),
            severity: KpiSeverity::Green,
            note: None,
        }
    }
    /// Builder: unit.
    pub fn with_unit(mut self, u: impl Into<String>) -> Self {
        self.unit = u.into();
        self
    }
    /// Builder: severity.
    pub fn with_severity(mut self, s: KpiSeverity) -> Self {
        self.severity = s;
        self
    }
    /// Builder: note.
    pub fn with_note(mut self, n: impl Into<String>) -> Self {
        self.note = Some(n.into());
        self
    }
}

// =============================================================================
// ComplianceSnapshot
// =============================================================================

/// One full snapshot.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ComplianceSnapshot {
    /// RFC 3339 generated.
    pub generated_at: String,
    /// Tenant scope (None = cross-tenant).
    pub tenant_id: Option<String>,
    /// All KPI tiles.
    pub kpis: Vec<Kpi>,
    /// Overall status (`Green` only if every KPI is Green).
    pub overall_severity: KpiSeverity,
    /// Free-text headline.
    pub headline: String,
}

impl ComplianceSnapshot {
    /// Filter KPIs by severity.
    pub fn kpis_at(&self, severity: KpiSeverity) -> Vec<&Kpi> {
        self.kpis.iter().filter(|k| k.severity == severity).collect()
    }
    /// `true` if any Red KPI.
    pub fn has_red(&self) -> bool {
        self.kpis.iter().any(|k| k.severity == KpiSeverity::Red)
    }
    /// `true` if any Amber KPI.
    pub fn has_amber(&self) -> bool {
        self.kpis.iter().any(|k| k.severity == KpiSeverity::Amber)
    }
}

// =============================================================================
// DashboardBuilder
// =============================================================================

/// Builder for [`ComplianceSnapshot`].
pub struct DashboardBuilder {
    tenant_id: Option<String>,
    kpis: Vec<Kpi>,
    headline: String,
}

impl Default for DashboardBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl DashboardBuilder {
    /// New empty builder.
    pub fn new() -> Self {
        Self {
            tenant_id: None,
            kpis: Vec::new(),
            headline: String::new(),
        }
    }
    /// Tenant scope.
    pub fn tenant(mut self, t: impl Into<String>) -> Self {
        self.tenant_id = Some(t.into());
        self
    }
    /// Headline.
    pub fn headline(mut self, h: impl Into<String>) -> Self {
        self.headline = h.into();
        self
    }
    /// Add a KPI.
    pub fn kpi(mut self, k: Kpi) -> Self {
        self.kpis.push(k);
        self
    }
    /// Build.
    pub fn build(self) -> ComplianceSnapshot {
        let overall = if self.kpis.iter().any(|k| k.severity == KpiSeverity::Red) {
            KpiSeverity::Red
        } else if self.kpis.iter().any(|k| k.severity == KpiSeverity::Amber) {
            KpiSeverity::Amber
        } else {
            KpiSeverity::Green
        };
        ComplianceSnapshot {
            generated_at: OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
            tenant_id: self.tenant_id,
            kpis: self.kpis,
            overall_severity: overall,
            headline: self.headline,
        }
    }
}

// =============================================================================
// SnapshotHistory
// =============================================================================

/// Append-only series of snapshots over time.
#[derive(Default)]
pub struct SnapshotHistory {
    inner: RwLock<Vec<ComplianceSnapshot>>,
}

impl std::fmt::Debug for SnapshotHistory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SnapshotHistory")
            .field("len", &self.len())
            .finish()
    }
}

impl SnapshotHistory {
    /// New empty.
    pub fn new() -> Self {
        Self::default()
    }
    /// Append.
    pub fn append(&self, s: ComplianceSnapshot) {
        if let Ok(mut g) = self.inner.write() {
            g.push(s);
        }
    }
    /// All snapshots.
    pub fn all(&self) -> Vec<ComplianceSnapshot> {
        self.inner.read().map(|g| g.clone()).unwrap_or_default()
    }
    /// Latest.
    pub fn latest(&self) -> Option<ComplianceSnapshot> {
        self.inner.read().ok()?.last().cloned()
    }
    /// Length.
    pub fn len(&self) -> usize {
        self.inner.read().map(|g| g.len()).unwrap_or(0)
    }
    /// Empty?
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Filter snapshots whose overall severity == `s`.
    pub fn filter_severity(&self, s: KpiSeverity) -> Vec<ComplianceSnapshot> {
        self.all()
            .into_iter()
            .filter(|x| x.overall_severity == s)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(id: &str, sev: KpiSeverity) -> Kpi {
        Kpi::green(id, id, 0.0).with_severity(sev)
    }

    #[test]
    fn empty_dashboard_is_green() {
        let s = DashboardBuilder::new().build();
        assert_eq!(s.overall_severity, KpiSeverity::Green);
    }

    #[test]
    fn one_red_makes_overall_red() {
        let s = DashboardBuilder::new()
            .kpi(k("a", KpiSeverity::Red))
            .build();
        assert_eq!(s.overall_severity, KpiSeverity::Red);
    }

    #[test]
    fn one_amber_no_red_makes_overall_amber() {
        let s = DashboardBuilder::new()
            .kpi(k("a", KpiSeverity::Amber))
            .kpi(k("b", KpiSeverity::Green))
            .build();
        assert_eq!(s.overall_severity, KpiSeverity::Amber);
    }

    #[test]
    fn all_green_overall_green() {
        let s = DashboardBuilder::new()
            .kpi(k("a", KpiSeverity::Green))
            .kpi(k("b", KpiSeverity::Green))
            .build();
        assert_eq!(s.overall_severity, KpiSeverity::Green);
    }

    #[test]
    fn kpis_at_filter() {
        let s = DashboardBuilder::new()
            .kpi(k("a", KpiSeverity::Green))
            .kpi(k("b", KpiSeverity::Red))
            .kpi(k("c", KpiSeverity::Red))
            .build();
        assert_eq!(s.kpis_at(KpiSeverity::Red).len(), 2);
        assert_eq!(s.kpis_at(KpiSeverity::Green).len(), 1);
    }

    #[test]
    fn has_red_helpers() {
        let s = DashboardBuilder::new()
            .kpi(k("a", KpiSeverity::Red))
            .build();
        assert!(s.has_red());
        assert!(!s.has_amber());
    }

    #[test]
    fn has_amber_helpers() {
        let s = DashboardBuilder::new()
            .kpi(k("a", KpiSeverity::Amber))
            .build();
        assert!(!s.has_red());
        assert!(s.has_amber());
    }

    #[test]
    fn tenant_recorded() {
        let s = DashboardBuilder::new().tenant("FAB").build();
        assert_eq!(s.tenant_id.as_deref(), Some("FAB"));
    }

    #[test]
    fn headline_recorded() {
        let s = DashboardBuilder::new().headline("All systems green").build();
        assert_eq!(s.headline, "All systems green");
    }

    #[test]
    fn kpi_with_unit_and_note() {
        let kpi = Kpi::green("x", "X", 95.0)
            .with_unit("%")
            .with_note("uptime");
        assert_eq!(kpi.unit, "%");
        assert_eq!(kpi.note.as_deref(), Some("uptime"));
    }

    #[test]
    fn snapshot_serde() {
        let s = DashboardBuilder::new().kpi(k("a", KpiSeverity::Red)).build();
        let j = serde_json::to_string(&s).unwrap();
        let p: ComplianceSnapshot = serde_json::from_str(&j).unwrap();
        assert_eq!(p, s);
    }

    #[test]
    fn kpi_serde() {
        let kpi = Kpi::green("x", "X", 1.0)
            .with_unit("u")
            .with_note("n");
        let j = serde_json::to_string(&kpi).unwrap();
        let p: Kpi = serde_json::from_str(&j).unwrap();
        assert_eq!(p, kpi);
    }

    #[test]
    fn severity_serde() {
        for s in [KpiSeverity::Green, KpiSeverity::Amber, KpiSeverity::Red] {
            let j = serde_json::to_string(&s).unwrap();
            let p: KpiSeverity = serde_json::from_str(&j).unwrap();
            assert_eq!(p, s);
        }
    }

    #[test]
    fn history_append_and_latest() {
        let h = SnapshotHistory::new();
        let s1 = DashboardBuilder::new().headline("a").build();
        let s2 = DashboardBuilder::new().headline("b").build();
        h.append(s1.clone());
        h.append(s2.clone());
        let latest = h.latest().unwrap();
        assert_eq!(latest.headline, "b");
    }

    #[test]
    fn history_filter_severity() {
        let h = SnapshotHistory::new();
        h.append(DashboardBuilder::new().kpi(k("a", KpiSeverity::Red)).build());
        h.append(DashboardBuilder::new().kpi(k("b", KpiSeverity::Green)).build());
        assert_eq!(h.filter_severity(KpiSeverity::Red).len(), 1);
        assert_eq!(h.filter_severity(KpiSeverity::Green).len(), 1);
    }

    #[test]
    fn history_empty() {
        let h = SnapshotHistory::new();
        assert!(h.is_empty());
        assert!(h.latest().is_none());
    }

    #[test]
    fn history_len_tracks() {
        let h = SnapshotHistory::new();
        for _ in 0..5 {
            h.append(DashboardBuilder::new().build());
        }
        assert_eq!(h.len(), 5);
    }

    #[test]
    fn snapshot_generated_at_set() {
        let s = DashboardBuilder::new().build();
        assert!(!s.generated_at.is_empty());
    }

    #[test]
    fn many_kpis_no_panic() {
        let mut b = DashboardBuilder::new();
        for i in 0..50 {
            b = b.kpi(k(&format!("k{i}"), KpiSeverity::Green));
        }
        let s = b.build();
        assert_eq!(s.kpis.len(), 50);
    }

    #[test]
    fn red_dominates_over_amber_and_green() {
        let s = DashboardBuilder::new()
            .kpi(k("a", KpiSeverity::Green))
            .kpi(k("b", KpiSeverity::Amber))
            .kpi(k("c", KpiSeverity::Red))
            .build();
        assert_eq!(s.overall_severity, KpiSeverity::Red);
    }

    #[test]
    fn all_kpis_recorded() {
        let s = DashboardBuilder::new()
            .kpi(Kpi::green("k1", "K1", 1.0).with_unit("%"))
            .kpi(Kpi::green("k2", "K2", 2.0).with_unit("%"))
            .build();
        assert_eq!(s.kpis.len(), 2);
    }

    #[test]
    fn snapshot_no_red_no_amber_means_green() {
        let s = DashboardBuilder::new()
            .kpi(k("a", KpiSeverity::Green))
            .build();
        assert!(!s.has_red() && !s.has_amber());
    }

    #[test]
    fn tenant_serde_round_trip() {
        let s = DashboardBuilder::new().tenant("FAB").build();
        let j = serde_json::to_string(&s).unwrap();
        let p: ComplianceSnapshot = serde_json::from_str(&j).unwrap();
        assert_eq!(p.tenant_id, s.tenant_id);
    }
}
