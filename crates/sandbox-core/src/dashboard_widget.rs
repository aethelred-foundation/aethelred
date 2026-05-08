//! Configurable dashboard widget definitions.
//!
//! Operators define dashboards composed of widgets (single-stat, time-series,
//! gauge, table, list) with a query reference and refresh policy. Composes
//! with [`crate::compliance_dashboard`] (KPI snapshots) and the metric
//! sources scattered across the protocol.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use time::OffsetDateTime;
use uuid::Uuid;

// =============================================================================
// WidgetKind
// =============================================================================

/// Kind of widget.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WidgetKind {
    /// Single number / KPI tile.
    SingleStat,
    /// Time series chart.
    TimeSeries,
    /// Gauge.
    Gauge,
    /// Table.
    Table,
    /// Log-style list.
    List,
    /// Heatmap.
    Heatmap,
}

// =============================================================================
// RefreshPolicy
// =============================================================================

/// How often to refresh.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefreshPolicy {
    /// Manual refresh only.
    Manual,
    /// Every minute.
    EveryMinute,
    /// Every 5 minutes.
    Every5Minutes,
    /// Every hour.
    Hourly,
    /// Daily.
    Daily,
}

impl RefreshPolicy {
    /// Interval in seconds.
    pub fn interval_seconds(self) -> i64 {
        match self {
            Self::Manual => i64::MAX,
            Self::EveryMinute => 60,
            Self::Every5Minutes => 300,
            Self::Hourly => 3600,
            Self::Daily => 86400,
        }
    }
}

// =============================================================================
// Widget
// =============================================================================

/// One widget.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Widget {
    /// Stable id.
    pub widget_id: String,
    /// Display title.
    pub title: String,
    /// Kind.
    pub kind: WidgetKind,
    /// Query reference (e.g. metric name, SQL alias).
    pub query: String,
    /// Refresh policy.
    pub refresh: RefreshPolicy,
    /// Position (col, row, width, height).
    pub layout: Layout,
    /// Free-form options (axis labels, thresholds, colors).
    pub options: HashMap<String, String>,
}

/// Grid placement.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct Layout {
    /// Column index.
    pub col: u32,
    /// Row index.
    pub row: u32,
    /// Width in cells.
    pub width: u32,
    /// Height in cells.
    pub height: u32,
}

// =============================================================================
// Dashboard
// =============================================================================

/// One dashboard.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Dashboard {
    /// Stable id.
    pub dashboard_id: Uuid,
    /// Name.
    pub name: String,
    /// Owner.
    pub owner: String,
    /// Tenant scope (None = cross-tenant).
    pub tenant_id: Option<String>,
    /// Widgets.
    pub widgets: Vec<Widget>,
    /// Tags.
    pub tags: Vec<String>,
    /// RFC 3339 created.
    pub created_at: String,
    /// RFC 3339 updated.
    pub updated_at: String,
}

impl Dashboard {
    /// Lookup widget.
    pub fn widget(&self, id: &str) -> Option<&Widget> {
        self.widgets.iter().find(|w| w.widget_id == id)
    }

    /// Total grid area used.
    pub fn total_grid_area(&self) -> u64 {
        self.widgets
            .iter()
            .map(|w| (w.layout.width as u64) * (w.layout.height as u64))
            .sum()
    }
}

// =============================================================================
// DashboardRegistry
// =============================================================================

#[derive(Default)]
struct State {
    dashboards: HashMap<Uuid, Dashboard>,
}

/// Registry.
pub struct DashboardRegistry {
    state: RwLock<State>,
}

impl Default for DashboardRegistry {
    fn default() -> Self {
        Self {
            state: RwLock::new(State::default()),
        }
    }
}

impl std::fmt::Debug for DashboardRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DashboardRegistry").field("dashboards", &self.len()).finish()
    }
}

impl DashboardRegistry {
    /// New empty.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a dashboard.
    pub fn create(
        &self,
        name: impl Into<String>,
        owner: impl Into<String>,
        tenant_id: Option<String>,
    ) -> SandboxResult<Dashboard> {
        let now = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        let d = Dashboard {
            dashboard_id: Uuid::now_v7(),
            name: name.into(),
            owner: owner.into(),
            tenant_id,
            widgets: Vec::new(),
            tags: Vec::new(),
            created_at: now.clone(),
            updated_at: now,
        };
        self.state
            .write()
            .map_err(|_| SandboxError::Other("dashboard registry poisoned".into()))?
            .dashboards
            .insert(d.dashboard_id, d.clone());
        Ok(d)
    }

    /// Add a widget.
    pub fn add_widget(&self, dashboard_id: Uuid, widget: Widget) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("dashboard registry poisoned".into()))?;
        let d = g
            .dashboards
            .get_mut(&dashboard_id)
            .ok_or_else(|| SandboxError::Other(format!("dashboard {} not found", dashboard_id)))?;
        if d.widgets.iter().any(|w| w.widget_id == widget.widget_id) {
            return Err(SandboxError::Other(format!(
                "widget {} already exists",
                widget.widget_id
            )));
        }
        d.widgets.push(widget);
        d.updated_at = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        Ok(())
    }

    /// Remove a widget.
    pub fn remove_widget(&self, dashboard_id: Uuid, widget_id: &str) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("dashboard registry poisoned".into()))?;
        let d = g
            .dashboards
            .get_mut(&dashboard_id)
            .ok_or_else(|| SandboxError::Other(format!("dashboard {} not found", dashboard_id)))?;
        let len = d.widgets.len();
        d.widgets.retain(|w| w.widget_id != widget_id);
        if d.widgets.len() == len {
            return Err(SandboxError::Other(format!(
                "widget {} not found",
                widget_id
            )));
        }
        d.updated_at = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        Ok(())
    }

    /// Add a tag.
    pub fn add_tag(&self, dashboard_id: Uuid, tag: impl Into<String>) -> SandboxResult<()> {
        let tag = tag.into();
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("dashboard registry poisoned".into()))?;
        let d = g
            .dashboards
            .get_mut(&dashboard_id)
            .ok_or_else(|| SandboxError::Other(format!("dashboard {} not found", dashboard_id)))?;
        if !d.tags.contains(&tag) {
            d.tags.push(tag);
        }
        Ok(())
    }

    /// Lookup.
    pub fn get(&self, id: Uuid) -> Option<Dashboard> {
        self.state.read().ok()?.dashboards.get(&id).cloned()
    }

    /// All.
    pub fn all(&self) -> Vec<Dashboard> {
        self.state
            .read()
            .map(|g| g.dashboards.values().cloned().collect())
            .unwrap_or_default()
    }

    /// By tenant.
    pub fn for_tenant(&self, tenant: &str) -> Vec<Dashboard> {
        self.all()
            .into_iter()
            .filter(|d| d.tenant_id.as_deref() == Some(tenant))
            .collect()
    }

    /// By tag.
    pub fn by_tag(&self, tag: &str) -> Vec<Dashboard> {
        self.all()
            .into_iter()
            .filter(|d| d.tags.iter().any(|t| t == tag))
            .collect()
    }

    /// Count.
    pub fn len(&self) -> usize {
        self.state.read().map(|g| g.dashboards.len()).unwrap_or(0)
    }

    /// Empty?
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn widget(id: &str, kind: WidgetKind) -> Widget {
        Widget {
            widget_id: id.into(),
            title: id.into(),
            kind,
            query: format!("query-{id}"),
            refresh: RefreshPolicy::Every5Minutes,
            layout: Layout {
                col: 0,
                row: 0,
                width: 4,
                height: 2,
            },
            options: HashMap::new(),
        }
    }

    #[test]
    fn create_dashboard() {
        let r = DashboardRegistry::new();
        let d = r.create("Compliance", "ciso", Some("FAB".into())).unwrap();
        assert_eq!(d.name, "Compliance");
        assert!(d.widgets.is_empty());
    }

    #[test]
    fn add_widget_appends() {
        let r = DashboardRegistry::new();
        let d = r.create("x", "y", None).unwrap();
        r.add_widget(d.dashboard_id, widget("w1", WidgetKind::SingleStat))
            .unwrap();
        assert_eq!(r.get(d.dashboard_id).unwrap().widgets.len(), 1);
    }

    #[test]
    fn duplicate_widget_errors() {
        let r = DashboardRegistry::new();
        let d = r.create("x", "y", None).unwrap();
        r.add_widget(d.dashboard_id, widget("w1", WidgetKind::SingleStat))
            .unwrap();
        assert!(r
            .add_widget(d.dashboard_id, widget("w1", WidgetKind::SingleStat))
            .is_err());
    }

    #[test]
    fn remove_widget_works() {
        let r = DashboardRegistry::new();
        let d = r.create("x", "y", None).unwrap();
        r.add_widget(d.dashboard_id, widget("w1", WidgetKind::SingleStat))
            .unwrap();
        r.remove_widget(d.dashboard_id, "w1").unwrap();
        assert!(r.get(d.dashboard_id).unwrap().widgets.is_empty());
    }

    #[test]
    fn remove_unknown_widget_errors() {
        let r = DashboardRegistry::new();
        let d = r.create("x", "y", None).unwrap();
        assert!(r.remove_widget(d.dashboard_id, "ghost").is_err());
    }

    #[test]
    fn add_tag_dedupes() {
        let r = DashboardRegistry::new();
        let d = r.create("x", "y", None).unwrap();
        r.add_tag(d.dashboard_id, "compliance").unwrap();
        r.add_tag(d.dashboard_id, "compliance").unwrap();
        assert_eq!(r.get(d.dashboard_id).unwrap().tags.len(), 1);
    }

    #[test]
    fn refresh_interval_seconds() {
        assert_eq!(RefreshPolicy::EveryMinute.interval_seconds(), 60);
        assert_eq!(RefreshPolicy::Hourly.interval_seconds(), 3600);
        assert_eq!(RefreshPolicy::Daily.interval_seconds(), 86400);
    }

    #[test]
    fn manual_interval_max() {
        assert_eq!(RefreshPolicy::Manual.interval_seconds(), i64::MAX);
    }

    #[test]
    fn widget_lookup() {
        let r = DashboardRegistry::new();
        let d = r.create("x", "y", None).unwrap();
        r.add_widget(d.dashboard_id, widget("w1", WidgetKind::Gauge)).unwrap();
        let updated = r.get(d.dashboard_id).unwrap();
        assert!(updated.widget("w1").is_some());
        assert!(updated.widget("ghost").is_none());
    }

    #[test]
    fn total_grid_area() {
        let r = DashboardRegistry::new();
        let d = r.create("x", "y", None).unwrap();
        r.add_widget(d.dashboard_id, widget("a", WidgetKind::SingleStat))
            .unwrap();
        r.add_widget(d.dashboard_id, widget("b", WidgetKind::SingleStat))
            .unwrap();
        let updated = r.get(d.dashboard_id).unwrap();
        // 2 widgets * 4*2 = 16.
        assert_eq!(updated.total_grid_area(), 16);
    }

    #[test]
    fn for_tenant_filters() {
        let r = DashboardRegistry::new();
        r.create("x", "y", Some("FAB".into())).unwrap();
        r.create("x", "y", Some("ENBD".into())).unwrap();
        assert_eq!(r.for_tenant("FAB").len(), 1);
        assert_eq!(r.for_tenant("ENBD").len(), 1);
    }

    #[test]
    fn by_tag_filters() {
        let r = DashboardRegistry::new();
        let d1 = r.create("x", "y", None).unwrap();
        r.add_tag(d1.dashboard_id, "compliance").unwrap();
        r.create("x", "y", None).unwrap();
        assert_eq!(r.by_tag("compliance").len(), 1);
    }

    #[test]
    fn dashboard_serde() {
        let r = DashboardRegistry::new();
        let d = r.create("x", "y", None).unwrap();
        let j = serde_json::to_string(&d).unwrap();
        let p: Dashboard = serde_json::from_str(&j).unwrap();
        assert_eq!(p, d);
    }

    #[test]
    fn widget_serde() {
        let w = widget("x", WidgetKind::TimeSeries);
        let j = serde_json::to_string(&w).unwrap();
        let p: Widget = serde_json::from_str(&j).unwrap();
        assert_eq!(p, w);
    }

    #[test]
    fn kind_serde() {
        for k in [
            WidgetKind::SingleStat,
            WidgetKind::TimeSeries,
            WidgetKind::Gauge,
            WidgetKind::Table,
            WidgetKind::List,
            WidgetKind::Heatmap,
        ] {
            let j = serde_json::to_string(&k).unwrap();
            let p: WidgetKind = serde_json::from_str(&j).unwrap();
            assert_eq!(p, k);
        }
    }

    #[test]
    fn refresh_serde() {
        for r in [
            RefreshPolicy::Manual,
            RefreshPolicy::EveryMinute,
            RefreshPolicy::Every5Minutes,
            RefreshPolicy::Hourly,
            RefreshPolicy::Daily,
        ] {
            let j = serde_json::to_string(&r).unwrap();
            let p: RefreshPolicy = serde_json::from_str(&j).unwrap();
            assert_eq!(p, r);
        }
    }

    #[test]
    fn updated_at_changes_on_widget_add() {
        let r = DashboardRegistry::new();
        let d = r.create("x", "y", None).unwrap();
        let original_updated = d.updated_at.clone();
        std::thread::sleep(std::time::Duration::from_millis(1100));
        r.add_widget(d.dashboard_id, widget("w1", WidgetKind::SingleStat))
            .unwrap();
        let new_updated = r.get(d.dashboard_id).unwrap().updated_at;
        assert_ne!(original_updated, new_updated);
    }

    #[test]
    fn count_tracks() {
        let r = DashboardRegistry::new();
        assert!(r.is_empty());
        r.create("x", "y", None).unwrap();
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn many_widgets() {
        let r = DashboardRegistry::new();
        let d = r.create("x", "y", None).unwrap();
        for i in 0..10 {
            r.add_widget(d.dashboard_id, widget(&format!("w{i}"), WidgetKind::Gauge))
                .unwrap();
        }
        assert_eq!(r.get(d.dashboard_id).unwrap().widgets.len(), 10);
    }

    #[test]
    fn lookup_unknown_returns_none() {
        let r = DashboardRegistry::new();
        assert!(r.get(Uuid::now_v7()).is_none());
    }

    #[test]
    fn add_widget_unknown_dashboard_errors() {
        let r = DashboardRegistry::new();
        assert!(r
            .add_widget(Uuid::now_v7(), widget("w1", WidgetKind::SingleStat))
            .is_err());
    }
}
