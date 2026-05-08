//! Cross-region replication state tracking.
//!
//! Records the state of replication between primary + secondary regions.
//! Per-region: lag in seconds, last-replicated seal id, replication status,
//! and operator-controlled mode (sync / async / catch-up / paused).
//!
//! Composes with [`crate::data_residency`] (which constrains which regions
//! a tenant *can* replicate to) and [`crate::business_continuity`]
//! (RTO/RPO enforcement).

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use time::OffsetDateTime;
use uuid::Uuid;

// =============================================================================
// ReplicationMode
// =============================================================================

/// Mode controlling replication behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplicationMode {
    /// Synchronous (writes wait for ack).
    Sync,
    /// Asynchronous (eventual consistency).
    Async,
    /// Catch-up (initial bulk load).
    CatchUp,
    /// Paused.
    Paused,
}

// =============================================================================
// ReplicationStatus
// =============================================================================

/// Per-region status snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplicationStatus {
    /// Healthy.
    Healthy,
    /// Lagging (within tolerance).
    Lagging,
    /// Unhealthy (lag exceeds threshold).
    Unhealthy,
    /// Paused / disabled.
    Paused,
}

// =============================================================================
// RegionReplica
// =============================================================================

/// One replica region.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegionReplica {
    /// Region id (e.g. `"eu-west-1"`).
    pub region: String,
    /// Mode.
    pub mode: ReplicationMode,
    /// Last replicated seal/event id.
    pub last_replicated_id: Option<Uuid>,
    /// RFC 3339 last successful replication.
    pub last_replicated_at: Option<String>,
    /// Lag in seconds since last successful replication.
    pub lag_seconds: i64,
    /// Maximum allowed lag in seconds before Unhealthy.
    pub max_lag_seconds: i64,
    /// Status.
    pub status: ReplicationStatus,
    /// Optional error message.
    pub last_error: Option<String>,
}

impl RegionReplica {
    /// Recompute status from lag + mode.
    pub fn recompute_status(&mut self) {
        self.status = if self.mode == ReplicationMode::Paused {
            ReplicationStatus::Paused
        } else if self.lag_seconds <= self.max_lag_seconds / 2 {
            ReplicationStatus::Healthy
        } else if self.lag_seconds <= self.max_lag_seconds {
            ReplicationStatus::Lagging
        } else {
            ReplicationStatus::Unhealthy
        };
    }
}

// =============================================================================
// ReplicationGroup
// =============================================================================

/// One replication group (one primary + N replicas).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReplicationGroup {
    /// Stable id (e.g. `"FAB-prod"`).
    pub group_id: String,
    /// Tenant.
    pub tenant_id: String,
    /// Primary region.
    pub primary_region: String,
    /// Secondaries.
    pub replicas: Vec<RegionReplica>,
    /// RFC 3339 created.
    pub created_at: String,
}

impl ReplicationGroup {
    /// Find replica by region.
    pub fn replica(&self, region: &str) -> Option<&RegionReplica> {
        self.replicas.iter().find(|r| r.region == region)
    }
    /// Number of unhealthy replicas.
    pub fn unhealthy_count(&self) -> usize {
        self.replicas
            .iter()
            .filter(|r| r.status == ReplicationStatus::Unhealthy)
            .count()
    }
    /// `true` if any replica is unhealthy.
    pub fn has_unhealthy(&self) -> bool {
        self.unhealthy_count() > 0
    }
    /// Worst-case lag across replicas.
    pub fn worst_lag_seconds(&self) -> i64 {
        self.replicas.iter().map(|r| r.lag_seconds).max().unwrap_or(0)
    }
}

// =============================================================================
// ReplicationRegistry
// =============================================================================

#[derive(Default)]
struct State {
    groups: HashMap<String, ReplicationGroup>,
}

/// Registry.
pub struct ReplicationRegistry {
    state: RwLock<State>,
}

impl Default for ReplicationRegistry {
    fn default() -> Self {
        Self {
            state: RwLock::new(State::default()),
        }
    }
}

impl std::fmt::Debug for ReplicationRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReplicationRegistry")
            .field("groups", &self.len())
            .finish()
    }
}

impl ReplicationRegistry {
    /// New empty.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a group.
    pub fn register(&self, g: ReplicationGroup) -> SandboxResult<()> {
        let mut s = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("replication registry poisoned".into()))?;
        if s.groups.contains_key(&g.group_id) {
            return Err(SandboxError::Other(format!(
                "group {} already registered",
                g.group_id
            )));
        }
        s.groups.insert(g.group_id.clone(), g);
        Ok(())
    }

    /// Add a replica region.
    pub fn add_replica(&self, group_id: &str, replica: RegionReplica) -> SandboxResult<()> {
        let mut s = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("replication registry poisoned".into()))?;
        let g = s
            .groups
            .get_mut(group_id)
            .ok_or_else(|| SandboxError::Other(format!("group {} not found", group_id)))?;
        if g.replicas.iter().any(|r| r.region == replica.region) {
            return Err(SandboxError::Other(format!(
                "replica {} already registered",
                replica.region
            )));
        }
        if g.primary_region == replica.region {
            return Err(SandboxError::Other(format!(
                "replica region cannot equal primary {}",
                replica.region
            )));
        }
        g.replicas.push(replica);
        Ok(())
    }

    /// Record a successful replication update.
    pub fn record_success(
        &self,
        group_id: &str,
        region: &str,
        last_id: Uuid,
        lag_seconds: i64,
    ) -> SandboxResult<()> {
        let mut s = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("replication registry poisoned".into()))?;
        let g = s
            .groups
            .get_mut(group_id)
            .ok_or_else(|| SandboxError::Other(format!("group {} not found", group_id)))?;
        let r = g
            .replicas
            .iter_mut()
            .find(|r| r.region == region)
            .ok_or_else(|| SandboxError::Other(format!("region {} not in group", region)))?;
        r.last_replicated_id = Some(last_id);
        r.last_replicated_at = Some(
            OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
        );
        r.lag_seconds = lag_seconds.max(0);
        r.last_error = None;
        r.recompute_status();
        Ok(())
    }

    /// Record an error.
    pub fn record_error(
        &self,
        group_id: &str,
        region: &str,
        error: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut s = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("replication registry poisoned".into()))?;
        let g = s
            .groups
            .get_mut(group_id)
            .ok_or_else(|| SandboxError::Other(format!("group {} not found", group_id)))?;
        let r = g
            .replicas
            .iter_mut()
            .find(|r| r.region == region)
            .ok_or_else(|| SandboxError::Other(format!("region {} not in group", region)))?;
        r.last_error = Some(error.into());
        r.recompute_status();
        Ok(())
    }

    /// Set mode (e.g. pause).
    pub fn set_mode(
        &self,
        group_id: &str,
        region: &str,
        mode: ReplicationMode,
    ) -> SandboxResult<()> {
        let mut s = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("replication registry poisoned".into()))?;
        let g = s
            .groups
            .get_mut(group_id)
            .ok_or_else(|| SandboxError::Other(format!("group {} not found", group_id)))?;
        let r = g
            .replicas
            .iter_mut()
            .find(|r| r.region == region)
            .ok_or_else(|| SandboxError::Other(format!("region {} not in group", region)))?;
        r.mode = mode;
        r.recompute_status();
        Ok(())
    }

    /// Promote a region to primary (failover).
    pub fn promote_to_primary(&self, group_id: &str, region: &str) -> SandboxResult<()> {
        let mut s = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("replication registry poisoned".into()))?;
        let g = s
            .groups
            .get_mut(group_id)
            .ok_or_else(|| SandboxError::Other(format!("group {} not found", group_id)))?;
        if !g.replicas.iter().any(|r| r.region == region) {
            return Err(SandboxError::Other(format!(
                "region {} not a replica of group {}",
                region, group_id
            )));
        }
        // Promote: old primary becomes a replica, requested region becomes primary.
        let old_primary = g.primary_region.clone();
        g.primary_region = region.to_string();
        // Remove the new primary from replicas, add the old primary.
        g.replicas.retain(|r| r.region != region);
        g.replicas.push(RegionReplica {
            region: old_primary,
            mode: ReplicationMode::Async,
            last_replicated_id: None,
            last_replicated_at: None,
            lag_seconds: 0,
            max_lag_seconds: 60,
            status: ReplicationStatus::Healthy,
            last_error: None,
        });
        Ok(())
    }

    /// Lookup.
    pub fn get(&self, id: &str) -> Option<ReplicationGroup> {
        self.state.read().ok()?.groups.get(id).cloned()
    }
    /// All.
    pub fn all(&self) -> Vec<ReplicationGroup> {
        self.state
            .read()
            .map(|g| g.groups.values().cloned().collect())
            .unwrap_or_default()
    }
    /// Groups for a tenant.
    pub fn for_tenant(&self, tenant: &str) -> Vec<ReplicationGroup> {
        self.all().into_iter().filter(|g| g.tenant_id == tenant).collect()
    }
    /// All groups with any unhealthy replica.
    pub fn unhealthy_groups(&self) -> Vec<ReplicationGroup> {
        self.all().into_iter().filter(|g| g.has_unhealthy()).collect()
    }
    /// Count.
    pub fn len(&self) -> usize {
        self.state.read().map(|g| g.groups.len()).unwrap_or(0)
    }
    /// Empty?
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn group() -> ReplicationGroup {
        ReplicationGroup {
            group_id: "FAB-prod".into(),
            tenant_id: "FAB".into(),
            primary_region: "eu-west-1".into(),
            replicas: vec![],
            created_at: OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
        }
    }

    fn replica(region: &str) -> RegionReplica {
        RegionReplica {
            region: region.into(),
            mode: ReplicationMode::Async,
            last_replicated_id: None,
            last_replicated_at: None,
            lag_seconds: 0,
            max_lag_seconds: 60,
            status: ReplicationStatus::Healthy,
            last_error: None,
        }
    }

    #[test]
    fn register_creates_group() {
        let r = ReplicationRegistry::new();
        r.register(group()).unwrap();
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn duplicate_register_errors() {
        let r = ReplicationRegistry::new();
        r.register(group()).unwrap();
        assert!(r.register(group()).is_err());
    }

    #[test]
    fn add_replica_succeeds() {
        let r = ReplicationRegistry::new();
        r.register(group()).unwrap();
        r.add_replica("FAB-prod", replica("eu-central-1")).unwrap();
        assert_eq!(r.get("FAB-prod").unwrap().replicas.len(), 1);
    }

    #[test]
    fn add_duplicate_replica_errors() {
        let r = ReplicationRegistry::new();
        r.register(group()).unwrap();
        r.add_replica("FAB-prod", replica("eu-central-1")).unwrap();
        assert!(r.add_replica("FAB-prod", replica("eu-central-1")).is_err());
    }

    #[test]
    fn add_replica_equal_to_primary_errors() {
        let r = ReplicationRegistry::new();
        r.register(group()).unwrap();
        assert!(r.add_replica("FAB-prod", replica("eu-west-1")).is_err());
    }

    #[test]
    fn record_success_updates() {
        let r = ReplicationRegistry::new();
        r.register(group()).unwrap();
        r.add_replica("FAB-prod", replica("eu-central-1")).unwrap();
        r.record_success("FAB-prod", "eu-central-1", Uuid::now_v7(), 5)
            .unwrap();
        let g = r.get("FAB-prod").unwrap();
        let rep = g.replica("eu-central-1").unwrap();
        assert!(rep.last_replicated_id.is_some());
        assert_eq!(rep.lag_seconds, 5);
    }

    #[test]
    fn lag_within_half_max_is_healthy() {
        let r = ReplicationRegistry::new();
        r.register(group()).unwrap();
        r.add_replica("FAB-prod", replica("eu-central-1")).unwrap();
        r.record_success("FAB-prod", "eu-central-1", Uuid::now_v7(), 20)
            .unwrap();
        let g = r.get("FAB-prod").unwrap();
        let rep = g.replica("eu-central-1").unwrap();
        assert_eq!(rep.status, ReplicationStatus::Healthy);
    }

    #[test]
    fn lag_above_half_lagging() {
        let r = ReplicationRegistry::new();
        r.register(group()).unwrap();
        r.add_replica("FAB-prod", replica("eu-central-1")).unwrap();
        r.record_success("FAB-prod", "eu-central-1", Uuid::now_v7(), 45)
            .unwrap();
        let g = r.get("FAB-prod").unwrap();
        assert_eq!(
            g.replica("eu-central-1").unwrap().status,
            ReplicationStatus::Lagging
        );
    }

    #[test]
    fn lag_above_max_unhealthy() {
        let r = ReplicationRegistry::new();
        r.register(group()).unwrap();
        r.add_replica("FAB-prod", replica("eu-central-1")).unwrap();
        r.record_success("FAB-prod", "eu-central-1", Uuid::now_v7(), 120)
            .unwrap();
        let g = r.get("FAB-prod").unwrap();
        assert_eq!(
            g.replica("eu-central-1").unwrap().status,
            ReplicationStatus::Unhealthy
        );
    }

    #[test]
    fn record_error_recomputes() {
        let r = ReplicationRegistry::new();
        r.register(group()).unwrap();
        r.add_replica("FAB-prod", replica("eu-central-1")).unwrap();
        r.record_error("FAB-prod", "eu-central-1", "timeout").unwrap();
        let g = r.get("FAB-prod").unwrap();
        assert_eq!(
            g.replica("eu-central-1").unwrap().last_error.as_deref(),
            Some("timeout")
        );
    }

    #[test]
    fn paused_mode_sets_paused_status() {
        let r = ReplicationRegistry::new();
        r.register(group()).unwrap();
        r.add_replica("FAB-prod", replica("eu-central-1")).unwrap();
        r.set_mode("FAB-prod", "eu-central-1", ReplicationMode::Paused).unwrap();
        assert_eq!(
            r.get("FAB-prod").unwrap().replica("eu-central-1").unwrap().status,
            ReplicationStatus::Paused
        );
    }

    #[test]
    fn promote_to_primary_swaps() {
        let r = ReplicationRegistry::new();
        r.register(group()).unwrap();
        r.add_replica("FAB-prod", replica("eu-central-1")).unwrap();
        r.promote_to_primary("FAB-prod", "eu-central-1").unwrap();
        let g = r.get("FAB-prod").unwrap();
        assert_eq!(g.primary_region, "eu-central-1");
        assert!(g.replicas.iter().any(|r| r.region == "eu-west-1"));
    }

    #[test]
    fn promote_unknown_errors() {
        let r = ReplicationRegistry::new();
        r.register(group()).unwrap();
        assert!(r.promote_to_primary("FAB-prod", "ghost").is_err());
    }

    #[test]
    fn unhealthy_groups_filter() {
        let r = ReplicationRegistry::new();
        r.register(group()).unwrap();
        r.add_replica("FAB-prod", replica("eu-central-1")).unwrap();
        r.record_success("FAB-prod", "eu-central-1", Uuid::now_v7(), 200)
            .unwrap();
        let unhealthy = r.unhealthy_groups();
        assert_eq!(unhealthy.len(), 1);
    }

    #[test]
    fn worst_lag_picks_max() {
        let r = ReplicationRegistry::new();
        r.register(group()).unwrap();
        r.add_replica("FAB-prod", replica("eu-central-1")).unwrap();
        r.add_replica("FAB-prod", replica("us-east-1")).unwrap();
        r.record_success("FAB-prod", "eu-central-1", Uuid::now_v7(), 5)
            .unwrap();
        r.record_success("FAB-prod", "us-east-1", Uuid::now_v7(), 100)
            .unwrap();
        let g = r.get("FAB-prod").unwrap();
        assert_eq!(g.worst_lag_seconds(), 100);
    }

    #[test]
    fn for_tenant_filters() {
        let r = ReplicationRegistry::new();
        r.register(group()).unwrap();
        let mut other = group();
        other.group_id = "ENBD-prod".into();
        other.tenant_id = "ENBD".into();
        r.register(other).unwrap();
        assert_eq!(r.for_tenant("FAB").len(), 1);
        assert_eq!(r.for_tenant("ENBD").len(), 1);
    }

    #[test]
    fn group_serde() {
        let g = group();
        let j = serde_json::to_string(&g).unwrap();
        let p: ReplicationGroup = serde_json::from_str(&j).unwrap();
        assert_eq!(p, g);
    }

    #[test]
    fn replica_serde() {
        let r = replica("x");
        let j = serde_json::to_string(&r).unwrap();
        let p: RegionReplica = serde_json::from_str(&j).unwrap();
        assert_eq!(p, r);
    }

    #[test]
    fn mode_serde() {
        for m in [
            ReplicationMode::Sync,
            ReplicationMode::Async,
            ReplicationMode::CatchUp,
            ReplicationMode::Paused,
        ] {
            let j = serde_json::to_string(&m).unwrap();
            let p: ReplicationMode = serde_json::from_str(&j).unwrap();
            assert_eq!(p, m);
        }
    }

    #[test]
    fn status_serde() {
        for s in [
            ReplicationStatus::Healthy,
            ReplicationStatus::Lagging,
            ReplicationStatus::Unhealthy,
            ReplicationStatus::Paused,
        ] {
            let j = serde_json::to_string(&s).unwrap();
            let p: ReplicationStatus = serde_json::from_str(&j).unwrap();
            assert_eq!(p, s);
        }
    }

    #[test]
    fn unknown_group_lookups_none() {
        let r = ReplicationRegistry::new();
        assert!(r.get("ghost").is_none());
    }

    #[test]
    fn record_success_unknown_group_errors() {
        let r = ReplicationRegistry::new();
        assert!(r
            .record_success("ghost", "x", Uuid::now_v7(), 0)
            .is_err());
    }

    #[test]
    fn record_success_unknown_region_errors() {
        let r = ReplicationRegistry::new();
        r.register(group()).unwrap();
        assert!(r
            .record_success("FAB-prod", "ghost", Uuid::now_v7(), 0)
            .is_err());
    }

    #[test]
    fn count_tracks() {
        let r = ReplicationRegistry::new();
        assert!(r.is_empty());
        r.register(group()).unwrap();
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn unhealthy_count_zero_for_healthy() {
        let r = ReplicationRegistry::new();
        r.register(group()).unwrap();
        r.add_replica("FAB-prod", replica("eu-central-1")).unwrap();
        let g = r.get("FAB-prod").unwrap();
        assert_eq!(g.unhealthy_count(), 0);
    }
}
