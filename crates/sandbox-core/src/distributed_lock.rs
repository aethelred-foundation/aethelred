//! Distributed lock primitives for multi-instance sandbox deployments.
//!
//! High-availability deployments run multiple sandbox replicas behind a load
//! balancer. Some operations must be **serialized across replicas**:
//!
//! - Key rotation (only one rotation can run at a time per KEK).
//! - Backup execution (one backup per tenant per period).
//! - Schema migration (one V1→V2 walker).
//! - Retention purge (one purge per tenant).
//!
//! This module models a *fencing-token-aware* lock interface following the
//! Martin Kleppmann pattern: each `acquire` returns a monotonically
//! increasing fence token; resources protected by the lock must reject any
//! request with a token less than the latest seen for that resource. This
//! fence prevents zombie clients (stale-lease holders) from making
//! conflicting writes after a network partition.
//!
//! ## Pluggable backend
//!
//! [`LockBackend`] is a trait — production wires up Redis/Redlock,
//! Etcd, Consul, or ZooKeeper. The default [`InMemoryLockBackend`] is for
//! tests and single-instance deployments.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use uuid::Uuid;

// =============================================================================
// LockResource
// =============================================================================

/// Stable name for a resource being locked.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct LockResource(pub String);

impl LockResource {
    /// New name.
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
    /// As `&str`.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// =============================================================================
// LeaseToken + FenceToken
// =============================================================================

/// Fence token — strictly increasing per resource. Resources reject any
/// access whose fence is less than the latest seen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FenceToken(pub u64);

/// Lease — proof that a holder owns the lock until `expires_at_micros`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lease {
    /// Resource locked.
    pub resource: LockResource,
    /// Holder's id.
    pub holder_id: String,
    /// Lease id.
    pub lease_id: Uuid,
    /// Fence token.
    pub fence: FenceToken,
    /// Microseconds since `Instant::now()` when lease expires (relative).
    /// Production code uses an absolute clock — this is intentionally
    /// monotonic-ish for test determinism.
    pub expires_at_micros: u128,
}

// =============================================================================
// LockBackend trait
// =============================================================================

/// Pluggable lock backend.
pub trait LockBackend: Send + Sync {
    /// Backend name (`"in-memory"`, `"redis-redlock"`, ...).
    fn backend_name(&self) -> &str;

    /// Try to acquire `resource` for `holder_id` with a `lease_ttl`.
    /// Returns `None` if the lock is currently held by someone else with a
    /// non-expired lease.
    fn try_acquire(
        &self,
        resource: &LockResource,
        holder_id: &str,
        lease_ttl: Duration,
    ) -> SandboxResult<Option<Lease>>;

    /// Renew an existing lease.
    fn renew(&self, lease: &Lease, lease_ttl: Duration) -> SandboxResult<Option<Lease>>;

    /// Release the lock.
    fn release(&self, lease: &Lease) -> SandboxResult<()>;

    /// Currently active lease for the resource, if any.
    fn current_lease(&self, resource: &LockResource) -> Option<Lease>;

    /// Latest fence token issued for this resource.
    fn latest_fence(&self, resource: &LockResource) -> FenceToken;
}

// =============================================================================
// InMemoryLockBackend
// =============================================================================

#[derive(Debug)]
struct LockEntry {
    holder_id: String,
    lease_id: Uuid,
    fence: FenceToken,
    /// Monotonic timestamp when the lease expires.
    expires_at: Instant,
}

#[derive(Debug, Default)]
struct InMemoryState {
    locks: HashMap<LockResource, LockEntry>,
    /// Per-resource fence counter — strictly increasing.
    fences: HashMap<LockResource, u64>,
}

/// In-memory backend (single-instance / test).
#[derive(Debug, Default)]
pub struct InMemoryLockBackend {
    state: Mutex<InMemoryState>,
}

impl InMemoryLockBackend {
    /// New empty backend.
    pub fn new() -> Self {
        Self::default()
    }
}

impl LockBackend for InMemoryLockBackend {
    fn backend_name(&self) -> &str {
        "in-memory"
    }

    fn try_acquire(
        &self,
        resource: &LockResource,
        holder_id: &str,
        lease_ttl: Duration,
    ) -> SandboxResult<Option<Lease>> {
        let mut g = self
            .state
            .lock()
            .map_err(|_| SandboxError::Other("lock backend poisoned".into()))?;
        let now = Instant::now();
        // Check current entry.
        if let Some(entry) = g.locks.get(resource) {
            if entry.expires_at > now {
                return Ok(None);
            }
        }
        // Allocate a fresh fence token.
        let next_fence = {
            let counter = g.fences.entry(resource.clone()).or_insert(0);
            *counter += 1;
            FenceToken(*counter)
        };
        let lease_id = Uuid::now_v7();
        let expires_at = now + lease_ttl;
        g.locks.insert(
            resource.clone(),
            LockEntry {
                holder_id: holder_id.to_string(),
                lease_id,
                fence: next_fence,
                expires_at,
            },
        );
        Ok(Some(Lease {
            resource: resource.clone(),
            holder_id: holder_id.to_string(),
            lease_id,
            fence: next_fence,
            expires_at_micros: lease_ttl.as_micros(),
        }))
    }

    fn renew(&self, lease: &Lease, lease_ttl: Duration) -> SandboxResult<Option<Lease>> {
        let mut g = self
            .state
            .lock()
            .map_err(|_| SandboxError::Other("lock backend poisoned".into()))?;
        let entry = match g.locks.get_mut(&lease.resource) {
            Some(e) => e,
            None => return Ok(None),
        };
        if entry.lease_id != lease.lease_id {
            return Ok(None); // someone else owns it now
        }
        entry.expires_at = Instant::now() + lease_ttl;
        Ok(Some(Lease {
            resource: lease.resource.clone(),
            holder_id: entry.holder_id.clone(),
            lease_id: entry.lease_id,
            fence: entry.fence,
            expires_at_micros: lease_ttl.as_micros(),
        }))
    }

    fn release(&self, lease: &Lease) -> SandboxResult<()> {
        let mut g = self
            .state
            .lock()
            .map_err(|_| SandboxError::Other("lock backend poisoned".into()))?;
        if let Some(entry) = g.locks.get(&lease.resource) {
            if entry.lease_id == lease.lease_id {
                g.locks.remove(&lease.resource);
            }
        }
        Ok(())
    }

    fn current_lease(&self, resource: &LockResource) -> Option<Lease> {
        let g = self.state.lock().ok()?;
        let entry = g.locks.get(resource)?;
        Some(Lease {
            resource: resource.clone(),
            holder_id: entry.holder_id.clone(),
            lease_id: entry.lease_id,
            fence: entry.fence,
            expires_at_micros: 0,
        })
    }

    fn latest_fence(&self, resource: &LockResource) -> FenceToken {
        self.state
            .lock()
            .ok()
            .and_then(|g| g.fences.get(resource).copied())
            .map(FenceToken)
            .unwrap_or(FenceToken(0))
    }
}

// =============================================================================
// FenceGuard — protects resources from stale-fence requests
// =============================================================================

/// Tracks the highest fence token seen per resource. Resources protected by
/// a lock must consult this guard to reject stale requests.
#[derive(Debug, Default)]
pub struct FenceGuard {
    inner: Mutex<HashMap<LockResource, FenceToken>>,
}

impl FenceGuard {
    /// New empty guard.
    pub fn new() -> Self {
        Self::default()
    }

    /// Verify a request with `fence` for `resource`. If `fence >= last_seen`,
    /// updates last_seen and returns Ok. Otherwise rejects.
    pub fn check_and_advance(
        &self,
        resource: &LockResource,
        fence: FenceToken,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .lock()
            .map_err(|_| SandboxError::Other("fence guard poisoned".into()))?;
        let cur = g.entry(resource.clone()).or_insert(FenceToken(0));
        if fence < *cur {
            return Err(SandboxError::Other(format!(
                "stale fence {} < {} for {}",
                fence.0,
                cur.0,
                resource.as_str()
            )));
        }
        *cur = fence;
        Ok(())
    }

    /// Read latest seen.
    pub fn latest(&self, resource: &LockResource) -> FenceToken {
        self.inner
            .lock()
            .ok()
            .and_then(|g| g.get(resource).copied())
            .unwrap_or(FenceToken(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(s: &str) -> LockResource {
        LockResource::new(s)
    }

    #[test]
    fn acquire_uncontended_succeeds() {
        let b = InMemoryLockBackend::new();
        let l = b
            .try_acquire(&r("rotation"), "node-1", Duration::from_secs(10))
            .unwrap();
        assert!(l.is_some());
    }

    #[test]
    fn second_acquire_blocked_while_held() {
        let b = InMemoryLockBackend::new();
        b.try_acquire(&r("x"), "n1", Duration::from_secs(10))
            .unwrap();
        let second = b.try_acquire(&r("x"), "n2", Duration::from_secs(10)).unwrap();
        assert!(second.is_none());
    }

    #[test]
    fn release_unblocks_others() {
        let b = InMemoryLockBackend::new();
        let l1 = b
            .try_acquire(&r("x"), "n1", Duration::from_secs(10))
            .unwrap()
            .unwrap();
        b.release(&l1).unwrap();
        let l2 = b.try_acquire(&r("x"), "n2", Duration::from_secs(10)).unwrap();
        assert!(l2.is_some());
    }

    #[test]
    fn fence_token_strictly_increases() {
        let b = InMemoryLockBackend::new();
        let l1 = b
            .try_acquire(&r("x"), "n1", Duration::from_millis(1))
            .unwrap()
            .unwrap();
        std::thread::sleep(Duration::from_millis(5));
        let l2 = b
            .try_acquire(&r("x"), "n2", Duration::from_secs(10))
            .unwrap()
            .unwrap();
        assert!(l2.fence > l1.fence);
    }

    #[test]
    fn renew_extends_lease() {
        let b = InMemoryLockBackend::new();
        let l = b
            .try_acquire(&r("x"), "n1", Duration::from_millis(10))
            .unwrap()
            .unwrap();
        let renewed = b.renew(&l, Duration::from_secs(60)).unwrap();
        assert!(renewed.is_some());
    }

    #[test]
    fn renew_after_takeover_fails() {
        let b = InMemoryLockBackend::new();
        let l1 = b
            .try_acquire(&r("x"), "n1", Duration::from_millis(1))
            .unwrap()
            .unwrap();
        std::thread::sleep(Duration::from_millis(5));
        b.try_acquire(&r("x"), "n2", Duration::from_secs(10)).unwrap();
        // n1's renew should fail.
        assert!(b.renew(&l1, Duration::from_secs(10)).unwrap().is_none());
    }

    #[test]
    fn release_unknown_lease_no_op() {
        let b = InMemoryLockBackend::new();
        let fake = Lease {
            resource: r("x"),
            holder_id: "fake".into(),
            lease_id: Uuid::now_v7(),
            fence: FenceToken(1),
            expires_at_micros: 0,
        };
        b.release(&fake).unwrap();
    }

    #[test]
    fn release_other_lease_does_not_affect() {
        let b = InMemoryLockBackend::new();
        let l1 = b
            .try_acquire(&r("x"), "n1", Duration::from_secs(10))
            .unwrap()
            .unwrap();
        // Build a fake lease for the same resource but different lease_id.
        let fake = Lease {
            resource: r("x"),
            holder_id: "fake".into(),
            lease_id: Uuid::now_v7(),
            fence: FenceToken(1),
            expires_at_micros: 0,
        };
        b.release(&fake).unwrap();
        // Original lease should still be valid.
        let cur = b.current_lease(&r("x")).unwrap();
        assert_eq!(cur.lease_id, l1.lease_id);
    }

    #[test]
    fn current_lease_returns_holder() {
        let b = InMemoryLockBackend::new();
        b.try_acquire(&r("x"), "n1", Duration::from_secs(10)).unwrap();
        let cur = b.current_lease(&r("x")).unwrap();
        assert_eq!(cur.holder_id, "n1");
    }

    #[test]
    fn latest_fence_starts_at_zero() {
        let b = InMemoryLockBackend::new();
        assert_eq!(b.latest_fence(&r("x")), FenceToken(0));
    }

    #[test]
    fn latest_fence_after_acquire() {
        let b = InMemoryLockBackend::new();
        b.try_acquire(&r("x"), "n1", Duration::from_secs(1)).unwrap();
        assert_eq!(b.latest_fence(&r("x")), FenceToken(1));
    }

    #[test]
    fn fence_guard_advances_with_higher() {
        let g = FenceGuard::new();
        g.check_and_advance(&r("x"), FenceToken(5)).unwrap();
        g.check_and_advance(&r("x"), FenceToken(10)).unwrap();
        assert_eq!(g.latest(&r("x")), FenceToken(10));
    }

    #[test]
    fn fence_guard_rejects_stale() {
        let g = FenceGuard::new();
        g.check_and_advance(&r("x"), FenceToken(10)).unwrap();
        let err = g.check_and_advance(&r("x"), FenceToken(5)).expect_err("stale");
        assert!(format!("{err}").contains("stale fence"));
    }

    #[test]
    fn fence_guard_accepts_equal_fence() {
        let g = FenceGuard::new();
        g.check_and_advance(&r("x"), FenceToken(5)).unwrap();
        g.check_and_advance(&r("x"), FenceToken(5)).unwrap();
    }

    #[test]
    fn fence_guard_isolated_per_resource() {
        let g = FenceGuard::new();
        g.check_and_advance(&r("x"), FenceToken(10)).unwrap();
        g.check_and_advance(&r("y"), FenceToken(1)).unwrap();
    }

    #[test]
    fn lease_expiry_unblocks_after_ttl() {
        let b = InMemoryLockBackend::new();
        b.try_acquire(&r("x"), "n1", Duration::from_millis(1)).unwrap();
        std::thread::sleep(Duration::from_millis(10));
        let l2 = b.try_acquire(&r("x"), "n2", Duration::from_secs(1)).unwrap();
        assert!(l2.is_some());
    }

    #[test]
    fn many_resources_independent() {
        let b = InMemoryLockBackend::new();
        let l1 = b
            .try_acquire(&r("rot"), "n1", Duration::from_secs(10))
            .unwrap();
        let l2 = b
            .try_acquire(&r("backup"), "n2", Duration::from_secs(10))
            .unwrap();
        assert!(l1.is_some());
        assert!(l2.is_some());
    }

    #[test]
    fn fence_token_serde_round_trip() {
        let f = FenceToken(42);
        let j = serde_json::to_string(&f).unwrap();
        let p: FenceToken = serde_json::from_str(&j).unwrap();
        assert_eq!(p, f);
    }

    #[test]
    fn lock_resource_serde_transparent() {
        let r = LockResource::new("x");
        let j = serde_json::to_string(&r).unwrap();
        assert_eq!(j, "\"x\"");
    }

    #[test]
    fn lease_serde_round_trip() {
        let l = Lease {
            resource: r("x"),
            holder_id: "n".into(),
            lease_id: Uuid::now_v7(),
            fence: FenceToken(1),
            expires_at_micros: 100,
        };
        let j = serde_json::to_string(&l).unwrap();
        let _: Lease = serde_json::from_str(&j).unwrap();
    }

    #[test]
    fn backend_name_in_memory() {
        let b = InMemoryLockBackend::new();
        assert_eq!(b.backend_name(), "in-memory");
    }

    #[test]
    fn fence_increments_across_handoffs() {
        let b = InMemoryLockBackend::new();
        let l1 = b
            .try_acquire(&r("x"), "n1", Duration::from_millis(1))
            .unwrap()
            .unwrap();
        std::thread::sleep(Duration::from_millis(5));
        let l2 = b
            .try_acquire(&r("x"), "n2", Duration::from_millis(1))
            .unwrap()
            .unwrap();
        std::thread::sleep(Duration::from_millis(5));
        let l3 = b
            .try_acquire(&r("x"), "n3", Duration::from_secs(10))
            .unwrap()
            .unwrap();
        assert!(l1.fence < l2.fence && l2.fence < l3.fence);
    }
}
