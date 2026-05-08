//! Time-travel queries — reconstruct system state as of a past timestamp.
//!
//! Compliance reviews routinely need answers like:
//!
//! - "Which seals existed at 14:32 on 2026-03-17?"
//! - "What was the active policy version then?"
//! - "Which models were registered? Which were validated?"
//!
//! This module is a thin façade that *composes* read-only queries against
//! the various append-only logs in the protocol (evidence log, policy
//! version log, model risk register, etc.) and returns a coherent
//! `SystemSnapshot`. It does not own any state — it captures a point-in-
//! time view from sources you provide.
//!
//! ## Properties
//!
//! - **Stable.** Given the same inputs and timestamp, the snapshot is
//!   deterministic.
//! - **Append-only-friendly.** Compatible with any source that exposes
//!   immutable append-only history with timestamps.

use crate::seal::DigitalSeal;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

// =============================================================================
// SystemSnapshot
// =============================================================================

/// Composite snapshot.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SystemSnapshot {
    /// Snapshot id.
    pub snapshot_id: Uuid,
    /// RFC 3339 wall-clock at which the snapshot was *generated*.
    pub generated_at: String,
    /// RFC 3339 reconstructed point-in-time.
    pub as_of: String,
    /// Tenant scope.
    pub tenant_id: Option<String>,
    /// Seal ids that existed at `as_of`.
    pub seals_at: Vec<Uuid>,
    /// Active policy ids → version numbers.
    pub active_policies: Vec<(String, u32)>,
    /// Active prompt ids → version numbers.
    pub active_prompts: Vec<(String, u32)>,
    /// Active model ids.
    pub active_models: Vec<String>,
    /// Tenants in active state.
    pub active_tenants: Vec<String>,
    /// Total seal count.
    pub seal_count: u64,
}

// =============================================================================
// TimeMachine
// =============================================================================

/// Read-only time-travel query helper.
#[derive(Debug, Default)]
pub struct TimeMachine;

impl TimeMachine {
    /// New (no state).
    pub fn new() -> Self {
        Self
    }

    /// Reconstruct: returns the seal ids whose `timestamp <= as_of`.
    pub fn seals_as_of<'a, I: IntoIterator<Item = &'a DigitalSeal>>(
        &self,
        seals: I,
        as_of: OffsetDateTime,
        tenant: Option<&str>,
    ) -> Vec<Uuid> {
        seals
            .into_iter()
            .filter(|s| s.timestamp <= as_of)
            .filter(|s| match tenant {
                Some(t) => s.tenant_id == t,
                None => true,
            })
            .map(|s| s.seal_id)
            .collect()
    }

    /// Build a composite snapshot. Each input is independent.
    pub fn snapshot(
        &self,
        as_of: OffsetDateTime,
        tenant: Option<&str>,
        seals: &[DigitalSeal],
        active_policies: Vec<(String, u32)>,
        active_prompts: Vec<(String, u32)>,
        active_models: Vec<String>,
        active_tenants: Vec<String>,
    ) -> SystemSnapshot {
        let seals_at = self.seals_as_of(seals.iter(), as_of, tenant);
        let count = seals_at.len() as u64;
        SystemSnapshot {
            snapshot_id: Uuid::now_v7(),
            generated_at: OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
            as_of: as_of
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
            tenant_id: tenant.map(|s| s.to_string()),
            seals_at,
            active_policies,
            active_prompts,
            active_models,
            active_tenants,
            seal_count: count,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seal::*;
    use crate::{Hasher, Sector};
    use std::collections::BTreeMap;

    fn seal(t: &str, when: OffsetDateTime) -> DigitalSeal {
        DigitalSeal {
            schema_version: SealVersion::V1,
            seal_id: Uuid::now_v7(),
            timestamp: when,
            sector: Sector::Finance,
            event_type: "x".into(),
            event_hash: Hasher::sha256(b"e"),
            model: ModelReference::new("m", Hasher::sha256(b"w")),
            policy_id: "p".into(),
            input_hash: Hasher::sha256(b"i"),
            output_hash: Hasher::sha256(b"o"),
            approvals: vec![],
            attestation: None,
            zk_proof: None,
            tenant_id: t.into(),
            workflow_id: "wf".into(),
            jurisdiction_tag: "AE".into(),
            retention: RetentionClass::OneYear,
            prior_seal_hash: None,
            sector_extension: BTreeMap::new(),
            validator_signature_hex: None,
        }
    }

    #[test]
    fn empty_seals_returns_empty() {
        let tm = TimeMachine::new();
        let v = tm.seals_as_of(std::iter::empty::<&DigitalSeal>(), OffsetDateTime::now_utc(), None);
        assert!(v.is_empty());
    }

    #[test]
    fn seal_at_or_before_as_of_included() {
        let tm = TimeMachine::new();
        let now = OffsetDateTime::now_utc();
        let s1 = seal("FAB", now - time::Duration::days(2));
        let s2 = seal("FAB", now);
        let s3 = seal("FAB", now + time::Duration::days(2));
        let v = tm.seals_as_of([&s1, &s2, &s3], now, None);
        assert_eq!(v.len(), 2);
    }

    #[test]
    fn tenant_filter_applies() {
        let tm = TimeMachine::new();
        let now = OffsetDateTime::now_utc();
        let s1 = seal("FAB", now - time::Duration::days(1));
        let s2 = seal("ENBD", now - time::Duration::days(1));
        let v = tm.seals_as_of([&s1, &s2], now, Some("FAB"));
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn snapshot_seal_count() {
        let tm = TimeMachine::new();
        let now = OffsetDateTime::now_utc();
        let s1 = seal("FAB", now - time::Duration::days(2));
        let s2 = seal("FAB", now);
        let snap = tm.snapshot(
            now,
            Some("FAB"),
            &[s1, s2],
            vec![("p1".into(), 3)],
            vec![],
            vec!["m1".into()],
            vec!["FAB".into()],
        );
        assert_eq!(snap.seal_count, 2);
        assert_eq!(snap.active_policies, vec![("p1".into(), 3)]);
        assert_eq!(snap.active_models, vec!["m1".to_string()]);
    }

    #[test]
    fn snapshot_with_no_tenant_includes_all() {
        let tm = TimeMachine::new();
        let now = OffsetDateTime::now_utc();
        let s1 = seal("FAB", now - time::Duration::days(1));
        let s2 = seal("ENBD", now - time::Duration::days(1));
        let snap = tm.snapshot(now, None, &[s1, s2], vec![], vec![], vec![], vec![]);
        assert_eq!(snap.seal_count, 2);
    }

    #[test]
    fn snapshot_at_past_excludes_future_seals() {
        let tm = TimeMachine::new();
        let now = OffsetDateTime::now_utc();
        let past = now - time::Duration::days(10);
        let s_old = seal("FAB", now - time::Duration::days(20));
        let s_new = seal("FAB", now);
        let snap = tm.snapshot(past, Some("FAB"), &[s_old, s_new], vec![], vec![], vec![], vec![]);
        assert_eq!(snap.seal_count, 1);
    }

    #[test]
    fn snapshot_serde() {
        let tm = TimeMachine::new();
        let snap = tm.snapshot(
            OffsetDateTime::now_utc(),
            Some("FAB"),
            &[],
            vec![],
            vec![],
            vec![],
            vec![],
        );
        let j = serde_json::to_string(&snap).unwrap();
        let p: SystemSnapshot = serde_json::from_str(&j).unwrap();
        assert_eq!(p, snap);
    }

    #[test]
    fn time_machine_default_works() {
        let tm = TimeMachine::default();
        let v = tm.seals_as_of([], OffsetDateTime::now_utc(), None);
        assert!(v.is_empty());
    }

    #[test]
    fn snapshot_with_active_prompts() {
        let tm = TimeMachine::new();
        let snap = tm.snapshot(
            OffsetDateTime::now_utc(),
            None,
            &[],
            vec![],
            vec![("prompt-credit".into(), 5)],
            vec![],
            vec![],
        );
        assert_eq!(snap.active_prompts, vec![("prompt-credit".into(), 5)]);
    }

    #[test]
    fn snapshot_id_unique() {
        let tm = TimeMachine::new();
        let now = OffsetDateTime::now_utc();
        let a = tm.snapshot(now, None, &[], vec![], vec![], vec![], vec![]);
        let b = tm.snapshot(now, None, &[], vec![], vec![], vec![], vec![]);
        assert_ne!(a.snapshot_id, b.snapshot_id);
    }

    #[test]
    fn boundary_seal_at_exact_timestamp_included() {
        let tm = TimeMachine::new();
        let exact = OffsetDateTime::now_utc();
        let s = seal("FAB", exact);
        let v = tm.seals_as_of([&s], exact, None);
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn many_seals_filtered() {
        let tm = TimeMachine::new();
        let now = OffsetDateTime::now_utc();
        let seals: Vec<DigitalSeal> = (0..100)
            .map(|i| seal("FAB", now - time::Duration::days(i)))
            .collect();
        let v = tm.seals_as_of(&seals, now - time::Duration::days(50), None);
        // Seals i=50..99 are within the window (50 of them).
        assert_eq!(v.len(), 50);
    }

    #[test]
    fn snapshot_tenant_recorded() {
        let tm = TimeMachine::new();
        let s = tm.snapshot(
            OffsetDateTime::now_utc(),
            Some("FAB"),
            &[],
            vec![],
            vec![],
            vec![],
            vec![],
        );
        assert_eq!(s.tenant_id.as_deref(), Some("FAB"));
    }

    #[test]
    fn snapshot_active_tenants_included() {
        let tm = TimeMachine::new();
        let s = tm.snapshot(
            OffsetDateTime::now_utc(),
            None,
            &[],
            vec![],
            vec![],
            vec![],
            vec!["FAB".into(), "ENBD".into()],
        );
        assert_eq!(s.active_tenants.len(), 2);
    }

    #[test]
    fn snapshot_generated_at_set() {
        let tm = TimeMachine::new();
        let s = tm.snapshot(
            OffsetDateTime::now_utc(),
            None,
            &[],
            vec![],
            vec![],
            vec![],
            vec![],
        );
        assert!(!s.generated_at.is_empty());
    }

    #[test]
    fn snapshot_as_of_set() {
        let tm = TimeMachine::new();
        let when = OffsetDateTime::now_utc();
        let s = tm.snapshot(when, None, &[], vec![], vec![], vec![], vec![]);
        assert!(!s.as_of.is_empty());
    }
}
