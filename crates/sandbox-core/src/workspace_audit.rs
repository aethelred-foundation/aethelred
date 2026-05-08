//! Workspace audit log — operator-action evidence.
//!
//! Where [`crate::audit`] tells the AI-event story over [`crate::DigitalSeal`]s,
//! `workspace_audit` records *operator actions* on the sandbox itself:
//!
//! - RBAC changes (role assignments, role revocations).
//! - Key rotations (signer rotation, attestation key rotation).
//! - Tenant lifecycle (suspension, reactivation).
//! - Policy / configuration changes.
//! - Approval threshold changes.
//! - Connector enable/disable.
//!
//! These are the events SOC 2 / ISO 27001 auditors ask about during a
//! security review. They are distinct from AI-event seals — they describe
//! *who changed the system* rather than *what the system decided*.
//!
//! ## Tamper evidence
//!
//! Each [`WorkspaceAuditEntry`] carries `prior_entry_hash`. The full log is a
//! Merkle-style hash chain: an attacker who removes or rewrites any entry
//! breaks the chain at every entry that follows. The chain root is exposed
//! via [`WorkspaceAuditLog::chain_root`].
//!
//! ## Query
//!
//! [`WorkspaceAuditLog`] supports the queries auditors actually run:
//!
//! - `entries_by_actor(actor)` — "show me everything the SRE team did".
//! - `entries_by_event_kind(kind)` — "show me every key rotation".
//! - `entries_in_range(from, to)` — quarterly review.
//! - `entries_by_correlation(id)` — link related operator actions
//!   (a planned rotation usually fans out into several entries that share
//!   one correlation id).
//!
//! ## Export
//!
//! [`WorkspaceAuditLog::to_jsonl`] emits one entry per line for SIEM ingestion
//! (Splunk, Datadog, Elastic).

use crate::hashing::{Hasher, Sha256Digest};
use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::sync::RwLock;
use time::OffsetDateTime;
use uuid::Uuid;

// =============================================================================
// WorkspaceAuditEventKind / WorkspaceAuditEvent
// =============================================================================

/// Kind discriminant — used for filtering and indexing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceAuditEventKind {
    /// A principal was granted a role.
    RoleAssigned,
    /// A principal had a role removed.
    RoleRevoked,
    /// A signing or attestation key was rotated.
    KeyRotated,
    /// A tenant was suspended (writes blocked).
    TenantSuspended,
    /// A tenant was reactivated.
    TenantReactivated,
    /// A policy document was created or modified.
    PolicyChanged,
    /// Sandbox configuration changed.
    SandboxConfigChanged,
    /// An approval threshold (M-of-N) was modified.
    ApprovalThresholdChanged,
    /// A data connector was enabled.
    ConnectorEnabled,
    /// A data connector was disabled.
    ConnectorDisabled,
    /// A capability token was issued out-of-band.
    TokenIssued,
    /// A capability token was revoked.
    TokenRevoked,
    /// A legal hold was applied.
    LegalHoldApplied,
    /// A legal hold was released.
    LegalHoldReleased,
    /// Other / custom event — payload describes.
    Other,
}

impl WorkspaceAuditEventKind {
    /// Stable string label.
    pub fn label(self) -> &'static str {
        match self {
            Self::RoleAssigned => "role_assigned",
            Self::RoleRevoked => "role_revoked",
            Self::KeyRotated => "key_rotated",
            Self::TenantSuspended => "tenant_suspended",
            Self::TenantReactivated => "tenant_reactivated",
            Self::PolicyChanged => "policy_changed",
            Self::SandboxConfigChanged => "sandbox_config_changed",
            Self::ApprovalThresholdChanged => "approval_threshold_changed",
            Self::ConnectorEnabled => "connector_enabled",
            Self::ConnectorDisabled => "connector_disabled",
            Self::TokenIssued => "token_issued",
            Self::TokenRevoked => "token_revoked",
            Self::LegalHoldApplied => "legal_hold_applied",
            Self::LegalHoldReleased => "legal_hold_released",
            Self::Other => "other",
        }
    }
}

/// Concrete operator action.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkspaceAuditEvent {
    /// Kind discriminant.
    pub kind: WorkspaceAuditEventKind,
    /// One-line summary (e.g. "rotated signer key from kid=abc to kid=def").
    pub summary: String,
    /// Optional resource identifier (tenant id, principal, key id...).
    pub resource_id: Option<String>,
    /// Optional prior value (for change events).
    pub previous_value: Option<String>,
    /// Optional new value (for change events).
    pub new_value: Option<String>,
}

impl WorkspaceAuditEvent {
    /// New event with kind and summary.
    pub fn new(kind: WorkspaceAuditEventKind, summary: impl Into<String>) -> Self {
        Self {
            kind,
            summary: summary.into(),
            resource_id: None,
            previous_value: None,
            new_value: None,
        }
    }

    /// Builder: attach resource id.
    pub fn with_resource(mut self, id: impl Into<String>) -> Self {
        self.resource_id = Some(id.into());
        self
    }

    /// Builder: attach a previous-value (for change events).
    pub fn with_previous(mut self, v: impl Into<String>) -> Self {
        self.previous_value = Some(v.into());
        self
    }

    /// Builder: attach the new value (for change events).
    pub fn with_new(mut self, v: impl Into<String>) -> Self {
        self.new_value = Some(v.into());
        self
    }
}

// =============================================================================
// WorkspaceAuditEntry — one append-only record
// =============================================================================

/// One entry in the workspace audit log.
///
/// Carries `prior_entry_hash` for tamper evidence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkspaceAuditEntry {
    /// Unique entry id.
    pub entry_id: Uuid,
    /// RFC 3339 wall-clock timestamp.
    pub timestamp: String,
    /// Actor (principal id, e.g. `"alice@bank"` or `"svc-deploy"`).
    pub actor: String,
    /// Operator session id (e.g. SSO session id) — optional.
    pub session_id: Option<String>,
    /// Source IP address (or `"local"` for in-process) — optional.
    pub source_ip: Option<String>,
    /// Reason / change-ticket id (e.g. `"CHG-1234"`).
    pub reason: Option<String>,
    /// Correlation id — links entries that belong to one operator workflow.
    pub correlation_id: Option<String>,
    /// The action recorded.
    pub event: WorkspaceAuditEvent,
    /// Hash of the previous entry (`None` for genesis).
    pub prior_entry_hash: Option<Sha256Digest>,
    /// Hash of *this* entry's content (excluding `entry_hash` itself).
    pub entry_hash: Sha256Digest,
}

impl WorkspaceAuditEntry {
    fn compute_hash(
        timestamp: &str,
        actor: &str,
        event: &WorkspaceAuditEvent,
        prior: Option<&Sha256Digest>,
        correlation_id: Option<&str>,
    ) -> Sha256Digest {
        let mut input = Vec::new();
        input.extend_from_slice(timestamp.as_bytes());
        input.push(0);
        input.extend_from_slice(actor.as_bytes());
        input.push(0);
        input.extend_from_slice(event.kind.label().as_bytes());
        input.push(0);
        input.extend_from_slice(event.summary.as_bytes());
        input.push(0);
        if let Some(r) = &event.resource_id {
            input.extend_from_slice(r.as_bytes());
        }
        input.push(0);
        if let Some(v) = &event.previous_value {
            input.extend_from_slice(v.as_bytes());
        }
        input.push(0);
        if let Some(v) = &event.new_value {
            input.extend_from_slice(v.as_bytes());
        }
        input.push(0);
        if let Some(p) = prior {
            input.extend_from_slice(&p.0);
        }
        input.push(0);
        if let Some(c) = correlation_id {
            input.extend_from_slice(c.as_bytes());
        }
        Hasher::sha256(&input)
    }
}

// =============================================================================
// WorkspaceAuditLog
// =============================================================================

/// Append-only operator-action log.
#[derive(Debug, Default)]
pub struct WorkspaceAuditLog {
    inner: RwLock<Vec<WorkspaceAuditEntry>>,
}

/// Free-form recording knobs.
#[derive(Debug, Default, Clone)]
pub struct RecordOptions {
    /// Operator session id (SSO session, JWT id...).
    pub session_id: Option<String>,
    /// Source IP for the operator action.
    pub source_ip: Option<String>,
    /// Reason / ticket id.
    pub reason: Option<String>,
    /// Correlation id grouping related entries.
    pub correlation_id: Option<String>,
}

impl WorkspaceAuditLog {
    /// New empty log.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a new entry.
    ///
    /// `actor` is the principal taking the action. Use [`RecordOptions`] to
    /// attach operator context.
    pub fn record(
        &self,
        actor: impl Into<String>,
        event: WorkspaceAuditEvent,
        opts: RecordOptions,
    ) -> SandboxResult<WorkspaceAuditEntry> {
        let actor = actor.into();
        let timestamp = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("workspace audit log poisoned".into()))?;
        let prior = g.last().map(|e| e.entry_hash.clone());
        let entry_hash = WorkspaceAuditEntry::compute_hash(
            &timestamp,
            &actor,
            &event,
            prior.as_ref(),
            opts.correlation_id.as_deref(),
        );
        let entry = WorkspaceAuditEntry {
            entry_id: Uuid::now_v7(),
            timestamp,
            actor,
            session_id: opts.session_id,
            source_ip: opts.source_ip,
            reason: opts.reason,
            correlation_id: opts.correlation_id,
            event,
            prior_entry_hash: prior,
            entry_hash,
        };
        g.push(entry.clone());
        Ok(entry)
    }

    /// Convenience: record with no operator metadata.
    pub fn record_simple(
        &self,
        actor: impl Into<String>,
        event: WorkspaceAuditEvent,
    ) -> SandboxResult<WorkspaceAuditEntry> {
        self.record(actor, event, RecordOptions::default())
    }

    /// Snapshot: all entries in append order.
    pub fn entries(&self) -> Vec<WorkspaceAuditEntry> {
        self.inner.read().map(|g| g.clone()).unwrap_or_default()
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.inner.read().map(|g| g.len()).unwrap_or(0)
    }

    /// `true` if no entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Hash of the most recent entry — the chain root for export.
    pub fn chain_root(&self) -> Option<Sha256Digest> {
        self.inner.read().ok()?.last().map(|e| e.entry_hash.clone())
    }

    /// Verify the chain integrity: each entry's `prior_entry_hash` matches
    /// the previous entry's `entry_hash`, and each entry's recomputed hash
    /// matches `entry_hash`.
    pub fn verify_chain(&self) -> SandboxResult<()> {
        let g = self
            .inner
            .read()
            .map_err(|_| SandboxError::Other("workspace audit log poisoned".into()))?;
        let mut prior: Option<&Sha256Digest> = None;
        for (i, e) in g.iter().enumerate() {
            // Prior chain link.
            match (&e.prior_entry_hash, prior) {
                (None, None) => {}
                (Some(a), Some(b)) if a == b => {}
                _ => {
                    return Err(SandboxError::Other(format!(
                        "workspace audit chain break at entry {}",
                        i
                    )))
                }
            }
            // Entry self-hash.
            let recomputed = WorkspaceAuditEntry::compute_hash(
                &e.timestamp,
                &e.actor,
                &e.event,
                e.prior_entry_hash.as_ref(),
                e.correlation_id.as_deref(),
            );
            if recomputed != e.entry_hash {
                return Err(SandboxError::Other(format!(
                    "workspace audit entry {} hash mismatch",
                    i
                )));
            }
            prior = Some(&e.entry_hash);
        }
        Ok(())
    }

    /// Filter: entries by actor.
    pub fn entries_by_actor(&self, actor: &str) -> Vec<WorkspaceAuditEntry> {
        self.entries().into_iter().filter(|e| e.actor == actor).collect()
    }

    /// Filter: entries by event kind.
    pub fn entries_by_event_kind(
        &self,
        kind: WorkspaceAuditEventKind,
    ) -> Vec<WorkspaceAuditEntry> {
        self.entries()
            .into_iter()
            .filter(|e| e.event.kind == kind)
            .collect()
    }

    /// Filter: entries by correlation id.
    pub fn entries_by_correlation(&self, id: &str) -> Vec<WorkspaceAuditEntry> {
        self.entries()
            .into_iter()
            .filter(|e| e.correlation_id.as_deref() == Some(id))
            .collect()
    }

    /// Filter: entries with timestamp in `[from, to]` (RFC 3339 string compare).
    pub fn entries_in_range(&self, from: &str, to: &str) -> Vec<WorkspaceAuditEntry> {
        self.entries()
            .into_iter()
            .filter(|e| e.timestamp.as_str() >= from && e.timestamp.as_str() <= to)
            .collect()
    }

    /// Export the log as JSONL — one entry per line, suitable for SIEM ingestion.
    pub fn to_jsonl(&self) -> SandboxResult<String> {
        let mut out = String::new();
        for e in self.entries() {
            let line = serde_json::to_string(&e).map_err(|e| {
                SandboxError::Other(format!("workspace audit serialize failed: {e}"))
            })?;
            out.push_str(&line);
            out.push('\n');
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(kind: WorkspaceAuditEventKind, summary: &str) -> WorkspaceAuditEvent {
        WorkspaceAuditEvent::new(kind, summary)
    }

    #[test]
    fn empty_log_is_empty() {
        let l = WorkspaceAuditLog::new();
        assert!(l.is_empty());
        assert_eq!(l.len(), 0);
        assert!(l.chain_root().is_none());
    }

    #[test]
    fn single_record_returns_entry() {
        let l = WorkspaceAuditLog::new();
        let e = l
            .record_simple("alice", ev(WorkspaceAuditEventKind::KeyRotated, "rotated kid"))
            .unwrap();
        assert_eq!(e.actor, "alice");
        assert_eq!(e.event.kind, WorkspaceAuditEventKind::KeyRotated);
        assert!(e.prior_entry_hash.is_none(), "first entry has no prior");
    }

    #[test]
    fn second_record_chains_to_first() {
        let l = WorkspaceAuditLog::new();
        let a = l
            .record_simple("alice", ev(WorkspaceAuditEventKind::KeyRotated, "k1"))
            .unwrap();
        let b = l
            .record_simple("alice", ev(WorkspaceAuditEventKind::KeyRotated, "k2"))
            .unwrap();
        assert_eq!(b.prior_entry_hash.as_ref(), Some(&a.entry_hash));
    }

    #[test]
    fn chain_root_is_last_entry_hash() {
        let l = WorkspaceAuditLog::new();
        l.record_simple("a", ev(WorkspaceAuditEventKind::Other, "x")).unwrap();
        let last = l
            .record_simple("a", ev(WorkspaceAuditEventKind::Other, "y"))
            .unwrap();
        assert_eq!(l.chain_root().as_ref(), Some(&last.entry_hash));
    }

    #[test]
    fn verify_chain_empty_log_ok() {
        let l = WorkspaceAuditLog::new();
        l.verify_chain().unwrap();
    }

    #[test]
    fn verify_chain_after_writes_ok() {
        let l = WorkspaceAuditLog::new();
        for i in 0..5 {
            l.record_simple(
                "alice",
                ev(WorkspaceAuditEventKind::Other, &format!("e{i}")),
            )
            .unwrap();
        }
        l.verify_chain().unwrap();
    }

    #[test]
    fn entries_by_actor_filters() {
        let l = WorkspaceAuditLog::new();
        l.record_simple("alice", ev(WorkspaceAuditEventKind::Other, "1")).unwrap();
        l.record_simple("bob", ev(WorkspaceAuditEventKind::Other, "2")).unwrap();
        l.record_simple("alice", ev(WorkspaceAuditEventKind::Other, "3")).unwrap();
        let alice = l.entries_by_actor("alice");
        assert_eq!(alice.len(), 2);
    }

    #[test]
    fn entries_by_event_kind_filters() {
        let l = WorkspaceAuditLog::new();
        l.record_simple("a", ev(WorkspaceAuditEventKind::KeyRotated, "k")).unwrap();
        l.record_simple("a", ev(WorkspaceAuditEventKind::TenantSuspended, "t")).unwrap();
        l.record_simple("a", ev(WorkspaceAuditEventKind::KeyRotated, "k2")).unwrap();
        assert_eq!(
            l.entries_by_event_kind(WorkspaceAuditEventKind::KeyRotated)
                .len(),
            2
        );
        assert_eq!(
            l.entries_by_event_kind(WorkspaceAuditEventKind::TenantSuspended)
                .len(),
            1
        );
    }

    #[test]
    fn entries_by_correlation_filters() {
        let l = WorkspaceAuditLog::new();
        l.record(
            "a",
            ev(WorkspaceAuditEventKind::KeyRotated, "1"),
            RecordOptions {
                correlation_id: Some("CHG-001".into()),
                ..Default::default()
            },
        )
        .unwrap();
        l.record(
            "a",
            ev(WorkspaceAuditEventKind::KeyRotated, "2"),
            RecordOptions {
                correlation_id: Some("CHG-002".into()),
                ..Default::default()
            },
        )
        .unwrap();
        l.record(
            "a",
            ev(WorkspaceAuditEventKind::KeyRotated, "3"),
            RecordOptions {
                correlation_id: Some("CHG-001".into()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(l.entries_by_correlation("CHG-001").len(), 2);
        assert_eq!(l.entries_by_correlation("CHG-002").len(), 1);
        assert_eq!(l.entries_by_correlation("CHG-999").len(), 0);
    }

    #[test]
    fn entries_in_range_filters() {
        let l = WorkspaceAuditLog::new();
        // Insert a few entries; timestamps are RFC 3339 strings.
        for _ in 0..3 {
            l.record_simple("a", ev(WorkspaceAuditEventKind::Other, "x")).unwrap();
        }
        // All entries should fall in this huge range.
        let r = l.entries_in_range("2000-01-01T00:00:00Z", "9999-12-31T23:59:59Z");
        assert_eq!(r.len(), 3);
        // None should be in 1999.
        let none = l.entries_in_range("1999-01-01T00:00:00Z", "1999-12-31T23:59:59Z");
        assert!(none.is_empty());
    }

    #[test]
    fn record_with_options_preserves_metadata() {
        let l = WorkspaceAuditLog::new();
        let e = l
            .record(
                "ops",
                ev(WorkspaceAuditEventKind::KeyRotated, "rotate"),
                RecordOptions {
                    session_id: Some("sess-9".into()),
                    source_ip: Some("10.0.1.5".into()),
                    reason: Some("CHG-77".into()),
                    correlation_id: Some("rot-2026-q2".into()),
                },
            )
            .unwrap();
        assert_eq!(e.session_id.as_deref(), Some("sess-9"));
        assert_eq!(e.source_ip.as_deref(), Some("10.0.1.5"));
        assert_eq!(e.reason.as_deref(), Some("CHG-77"));
        assert_eq!(e.correlation_id.as_deref(), Some("rot-2026-q2"));
    }

    #[test]
    fn event_builders_compose() {
        let e = ev(WorkspaceAuditEventKind::ApprovalThresholdChanged, "raised m")
            .with_resource("policy-v3")
            .with_previous("2-of-3")
            .with_new("3-of-5");
        assert_eq!(e.resource_id.as_deref(), Some("policy-v3"));
        assert_eq!(e.previous_value.as_deref(), Some("2-of-3"));
        assert_eq!(e.new_value.as_deref(), Some("3-of-5"));
    }

    #[test]
    fn jsonl_export_round_trips() {
        let l = WorkspaceAuditLog::new();
        l.record_simple("a", ev(WorkspaceAuditEventKind::Other, "x"))
            .unwrap();
        l.record_simple("b", ev(WorkspaceAuditEventKind::Other, "y"))
            .unwrap();
        let jsonl = l.to_jsonl().unwrap();
        let lines: Vec<&str> = jsonl.lines().collect();
        assert_eq!(lines.len(), 2);
        let first: WorkspaceAuditEntry = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first.actor, "a");
    }

    #[test]
    fn jsonl_empty_log_yields_empty_string() {
        let l = WorkspaceAuditLog::new();
        assert_eq!(l.to_jsonl().unwrap(), "");
    }

    #[test]
    fn entry_serde_round_trip() {
        let l = WorkspaceAuditLog::new();
        let e = l
            .record_simple("a", ev(WorkspaceAuditEventKind::KeyRotated, "k"))
            .unwrap();
        let j = serde_json::to_string(&e).unwrap();
        let p: WorkspaceAuditEntry = serde_json::from_str(&j).unwrap();
        assert_eq!(p, e);
    }

    #[test]
    fn event_kind_label_stable() {
        assert_eq!(WorkspaceAuditEventKind::KeyRotated.label(), "key_rotated");
        assert_eq!(
            WorkspaceAuditEventKind::ApprovalThresholdChanged.label(),
            "approval_threshold_changed"
        );
        assert_eq!(WorkspaceAuditEventKind::Other.label(), "other");
    }

    #[test]
    fn distinct_summaries_produce_distinct_hashes() {
        let l = WorkspaceAuditLog::new();
        let a = l
            .record_simple("a", ev(WorkspaceAuditEventKind::Other, "one"))
            .unwrap();
        let b = l
            .record_simple("a", ev(WorkspaceAuditEventKind::Other, "two"))
            .unwrap();
        assert_ne!(a.entry_hash, b.entry_hash);
    }

    #[test]
    fn correlation_id_affects_hash() {
        let mut a_evt = ev(WorkspaceAuditEventKind::Other, "x");
        let mut b_evt = ev(WorkspaceAuditEventKind::Other, "x");
        let _ = (&mut a_evt, &mut b_evt);
        let h1 = WorkspaceAuditEntry::compute_hash(
            "2026-01-01T00:00:00Z",
            "a",
            &ev(WorkspaceAuditEventKind::Other, "x"),
            None,
            Some("c1"),
        );
        let h2 = WorkspaceAuditEntry::compute_hash(
            "2026-01-01T00:00:00Z",
            "a",
            &ev(WorkspaceAuditEventKind::Other, "x"),
            None,
            Some("c2"),
        );
        assert_ne!(h1, h2);
    }

    #[test]
    fn many_entries_chain_intact() {
        let l = WorkspaceAuditLog::new();
        for i in 0..50 {
            l.record_simple(
                "alice",
                ev(WorkspaceAuditEventKind::Other, &format!("event-{i}")),
            )
            .unwrap();
        }
        l.verify_chain().unwrap();
        assert_eq!(l.len(), 50);
    }

    #[test]
    fn chain_root_changes_with_each_write() {
        let l = WorkspaceAuditLog::new();
        l.record_simple("a", ev(WorkspaceAuditEventKind::Other, "x"))
            .unwrap();
        let r1 = l.chain_root().unwrap();
        l.record_simple("a", ev(WorkspaceAuditEventKind::Other, "y"))
            .unwrap();
        let r2 = l.chain_root().unwrap();
        assert_ne!(r1, r2);
    }

    #[test]
    fn record_options_default_is_none() {
        let o = RecordOptions::default();
        assert!(o.session_id.is_none());
        assert!(o.source_ip.is_none());
        assert!(o.reason.is_none());
        assert!(o.correlation_id.is_none());
    }

    #[test]
    fn event_summary_is_kept() {
        let e = ev(WorkspaceAuditEventKind::Other, "rotated kid=abc");
        assert_eq!(e.summary, "rotated kid=abc");
    }

    #[test]
    fn role_assigned_event_records_principal_role() {
        let l = WorkspaceAuditLog::new();
        let e = l
            .record_simple(
                "admin",
                ev(WorkspaceAuditEventKind::RoleAssigned, "granted role")
                    .with_resource("alice@bank")
                    .with_new("compliance_officer"),
            )
            .unwrap();
        assert_eq!(e.event.resource_id.as_deref(), Some("alice@bank"));
        assert_eq!(e.event.new_value.as_deref(), Some("compliance_officer"));
    }

    #[test]
    fn tenant_suspension_pair_links_via_correlation() {
        let l = WorkspaceAuditLog::new();
        let cid = "incident-2026-04-15".to_string();
        l.record(
            "ops",
            ev(WorkspaceAuditEventKind::TenantSuspended, "suspend FAB").with_resource("FAB"),
            RecordOptions {
                correlation_id: Some(cid.clone()),
                ..Default::default()
            },
        )
        .unwrap();
        l.record(
            "ops",
            ev(WorkspaceAuditEventKind::TenantReactivated, "reactivate FAB").with_resource("FAB"),
            RecordOptions {
                correlation_id: Some(cid.clone()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(l.entries_by_correlation(&cid).len(), 2);
    }
}
