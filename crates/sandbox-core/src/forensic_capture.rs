//! Forensic-snapshot register — chain-of-custody preserved evidence
//! captured during incident response.
//!
//! Maps to NIST 800-86 (Computer Forensics Integration into Incident
//! Response), ISO 27037 (digital evidence handling), SANS chain-of-custody
//! best practice. Whenever an incident calls for evidence preservation —
//! a memory dump, a log slice, a database snapshot, a binary blob — the
//! incident commander records a [`ForensicCapture`] with:
//!
//! - **Integrity hash** (SHA-256 over the evidence bytes).
//! - **Custody chain** — every `(actor, action, at)` transition.
//! - **Storage locator** — pointer to where the bytes actually live
//!   (object store URI, S3 ARN, etc.). The registry stores **metadata
//!   only**; the bytes themselves are out-of-band.
//!
//! Distinct from [`crate::evidence`] (the seal-evidence audit log) and
//! [`crate::audit_archival`] (long-term audit storage); this is the
//! **chain-of-custody record** that must survive evidentiary review.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

// =============================================================================
// EvidenceKind
// =============================================================================

/// Kind of forensic evidence captured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    /// Process memory dump.
    MemoryDump,
    /// Disk image (full or partial).
    DiskImage,
    /// Database snapshot.
    DatabaseSnapshot,
    /// Application log slice.
    LogSlice,
    /// Network packet capture.
    PacketCapture,
    /// Container / VM image.
    ContainerImage,
    /// Configuration export.
    ConfigExport,
    /// Binary artifact (compiled code).
    Binary,
    /// Other.
    Other,
}

// =============================================================================
// CustodyAction
// =============================================================================

/// Action recorded in the custody chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CustodyAction {
    /// Initial capture.
    Captured,
    /// Hash recomputed and verified equal.
    Verified,
    /// Hash recomputed and *did not* match. Triggers tamper alert.
    VerificationFailed,
    /// Transferred to another actor / system.
    Transferred,
    /// Released to law enforcement / regulator.
    Released,
    /// Sealed (no further mutations permitted on metadata).
    Sealed,
    /// Destroyed (with documented authorisation).
    Destroyed,
}

impl CustodyAction {
    /// Whether this action is a custody-breaking event.
    pub fn breaks_custody(self) -> bool {
        matches!(self, Self::VerificationFailed | Self::Destroyed)
    }
}

// =============================================================================
// CustodyEvent
// =============================================================================

/// One event in the chain of custody.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CustodyEvent {
    /// RFC 3339.
    pub at: String,
    /// Operator / system actor.
    pub actor: String,
    /// What happened.
    pub action: CustodyAction,
    /// Optional recipient (for Transferred / Released).
    pub recipient: Option<String>,
    /// Free-text note.
    pub note: Option<String>,
}

// =============================================================================
// ForensicCapture
// =============================================================================

/// One captured piece of evidence with chain-of-custody metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ForensicCapture {
    /// Unique id.
    pub capture_id: String,
    /// Tenant scope.
    pub tenant_id: String,
    /// Linked incident id.
    pub incident_id: String,
    /// Kind of evidence.
    pub kind: EvidenceKind,
    /// Display title.
    pub title: String,
    /// Long-form description.
    pub description: String,
    /// Operator who captured it.
    pub captured_by: String,
    /// SHA-256 hex of the evidence bytes.
    pub sha256: String,
    /// Size in bytes.
    pub size_bytes: u64,
    /// Storage URI (e.g., "s3://bucket/key", "vault://...", file path).
    pub storage_uri: String,
    /// True if the metadata is sealed (no further mutations).
    pub sealed: bool,
    /// True if a custody-breaking event has been recorded.
    pub custody_broken: bool,
    /// Custody chain.
    pub custody: Vec<CustodyEvent>,
    /// RFC 3339 — captured.
    pub captured_at: String,
    /// Free-form tags.
    pub tags: Vec<String>,
}

impl ForensicCapture {
    /// New capture with the initial `Captured` event recorded.
    pub fn new(
        capture_id: impl Into<String>,
        tenant_id: impl Into<String>,
        incident_id: impl Into<String>,
        kind: EvidenceKind,
        title: impl Into<String>,
        description: impl Into<String>,
        captured_by: impl Into<String>,
        sha256: impl Into<String>,
        size_bytes: u64,
        storage_uri: impl Into<String>,
        captured_at: impl Into<String>,
    ) -> Self {
        let when = captured_at.into();
        let actor = captured_by.into();
        let initial = CustodyEvent {
            at: when.clone(),
            actor: actor.clone(),
            action: CustodyAction::Captured,
            recipient: None,
            note: None,
        };
        Self {
            capture_id: capture_id.into(),
            tenant_id: tenant_id.into(),
            incident_id: incident_id.into(),
            kind,
            title: title.into(),
            description: description.into(),
            captured_by: actor,
            sha256: sha256.into(),
            size_bytes,
            storage_uri: storage_uri.into(),
            sealed: false,
            custody_broken: false,
            custody: vec![initial],
            captured_at: when,
            tags: Vec::new(),
        }
    }

    /// Most recent custody event.
    pub fn latest_event(&self) -> Option<&CustodyEvent> {
        self.custody.last()
    }
}

// =============================================================================
// ForensicCaptureRegistry
// =============================================================================

/// Thread-safe registry of forensic captures.
#[derive(Debug, Default)]
pub struct ForensicCaptureRegistry {
    inner: RwLock<HashMap<String, ForensicCapture>>,
}

impl ForensicCaptureRegistry {
    /// New empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new capture. Errors on duplicate id.
    pub fn register(&self, capture: ForensicCapture) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("forensic capture registry poisoned".into()))?;
        if g.contains_key(&capture.capture_id) {
            return Err(SandboxError::Other(format!(
                "capture already registered: {}",
                capture.capture_id
            )));
        }
        g.insert(capture.capture_id.clone(), capture);
        Ok(())
    }

    /// Append a custody event. If `action == VerificationFailed` the
    /// `custody_broken` flag is set. If `action == Sealed` the `sealed`
    /// flag is set (and further appends are still permitted but auditors
    /// should be alerted). Returns the updated capture.
    pub fn record_custody(
        &self,
        capture_id: &str,
        event: CustodyEvent,
    ) -> SandboxResult<ForensicCapture> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("forensic capture registry poisoned".into()))?;
        let c = g
            .get_mut(capture_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown capture {capture_id}")))?;
        if c.sealed {
            return Err(SandboxError::Other(format!(
                "capture {capture_id} is sealed; cannot record further events"
            )));
        }
        if event.action == CustodyAction::Sealed {
            c.sealed = true;
        }
        if event.action.breaks_custody() {
            c.custody_broken = true;
        }
        c.custody.push(event);
        Ok(c.clone())
    }

    /// Verify the SHA-256 against an externally-recomputed value. If
    /// matches — appends a `Verified` event. Otherwise — appends a
    /// `VerificationFailed` event and sets `custody_broken`.
    pub fn verify(
        &self,
        capture_id: &str,
        actor: impl Into<String>,
        recomputed_sha256: &str,
        at: impl Into<String>,
    ) -> SandboxResult<bool> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("forensic capture registry poisoned".into()))?;
        let c = g
            .get_mut(capture_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown capture {capture_id}")))?;
        let actor = actor.into();
        let when = at.into();
        let matches = c.sha256.eq_ignore_ascii_case(recomputed_sha256);
        let action = if matches {
            CustodyAction::Verified
        } else {
            c.custody_broken = true;
            CustodyAction::VerificationFailed
        };
        c.custody.push(CustodyEvent {
            at: when,
            actor,
            action,
            recipient: None,
            note: Some(format!("recomputed={recomputed_sha256}")),
        });
        Ok(matches)
    }

    /// Add a tag (deduplicated).
    pub fn add_tag(&self, capture_id: &str, tag: impl Into<String>) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("forensic capture registry poisoned".into()))?;
        let c = g
            .get_mut(capture_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown capture {capture_id}")))?;
        let tag = tag.into();
        if !c.tags.contains(&tag) {
            c.tags.push(tag);
        }
        Ok(())
    }

    /// Look up.
    pub fn get(&self, capture_id: &str) -> Option<ForensicCapture> {
        let g = self.inner.read().ok()?;
        g.get(capture_id).cloned()
    }

    /// All captures.
    pub fn all(&self) -> Vec<ForensicCapture> {
        match self.inner.read() {
            Ok(g) => g.values().cloned().collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Captures for a tenant.
    pub fn for_tenant(&self, tenant_id: &str) -> Vec<ForensicCapture> {
        self.all()
            .into_iter()
            .filter(|c| c.tenant_id == tenant_id)
            .collect()
    }

    /// Captures for an incident.
    pub fn for_incident(&self, incident_id: &str) -> Vec<ForensicCapture> {
        self.all()
            .into_iter()
            .filter(|c| c.incident_id == incident_id)
            .collect()
    }

    /// Captures of a given kind.
    pub fn by_kind(&self, kind: EvidenceKind) -> Vec<ForensicCapture> {
        self.all().into_iter().filter(|c| c.kind == kind).collect()
    }

    /// Captures whose chain of custody has been broken.
    pub fn broken_custody(&self) -> Vec<ForensicCapture> {
        self.all()
            .into_iter()
            .filter(|c| c.custody_broken)
            .collect()
    }

    /// Sealed captures.
    pub fn sealed(&self) -> Vec<ForensicCapture> {
        self.all().into_iter().filter(|c| c.sealed).collect()
    }

    /// Number of registered captures.
    pub fn count(&self) -> usize {
        self.inner.read().map(|g| g.len()).unwrap_or(0)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn cap(id: &str, kind: EvidenceKind) -> ForensicCapture {
        ForensicCapture::new(
            id,
            "tenant-a",
            format!("incident-{id}"),
            kind,
            format!("title-{id}"),
            "description",
            "alice",
            "abc123",
            1024,
            format!("s3://bucket/{id}"),
            "2025-05-08T00:00:00Z",
        )
    }

    fn ev(action: CustodyAction, actor: &str, at: &str) -> CustodyEvent {
        CustodyEvent {
            at: at.into(),
            actor: actor.into(),
            action,
            recipient: None,
            note: None,
        }
    }

    #[test]
    fn register_includes_initial_event() {
        let r = ForensicCaptureRegistry::new();
        r.register(cap("c1", EvidenceKind::MemoryDump)).unwrap();
        let c = r.get("c1").unwrap();
        assert_eq!(c.custody.len(), 1);
        assert_eq!(c.custody[0].action, CustodyAction::Captured);
        assert!(!c.sealed);
        assert!(!c.custody_broken);
    }

    #[test]
    fn duplicate_register_errors() {
        let r = ForensicCaptureRegistry::new();
        r.register(cap("c1", EvidenceKind::MemoryDump)).unwrap();
        let err = r.register(cap("c1", EvidenceKind::MemoryDump)).unwrap_err();
        assert!(format!("{err}").contains("already registered"));
    }

    #[test]
    fn record_custody_appends() {
        let r = ForensicCaptureRegistry::new();
        r.register(cap("c1", EvidenceKind::MemoryDump)).unwrap();
        r.record_custody(
            "c1",
            ev(CustodyAction::Transferred, "bob", "2025-05-08T01:00:00Z"),
        )
        .unwrap();
        assert_eq!(r.get("c1").unwrap().custody.len(), 2);
    }

    #[test]
    fn record_custody_unknown_errors() {
        let r = ForensicCaptureRegistry::new();
        let err = r
            .record_custody(
                "x",
                ev(CustodyAction::Verified, "alice", "2025-05-08T00:01:00Z"),
            )
            .unwrap_err();
        assert!(format!("{err}").contains("unknown capture"));
    }

    #[test]
    fn seal_blocks_further_records() {
        let r = ForensicCaptureRegistry::new();
        r.register(cap("c1", EvidenceKind::MemoryDump)).unwrap();
        r.record_custody(
            "c1",
            ev(CustodyAction::Sealed, "alice", "2025-05-08T00:01:00Z"),
        )
        .unwrap();
        let err = r
            .record_custody(
                "c1",
                ev(CustodyAction::Verified, "alice", "2025-05-08T00:02:00Z"),
            )
            .unwrap_err();
        assert!(format!("{err}").contains("sealed"));
    }

    #[test]
    fn verification_failed_breaks_custody() {
        let r = ForensicCaptureRegistry::new();
        r.register(cap("c1", EvidenceKind::MemoryDump)).unwrap();
        r.record_custody(
            "c1",
            ev(
                CustodyAction::VerificationFailed,
                "auditor",
                "2025-05-08T00:01:00Z",
            ),
        )
        .unwrap();
        assert!(r.get("c1").unwrap().custody_broken);
    }

    #[test]
    fn destroyed_breaks_custody() {
        let r = ForensicCaptureRegistry::new();
        r.register(cap("c1", EvidenceKind::MemoryDump)).unwrap();
        r.record_custody(
            "c1",
            ev(CustodyAction::Destroyed, "ops", "2025-05-08T00:01:00Z"),
        )
        .unwrap();
        assert!(r.get("c1").unwrap().custody_broken);
    }

    #[test]
    fn verify_matches_appends_verified() {
        let r = ForensicCaptureRegistry::new();
        r.register(cap("c1", EvidenceKind::MemoryDump)).unwrap();
        let ok = r
            .verify("c1", "auditor", "abc123", "2025-05-08T00:01:00Z")
            .unwrap();
        assert!(ok);
        let c = r.get("c1").unwrap();
        assert_eq!(c.custody.last().unwrap().action, CustodyAction::Verified);
        assert!(!c.custody_broken);
    }

    #[test]
    fn verify_mismatch_breaks_custody() {
        let r = ForensicCaptureRegistry::new();
        r.register(cap("c1", EvidenceKind::MemoryDump)).unwrap();
        let ok = r
            .verify("c1", "auditor", "DEADBEEF", "2025-05-08T00:01:00Z")
            .unwrap();
        assert!(!ok);
        let c = r.get("c1").unwrap();
        assert_eq!(
            c.custody.last().unwrap().action,
            CustodyAction::VerificationFailed
        );
        assert!(c.custody_broken);
    }

    #[test]
    fn verify_case_insensitive() {
        let r = ForensicCaptureRegistry::new();
        r.register(cap("c1", EvidenceKind::MemoryDump)).unwrap();
        let ok = r
            .verify("c1", "auditor", "ABC123", "2025-05-08T00:01:00Z")
            .unwrap();
        assert!(ok);
    }

    #[test]
    fn verify_unknown_errors() {
        let r = ForensicCaptureRegistry::new();
        let err = r
            .verify("nope", "auditor", "abc", "2025-05-08T00:01:00Z")
            .unwrap_err();
        assert!(format!("{err}").contains("unknown capture"));
    }

    #[test]
    fn add_tag_dedupes() {
        let r = ForensicCaptureRegistry::new();
        r.register(cap("c1", EvidenceKind::MemoryDump)).unwrap();
        r.add_tag("c1", "compliance").unwrap();
        r.add_tag("c1", "compliance").unwrap();
        r.add_tag("c1", "regulator").unwrap();
        assert_eq!(r.get("c1").unwrap().tags, vec!["compliance", "regulator"]);
    }

    #[test]
    fn for_tenant_for_incident_filters() {
        let r = ForensicCaptureRegistry::new();
        r.register(cap("c1", EvidenceKind::MemoryDump)).unwrap();
        let mut other = cap("c2", EvidenceKind::DiskImage);
        other.tenant_id = "tenant-b".into();
        other.incident_id = "incident-other".into();
        r.register(other).unwrap();
        assert_eq!(r.for_tenant("tenant-a").len(), 1);
        assert_eq!(r.for_tenant("tenant-b").len(), 1);
        assert_eq!(r.for_incident("incident-c1").len(), 1);
        assert_eq!(r.for_incident("incident-other").len(), 1);
    }

    #[test]
    fn by_kind_filters() {
        let r = ForensicCaptureRegistry::new();
        r.register(cap("c1", EvidenceKind::MemoryDump)).unwrap();
        r.register(cap("c2", EvidenceKind::DiskImage)).unwrap();
        assert_eq!(r.by_kind(EvidenceKind::MemoryDump).len(), 1);
        assert_eq!(r.by_kind(EvidenceKind::DiskImage).len(), 1);
        assert_eq!(r.by_kind(EvidenceKind::PacketCapture).len(), 0);
    }

    #[test]
    fn broken_custody_query() {
        let r = ForensicCaptureRegistry::new();
        r.register(cap("c1", EvidenceKind::MemoryDump)).unwrap();
        r.register(cap("c2", EvidenceKind::MemoryDump)).unwrap();
        r.verify("c2", "auditor", "wrong", "2025-05-08T00:01:00Z")
            .unwrap();
        let bk = r.broken_custody();
        let ids: Vec<_> = bk.iter().map(|c| c.capture_id.clone()).collect();
        assert_eq!(ids, vec!["c2"]);
    }

    #[test]
    fn sealed_query() {
        let r = ForensicCaptureRegistry::new();
        r.register(cap("c1", EvidenceKind::MemoryDump)).unwrap();
        r.register(cap("c2", EvidenceKind::MemoryDump)).unwrap();
        r.record_custody(
            "c1",
            ev(CustodyAction::Sealed, "alice", "2025-05-08T00:01:00Z"),
        )
        .unwrap();
        assert_eq!(r.sealed().len(), 1);
        assert_eq!(r.sealed()[0].capture_id, "c1");
    }

    #[test]
    fn count_tracks() {
        let r = ForensicCaptureRegistry::new();
        assert_eq!(r.count(), 0);
        r.register(cap("c1", EvidenceKind::MemoryDump)).unwrap();
        assert_eq!(r.count(), 1);
    }

    #[test]
    fn breaks_custody_helpers() {
        assert!(CustodyAction::VerificationFailed.breaks_custody());
        assert!(CustodyAction::Destroyed.breaks_custody());
        assert!(!CustodyAction::Verified.breaks_custody());
        assert!(!CustodyAction::Sealed.breaks_custody());
    }

    #[test]
    fn latest_event_returns_most_recent() {
        let r = ForensicCaptureRegistry::new();
        r.register(cap("c1", EvidenceKind::MemoryDump)).unwrap();
        r.record_custody(
            "c1",
            ev(CustodyAction::Verified, "auditor", "2025-05-08T00:01:00Z"),
        )
        .unwrap();
        let c = r.get("c1").unwrap();
        assert_eq!(c.latest_event().unwrap().action, CustodyAction::Verified);
    }

    #[test]
    fn capture_serde() {
        let c = cap("c1", EvidenceKind::MemoryDump);
        let j = serde_json::to_string(&c).unwrap();
        let back: ForensicCapture = serde_json::from_str(&j).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn enums_serde() {
        for k in [
            EvidenceKind::MemoryDump,
            EvidenceKind::DiskImage,
            EvidenceKind::DatabaseSnapshot,
            EvidenceKind::LogSlice,
            EvidenceKind::PacketCapture,
            EvidenceKind::ContainerImage,
            EvidenceKind::ConfigExport,
            EvidenceKind::Binary,
            EvidenceKind::Other,
        ] {
            assert_eq!(
                k,
                serde_json::from_str::<EvidenceKind>(&serde_json::to_string(&k).unwrap()).unwrap()
            );
        }
        for a in [
            CustodyAction::Captured,
            CustodyAction::Verified,
            CustodyAction::VerificationFailed,
            CustodyAction::Transferred,
            CustodyAction::Released,
            CustodyAction::Sealed,
            CustodyAction::Destroyed,
        ] {
            assert_eq!(
                a,
                serde_json::from_str::<CustodyAction>(&serde_json::to_string(&a).unwrap()).unwrap()
            );
        }
    }
}
