//! Secrets / credential rotation tracking.
//!
//! Maps to NIST 800-53 IA-5 (Authenticator Management) / PCI 8.2.4 / SOC2
//! CC6.1: every secret has a documented owner, max age, last-rotated
//! timestamp, and rotation history. The registry exposes a `due_for_rotation`
//! query so monitoring jobs can alert before secrets exceed their max age.
//!
//! This module does **not** store the secret material — only the metadata
//! needed for compliance evidence. Use [`crate::bring_your_own_key`] for the
//! key-material lifecycle.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

// =============================================================================
// SecretKind
// =============================================================================

/// Logical kind of secret being tracked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    /// API key for an internal service.
    ApiKey,
    /// Database connection password.
    DatabasePassword,
    /// Service account credential / OAuth client secret.
    ServiceAccount,
    /// Symmetric encryption key.
    EncryptionKey,
    /// Asymmetric signing key.
    SigningKey,
    /// TLS certificate (private side).
    TlsCertificate,
    /// SSH host or user key.
    SshKey,
    /// Webhook signing secret.
    WebhookSecret,
    /// Other / generic credential.
    Other,
}

// =============================================================================
// RotationOutcome
// =============================================================================

/// Outcome of a single rotation attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationOutcome {
    /// Rotation completed.
    Rotated,
    /// Rotation attempted but failed.
    Failed,
    /// Skipped — out-of-band rotation already happened.
    Skipped,
}

// =============================================================================
// RotationEvent
// =============================================================================

/// One rotation event recorded against a secret.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RotationEvent {
    /// RFC 3339 timestamp.
    pub at: String,
    /// Outcome.
    pub outcome: RotationOutcome,
    /// Operator who triggered (or "system").
    pub actor: String,
    /// Free-text reason / context.
    pub reason: Option<String>,
    /// New version label (e.g., "v3", "2025-05-08").
    pub new_version: Option<String>,
}

// =============================================================================
// SecretRecord
// =============================================================================

/// One tracked secret.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SecretRecord {
    /// Unique id.
    pub secret_id: String,
    /// Tenant scope.
    pub tenant_id: String,
    /// Logical name (e.g., "stripe-api-key", "primary-postgres").
    pub name: String,
    /// Kind.
    pub kind: SecretKind,
    /// Owning team / individual.
    pub owner: String,
    /// Maximum age in days; 0 = never expires.
    pub max_age_days: u64,
    /// RFC 3339 — when secret was created or first registered.
    pub created_at: String,
    /// RFC 3339 — most recent successful rotation.
    pub last_rotated_at: Option<String>,
    /// Current version label.
    pub current_version: Option<String>,
    /// Rotation history.
    pub history: Vec<RotationEvent>,
    /// Free-form tags ("prod", "pii", "compliance").
    pub tags: Vec<String>,
}

impl SecretRecord {
    /// Construct a new tracked secret.
    pub fn new(
        secret_id: impl Into<String>,
        tenant_id: impl Into<String>,
        name: impl Into<String>,
        kind: SecretKind,
        owner: impl Into<String>,
        created_at: impl Into<String>,
        max_age_days: u64,
    ) -> Self {
        Self {
            secret_id: secret_id.into(),
            tenant_id: tenant_id.into(),
            name: name.into(),
            kind,
            owner: owner.into(),
            max_age_days,
            created_at: created_at.into(),
            last_rotated_at: None,
            current_version: None,
            history: Vec::new(),
            tags: Vec::new(),
        }
    }

    /// Effective "last touched" timestamp (last rotation or created_at).
    pub fn effective_anchor(&self) -> &str {
        self.last_rotated_at.as_deref().unwrap_or(&self.created_at)
    }

    /// True if `now` minus the effective anchor exceeds `max_age_days`.
    /// `now` and the anchor must be RFC 3339 in UTC. Returns `false` if
    /// `max_age_days == 0` or parsing fails (fail-open for telemetry, callers
    /// should handle parse errors separately).
    pub fn is_due_for_rotation(&self, now: &str) -> bool {
        if self.max_age_days == 0 {
            return false;
        }
        match age_in_days(self.effective_anchor(), now) {
            Some(d) => d >= self.max_age_days as i64,
            None => false,
        }
    }
}

// =============================================================================
// SecretsRotationRegistry
// =============================================================================

/// Thread-safe registry of tracked secrets.
#[derive(Debug, Default)]
pub struct SecretsRotationRegistry {
    inner: RwLock<HashMap<String, SecretRecord>>,
}

impl SecretsRotationRegistry {
    /// New empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new secret. Errors on duplicate id.
    pub fn register(&self, record: SecretRecord) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("secrets rotation registry poisoned".into()))?;
        if g.contains_key(&record.secret_id) {
            return Err(SandboxError::Other(format!(
                "secret already registered: {}",
                record.secret_id
            )));
        }
        g.insert(record.secret_id.clone(), record);
        Ok(())
    }

    /// Record a rotation event. On a `Rotated` outcome, also updates
    /// `last_rotated_at` and `current_version`.
    pub fn record_rotation(
        &self,
        secret_id: &str,
        event: RotationEvent,
    ) -> SandboxResult<SecretRecord> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("secrets rotation registry poisoned".into()))?;
        let r = g
            .get_mut(secret_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown secret {secret_id}")))?;
        if matches!(event.outcome, RotationOutcome::Rotated) {
            r.last_rotated_at = Some(event.at.clone());
            if let Some(v) = &event.new_version {
                r.current_version = Some(v.clone());
            }
        }
        r.history.push(event);
        Ok(r.clone())
    }

    /// Add a tag (deduplicated).
    pub fn add_tag(&self, secret_id: &str, tag: impl Into<String>) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("secrets rotation registry poisoned".into()))?;
        let r = g
            .get_mut(secret_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown secret {secret_id}")))?;
        let tag = tag.into();
        if !r.tags.contains(&tag) {
            r.tags.push(tag);
        }
        Ok(())
    }

    /// Update the maximum age policy.
    pub fn set_max_age(&self, secret_id: &str, days: u64) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("secrets rotation registry poisoned".into()))?;
        let r = g
            .get_mut(secret_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown secret {secret_id}")))?;
        r.max_age_days = days;
        Ok(())
    }

    /// Look up a secret.
    pub fn get(&self, secret_id: &str) -> Option<SecretRecord> {
        let g = self.inner.read().ok()?;
        g.get(secret_id).cloned()
    }

    /// All secrets.
    pub fn all(&self) -> Vec<SecretRecord> {
        match self.inner.read() {
            Ok(g) => g.values().cloned().collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Secrets owned by a tenant.
    pub fn for_tenant(&self, tenant_id: &str) -> Vec<SecretRecord> {
        self.all()
            .into_iter()
            .filter(|s| s.tenant_id == tenant_id)
            .collect()
    }

    /// Secrets of a given kind.
    pub fn by_kind(&self, kind: SecretKind) -> Vec<SecretRecord> {
        self.all().into_iter().filter(|s| s.kind == kind).collect()
    }

    /// Secrets whose effective anchor exceeds their max age at `now`.
    pub fn due_for_rotation(&self, now: &str) -> Vec<SecretRecord> {
        self.all()
            .into_iter()
            .filter(|s| s.is_due_for_rotation(now))
            .collect()
    }

    /// Number of registered secrets.
    pub fn count(&self) -> usize {
        self.inner.read().map(|g| g.len()).unwrap_or(0)
    }
}

/// Days between two RFC 3339 timestamps (later - earlier). Negative if the
/// order is reversed; `None` if parsing fails.
fn age_in_days(earlier_rfc3339: &str, later_rfc3339: &str) -> Option<i64> {
    use time::format_description::well_known::Rfc3339;
    let a = time::OffsetDateTime::parse(earlier_rfc3339, &Rfc3339).ok()?;
    let b = time::OffsetDateTime::parse(later_rfc3339, &Rfc3339).ok()?;
    Some((b - a).whole_days())
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(id: &str, max: u64) -> SecretRecord {
        SecretRecord::new(
            id,
            "tenant-a",
            format!("name-{id}"),
            SecretKind::ApiKey,
            "sec-team",
            "2025-01-01T00:00:00Z",
            max,
        )
    }

    fn ev(at: &str, outcome: RotationOutcome, actor: &str) -> RotationEvent {
        RotationEvent {
            at: at.into(),
            outcome,
            actor: actor.into(),
            reason: None,
            new_version: None,
        }
    }

    #[test]
    fn register_and_get() {
        let r = SecretsRotationRegistry::new();
        r.register(rec("s1", 90)).unwrap();
        let got = r.get("s1").unwrap();
        assert_eq!(got.kind, SecretKind::ApiKey);
        assert!(got.last_rotated_at.is_none());
    }

    #[test]
    fn duplicate_id_errors() {
        let r = SecretsRotationRegistry::new();
        r.register(rec("s1", 90)).unwrap();
        let err = r.register(rec("s1", 30)).unwrap_err();
        assert!(format!("{err}").contains("already registered"));
    }

    #[test]
    fn record_rotated_updates_anchor() {
        let r = SecretsRotationRegistry::new();
        r.register(rec("s1", 90)).unwrap();
        let mut e = ev("2025-04-01T00:00:00Z", RotationOutcome::Rotated, "alice");
        e.new_version = Some("v2".into());
        r.record_rotation("s1", e).unwrap();
        let got = r.get("s1").unwrap();
        assert_eq!(got.last_rotated_at.as_deref(), Some("2025-04-01T00:00:00Z"));
        assert_eq!(got.current_version.as_deref(), Some("v2"));
        assert_eq!(got.history.len(), 1);
    }

    #[test]
    fn record_failed_keeps_anchor() {
        let r = SecretsRotationRegistry::new();
        r.register(rec("s1", 90)).unwrap();
        r.record_rotation(
            "s1",
            ev("2025-04-01T00:00:00Z", RotationOutcome::Failed, "alice"),
        )
        .unwrap();
        let got = r.get("s1").unwrap();
        assert!(got.last_rotated_at.is_none());
        assert_eq!(got.history.len(), 1);
    }

    #[test]
    fn record_skipped_keeps_anchor() {
        let r = SecretsRotationRegistry::new();
        r.register(rec("s1", 90)).unwrap();
        r.record_rotation(
            "s1",
            ev("2025-04-01T00:00:00Z", RotationOutcome::Skipped, "alice"),
        )
        .unwrap();
        assert!(r.get("s1").unwrap().last_rotated_at.is_none());
    }

    #[test]
    fn record_unknown_secret_errors() {
        let r = SecretsRotationRegistry::new();
        let err = r
            .record_rotation(
                "nope",
                ev("2025-04-01T00:00:00Z", RotationOutcome::Rotated, "alice"),
            )
            .unwrap_err();
        assert!(format!("{err}").contains("unknown secret"));
    }

    #[test]
    fn add_tag_dedupes() {
        let r = SecretsRotationRegistry::new();
        r.register(rec("s1", 90)).unwrap();
        r.add_tag("s1", "prod").unwrap();
        r.add_tag("s1", "prod").unwrap();
        r.add_tag("s1", "pii").unwrap();
        assert_eq!(r.get("s1").unwrap().tags, vec!["prod", "pii"]);
    }

    #[test]
    fn set_max_age_updates() {
        let r = SecretsRotationRegistry::new();
        r.register(rec("s1", 90)).unwrap();
        r.set_max_age("s1", 30).unwrap();
        assert_eq!(r.get("s1").unwrap().max_age_days, 30);
    }

    #[test]
    fn due_for_rotation_zero_age_never_due() {
        let s = rec("s1", 0);
        assert!(!s.is_due_for_rotation("2030-01-01T00:00:00Z"));
    }

    #[test]
    fn due_for_rotation_uses_created_at() {
        let s = rec("s1", 90);
        // Created 2025-01-01, asking now=2025-04-15 — that's 104d > 90d.
        assert!(s.is_due_for_rotation("2025-04-15T00:00:00Z"));
        assert!(!s.is_due_for_rotation("2025-02-01T00:00:00Z"));
    }

    #[test]
    fn due_for_rotation_uses_last_rotated_when_present() {
        let r = SecretsRotationRegistry::new();
        r.register(rec("s1", 90)).unwrap();
        r.record_rotation(
            "s1",
            ev("2025-04-01T00:00:00Z", RotationOutcome::Rotated, "alice"),
        )
        .unwrap();
        let s = r.get("s1").unwrap();
        // Anchor moved to 2025-04-01.
        assert!(!s.is_due_for_rotation("2025-06-01T00:00:00Z"));
        assert!(s.is_due_for_rotation("2025-08-01T00:00:00Z"));
    }

    #[test]
    fn due_for_rotation_query() {
        let r = SecretsRotationRegistry::new();
        r.register(rec("s1", 30)).unwrap();
        r.register(rec("s2", 0)).unwrap(); // never expires
        r.register(rec("s3", 365)).unwrap();
        let due = r.due_for_rotation("2025-03-01T00:00:00Z");
        let ids: Vec<_> = due.iter().map(|s| s.secret_id.clone()).collect();
        assert!(ids.contains(&"s1".to_string()));
        assert!(!ids.contains(&"s2".to_string()));
        assert!(!ids.contains(&"s3".to_string()));
    }

    #[test]
    fn for_tenant_filters() {
        let r = SecretsRotationRegistry::new();
        r.register(rec("s1", 30)).unwrap();
        let mut other = rec("s2", 30);
        other.tenant_id = "tenant-b".into();
        r.register(other).unwrap();
        assert_eq!(r.for_tenant("tenant-a").len(), 1);
        assert_eq!(r.for_tenant("tenant-b").len(), 1);
    }

    #[test]
    fn by_kind_filters() {
        let r = SecretsRotationRegistry::new();
        r.register(rec("s1", 30)).unwrap();
        let mut other = rec("s2", 30);
        other.kind = SecretKind::SigningKey;
        r.register(other).unwrap();
        assert_eq!(r.by_kind(SecretKind::ApiKey).len(), 1);
        assert_eq!(r.by_kind(SecretKind::SigningKey).len(), 1);
        assert_eq!(r.by_kind(SecretKind::TlsCertificate).len(), 0);
    }

    #[test]
    fn count_tracks() {
        let r = SecretsRotationRegistry::new();
        assert_eq!(r.count(), 0);
        r.register(rec("a", 1)).unwrap();
        r.register(rec("b", 1)).unwrap();
        assert_eq!(r.count(), 2);
    }

    #[test]
    fn effective_anchor_uses_created_when_no_rotation() {
        let s = rec("s1", 90);
        assert_eq!(s.effective_anchor(), "2025-01-01T00:00:00Z");
    }

    #[test]
    fn many_rotations_accumulate() {
        let r = SecretsRotationRegistry::new();
        r.register(rec("s1", 90)).unwrap();
        for i in 1..=5 {
            r.record_rotation(
                "s1",
                ev(
                    &format!("2025-0{i}-01T00:00:00Z"),
                    RotationOutcome::Rotated,
                    "system",
                ),
            )
            .unwrap();
        }
        assert_eq!(r.get("s1").unwrap().history.len(), 5);
    }

    #[test]
    fn record_serde() {
        let s = rec("s1", 30);
        let j = serde_json::to_string(&s).unwrap();
        let back: SecretRecord = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn event_serde() {
        let e = ev("2025-04-01T00:00:00Z", RotationOutcome::Rotated, "x");
        let j = serde_json::to_string(&e).unwrap();
        let back: RotationEvent = serde_json::from_str(&j).unwrap();
        assert_eq!(e, back);
    }

    #[test]
    fn kind_serde() {
        for k in [
            SecretKind::ApiKey,
            SecretKind::DatabasePassword,
            SecretKind::ServiceAccount,
            SecretKind::EncryptionKey,
            SecretKind::SigningKey,
            SecretKind::TlsCertificate,
            SecretKind::SshKey,
            SecretKind::WebhookSecret,
            SecretKind::Other,
        ] {
            let j = serde_json::to_string(&k).unwrap();
            let back: SecretKind = serde_json::from_str(&j).unwrap();
            assert_eq!(k, back);
        }
    }

    #[test]
    fn outcome_serde() {
        for o in [
            RotationOutcome::Rotated,
            RotationOutcome::Failed,
            RotationOutcome::Skipped,
        ] {
            let j = serde_json::to_string(&o).unwrap();
            let back: RotationOutcome = serde_json::from_str(&j).unwrap();
            assert_eq!(o, back);
        }
    }

    #[test]
    fn age_helper_negative_for_reversed() {
        assert_eq!(
            age_in_days("2025-04-01T00:00:00Z", "2025-01-01T00:00:00Z").unwrap(),
            -90
        );
    }
}
