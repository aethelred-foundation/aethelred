//! Customer consent — granular per-purpose consent records.
//!
//! GDPR Art. 6/7 and the equivalent California / UAE provisions require
//! organizations to record consent at *purpose-level granularity*, with the
//! version of the consent text the user agreed to and a clear timestamp.
//!
//! This module is the canonical store. Consent can be `Granted`,
//! `Withdrawn`, `Expired` (after a TTL), or never given. Operators query
//! `is_active(subject, purpose, now)` before processing.

use crate::hashing::{Hasher, Sha256Digest};
use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use time::OffsetDateTime;
use uuid::Uuid;

// =============================================================================
// PurposeId
// =============================================================================

/// Stable purpose id (e.g. `"marketing-email"`, `"credit-decisioning"`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PurposeId(pub String);

impl PurposeId {
    /// New.
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
    /// `&str`.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// =============================================================================
// ConsentStatus
// =============================================================================

/// Per-record status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentStatus {
    /// Granted.
    Granted,
    /// Withdrawn.
    Withdrawn,
    /// Expired.
    Expired,
    /// Never given.
    NotGiven,
}

// =============================================================================
// ConsentRecord
// =============================================================================

/// One consent record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsentRecord {
    /// Stable id.
    pub record_id: Uuid,
    /// Subject (typically a hashed customer id).
    pub subject_id: String,
    /// Purpose.
    pub purpose: PurposeId,
    /// Hash of the consent text version agreed to.
    pub text_hash: Sha256Digest,
    /// Free-form text version label (e.g. `"v3.1-en-US"`).
    pub text_version: String,
    /// Status.
    pub status: ConsentStatus,
    /// RFC 3339 granted at.
    pub granted_at: Option<String>,
    /// RFC 3339 withdrawn at.
    pub withdrawn_at: Option<String>,
    /// RFC 3339 expires at.
    pub expires_at: Option<String>,
    /// Channel of consent (e.g. `"web-form"`, `"voice-recording"`).
    pub channel: String,
}

impl ConsentRecord {
    /// Effective status as of `now`.
    pub fn effective_status(&self, now: OffsetDateTime) -> ConsentStatus {
        if self.status == ConsentStatus::Withdrawn {
            return ConsentStatus::Withdrawn;
        }
        if self.status == ConsentStatus::NotGiven {
            return ConsentStatus::NotGiven;
        }
        if let Some(exp) = &self.expires_at {
            if let Ok(t) = OffsetDateTime::parse(
                exp,
                &time::format_description::well_known::Rfc3339,
            ) {
                if now >= t {
                    return ConsentStatus::Expired;
                }
            }
        }
        self.status
    }
}

// =============================================================================
// ConsentRegistry
// =============================================================================

#[derive(Default)]
struct State {
    /// `(subject_id, purpose)` → latest record.
    records: HashMap<(String, PurposeId), ConsentRecord>,
}

/// Registry.
pub struct ConsentRegistry {
    state: RwLock<State>,
}

impl Default for ConsentRegistry {
    fn default() -> Self {
        Self {
            state: RwLock::new(State::default()),
        }
    }
}

impl std::fmt::Debug for ConsentRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConsentRegistry")
            .field("records", &self.len())
            .finish()
    }
}

impl ConsentRegistry {
    /// New empty.
    pub fn new() -> Self {
        Self::default()
    }

    /// Grant consent.
    pub fn grant(
        &self,
        subject_id: impl Into<String>,
        purpose: PurposeId,
        text_version: impl Into<String>,
        text: &[u8],
        channel: impl Into<String>,
        expires_at: Option<OffsetDateTime>,
    ) -> SandboxResult<ConsentRecord> {
        let subject_id = subject_id.into();
        let now = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        let exp = expires_at.map(|t| {
            t.format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default()
        });
        let r = ConsentRecord {
            record_id: Uuid::now_v7(),
            subject_id: subject_id.clone(),
            purpose: purpose.clone(),
            text_hash: Hasher::sha256(text),
            text_version: text_version.into(),
            status: ConsentStatus::Granted,
            granted_at: Some(now),
            withdrawn_at: None,
            expires_at: exp,
            channel: channel.into(),
        };
        self.state
            .write()
            .map_err(|_| SandboxError::Other("consent registry poisoned".into()))?
            .records
            .insert((subject_id, purpose), r.clone());
        Ok(r)
    }

    /// Withdraw consent.
    pub fn withdraw(
        &self,
        subject_id: &str,
        purpose: &PurposeId,
    ) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("consent registry poisoned".into()))?;
        let r = g
            .records
            .get_mut(&(subject_id.to_string(), purpose.clone()))
            .ok_or_else(|| SandboxError::Other("consent record not found".into()))?;
        r.status = ConsentStatus::Withdrawn;
        r.withdrawn_at = Some(
            OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
        );
        Ok(())
    }

    /// Check whether consent is active.
    pub fn is_active(
        &self,
        subject_id: &str,
        purpose: &PurposeId,
        now: OffsetDateTime,
    ) -> bool {
        let g = match self.state.read() {
            Ok(g) => g,
            Err(_) => return false,
        };
        match g.records.get(&(subject_id.to_string(), purpose.clone())) {
            Some(r) => r.effective_status(now) == ConsentStatus::Granted,
            None => false,
        }
    }

    /// Lookup record.
    pub fn get(&self, subject_id: &str, purpose: &PurposeId) -> Option<ConsentRecord> {
        self.state
            .read()
            .ok()?
            .records
            .get(&(subject_id.to_string(), purpose.clone()))
            .cloned()
    }

    /// All records for a subject.
    pub fn for_subject(&self, subject_id: &str) -> Vec<ConsentRecord> {
        self.state
            .read()
            .map(|g| {
                g.records
                    .iter()
                    .filter(|((s, _), _)| s == subject_id)
                    .map(|(_, r)| r.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// All purposes a subject has currently active consent for.
    pub fn active_purposes(
        &self,
        subject_id: &str,
        now: OffsetDateTime,
    ) -> Vec<PurposeId> {
        self.for_subject(subject_id)
            .into_iter()
            .filter(|r| r.effective_status(now) == ConsentStatus::Granted)
            .map(|r| r.purpose)
            .collect()
    }

    /// Count.
    pub fn len(&self) -> usize {
        self.state.read().map(|g| g.records.len()).unwrap_or(0)
    }
    /// Empty?
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }

    #[test]
    fn grant_records_consent() {
        let r = ConsentRegistry::new();
        let rec = r
            .grant(
                "alice",
                PurposeId::new("marketing-email"),
                "v1",
                b"text",
                "web",
                None,
            )
            .unwrap();
        assert_eq!(rec.status, ConsentStatus::Granted);
    }

    #[test]
    fn is_active_after_grant() {
        let r = ConsentRegistry::new();
        r.grant(
            "alice",
            PurposeId::new("marketing-email"),
            "v1",
            b"x",
            "web",
            None,
        )
        .unwrap();
        assert!(r.is_active("alice", &PurposeId::new("marketing-email"), now()));
    }

    #[test]
    fn withdraw_clears_active() {
        let r = ConsentRegistry::new();
        r.grant(
            "alice",
            PurposeId::new("marketing-email"),
            "v1",
            b"x",
            "web",
            None,
        )
        .unwrap();
        r.withdraw("alice", &PurposeId::new("marketing-email"))
            .unwrap();
        assert!(!r.is_active("alice", &PurposeId::new("marketing-email"), now()));
    }

    #[test]
    fn expired_is_inactive() {
        let r = ConsentRegistry::new();
        let past = OffsetDateTime::now_utc() - time::Duration::days(1);
        r.grant(
            "alice",
            PurposeId::new("marketing-email"),
            "v1",
            b"x",
            "web",
            Some(past),
        )
        .unwrap();
        assert!(!r.is_active("alice", &PurposeId::new("marketing-email"), now()));
    }

    #[test]
    fn future_expiry_still_active() {
        let r = ConsentRegistry::new();
        let future = OffsetDateTime::now_utc() + time::Duration::days(365);
        r.grant(
            "alice",
            PurposeId::new("marketing-email"),
            "v1",
            b"x",
            "web",
            Some(future),
        )
        .unwrap();
        assert!(r.is_active("alice", &PurposeId::new("marketing-email"), now()));
    }

    #[test]
    fn unknown_consent_inactive() {
        let r = ConsentRegistry::new();
        assert!(!r.is_active("ghost", &PurposeId::new("x"), now()));
    }

    #[test]
    fn withdraw_unknown_errors() {
        let r = ConsentRegistry::new();
        assert!(r.withdraw("ghost", &PurposeId::new("x")).is_err());
    }

    #[test]
    fn re_grant_overwrites() {
        let r = ConsentRegistry::new();
        let p = PurposeId::new("marketing-email");
        r.grant("alice", p.clone(), "v1", b"x", "web", None).unwrap();
        r.withdraw("alice", &p).unwrap();
        // New grant should make it active again.
        r.grant("alice", p.clone(), "v2", b"y", "web", None).unwrap();
        assert!(r.is_active("alice", &p, now()));
    }

    #[test]
    fn for_subject_returns_all() {
        let r = ConsentRegistry::new();
        r.grant(
            "alice",
            PurposeId::new("a"),
            "v1",
            b"x",
            "web",
            None,
        )
        .unwrap();
        r.grant(
            "alice",
            PurposeId::new("b"),
            "v1",
            b"x",
            "web",
            None,
        )
        .unwrap();
        r.grant("bob", PurposeId::new("c"), "v1", b"x", "web", None)
            .unwrap();
        assert_eq!(r.for_subject("alice").len(), 2);
    }

    #[test]
    fn active_purposes_excludes_inactive() {
        let r = ConsentRegistry::new();
        r.grant(
            "alice",
            PurposeId::new("a"),
            "v1",
            b"x",
            "web",
            None,
        )
        .unwrap();
        r.grant(
            "alice",
            PurposeId::new("b"),
            "v1",
            b"x",
            "web",
            None,
        )
        .unwrap();
        r.withdraw("alice", &PurposeId::new("b")).unwrap();
        let active = r.active_purposes("alice", now());
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].as_str(), "a");
    }

    #[test]
    fn text_hash_records_content() {
        let r = ConsentRegistry::new();
        let rec = r
            .grant(
                "alice",
                PurposeId::new("x"),
                "v1",
                b"some text",
                "web",
                None,
            )
            .unwrap();
        assert_eq!(rec.text_hash, Hasher::sha256(b"some text"));
    }

    #[test]
    fn record_serde() {
        let r = ConsentRegistry::new();
        let rec = r
            .grant(
                "alice",
                PurposeId::new("x"),
                "v1",
                b"t",
                "web",
                None,
            )
            .unwrap();
        let j = serde_json::to_string(&rec).unwrap();
        let p: ConsentRecord = serde_json::from_str(&j).unwrap();
        assert_eq!(p, rec);
    }

    #[test]
    fn purpose_serde_transparent() {
        let p = PurposeId::new("x");
        assert_eq!(serde_json::to_string(&p).unwrap(), "\"x\"");
    }

    #[test]
    fn status_serde() {
        for s in [
            ConsentStatus::Granted,
            ConsentStatus::Withdrawn,
            ConsentStatus::Expired,
            ConsentStatus::NotGiven,
        ] {
            let j = serde_json::to_string(&s).unwrap();
            let p: ConsentStatus = serde_json::from_str(&j).unwrap();
            assert_eq!(s, p);
        }
    }

    #[test]
    fn effective_status_evaluates_expiry() {
        let r = ConsentRegistry::new();
        let exp = OffsetDateTime::now_utc() - time::Duration::seconds(1);
        let rec = r
            .grant(
                "alice",
                PurposeId::new("x"),
                "v1",
                b"t",
                "web",
                Some(exp),
            )
            .unwrap();
        assert_eq!(
            rec.effective_status(OffsetDateTime::now_utc()),
            ConsentStatus::Expired
        );
    }

    #[test]
    fn registry_count_tracks() {
        let r = ConsentRegistry::new();
        assert!(r.is_empty());
        r.grant(
            "alice",
            PurposeId::new("x"),
            "v1",
            b"t",
            "web",
            None,
        )
        .unwrap();
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn lookup_returns_record() {
        let r = ConsentRegistry::new();
        r.grant(
            "alice",
            PurposeId::new("x"),
            "v1",
            b"t",
            "web",
            None,
        )
        .unwrap();
        assert!(r.get("alice", &PurposeId::new("x")).is_some());
    }

    #[test]
    fn withdraw_records_timestamp() {
        let r = ConsentRegistry::new();
        r.grant(
            "alice",
            PurposeId::new("x"),
            "v1",
            b"t",
            "web",
            None,
        )
        .unwrap();
        r.withdraw("alice", &PurposeId::new("x")).unwrap();
        let rec = r.get("alice", &PurposeId::new("x")).unwrap();
        assert!(rec.withdrawn_at.is_some());
    }

    #[test]
    fn channel_recorded() {
        let r = ConsentRegistry::new();
        let rec = r
            .grant(
                "alice",
                PurposeId::new("x"),
                "v1",
                b"t",
                "voice-recording",
                None,
            )
            .unwrap();
        assert_eq!(rec.channel, "voice-recording");
    }

    #[test]
    fn many_purposes_per_subject() {
        let r = ConsentRegistry::new();
        for i in 0..10 {
            r.grant(
                "alice",
                PurposeId::new(&format!("p{i}")),
                "v1",
                b"t",
                "web",
                None,
            )
            .unwrap();
        }
        assert_eq!(r.for_subject("alice").len(), 10);
    }
}
