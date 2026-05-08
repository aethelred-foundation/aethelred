//! Operator user-session tracking — login / activity / logout audit.
//!
//! Distinct from [`crate::agent_session`] (LLM conversational turns) and
//! [`crate::capability_token`] (signed delegation tokens), this module tracks
//! human operator sessions: who logged in, from where, with what MFA factor,
//! how long, and how the session ended. The stored data answers SOC2 CC6.1
//! (logical access) and ISO 27001 A.9.4 audit questions.
//!
//! # Lifecycle
//!
//! `Active` → (`Expired` | `Revoked` | `LoggedOut`)
//!
//! Once a session leaves `Active` it is terminal and immutable. To resume work
//! the operator must mint a new session id.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

// =============================================================================
// SessionState
// =============================================================================

/// Lifecycle state of a user session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    /// Currently active and able to make calls.
    Active,
    /// Idle/absolute timeout reached.
    Expired,
    /// Administratively revoked / force-logged-out.
    Revoked,
    /// User-initiated logout.
    LoggedOut,
}

impl SessionState {
    /// Whether requests should be served on this session.
    pub fn is_open(self) -> bool {
        matches!(self, Self::Active)
    }

    /// Whether the session has reached a terminal state.
    pub fn is_terminal(self) -> bool {
        !self.is_open()
    }
}

// =============================================================================
// MfaFactor
// =============================================================================

/// MFA factor used to start the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MfaFactor {
    /// No MFA — discouraged outside dev tenants.
    None,
    /// TOTP / authenticator app.
    Totp,
    /// FIDO2 / WebAuthn.
    Webauthn,
    /// Hardware security key (YubiKey, etc.).
    HardwareKey,
    /// Push to authenticator app.
    Push,
    /// SMS code (low assurance).
    Sms,
}

impl MfaFactor {
    /// Whether the factor is phishing-resistant.
    pub fn is_phishing_resistant(self) -> bool {
        matches!(self, Self::Webauthn | Self::HardwareKey)
    }
}

// =============================================================================
// SessionActivity
// =============================================================================

/// One activity event recorded against a session.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SessionActivity {
    /// RFC 3339 timestamp.
    pub at: String,
    /// Short kind label (e.g., "page_view", "api_call", "approval_signed").
    pub kind: String,
    /// Optional resource id this activity touched.
    pub resource_id: Option<String>,
    /// Optional client IP for this activity (may differ from login IP).
    pub ip: Option<String>,
}

// =============================================================================
// UserSession
// =============================================================================

/// One operator session.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UserSession {
    /// Unique id for this session.
    pub session_id: String,
    /// Logical user id.
    pub user_id: String,
    /// Tenant the session is scoped to.
    pub tenant_id: String,
    /// MFA factor at login.
    pub mfa: MfaFactor,
    /// Login IP.
    pub login_ip: Option<String>,
    /// Login user agent.
    pub user_agent: Option<String>,
    /// Current state.
    pub state: SessionState,
    /// RFC 3339 — login time.
    pub started_at: String,
    /// RFC 3339 — last activity (drives idle timeout).
    pub last_seen_at: String,
    /// RFC 3339 — when the session ended.
    pub ended_at: Option<String>,
    /// Reason the session ended (free text).
    pub end_reason: Option<String>,
    /// Idle timeout in seconds; 0 = no idle timeout.
    pub idle_timeout_secs: u64,
    /// Absolute lifetime in seconds; 0 = no absolute cap.
    pub absolute_lifetime_secs: u64,
    /// Activity log.
    pub activity: Vec<SessionActivity>,
    /// Free-form tags (e.g., "break-glass", "support-engineer").
    pub tags: Vec<String>,
}

impl UserSession {
    /// Construct a new active session.
    pub fn new(
        session_id: impl Into<String>,
        user_id: impl Into<String>,
        tenant_id: impl Into<String>,
        mfa: MfaFactor,
        started_at: impl Into<String>,
    ) -> Self {
        let started = started_at.into();
        Self {
            session_id: session_id.into(),
            user_id: user_id.into(),
            tenant_id: tenant_id.into(),
            mfa,
            login_ip: None,
            user_agent: None,
            state: SessionState::Active,
            started_at: started.clone(),
            last_seen_at: started,
            ended_at: None,
            end_reason: None,
            idle_timeout_secs: 0,
            absolute_lifetime_secs: 0,
            activity: Vec::new(),
            tags: Vec::new(),
        }
    }

    /// Whether the session is open.
    pub fn is_open(&self) -> bool {
        self.state.is_open()
    }
}

// =============================================================================
// UserSessionRegistry
// =============================================================================

/// Thread-safe registry of operator sessions.
#[derive(Debug, Default)]
pub struct UserSessionRegistry {
    inner: RwLock<HashMap<String, UserSession>>,
}

impl UserSessionRegistry {
    /// New empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new session. Errors if `session_id` collides.
    pub fn open(&self, session: UserSession) -> SandboxResult<()> {
        if !matches!(session.state, SessionState::Active) {
            return Err(SandboxError::Other(format!(
                "session must start Active, got {:?}",
                session.state
            )));
        }
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("user session registry poisoned".into()))?;
        if g.contains_key(&session.session_id) {
            return Err(SandboxError::Other(format!(
                "session id already registered: {}",
                session.session_id
            )));
        }
        g.insert(session.session_id.clone(), session);
        Ok(())
    }

    /// Record a heartbeat / activity event. No-op if session already terminal.
    pub fn record_activity(
        &self,
        session_id: &str,
        activity: SessionActivity,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("user session registry poisoned".into()))?;
        let s = g
            .get_mut(session_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown session {session_id}")))?;
        if s.state.is_terminal() {
            return Err(SandboxError::Other(format!(
                "session {session_id} terminal; cannot record activity"
            )));
        }
        s.last_seen_at = activity.at.clone();
        s.activity.push(activity);
        Ok(())
    }

    /// Add a tag (deduplicated).
    pub fn add_tag(&self, session_id: &str, tag: impl Into<String>) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("user session registry poisoned".into()))?;
        let s = g
            .get_mut(session_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown session {session_id}")))?;
        let tag = tag.into();
        if !s.tags.contains(&tag) {
            s.tags.push(tag);
        }
        Ok(())
    }

    /// Set login network metadata.
    pub fn set_network(
        &self,
        session_id: &str,
        ip: Option<String>,
        user_agent: Option<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("user session registry poisoned".into()))?;
        let s = g
            .get_mut(session_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown session {session_id}")))?;
        if let Some(ip) = ip {
            s.login_ip = Some(ip);
        }
        if let Some(ua) = user_agent {
            s.user_agent = Some(ua);
        }
        Ok(())
    }

    /// Set timeouts.
    pub fn set_timeouts(
        &self,
        session_id: &str,
        idle_secs: u64,
        absolute_secs: u64,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("user session registry poisoned".into()))?;
        let s = g
            .get_mut(session_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown session {session_id}")))?;
        s.idle_timeout_secs = idle_secs;
        s.absolute_lifetime_secs = absolute_secs;
        Ok(())
    }

    /// User-initiated logout.
    pub fn logout(
        &self,
        session_id: &str,
        ended_at: impl Into<String>,
    ) -> SandboxResult<UserSession> {
        self.terminate(session_id, ended_at, SessionState::LoggedOut, "user logout")
    }

    /// Administrative revoke / force-logout.
    pub fn revoke(
        &self,
        session_id: &str,
        ended_at: impl Into<String>,
        reason: impl Into<String>,
    ) -> SandboxResult<UserSession> {
        self.terminate(session_id, ended_at, SessionState::Revoked, reason.into())
    }

    /// Mark expired (idle/absolute timeout reached).
    pub fn expire(
        &self,
        session_id: &str,
        ended_at: impl Into<String>,
        reason: impl Into<String>,
    ) -> SandboxResult<UserSession> {
        self.terminate(session_id, ended_at, SessionState::Expired, reason.into())
    }

    fn terminate(
        &self,
        session_id: &str,
        ended_at: impl Into<String>,
        new_state: SessionState,
        reason: impl Into<String>,
    ) -> SandboxResult<UserSession> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("user session registry poisoned".into()))?;
        let s = g
            .get_mut(session_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown session {session_id}")))?;
        if s.state.is_terminal() {
            return Err(SandboxError::Other(format!(
                "session {session_id} already terminal: {:?}",
                s.state
            )));
        }
        s.state = new_state;
        s.ended_at = Some(ended_at.into());
        s.end_reason = Some(reason.into());
        Ok(s.clone())
    }

    /// Look up by id.
    pub fn get(&self, session_id: &str) -> Option<UserSession> {
        let g = self.inner.read().ok()?;
        g.get(session_id).cloned()
    }

    /// All sessions.
    pub fn all(&self) -> Vec<UserSession> {
        match self.inner.read() {
            Ok(g) => g.values().cloned().collect(),
            Err(_) => Vec::new(),
        }
    }

    /// All active sessions.
    pub fn active(&self) -> Vec<UserSession> {
        self.all().into_iter().filter(|s| s.is_open()).collect()
    }

    /// All sessions for a user.
    pub fn for_user(&self, user_id: &str) -> Vec<UserSession> {
        self.all()
            .into_iter()
            .filter(|s| s.user_id == user_id)
            .collect()
    }

    /// All sessions for a tenant.
    pub fn for_tenant(&self, tenant_id: &str) -> Vec<UserSession> {
        self.all()
            .into_iter()
            .filter(|s| s.tenant_id == tenant_id)
            .collect()
    }

    /// All sessions in a given state.
    pub fn by_state(&self, state: SessionState) -> Vec<UserSession> {
        self.all().into_iter().filter(|s| s.state == state).collect()
    }

    /// Number of registered sessions.
    pub fn count(&self) -> usize {
        self.inner.read().map(|g| g.len()).unwrap_or(0)
    }

    /// Run a sweep at `now` — terminate Active sessions whose idle or
    /// absolute deadline has passed. RFC 3339 string comparison is used.
    /// Returns the number of sessions terminated.
    pub fn sweep_expirations(&self, now: &str) -> SandboxResult<usize> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("user session registry poisoned".into()))?;
        let mut count = 0usize;
        for s in g.values_mut() {
            if !s.state.is_open() {
                continue;
            }
            let mut expired = false;
            let mut reason = String::new();
            if s.absolute_lifetime_secs > 0 {
                if let Some(deadline) = add_seconds(&s.started_at, s.absolute_lifetime_secs) {
                    if now >= deadline.as_str() {
                        expired = true;
                        reason = "absolute lifetime exceeded".into();
                    }
                }
            }
            if !expired && s.idle_timeout_secs > 0 {
                if let Some(deadline) = add_seconds(&s.last_seen_at, s.idle_timeout_secs) {
                    if now >= deadline.as_str() {
                        expired = true;
                        reason = "idle timeout exceeded".into();
                    }
                }
            }
            if expired {
                s.state = SessionState::Expired;
                s.ended_at = Some(now.to_string());
                s.end_reason = Some(reason);
                count += 1;
            }
        }
        Ok(count)
    }
}

/// Add `secs` seconds to an RFC 3339 timestamp. Returns RFC 3339 in UTC, or
/// `None` if parsing fails.
fn add_seconds(rfc3339: &str, secs: u64) -> Option<String> {
    use time::format_description::well_known::Rfc3339;
    let t = time::OffsetDateTime::parse(rfc3339, &Rfc3339).ok()?;
    let d = time::Duration::seconds(secs as i64);
    let out = t + d;
    out.format(&Rfc3339).ok()
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn s(id: &str) -> UserSession {
        UserSession::new(id, "alice", "tenant-a", MfaFactor::Totp, "2025-01-01T00:00:00Z")
    }

    fn act(at: &str, kind: &str) -> SessionActivity {
        SessionActivity {
            at: at.into(),
            kind: kind.into(),
            resource_id: None,
            ip: None,
        }
    }

    #[test]
    fn open_creates_active() {
        let r = UserSessionRegistry::new();
        r.open(s("abc")).unwrap();
        let got = r.get("abc").unwrap();
        assert_eq!(got.state, SessionState::Active);
        assert!(got.is_open());
    }

    #[test]
    fn duplicate_session_errors() {
        let r = UserSessionRegistry::new();
        r.open(s("abc")).unwrap();
        let err = r.open(s("abc")).unwrap_err();
        assert!(format!("{err}").contains("already registered"));
    }

    #[test]
    fn must_start_active() {
        let mut sess = s("abc");
        sess.state = SessionState::Expired;
        let r = UserSessionRegistry::new();
        let err = r.open(sess).unwrap_err();
        assert!(format!("{err}").contains("must start Active"));
    }

    #[test]
    fn record_activity_updates_last_seen() {
        let r = UserSessionRegistry::new();
        r.open(s("abc")).unwrap();
        r.record_activity("abc", act("2025-01-01T00:01:00Z", "page_view"))
            .unwrap();
        let got = r.get("abc").unwrap();
        assert_eq!(got.activity.len(), 1);
        assert_eq!(got.last_seen_at, "2025-01-01T00:01:00Z");
    }

    #[test]
    fn record_activity_after_terminal_errors() {
        let r = UserSessionRegistry::new();
        r.open(s("abc")).unwrap();
        r.logout("abc", "2025-01-01T01:00:00Z").unwrap();
        let err = r
            .record_activity("abc", act("2025-01-01T01:01:00Z", "ping"))
            .unwrap_err();
        assert!(format!("{err}").contains("terminal"));
    }

    #[test]
    fn add_tag_dedupes() {
        let r = UserSessionRegistry::new();
        r.open(s("abc")).unwrap();
        r.add_tag("abc", "support").unwrap();
        r.add_tag("abc", "support").unwrap();
        r.add_tag("abc", "break-glass").unwrap();
        let got = r.get("abc").unwrap();
        assert_eq!(got.tags, vec!["support", "break-glass"]);
    }

    #[test]
    fn set_network_metadata() {
        let r = UserSessionRegistry::new();
        r.open(s("abc")).unwrap();
        r.set_network(
            "abc",
            Some("10.1.2.3".into()),
            Some("Mozilla/5.0".into()),
        )
        .unwrap();
        let got = r.get("abc").unwrap();
        assert_eq!(got.login_ip.as_deref(), Some("10.1.2.3"));
        assert_eq!(got.user_agent.as_deref(), Some("Mozilla/5.0"));
    }

    #[test]
    fn logout_terminates() {
        let r = UserSessionRegistry::new();
        r.open(s("abc")).unwrap();
        let ended = r.logout("abc", "2025-01-01T01:00:00Z").unwrap();
        assert_eq!(ended.state, SessionState::LoggedOut);
        assert_eq!(ended.end_reason.as_deref(), Some("user logout"));
    }

    #[test]
    fn revoke_terminates() {
        let r = UserSessionRegistry::new();
        r.open(s("abc")).unwrap();
        let ended = r
            .revoke("abc", "2025-01-01T01:00:00Z", "compromised credentials")
            .unwrap();
        assert_eq!(ended.state, SessionState::Revoked);
        assert_eq!(ended.end_reason.as_deref(), Some("compromised credentials"));
    }

    #[test]
    fn expire_terminates() {
        let r = UserSessionRegistry::new();
        r.open(s("abc")).unwrap();
        let ended = r
            .expire("abc", "2025-01-01T01:00:00Z", "idle")
            .unwrap();
        assert_eq!(ended.state, SessionState::Expired);
    }

    #[test]
    fn cannot_terminate_twice() {
        let r = UserSessionRegistry::new();
        r.open(s("abc")).unwrap();
        r.logout("abc", "2025-01-01T01:00:00Z").unwrap();
        let err = r.logout("abc", "2025-01-01T01:01:00Z").unwrap_err();
        assert!(format!("{err}").contains("already terminal"));
    }

    #[test]
    fn unknown_session_errors() {
        let r = UserSessionRegistry::new();
        let err = r.logout("nope", "2025-01-01T01:00:00Z").unwrap_err();
        assert!(format!("{err}").contains("unknown session"));
    }

    #[test]
    fn for_user_filters() {
        let r = UserSessionRegistry::new();
        r.open(s("a1")).unwrap();
        let mut other = s("b1");
        other.user_id = "bob".into();
        r.open(other).unwrap();
        assert_eq!(r.for_user("alice").len(), 1);
        assert_eq!(r.for_user("bob").len(), 1);
        assert_eq!(r.for_user("nobody").len(), 0);
    }

    #[test]
    fn for_tenant_filters() {
        let r = UserSessionRegistry::new();
        r.open(s("a1")).unwrap();
        let mut other = s("b1");
        other.tenant_id = "tenant-b".into();
        r.open(other).unwrap();
        assert_eq!(r.for_tenant("tenant-a").len(), 1);
        assert_eq!(r.for_tenant("tenant-b").len(), 1);
    }

    #[test]
    fn active_excludes_terminal() {
        let r = UserSessionRegistry::new();
        r.open(s("a1")).unwrap();
        r.open(s("a2")).unwrap();
        r.logout("a1", "2025-01-01T01:00:00Z").unwrap();
        assert_eq!(r.active().len(), 1);
    }

    #[test]
    fn by_state_filters() {
        let r = UserSessionRegistry::new();
        r.open(s("a1")).unwrap();
        r.open(s("a2")).unwrap();
        r.revoke("a2", "2025-01-01T01:00:00Z", "x").unwrap();
        assert_eq!(r.by_state(SessionState::Active).len(), 1);
        assert_eq!(r.by_state(SessionState::Revoked).len(), 1);
        assert_eq!(r.by_state(SessionState::LoggedOut).len(), 0);
    }

    #[test]
    fn count_tracks() {
        let r = UserSessionRegistry::new();
        assert_eq!(r.count(), 0);
        r.open(s("a")).unwrap();
        r.open(s("b")).unwrap();
        assert_eq!(r.count(), 2);
    }

    #[test]
    fn state_helpers() {
        assert!(SessionState::Active.is_open());
        assert!(!SessionState::Active.is_terminal());
        for st in [
            SessionState::Expired,
            SessionState::Revoked,
            SessionState::LoggedOut,
        ] {
            assert!(!st.is_open());
            assert!(st.is_terminal());
        }
    }

    #[test]
    fn mfa_phishing_resistance() {
        assert!(MfaFactor::Webauthn.is_phishing_resistant());
        assert!(MfaFactor::HardwareKey.is_phishing_resistant());
        assert!(!MfaFactor::Totp.is_phishing_resistant());
        assert!(!MfaFactor::Sms.is_phishing_resistant());
        assert!(!MfaFactor::None.is_phishing_resistant());
    }

    #[test]
    fn sweep_idle_timeout() {
        let r = UserSessionRegistry::new();
        r.open(s("abc")).unwrap();
        r.set_timeouts("abc", 60, 0).unwrap();
        // last_seen at started_at == "2025-01-01T00:00:00Z"; +60s = 00:01:00
        let n = r.sweep_expirations("2025-01-01T00:02:00Z").unwrap();
        assert_eq!(n, 1);
        let got = r.get("abc").unwrap();
        assert_eq!(got.state, SessionState::Expired);
        assert!(got
            .end_reason
            .as_deref()
            .unwrap()
            .contains("idle timeout"));
    }

    #[test]
    fn sweep_absolute_lifetime() {
        let r = UserSessionRegistry::new();
        r.open(s("abc")).unwrap();
        r.set_timeouts("abc", 0, 30).unwrap();
        let n = r.sweep_expirations("2025-01-01T00:01:00Z").unwrap();
        assert_eq!(n, 1);
        let got = r.get("abc").unwrap();
        assert!(got
            .end_reason
            .as_deref()
            .unwrap()
            .contains("absolute lifetime"));
    }

    #[test]
    fn sweep_skips_already_terminal() {
        let r = UserSessionRegistry::new();
        r.open(s("abc")).unwrap();
        r.set_timeouts("abc", 60, 0).unwrap();
        r.logout("abc", "2025-01-01T00:00:30Z").unwrap();
        let n = r.sweep_expirations("2025-01-01T00:02:00Z").unwrap();
        assert_eq!(n, 0); // already LoggedOut, not re-expired
    }

    #[test]
    fn sweep_does_not_expire_within_window() {
        let r = UserSessionRegistry::new();
        r.open(s("abc")).unwrap();
        r.set_timeouts("abc", 600, 0).unwrap();
        let n = r.sweep_expirations("2025-01-01T00:01:00Z").unwrap();
        assert_eq!(n, 0);
        assert_eq!(r.get("abc").unwrap().state, SessionState::Active);
    }

    #[test]
    fn sweep_multiple_sessions() {
        let r = UserSessionRegistry::new();
        r.open(s("a")).unwrap();
        r.open(s("b")).unwrap();
        r.set_timeouts("a", 60, 0).unwrap();
        // b has no timeouts → won't expire
        let n = r.sweep_expirations("2025-01-01T00:05:00Z").unwrap();
        assert_eq!(n, 1);
        assert_eq!(r.get("a").unwrap().state, SessionState::Expired);
        assert_eq!(r.get("b").unwrap().state, SessionState::Active);
    }

    #[test]
    fn session_serde() {
        let sess = s("abc");
        let s_json = serde_json::to_string(&sess).unwrap();
        let back: UserSession = serde_json::from_str(&s_json).unwrap();
        assert_eq!(sess, back);
    }

    #[test]
    fn activity_serde() {
        let a = act("2025-01-01T00:01:00Z", "page_view");
        let s_json = serde_json::to_string(&a).unwrap();
        let back: SessionActivity = serde_json::from_str(&s_json).unwrap();
        assert_eq!(a, back);
    }

    #[test]
    fn state_serde_roundtrip() {
        for st in [
            SessionState::Active,
            SessionState::Expired,
            SessionState::Revoked,
            SessionState::LoggedOut,
        ] {
            let s = serde_json::to_string(&st).unwrap();
            let back: SessionState = serde_json::from_str(&s).unwrap();
            assert_eq!(st, back);
        }
    }

    #[test]
    fn mfa_serde_roundtrip() {
        for m in [
            MfaFactor::None,
            MfaFactor::Totp,
            MfaFactor::Webauthn,
            MfaFactor::HardwareKey,
            MfaFactor::Push,
            MfaFactor::Sms,
        ] {
            let s = serde_json::to_string(&m).unwrap();
            let back: MfaFactor = serde_json::from_str(&s).unwrap();
            assert_eq!(m, back);
        }
    }
}
