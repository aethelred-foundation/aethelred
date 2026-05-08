//! Anti-replay defense — nonce + timestamp window.
//!
//! Many incoming requests carry HMAC-signed payloads (capability tokens,
//! webhook callbacks, partner API requests). A signature alone doesn't stop
//! *replay attacks* where an attacker captures a valid request and replays
//! it later. This module provides the standard countermeasure:
//!
//! 1. Each request must carry a `timestamp` and `nonce`.
//! 2. The verifier rejects requests outside an acceptance window
//!    (default ±5 minutes around current time).
//! 3. The verifier remembers nonces it has seen within the window and
//!    rejects duplicates.
//! 4. Old nonces are pruned automatically once they fall outside the
//!    window — bounded memory.
//!
//! This is the same mechanism used by AWS Sig V4, Stripe webhooks, and
//! GitHub webhooks.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use time::{Duration, OffsetDateTime};

// =============================================================================
// AntiReplayConfig
// =============================================================================

/// Window configuration.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct AntiReplayConfig {
    /// Maximum allowed clock skew in either direction.
    pub window_seconds: i64,
    /// Maximum tracked nonces (oldest evicted).
    pub max_tracked_nonces: usize,
}

impl Default for AntiReplayConfig {
    fn default() -> Self {
        Self {
            window_seconds: 300, // ±5 minutes
            max_tracked_nonces: 100_000,
        }
    }
}

// =============================================================================
// VerifyOutcome
// =============================================================================

/// Per-request verification outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "outcome")]
pub enum VerifyOutcome {
    /// Accepted (timestamp within window, nonce fresh).
    Ok,
    /// Timestamp outside the window.
    OutsideWindow {
        /// Skew in seconds (positive = future, negative = past).
        skew_seconds: i64,
    },
    /// Nonce already seen within the window.
    DuplicateNonce {
        /// The nonce.
        nonce: String,
    },
}

impl VerifyOutcome {
    /// `true` if the request is accepted.
    pub fn is_ok(&self) -> bool {
        matches!(self, VerifyOutcome::Ok)
    }
}

// =============================================================================
// AntiReplayVerifier
// =============================================================================

#[derive(Debug)]
struct State {
    /// nonce → last-seen unix-ts.
    nonces: HashMap<String, i64>,
    /// Per-scope counters for accepted/rejected (audit).
    accepted: u64,
    rejected_skew: u64,
    rejected_replay: u64,
}

/// Stateful nonce + timestamp verifier.
#[derive(Debug)]
pub struct AntiReplayVerifier {
    cfg: AntiReplayConfig,
    state: Mutex<State>,
}

impl Default for AntiReplayVerifier {
    fn default() -> Self {
        Self::new(AntiReplayConfig::default())
    }
}

impl AntiReplayVerifier {
    /// New verifier with config.
    pub fn new(cfg: AntiReplayConfig) -> Self {
        Self {
            cfg,
            state: Mutex::new(State {
                nonces: HashMap::new(),
                accepted: 0,
                rejected_skew: 0,
                rejected_replay: 0,
            }),
        }
    }

    /// Verify `(nonce, timestamp)` against `now`.
    pub fn verify_at(
        &self,
        nonce: &str,
        timestamp: OffsetDateTime,
        now: OffsetDateTime,
    ) -> SandboxResult<VerifyOutcome> {
        let skew = now.unix_timestamp() - timestamp.unix_timestamp();
        if skew.abs() > self.cfg.window_seconds {
            self.bump(|s| s.rejected_skew += 1)?;
            return Ok(VerifyOutcome::OutsideWindow {
                skew_seconds: skew,
            });
        }
        let mut g = self
            .state
            .lock()
            .map_err(|_| SandboxError::Other("anti-replay state poisoned".into()))?;
        // Prune expired.
        let cutoff = now.unix_timestamp() - self.cfg.window_seconds;
        g.nonces.retain(|_, ts| *ts >= cutoff);
        // Memory cap.
        if g.nonces.len() >= self.cfg.max_tracked_nonces {
            // Evict the oldest 10% to amortize.
            let mut entries: Vec<(String, i64)> =
                g.nonces.iter().map(|(k, v)| (k.clone(), *v)).collect();
            entries.sort_by_key(|(_, v)| *v);
            let drop_n = entries.len() / 10;
            for (k, _) in entries.into_iter().take(drop_n) {
                g.nonces.remove(&k);
            }
        }
        if g.nonces.contains_key(nonce) {
            g.rejected_replay += 1;
            return Ok(VerifyOutcome::DuplicateNonce {
                nonce: nonce.to_string(),
            });
        }
        g.nonces.insert(nonce.to_string(), timestamp.unix_timestamp());
        g.accepted += 1;
        Ok(VerifyOutcome::Ok)
    }

    /// Verify against `OffsetDateTime::now_utc()`.
    pub fn verify(
        &self,
        nonce: &str,
        timestamp: OffsetDateTime,
    ) -> SandboxResult<VerifyOutcome> {
        self.verify_at(nonce, timestamp, OffsetDateTime::now_utc())
    }

    /// Force-prune expired nonces (manual maintenance).
    pub fn prune_at(&self, now: OffsetDateTime) -> SandboxResult<usize> {
        let mut g = self
            .state
            .lock()
            .map_err(|_| SandboxError::Other("anti-replay state poisoned".into()))?;
        let cutoff = now.unix_timestamp() - self.cfg.window_seconds;
        let before = g.nonces.len();
        g.nonces.retain(|_, ts| *ts >= cutoff);
        Ok(before - g.nonces.len())
    }

    /// Snapshot of (accepted, rejected_skew, rejected_replay).
    pub fn stats(&self) -> (u64, u64, u64) {
        self.state
            .lock()
            .ok()
            .map(|g| (g.accepted, g.rejected_skew, g.rejected_replay))
            .unwrap_or((0, 0, 0))
    }

    /// Number of currently-tracked nonces.
    pub fn tracked(&self) -> usize {
        self.state.lock().map(|g| g.nonces.len()).unwrap_or(0)
    }

    fn bump<F: FnOnce(&mut State)>(&self, f: F) -> SandboxResult<()> {
        let mut g = self
            .state
            .lock()
            .map_err(|_| SandboxError::Other("anti-replay state poisoned".into()))?;
        f(&mut g);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }

    #[test]
    fn fresh_nonce_in_window_accepted() {
        let v = AntiReplayVerifier::default();
        let n = now();
        assert_eq!(v.verify_at("n1", n, n).unwrap(), VerifyOutcome::Ok);
    }

    #[test]
    fn duplicate_nonce_rejected() {
        let v = AntiReplayVerifier::default();
        let n = now();
        v.verify_at("n1", n, n).unwrap();
        let r = v.verify_at("n1", n, n).unwrap();
        match r {
            VerifyOutcome::DuplicateNonce { nonce } => assert_eq!(nonce, "n1"),
            _ => panic!("expected duplicate"),
        }
    }

    #[test]
    fn timestamp_in_future_outside_window_rejected() {
        let v = AntiReplayVerifier::default();
        let n = now();
        let future = n + Duration::seconds(600);
        let r = v.verify_at("n1", future, n).unwrap();
        match r {
            VerifyOutcome::OutsideWindow { skew_seconds } => assert!(skew_seconds < 0),
            _ => panic!("expected outside window"),
        }
    }

    #[test]
    fn timestamp_in_past_outside_window_rejected() {
        let v = AntiReplayVerifier::default();
        let n = now();
        let past = n - Duration::seconds(600);
        let r = v.verify_at("n1", past, n).unwrap();
        match r {
            VerifyOutcome::OutsideWindow { skew_seconds } => assert!(skew_seconds > 0),
            _ => panic!("expected outside window"),
        }
    }

    #[test]
    fn timestamp_at_window_boundary_accepted() {
        let v = AntiReplayVerifier::default();
        let n = now();
        // Exactly at +window.
        let edge = n + Duration::seconds(300);
        assert!(v.verify_at("n1", edge, n).unwrap().is_ok());
    }

    #[test]
    fn nonce_after_window_can_be_reused() {
        let v = AntiReplayVerifier::default();
        let t0 = now();
        v.verify_at("n1", t0, t0).unwrap();
        // 600s later — original nonce timestamp is now outside the window.
        let t1 = t0 + Duration::seconds(600);
        // Replay the original nonce with a fresh timestamp:
        // since pruning ran, "n1" will be accepted again.
        let outcome = v.verify_at("n1", t1, t1).unwrap();
        assert_eq!(outcome, VerifyOutcome::Ok);
    }

    #[test]
    fn different_nonces_independent() {
        let v = AntiReplayVerifier::default();
        let n = now();
        for i in 0..50 {
            let s = format!("n{i}");
            assert!(v.verify_at(&s, n, n).unwrap().is_ok());
        }
    }

    #[test]
    fn stats_track_accepted_and_rejected() {
        let v = AntiReplayVerifier::default();
        let n = now();
        v.verify_at("n1", n, n).unwrap(); // ok
        v.verify_at("n1", n, n).unwrap(); // duplicate
        v.verify_at("n2", n + Duration::seconds(600), n).unwrap(); // skew
        let (a, s, r) = v.stats();
        assert_eq!(a, 1);
        assert_eq!(s, 1);
        assert_eq!(r, 1);
    }

    #[test]
    fn prune_removes_expired() {
        let v = AntiReplayVerifier::default();
        let t0 = now();
        v.verify_at("n", t0, t0).unwrap();
        let dropped = v.prune_at(t0 + Duration::seconds(600)).unwrap();
        assert_eq!(dropped, 1);
    }

    #[test]
    fn tracked_count_reflects_accepted() {
        let v = AntiReplayVerifier::default();
        let n = now();
        for i in 0..10 {
            v.verify_at(&format!("n{i}"), n, n).unwrap();
        }
        assert_eq!(v.tracked(), 10);
    }

    #[test]
    fn outcome_serde_round_trip() {
        for o in [
            VerifyOutcome::Ok,
            VerifyOutcome::OutsideWindow {
                skew_seconds: 600,
            },
            VerifyOutcome::DuplicateNonce {
                nonce: "x".into(),
            },
        ] {
            let j = serde_json::to_string(&o).unwrap();
            let p: VerifyOutcome = serde_json::from_str(&j).unwrap();
            assert_eq!(p, o);
        }
    }

    #[test]
    fn config_default_is_5_minutes() {
        let c = AntiReplayConfig::default();
        assert_eq!(c.window_seconds, 300);
    }

    #[test]
    fn custom_window_respected() {
        let v = AntiReplayVerifier::new(AntiReplayConfig {
            window_seconds: 60,
            max_tracked_nonces: 10,
        });
        let n = now();
        let outside = n + Duration::seconds(100);
        assert!(matches!(
            v.verify_at("n1", outside, n).unwrap(),
            VerifyOutcome::OutsideWindow { .. }
        ));
    }

    #[test]
    fn memory_cap_evicts_old_entries() {
        let v = AntiReplayVerifier::new(AntiReplayConfig {
            window_seconds: 3600,
            max_tracked_nonces: 10,
        });
        let n = now();
        for i in 0..20 {
            v.verify_at(&format!("n{i}"), n, n).unwrap();
        }
        // Cap is 10 — but eviction is "10% of current" so we may be over
        // briefly. Just assert we're under 2x cap.
        assert!(v.tracked() < 20);
    }

    #[test]
    fn outcome_is_ok_helper() {
        assert!(VerifyOutcome::Ok.is_ok());
        assert!(!VerifyOutcome::OutsideWindow {
            skew_seconds: 0
        }
        .is_ok());
        assert!(!VerifyOutcome::DuplicateNonce {
            nonce: "x".into()
        }
        .is_ok());
    }

    #[test]
    fn verify_uses_now_clock() {
        let v = AntiReplayVerifier::default();
        let r = v.verify("n", OffsetDateTime::now_utc()).unwrap();
        assert!(r.is_ok());
    }

    #[test]
    fn stats_zero_initially() {
        let v = AntiReplayVerifier::default();
        assert_eq!(v.stats(), (0, 0, 0));
    }

    #[test]
    fn skew_sign_correct_for_past() {
        let v = AntiReplayVerifier::default();
        let n = now();
        let r = v
            .verify_at("n", n - Duration::seconds(600), n)
            .unwrap();
        match r {
            VerifyOutcome::OutsideWindow { skew_seconds } => assert!(skew_seconds > 0),
            _ => panic!(),
        }
    }

    #[test]
    fn skew_sign_correct_for_future() {
        let v = AntiReplayVerifier::default();
        let n = now();
        let r = v
            .verify_at("n", n + Duration::seconds(600), n)
            .unwrap();
        match r {
            VerifyOutcome::OutsideWindow { skew_seconds } => assert!(skew_seconds < 0),
            _ => panic!(),
        }
    }

    #[test]
    fn many_unique_nonces_all_accepted() {
        let v = AntiReplayVerifier::default();
        let n = now();
        for i in 0..1_000 {
            assert!(v.verify_at(&format!("n{i}"), n, n).unwrap().is_ok());
        }
        assert_eq!(v.stats().0, 1000);
    }
}
