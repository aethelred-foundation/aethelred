//! Per-tenant rate limiting and circuit breaking.
//!
//! Two complementary controls for keeping the sandbox healthy under load:
//!
//! 1. [`TokenBucket`] — burst-tolerant but capped throughput per tenant.
//!    Each tenant has a bucket with `capacity` tokens, refilled at
//!    `refill_per_sec` tokens/second. A request consumes one token.
//!    If the bucket is empty, the request is rejected (fail-closed).
//!
//! 2. [`CircuitBreaker`] — stop cascading failure when a downstream is sick.
//!    Tracks recent error rate over a sliding window. If error rate breaches
//!    `failure_threshold`, the circuit *opens* (reject fast) for `cool_down`.
//!    After cool-down, transitions to *half-open* (probe with one request);
//!    on success → *closed*, on failure → *open* again.
//!
//! [`RateLimiter`] composes both per-tenant.
//!
//! ## Usage
//!
//! ```ignore
//! let rl = RateLimiter::new(BucketConfig {
//!     capacity: 100,
//!     refill_per_sec: 50.0,
//! }, BreakerConfig::default());
//! match rl.check("FAB") {
//!     RateDecision::Allow => { /* proceed */ }
//!     RateDecision::ThrottleBucket => { /* 429 too many requests */ }
//!     RateDecision::CircuitOpen => { /* 503 fail fast */ }
//! }
//! // After call:
//! rl.record_outcome("FAB", true);   // success → closes breaker
//! rl.record_outcome("FAB", false);  // failure → counts toward threshold
//! ```

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

// =============================================================================
// TokenBucket
// =============================================================================

/// Configuration for a per-tenant token bucket.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct BucketConfig {
    /// Maximum tokens (burst capacity).
    pub capacity: u32,
    /// Refill rate in tokens/second.
    pub refill_per_sec: f64,
}

impl Default for BucketConfig {
    fn default() -> Self {
        Self {
            capacity: 100,
            refill_per_sec: 50.0,
        }
    }
}

#[derive(Debug)]
struct BucketState {
    tokens: f64,
    last_refill: Instant,
}

impl BucketState {
    fn fresh(capacity: u32) -> Self {
        Self {
            tokens: capacity as f64,
            last_refill: Instant::now(),
        }
    }

    fn refill(&mut self, cfg: &BucketConfig, now: Instant) {
        let elapsed = now.saturating_duration_since(self.last_refill).as_secs_f64();
        if elapsed > 0.0 {
            self.tokens =
                (self.tokens + elapsed * cfg.refill_per_sec).min(cfg.capacity as f64);
            self.last_refill = now;
        }
    }

    fn try_take(&mut self, cfg: &BucketConfig, now: Instant) -> bool {
        self.refill(cfg, now);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    fn current(&self) -> f64 {
        self.tokens
    }
}

/// One-tenant token bucket (instances are managed by [`RateLimiter`]).
#[derive(Debug)]
pub struct TokenBucket {
    cfg: BucketConfig,
    state: Mutex<BucketState>,
}

impl TokenBucket {
    /// New bucket starting full.
    pub fn new(cfg: BucketConfig) -> Self {
        Self {
            state: Mutex::new(BucketState::fresh(cfg.capacity)),
            cfg,
        }
    }

    /// Try to take one token. Returns `false` if empty.
    pub fn try_take(&self) -> bool {
        self.try_take_at(Instant::now())
    }

    /// Try to take one token at a given instant (for tests).
    pub fn try_take_at(&self, now: Instant) -> bool {
        match self.state.lock() {
            Ok(mut g) => g.try_take(&self.cfg, now),
            Err(_) => false,
        }
    }

    /// Approximate current token count (for metrics).
    pub fn current(&self) -> f64 {
        self.state.lock().map(|g| g.current()).unwrap_or(0.0)
    }

    /// Bucket capacity.
    pub fn capacity(&self) -> u32 {
        self.cfg.capacity
    }
}

// =============================================================================
// CircuitBreaker
// =============================================================================

/// Configuration for the circuit breaker.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct BreakerConfig {
    /// Minimum samples in the window before deciding to open.
    pub min_samples: u32,
    /// Failure ratio (0.0..=1.0) at which the circuit opens.
    pub failure_threshold: f64,
    /// How long the circuit stays open before going half-open.
    pub cool_down: Duration,
    /// Sliding window over which failures are counted.
    pub window: Duration,
}

impl Default for BreakerConfig {
    fn default() -> Self {
        Self {
            min_samples: 10,
            failure_threshold: 0.5,
            cool_down: Duration::from_secs(30),
            window: Duration::from_secs(60),
        }
    }
}

/// Circuit state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CircuitState {
    /// Healthy — requests flow through.
    Closed,
    /// Tripped — requests rejected immediately.
    Open,
    /// Probing — one request allowed; success closes, failure re-opens.
    HalfOpen,
}

#[derive(Debug)]
struct Sample {
    at: Instant,
    success: bool,
}

#[derive(Debug)]
struct BreakerState {
    state: CircuitState,
    opened_at: Option<Instant>,
    samples: Vec<Sample>,
    half_open_in_flight: bool,
}

impl BreakerState {
    fn new() -> Self {
        Self {
            state: CircuitState::Closed,
            opened_at: None,
            samples: Vec::new(),
            half_open_in_flight: false,
        }
    }

    fn prune(&mut self, cfg: &BreakerConfig, now: Instant) {
        self.samples
            .retain(|s| now.saturating_duration_since(s.at) <= cfg.window);
    }

    fn ratio(&self) -> (u32, f64) {
        if self.samples.is_empty() {
            return (0, 0.0);
        }
        let total = self.samples.len() as u32;
        let failures = self.samples.iter().filter(|s| !s.success).count() as f64;
        (total, failures / total as f64)
    }
}

/// Circuit breaker (one per tenant).
#[derive(Debug)]
pub struct CircuitBreaker {
    cfg: BreakerConfig,
    state: Mutex<BreakerState>,
}

impl CircuitBreaker {
    /// New closed breaker.
    pub fn new(cfg: BreakerConfig) -> Self {
        Self {
            cfg,
            state: Mutex::new(BreakerState::new()),
        }
    }

    /// Decide whether to allow a request now.
    pub fn allow(&self) -> bool {
        self.allow_at(Instant::now())
    }

    /// Decide whether to allow a request at a given instant.
    pub fn allow_at(&self, now: Instant) -> bool {
        let mut g = match self.state.lock() {
            Ok(g) => g,
            Err(_) => return false,
        };
        match g.state {
            CircuitState::Closed => true,
            CircuitState::Open => {
                if let Some(opened) = g.opened_at {
                    if now.saturating_duration_since(opened) >= self.cfg.cool_down {
                        g.state = CircuitState::HalfOpen;
                        g.half_open_in_flight = true;
                        return true;
                    }
                }
                false
            }
            CircuitState::HalfOpen => {
                if g.half_open_in_flight {
                    false
                } else {
                    g.half_open_in_flight = true;
                    true
                }
            }
        }
    }

    /// Record the outcome of a request the breaker permitted.
    pub fn record(&self, success: bool) {
        self.record_at(success, Instant::now())
    }

    /// Record at a given instant (for tests).
    pub fn record_at(&self, success: bool, now: Instant) {
        let mut g = match self.state.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        // Half-open probe outcome controls transition.
        if matches!(g.state, CircuitState::HalfOpen) {
            g.half_open_in_flight = false;
            if success {
                g.state = CircuitState::Closed;
                g.opened_at = None;
                g.samples.clear();
            } else {
                g.state = CircuitState::Open;
                g.opened_at = Some(now);
            }
            return;
        }
        // Normal sample bookkeeping.
        g.samples.push(Sample { at: now, success });
        g.prune(&self.cfg, now);
        let (total, ratio) = g.ratio();
        if total >= self.cfg.min_samples
            && ratio >= self.cfg.failure_threshold
            && matches!(g.state, CircuitState::Closed)
        {
            g.state = CircuitState::Open;
            g.opened_at = Some(now);
        }
    }

    /// Current state.
    pub fn state(&self) -> CircuitState {
        self.state.lock().map(|g| g.state).unwrap_or(CircuitState::Closed)
    }

    /// Force the breaker open (operator override).
    pub fn force_open(&self) {
        if let Ok(mut g) = self.state.lock() {
            g.state = CircuitState::Open;
            g.opened_at = Some(Instant::now());
        }
    }

    /// Force the breaker closed (operator override).
    pub fn force_close(&self) {
        if let Ok(mut g) = self.state.lock() {
            g.state = CircuitState::Closed;
            g.opened_at = None;
            g.samples.clear();
            g.half_open_in_flight = false;
        }
    }
}

// =============================================================================
// RateLimiter — per-tenant composition
// =============================================================================

/// Per-tenant decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RateDecision {
    /// Request is allowed.
    Allow,
    /// Bucket empty (HTTP 429-style throttle).
    ThrottleBucket,
    /// Circuit breaker is open (HTTP 503-style fail-fast).
    CircuitOpen,
}

/// Per-tenant rate limiter + circuit breaker.
#[derive(Debug)]
pub struct RateLimiter {
    bucket_cfg: BucketConfig,
    breaker_cfg: BreakerConfig,
    buckets: Mutex<HashMap<String, TokenBucket>>,
    breakers: Mutex<HashMap<String, CircuitBreaker>>,
}

impl RateLimiter {
    /// New limiter with per-tenant defaults.
    pub fn new(bucket_cfg: BucketConfig, breaker_cfg: BreakerConfig) -> Self {
        Self {
            bucket_cfg,
            breaker_cfg,
            buckets: Mutex::new(HashMap::new()),
            breakers: Mutex::new(HashMap::new()),
        }
    }

    /// Check whether a tenant may proceed now.
    ///
    /// Order: circuit breaker first (fail-fast on broken downstream), then
    /// token bucket (cap accepted load).
    pub fn check(&self, tenant: &str) -> SandboxResult<RateDecision> {
        // Breaker.
        {
            let mut g = self
                .breakers
                .lock()
                .map_err(|_| SandboxError::Other("breaker map poisoned".into()))?;
            let br = g
                .entry(tenant.to_string())
                .or_insert_with(|| CircuitBreaker::new(self.breaker_cfg));
            if !br.allow() {
                return Ok(RateDecision::CircuitOpen);
            }
        }
        // Bucket.
        {
            let mut g = self
                .buckets
                .lock()
                .map_err(|_| SandboxError::Other("bucket map poisoned".into()))?;
            let b = g
                .entry(tenant.to_string())
                .or_insert_with(|| TokenBucket::new(self.bucket_cfg));
            if !b.try_take() {
                return Ok(RateDecision::ThrottleBucket);
            }
        }
        Ok(RateDecision::Allow)
    }

    /// Record an outcome for a request that was allowed through.
    pub fn record_outcome(&self, tenant: &str, success: bool) -> SandboxResult<()> {
        let mut g = self
            .breakers
            .lock()
            .map_err(|_| SandboxError::Other("breaker map poisoned".into()))?;
        let br = g
            .entry(tenant.to_string())
            .or_insert_with(|| CircuitBreaker::new(self.breaker_cfg));
        br.record(success);
        Ok(())
    }

    /// Get the breaker state for a tenant (creates a fresh closed breaker if none).
    pub fn breaker_state(&self, tenant: &str) -> SandboxResult<CircuitState> {
        let mut g = self
            .breakers
            .lock()
            .map_err(|_| SandboxError::Other("breaker map poisoned".into()))?;
        let br = g
            .entry(tenant.to_string())
            .or_insert_with(|| CircuitBreaker::new(self.breaker_cfg));
        Ok(br.state())
    }

    /// Approximate token count for a tenant.
    pub fn tokens_remaining(&self, tenant: &str) -> SandboxResult<f64> {
        let mut g = self
            .buckets
            .lock()
            .map_err(|_| SandboxError::Other("bucket map poisoned".into()))?;
        let b = g
            .entry(tenant.to_string())
            .or_insert_with(|| TokenBucket::new(self.bucket_cfg));
        Ok(b.current())
    }

    /// Force a tenant's breaker open (incident response).
    pub fn force_open(&self, tenant: &str) -> SandboxResult<()> {
        let mut g = self
            .breakers
            .lock()
            .map_err(|_| SandboxError::Other("breaker map poisoned".into()))?;
        g.entry(tenant.to_string())
            .or_insert_with(|| CircuitBreaker::new(self.breaker_cfg))
            .force_open();
        Ok(())
    }

    /// Force a tenant's breaker closed (incident remediation).
    pub fn force_close(&self, tenant: &str) -> SandboxResult<()> {
        let mut g = self
            .breakers
            .lock()
            .map_err(|_| SandboxError::Other("breaker map poisoned".into()))?;
        g.entry(tenant.to_string())
            .or_insert_with(|| CircuitBreaker::new(self.breaker_cfg))
            .force_close();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_small() -> BucketConfig {
        BucketConfig { capacity: 3, refill_per_sec: 0.0 }
    }

    fn cfg_breaker_small() -> BreakerConfig {
        BreakerConfig {
            min_samples: 4,
            failure_threshold: 0.5,
            cool_down: Duration::from_millis(50),
            window: Duration::from_secs(60),
        }
    }

    #[test]
    fn bucket_starts_full() {
        let b = TokenBucket::new(cfg_small());
        assert_eq!(b.capacity(), 3);
        assert!((b.current() - 3.0).abs() < 1e-6);
    }

    #[test]
    fn bucket_drains_to_empty() {
        let b = TokenBucket::new(cfg_small());
        assert!(b.try_take());
        assert!(b.try_take());
        assert!(b.try_take());
        assert!(!b.try_take());
    }

    #[test]
    fn bucket_refills_over_time() {
        let b = TokenBucket::new(BucketConfig { capacity: 2, refill_per_sec: 100.0 });
        let t0 = Instant::now();
        assert!(b.try_take_at(t0));
        assert!(b.try_take_at(t0));
        assert!(!b.try_take_at(t0));
        // Move forward 50ms → ~5 tokens refilled (capped at 2).
        let t1 = t0 + Duration::from_millis(50);
        assert!(b.try_take_at(t1));
        assert!(b.try_take_at(t1));
        assert!(!b.try_take_at(t1));
    }

    #[test]
    fn bucket_cap_respected() {
        let b = TokenBucket::new(BucketConfig { capacity: 2, refill_per_sec: 100.0 });
        let t0 = Instant::now();
        // Long idle → bucket should still be capped at 2.
        let t1 = t0 + Duration::from_secs(60);
        assert!(b.try_take_at(t1));
        assert!(b.try_take_at(t1));
        assert!(!b.try_take_at(t1));
    }

    #[test]
    fn breaker_starts_closed() {
        let br = CircuitBreaker::new(cfg_breaker_small());
        assert_eq!(br.state(), CircuitState::Closed);
        assert!(br.allow());
    }

    #[test]
    fn breaker_opens_when_failures_exceed_threshold() {
        let br = CircuitBreaker::new(cfg_breaker_small());
        let t = Instant::now();
        // 4 samples (min), 3 failures → ratio 0.75 ≥ 0.5 → opens.
        for _ in 0..3 {
            br.record_at(false, t);
        }
        br.record_at(true, t);
        assert_eq!(br.state(), CircuitState::Open);
    }

    #[test]
    fn breaker_does_not_open_below_min_samples() {
        let br = CircuitBreaker::new(cfg_breaker_small());
        let t = Instant::now();
        // Only 3 samples, below min_samples=4 → stays closed even all failed.
        for _ in 0..3 {
            br.record_at(false, t);
        }
        assert_eq!(br.state(), CircuitState::Closed);
    }

    #[test]
    fn breaker_open_rejects() {
        let br = CircuitBreaker::new(cfg_breaker_small());
        br.force_open();
        assert!(!br.allow());
    }

    #[test]
    fn breaker_half_open_after_cool_down() {
        let br = CircuitBreaker::new(cfg_breaker_small());
        br.force_open();
        // Force opened_at by injecting failures via half-open path.
        // Wait past cool-down using allow_at.
        let t1 = Instant::now() + Duration::from_secs(1);
        let allowed = br.allow_at(t1);
        assert!(allowed, "should permit one probe");
        assert_eq!(br.state(), CircuitState::HalfOpen);
    }

    #[test]
    fn breaker_half_open_success_closes() {
        let br = CircuitBreaker::new(cfg_breaker_small());
        br.force_open();
        let t1 = Instant::now() + Duration::from_secs(1);
        br.allow_at(t1);
        br.record_at(true, t1);
        assert_eq!(br.state(), CircuitState::Closed);
    }

    #[test]
    fn breaker_half_open_failure_reopens() {
        let br = CircuitBreaker::new(cfg_breaker_small());
        br.force_open();
        let t1 = Instant::now() + Duration::from_secs(1);
        br.allow_at(t1);
        br.record_at(false, t1);
        assert_eq!(br.state(), CircuitState::Open);
    }

    #[test]
    fn breaker_half_open_only_one_probe() {
        let br = CircuitBreaker::new(cfg_breaker_small());
        br.force_open();
        let t1 = Instant::now() + Duration::from_secs(1);
        assert!(br.allow_at(t1));
        // Second probe blocked while first is in flight.
        assert!(!br.allow_at(t1));
    }

    #[test]
    fn rate_limiter_allows_under_capacity() {
        let rl = RateLimiter::new(cfg_small(), cfg_breaker_small());
        assert_eq!(rl.check("FAB").unwrap(), RateDecision::Allow);
        assert_eq!(rl.check("FAB").unwrap(), RateDecision::Allow);
        assert_eq!(rl.check("FAB").unwrap(), RateDecision::Allow);
    }

    #[test]
    fn rate_limiter_throttles_on_empty_bucket() {
        let rl = RateLimiter::new(cfg_small(), cfg_breaker_small());
        for _ in 0..3 {
            rl.check("FAB").unwrap();
        }
        assert_eq!(rl.check("FAB").unwrap(), RateDecision::ThrottleBucket);
    }

    #[test]
    fn rate_limiter_isolates_tenants() {
        let rl = RateLimiter::new(cfg_small(), cfg_breaker_small());
        for _ in 0..3 {
            rl.check("FAB").unwrap();
        }
        // FAB exhausted; ENBD still has full bucket.
        assert_eq!(rl.check("FAB").unwrap(), RateDecision::ThrottleBucket);
        assert_eq!(rl.check("ENBD").unwrap(), RateDecision::Allow);
    }

    #[test]
    fn rate_limiter_circuit_open_returns_circuit_open() {
        let rl = RateLimiter::new(cfg_small(), cfg_breaker_small());
        rl.force_open("FAB").unwrap();
        assert_eq!(rl.check("FAB").unwrap(), RateDecision::CircuitOpen);
    }

    #[test]
    fn record_outcome_progresses_breaker_state() {
        let rl = RateLimiter::new(
            BucketConfig { capacity: 1000, refill_per_sec: 0.0 },
            cfg_breaker_small(),
        );
        // 4 calls all failure → breaker opens.
        for _ in 0..4 {
            rl.check("FAB").unwrap();
            rl.record_outcome("FAB", false).unwrap();
        }
        assert_eq!(rl.breaker_state("FAB").unwrap(), CircuitState::Open);
    }

    #[test]
    fn force_close_resets_state() {
        let rl = RateLimiter::new(cfg_small(), cfg_breaker_small());
        rl.force_open("FAB").unwrap();
        assert_eq!(rl.breaker_state("FAB").unwrap(), CircuitState::Open);
        rl.force_close("FAB").unwrap();
        assert_eq!(rl.breaker_state("FAB").unwrap(), CircuitState::Closed);
    }

    #[test]
    fn tokens_remaining_reports_count() {
        let rl = RateLimiter::new(cfg_small(), cfg_breaker_small());
        let t0 = rl.tokens_remaining("FAB").unwrap();
        assert!((t0 - 3.0).abs() < 1e-6);
        rl.check("FAB").unwrap();
        let t1 = rl.tokens_remaining("FAB").unwrap();
        assert!(t1 < t0);
    }

    #[test]
    fn rate_decision_serde_round_trip() {
        for d in [
            RateDecision::Allow,
            RateDecision::ThrottleBucket,
            RateDecision::CircuitOpen,
        ] {
            let j = serde_json::to_string(&d).unwrap();
            let p: RateDecision = serde_json::from_str(&j).unwrap();
            assert_eq!(p, d);
        }
    }

    #[test]
    fn circuit_state_serde_round_trip() {
        for s in [
            CircuitState::Closed,
            CircuitState::Open,
            CircuitState::HalfOpen,
        ] {
            let j = serde_json::to_string(&s).unwrap();
            let p: CircuitState = serde_json::from_str(&j).unwrap();
            assert_eq!(p, s);
        }
    }

    #[test]
    fn bucket_cfg_default_sane() {
        let d = BucketConfig::default();
        assert_eq!(d.capacity, 100);
        assert!(d.refill_per_sec > 0.0);
    }

    #[test]
    fn breaker_cfg_default_sane() {
        let d = BreakerConfig::default();
        assert!(d.min_samples > 0);
        assert!(d.failure_threshold > 0.0 && d.failure_threshold <= 1.0);
        assert!(d.cool_down.as_secs() > 0);
    }

    #[test]
    fn breaker_window_drops_old_samples() {
        let cfg = BreakerConfig {
            min_samples: 3,
            failure_threshold: 0.5,
            cool_down: Duration::from_secs(1),
            window: Duration::from_millis(100),
        };
        let br = CircuitBreaker::new(cfg);
        let t = Instant::now();
        // Old failures.
        br.record_at(false, t);
        br.record_at(false, t);
        // Wait past window.
        let t2 = t + Duration::from_millis(200);
        // Two successes after window — old failures should be pruned, breaker stays closed.
        br.record_at(true, t2);
        br.record_at(true, t2);
        br.record_at(true, t2);
        assert_eq!(br.state(), CircuitState::Closed);
    }

    #[test]
    fn unknown_tenant_breaker_state_is_closed() {
        let rl = RateLimiter::new(cfg_small(), cfg_breaker_small());
        assert_eq!(rl.breaker_state("NEW").unwrap(), CircuitState::Closed);
    }

    #[test]
    fn force_open_without_prior_traffic_works() {
        let rl = RateLimiter::new(cfg_small(), cfg_breaker_small());
        rl.force_open("NEW").unwrap();
        assert_eq!(rl.check("NEW").unwrap(), RateDecision::CircuitOpen);
    }
}
