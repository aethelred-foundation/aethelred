//! Rate Limiting Middleware
//!
//! Protects the mempool from spam and DoS attacks.
//!
//! # Rate Limit Types
//!
//! - Per-address: Limits transactions from a single sender
//! - Per-type: Limits specific transaction types
//! - Global: Overall transaction throughput limit

use super::{Middleware, MiddlewareAction, MiddlewareContext, MiddlewareResult};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Rate limit middleware
pub struct RateLimitMiddleware {
    /// Per-address rate limiters
    address_limiters: Arc<RwLock<HashMap<[u8; 21], RateLimiter>>>,
    /// Per-type rate limiters
    type_limiters: Arc<RwLock<HashMap<u8, RateLimiter>>>,
    /// Global rate limiter
    global_limiter: Arc<RwLock<RateLimiter>>,
    /// Cleanup interval
    last_cleanup: Arc<RwLock<Instant>>,
}

impl RateLimitMiddleware {
    /// Create new rate limit middleware
    pub fn new() -> Self {
        Self {
            address_limiters: Arc::new(RwLock::new(HashMap::new())),
            type_limiters: Arc::new(RwLock::new(HashMap::new())),
            global_limiter: Arc::new(RwLock::new(RateLimiter::new(
                10_000,
                Duration::from_secs(1),
            ))),
            last_cleanup: Arc::new(RwLock::new(Instant::now())),
        }
    }

    /// Clean up stale limiters
    fn cleanup_if_needed(&self) {
        let mut last_cleanup = self.last_cleanup.write().unwrap();
        if last_cleanup.elapsed() > Duration::from_secs(60) {
            // Cleanup address limiters
            let mut address_limiters = self.address_limiters.write().unwrap();
            address_limiters.retain(|_, limiter| !limiter.is_stale());

            // Cleanup type limiters
            let mut type_limiters = self.type_limiters.write().unwrap();
            type_limiters.retain(|_, limiter| !limiter.is_stale());

            *last_cleanup = Instant::now();
        }
    }

    /// Get or create address limiter
    fn get_address_limiter(&self, address: [u8; 21], limit: u32) -> bool {
        let mut limiters = self.address_limiters.write().unwrap();

        let limiter = limiters
            .entry(address)
            .or_insert_with(|| RateLimiter::new(limit, Duration::from_secs(60)));

        limiter.try_acquire()
    }

    /// Get or create type limiter
    fn get_type_limiter(&self, tx_type: u8) -> bool {
        let mut limiters = self.type_limiters.write().unwrap();

        // Different limits per type
        let limit = match tx_type {
            0x01 => 1000, // Transfer: 1000/sec
            0x02 => 100,  // ComputeJob: 100/sec
            0x03 => 100,  // Seal: 100/sec
            0x04 => 10,   // Stake: 10/sec
            0x05 => 10,   // Unstake: 10/sec
            0x06 => 1,    // Propose: 1/sec
            0x07 => 100,  // Vote: 100/sec
            _ => 100,
        };

        let limiter = limiters
            .entry(tx_type)
            .or_insert_with(|| RateLimiter::new(limit, Duration::from_secs(1)));

        limiter.try_acquire()
    }

    /// Check global rate limit
    fn check_global(&self) -> bool {
        let mut limiter = self.global_limiter.write().unwrap();
        limiter.try_acquire()
    }
}

impl Default for RateLimitMiddleware {
    fn default() -> Self {
        Self::new()
    }
}

impl Middleware for RateLimitMiddleware {
    fn process(&self, ctx: &mut MiddlewareContext) -> MiddlewareResult<MiddlewareAction> {
        // Cleanup stale limiters periodically
        self.cleanup_if_needed();

        // Get parsed transaction
        let (sender, tx_type) = match &ctx.parsed_tx {
            Some(p) => (p.sender, p.tx_type),
            None => return Ok(MiddlewareAction::Continue),
        };
        let per_address_limit = ctx.config.rate_limit_per_address;

        // 1. Check global rate limit
        if !self.check_global() {
            ctx.add_tag("rate_limit_type", "global");
            return Ok(MiddlewareAction::Reject(
                "Global rate limit exceeded".into(),
            ));
        }

        // 2. Check per-address rate limit
        if !self.get_address_limiter(sender, per_address_limit) {
            ctx.add_tag("rate_limit_type", "address");
            return Ok(MiddlewareAction::Delay {
                milliseconds: 1000,
                reason: format!("Address rate limit exceeded ({}/min)", per_address_limit),
            });
        }

        // 3. Check per-type rate limit
        if !self.get_type_limiter(tx_type) {
            ctx.add_tag("rate_limit_type", "tx_type");
            return Ok(MiddlewareAction::Delay {
                milliseconds: 500,
                reason: format!("Transaction type {} rate limit exceeded", tx_type),
            });
        }

        // Add rate limit info to context
        ctx.add_tag("rate_limited", "false");

        Ok(MiddlewareAction::Continue)
    }

    fn name(&self) -> &'static str {
        "rate_limit"
    }

    fn priority(&self) -> u32 {
        30 // After compliance (20)
    }
}

/// Token bucket rate limiter
pub struct RateLimiter {
    /// Maximum tokens (burst capacity)
    capacity: u32,
    /// Current tokens
    tokens: f64,
    /// Tokens per interval
    refill_rate: f64,
    /// Last update time
    last_update: Instant,
    /// Last activity time (for staleness check)
    last_activity: Instant,
}

impl RateLimiter {
    /// Create new rate limiter
    pub fn new(limit: u32, interval: Duration) -> Self {
        Self {
            capacity: limit,
            tokens: limit as f64,
            refill_rate: limit as f64 / interval.as_secs_f64(),
            last_update: Instant::now(),
            last_activity: Instant::now(),
        }
    }

    /// Try to acquire a token
    pub fn try_acquire(&mut self) -> bool {
        self.refill();
        self.last_activity = Instant::now();

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Refill tokens based on elapsed time
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_update).as_secs_f64();

        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.capacity as f64);
        self.last_update = now;
    }

    /// Check if limiter is stale (no activity for 5 minutes)
    pub fn is_stale(&self) -> bool {
        self.last_activity.elapsed() > Duration::from_secs(300)
    }

    /// Get remaining tokens
    pub fn remaining(&self) -> u32 {
        self.tokens as u32
    }

    /// Get time until next token
    pub fn time_until_available(&self) -> Duration {
        if self.tokens >= 1.0 {
            Duration::ZERO
        } else {
            let needed = 1.0 - self.tokens;
            Duration::from_secs_f64(needed / self.refill_rate)
        }
    }
}

/// Sliding window rate limiter (more accurate but higher memory)
pub struct SlidingWindowLimiter {
    /// Window duration
    window: Duration,
    /// Maximum requests per window
    max_requests: u32,
    /// Request timestamps
    timestamps: Vec<Instant>,
}

impl SlidingWindowLimiter {
    /// Create new sliding window limiter
    pub fn new(max_requests: u32, window: Duration) -> Self {
        Self {
            window,
            max_requests,
            timestamps: Vec::with_capacity(max_requests as usize),
        }
    }

    /// Try to record a request
    pub fn try_acquire(&mut self) -> bool {
        let now = Instant::now();
        let cutoff = now - self.window;

        // Remove old timestamps
        self.timestamps.retain(|&t| t > cutoff);

        // Check limit
        if self.timestamps.len() >= self.max_requests as usize {
            false
        } else {
            self.timestamps.push(now);
            true
        }
    }

    /// Get current count
    pub fn current_count(&mut self) -> u32 {
        let cutoff = Instant::now() - self.window;
        self.timestamps.retain(|&t| t > cutoff);
        self.timestamps.len() as u32
    }

    /// Get remaining capacity
    pub fn remaining(&mut self) -> u32 {
        self.max_requests.saturating_sub(self.current_count())
    }
}

/// Rate limit statistics
#[derive(Debug, Default, Clone)]
pub struct RateLimitStats {
    /// Total requests
    pub total_requests: u64,
    /// Allowed requests
    pub allowed: u64,
    /// Denied requests
    pub denied: u64,
    /// Delayed requests
    pub delayed: u64,
    /// Unique addresses seen
    pub unique_addresses: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_bucket() {
        let mut limiter = RateLimiter::new(10, Duration::from_secs(1));

        // Should allow first 10 requests
        for _ in 0..10 {
            assert!(limiter.try_acquire());
        }

        // 11th should fail
        assert!(!limiter.try_acquire());
    }

    #[test]
    fn test_token_refill() {
        let mut limiter = RateLimiter::new(10, Duration::from_secs(1));

        // Exhaust tokens
        for _ in 0..10 {
            limiter.try_acquire();
        }
        assert!(!limiter.try_acquire());

        // Wait for refill
        std::thread::sleep(Duration::from_millis(200));

        // Should have some tokens now
        assert!(limiter.remaining() > 0 || limiter.try_acquire());
    }

    #[test]
    fn test_sliding_window() {
        let mut limiter = SlidingWindowLimiter::new(5, Duration::from_secs(1));

        // Should allow first 5
        for _ in 0..5 {
            assert!(limiter.try_acquire());
        }

        // 6th should fail
        assert!(!limiter.try_acquire());

        // After window passes, should allow again
        std::thread::sleep(Duration::from_secs(1));
        assert!(limiter.try_acquire());
    }

    #[test]
    fn test_rate_limit_middleware() {
        let middleware = RateLimitMiddleware::new();

        // Create mock context
        let config = Arc::new(super::super::MiddlewareConfig::default());
        let mut ctx = super::super::MiddlewareContext::new(vec![0; 100], config);

        ctx.parsed_tx = Some(super::super::ParsedTransaction {
            tx_id: [0; 32],
            sender: [1; 21],
            tx_type: 0x01,
            nonce: 0,
            gas_price: 1,
            gas_limit: 21000,
            chain_id: 1,
            size: 100,
            signature_valid: true,
            compliance_metadata: None,
        });

        // First request should succeed
        let action = middleware.process(&mut ctx).unwrap();
        assert_eq!(action, MiddlewareAction::Continue);
    }

    #[test]
    fn test_staleness() {
        let limiter = RateLimiter::new(10, Duration::from_secs(1));
        assert!(!limiter.is_stale()); // Just created, not stale
    }
}
