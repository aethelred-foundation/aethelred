//! Reusable retry policy with backoff strategies.
//!
//! Centralized retry/backoff helper. Used by webhook delivery, anchor
//! retries, connector reconnects. Distinct from
//! [`crate::webhook_subscriptions::RetryPolicy`] (specific to webhook
//! deliveries) by being kind-pluggable.

use serde::{Deserialize, Serialize};
use std::time::Duration;

// =============================================================================
// BackoffKind
// =============================================================================

/// Backoff strategy.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BackoffKind {
    /// Constant delay.
    Constant {
        /// Constant seconds.
        seconds: f64,
    },
    /// Linear: base + (attempt-1) * step.
    Linear {
        /// Base.
        base_seconds: f64,
        /// Step.
        step_seconds: f64,
    },
    /// Exponential: base * factor^(attempt-1).
    Exponential {
        /// Base.
        base_seconds: f64,
        /// Multiplier.
        factor: f64,
    },
    /// Jittered exponential — same as Exponential with ±50% randomness.
    JitteredExponential {
        /// Base.
        base_seconds: f64,
        /// Multiplier.
        factor: f64,
    },
}

// =============================================================================
// RetrySpec
// =============================================================================

/// Reusable spec.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct RetrySpec {
    /// Maximum attempts (1 = no retry).
    pub max_attempts: u32,
    /// Backoff kind.
    pub backoff: BackoffKind,
    /// Cap on individual delay.
    pub cap_seconds: f64,
    /// Total budget (sum of delays) — once exceeded, stop.
    pub budget_seconds: Option<f64>,
}

impl Default for RetrySpec {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            backoff: BackoffKind::Exponential {
                base_seconds: 1.0,
                factor: 2.0,
            },
            cap_seconds: 60.0,
            budget_seconds: Some(300.0),
        }
    }
}

impl RetrySpec {
    /// Compute delay for `attempt` (1-indexed). `seed` is used for jitter
    /// (deterministic).
    pub fn delay(&self, attempt: u32, seed: u64) -> Duration {
        let raw = match self.backoff {
            BackoffKind::Constant { seconds } => seconds,
            BackoffKind::Linear {
                base_seconds,
                step_seconds,
            } => base_seconds + (attempt.saturating_sub(1) as f64) * step_seconds,
            BackoffKind::Exponential {
                base_seconds,
                factor,
            } => base_seconds * factor.powi((attempt as i32).saturating_sub(1).max(0)),
            BackoffKind::JitteredExponential {
                base_seconds,
                factor,
            } => {
                let raw = base_seconds * factor.powi((attempt as i32).saturating_sub(1).max(0));
                // ±50% jitter from a seeded LCG (deterministic).
                let mut s = seed.wrapping_mul(attempt as u64 + 1);
                s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                let normalized = (s >> 11) as f64 / ((1u64 << 53) as f64);
                let jitter_factor = 0.5 + normalized; // in [0.5, 1.5)
                raw * jitter_factor
            }
        };
        let capped = raw.min(self.cap_seconds).max(0.0);
        Duration::from_secs_f64(capped)
    }

    /// Total delay across attempts 1..=N.
    pub fn total_delay(&self, attempts: u32, seed: u64) -> Duration {
        let mut total = 0.0;
        for a in 1..=attempts {
            total += self.delay(a, seed).as_secs_f64();
        }
        Duration::from_secs_f64(total)
    }

    /// `true` if next attempt would exceed budget given cumulative.
    pub fn budget_exhausted(&self, cumulative_seconds: f64) -> bool {
        match self.budget_seconds {
            Some(b) => cumulative_seconds >= b,
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_delay() {
        let s = RetrySpec {
            max_attempts: 3,
            backoff: BackoffKind::Constant { seconds: 2.0 },
            cap_seconds: 60.0,
            budget_seconds: None,
        };
        assert_eq!(s.delay(1, 0).as_secs_f64(), 2.0);
        assert_eq!(s.delay(5, 0).as_secs_f64(), 2.0);
    }

    #[test]
    fn linear_delay() {
        let s = RetrySpec {
            max_attempts: 5,
            backoff: BackoffKind::Linear {
                base_seconds: 1.0,
                step_seconds: 2.0,
            },
            cap_seconds: 60.0,
            budget_seconds: None,
        };
        assert_eq!(s.delay(1, 0).as_secs_f64(), 1.0);
        assert_eq!(s.delay(2, 0).as_secs_f64(), 3.0);
        assert_eq!(s.delay(3, 0).as_secs_f64(), 5.0);
    }

    #[test]
    fn exponential_delay() {
        let s = RetrySpec {
            max_attempts: 5,
            backoff: BackoffKind::Exponential {
                base_seconds: 1.0,
                factor: 2.0,
            },
            cap_seconds: 60.0,
            budget_seconds: None,
        };
        assert_eq!(s.delay(1, 0).as_secs_f64(), 1.0);
        assert_eq!(s.delay(2, 0).as_secs_f64(), 2.0);
        assert_eq!(s.delay(3, 0).as_secs_f64(), 4.0);
        assert_eq!(s.delay(4, 0).as_secs_f64(), 8.0);
    }

    #[test]
    fn cap_respected() {
        let s = RetrySpec {
            max_attempts: 10,
            backoff: BackoffKind::Exponential {
                base_seconds: 1.0,
                factor: 10.0,
            },
            cap_seconds: 5.0,
            budget_seconds: None,
        };
        assert_eq!(s.delay(10, 0).as_secs_f64(), 5.0);
    }

    #[test]
    fn jittered_within_band() {
        let s = RetrySpec {
            max_attempts: 5,
            backoff: BackoffKind::JitteredExponential {
                base_seconds: 1.0,
                factor: 2.0,
            },
            cap_seconds: 1000.0,
            budget_seconds: None,
        };
        for seed in [1u64, 2, 3, 100, 12345] {
            let d = s.delay(3, seed).as_secs_f64();
            // Raw = 4.0, jitter band [2.0, 6.0).
            assert!((2.0..6.0).contains(&d), "out of band: {} (seed {})", d, seed);
        }
    }

    #[test]
    fn jittered_deterministic_with_same_seed() {
        let s = RetrySpec {
            max_attempts: 5,
            backoff: BackoffKind::JitteredExponential {
                base_seconds: 1.0,
                factor: 2.0,
            },
            cap_seconds: 1000.0,
            budget_seconds: None,
        };
        assert_eq!(s.delay(3, 42).as_secs_f64(), s.delay(3, 42).as_secs_f64());
    }

    #[test]
    fn total_delay_sums() {
        let s = RetrySpec {
            max_attempts: 5,
            backoff: BackoffKind::Constant { seconds: 2.0 },
            cap_seconds: 60.0,
            budget_seconds: None,
        };
        assert_eq!(s.total_delay(3, 0).as_secs_f64(), 6.0);
    }

    #[test]
    fn budget_exhausted_check() {
        let s = RetrySpec {
            max_attempts: 10,
            backoff: BackoffKind::Constant { seconds: 1.0 },
            cap_seconds: 60.0,
            budget_seconds: Some(5.0),
        };
        assert!(!s.budget_exhausted(3.0));
        assert!(s.budget_exhausted(5.0));
        assert!(s.budget_exhausted(7.0));
    }

    #[test]
    fn no_budget_never_exhausted() {
        let s = RetrySpec {
            max_attempts: 10,
            backoff: BackoffKind::Constant { seconds: 1.0 },
            cap_seconds: 60.0,
            budget_seconds: None,
        };
        assert!(!s.budget_exhausted(1_000_000.0));
    }

    #[test]
    fn default_values_sane() {
        let s = RetrySpec::default();
        assert_eq!(s.max_attempts, 5);
        assert_eq!(s.cap_seconds, 60.0);
    }

    #[test]
    fn attempt_zero_treated_as_one() {
        let s = RetrySpec {
            max_attempts: 5,
            backoff: BackoffKind::Exponential {
                base_seconds: 2.0,
                factor: 3.0,
            },
            cap_seconds: 1000.0,
            budget_seconds: None,
        };
        // 2 * 3^0 = 2.
        assert_eq!(s.delay(1, 0).as_secs_f64(), 2.0);
        assert_eq!(s.delay(0, 0).as_secs_f64(), 2.0);
    }

    #[test]
    fn negative_seconds_clamped_zero() {
        let s = RetrySpec {
            max_attempts: 1,
            backoff: BackoffKind::Constant {
                seconds: -10.0,
            },
            cap_seconds: 100.0,
            budget_seconds: None,
        };
        assert_eq!(s.delay(1, 0).as_secs_f64(), 0.0);
    }

    #[test]
    fn spec_serde() {
        let s = RetrySpec::default();
        let j = serde_json::to_string(&s).unwrap();
        let p: RetrySpec = serde_json::from_str(&j).unwrap();
        assert_eq!(p, s);
    }

    #[test]
    fn backoff_serde_constant() {
        let b = BackoffKind::Constant { seconds: 1.5 };
        let j = serde_json::to_string(&b).unwrap();
        let p: BackoffKind = serde_json::from_str(&j).unwrap();
        assert_eq!(p, b);
    }

    #[test]
    fn backoff_serde_linear() {
        let b = BackoffKind::Linear {
            base_seconds: 1.0,
            step_seconds: 2.0,
        };
        let j = serde_json::to_string(&b).unwrap();
        let p: BackoffKind = serde_json::from_str(&j).unwrap();
        assert_eq!(p, b);
    }

    #[test]
    fn backoff_serde_exponential() {
        let b = BackoffKind::Exponential {
            base_seconds: 1.0,
            factor: 2.0,
        };
        let j = serde_json::to_string(&b).unwrap();
        let p: BackoffKind = serde_json::from_str(&j).unwrap();
        assert_eq!(p, b);
    }

    #[test]
    fn backoff_serde_jittered() {
        let b = BackoffKind::JitteredExponential {
            base_seconds: 1.0,
            factor: 2.0,
        };
        let j = serde_json::to_string(&b).unwrap();
        let p: BackoffKind = serde_json::from_str(&j).unwrap();
        assert_eq!(p, b);
    }

    #[test]
    fn linear_with_zero_step_constant() {
        let s = RetrySpec {
            max_attempts: 5,
            backoff: BackoffKind::Linear {
                base_seconds: 3.0,
                step_seconds: 0.0,
            },
            cap_seconds: 100.0,
            budget_seconds: None,
        };
        assert_eq!(s.delay(1, 0).as_secs_f64(), 3.0);
        assert_eq!(s.delay(5, 0).as_secs_f64(), 3.0);
    }

    #[test]
    fn exponential_factor_one_is_constant() {
        let s = RetrySpec {
            max_attempts: 5,
            backoff: BackoffKind::Exponential {
                base_seconds: 7.0,
                factor: 1.0,
            },
            cap_seconds: 100.0,
            budget_seconds: None,
        };
        for a in 1..=5 {
            assert_eq!(s.delay(a, 0).as_secs_f64(), 7.0);
        }
    }

    #[test]
    fn total_delay_zero_attempts_zero() {
        let s = RetrySpec::default();
        assert_eq!(s.total_delay(0, 0).as_secs_f64(), 0.0);
    }

    #[test]
    fn cap_does_not_clip_below_value() {
        let s = RetrySpec {
            max_attempts: 5,
            backoff: BackoffKind::Constant { seconds: 1.0 },
            cap_seconds: 100.0,
            budget_seconds: None,
        };
        assert_eq!(s.delay(1, 0).as_secs_f64(), 1.0);
    }
}
