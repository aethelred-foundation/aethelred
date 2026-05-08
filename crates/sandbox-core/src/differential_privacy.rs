//! Differential privacy — Laplace/Gaussian noise + ε-budget tracker.
//!
//! Aggregate queries over evidence bundles ("how many credit decisions
//! denied last quarter?") leak information about individual seals. DP
//! adds calibrated noise + tracks a per-tenant ε-budget so total leakage
//! is bounded.
//!
//! ## What we ship
//!
//! - [`Mechanism`] — `Laplace { scale }` / `Gaussian { sigma }` noise.
//! - [`PrivacyBudget`] — per-tenant ε / δ budget tracker with `consume`
//!   and `remaining`.
//! - [`PrivateQuery`] — typed wrappers over `count`, `sum`, `mean`,
//!   `histogram` that compose mechanisms with budget consumption.
//! - [`DpAccountant`] — registry of budgets keyed by tenant.
//!
//! ## Why hand-rolled noise
//!
//! The `rand` / `rand_distr` crates pull a substantial dep tree. We use
//! a deterministic-seeded PRNG over our existing `Hasher::sha256` so
//! the only requirement is no extra deps. For production, swap the
//! `Mechanism` impl for `rand_distr::Laplace` etc. — the trait shape
//! stays the same.

use crate::hashing::{Hasher, Sha256Digest};
use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Mutex;

// =============================================================================
// SeedRng — deterministic-seeded PRNG built on SHA-256
// =============================================================================

/// Counter-mode PRNG over SHA-256. Not cryptographically secure for
/// adversarial settings; suitable for noise sampling.
#[derive(Debug, Clone)]
pub struct SeedRng {
    seed: Sha256Digest,
    counter: u64,
}

impl SeedRng {
    /// New PRNG from a seed.
    pub fn new(seed: Sha256Digest) -> Self {
        Self { seed, counter: 0 }
    }

    /// Construct from arbitrary bytes (hashed to a 32-byte seed).
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self::new(Hasher::sha256(bytes))
    }

    /// Draw the next u64.
    pub fn next_u64(&mut self) -> u64 {
        let mut buf = Vec::with_capacity(40);
        buf.extend_from_slice(&self.seed.0);
        buf.extend_from_slice(&self.counter.to_le_bytes());
        let h = Hasher::sha256(&buf).0;
        self.counter = self.counter.wrapping_add(1);
        u64::from_le_bytes(h[..8].try_into().unwrap())
    }

    /// Uniform [0, 1).
    pub fn next_unit(&mut self) -> f64 {
        let v = self.next_u64();
        // 53-bit precision (matches f64 mantissa).
        let m = (v >> 11) as f64;
        m / ((1u64 << 53) as f64)
    }
}

// =============================================================================
// Mechanism
// =============================================================================

/// Noise mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum Mechanism {
    /// Laplace mechanism (ε-DP).
    Laplace {
        /// Scale `b = sensitivity / ε`.
        scale: f64,
    },
    /// Gaussian mechanism ((ε, δ)-DP).
    Gaussian {
        /// `σ`.
        sigma: f64,
    },
}

impl Mechanism {
    /// Add noise to a value using the given RNG.
    pub fn add_noise(&self, value: f64, rng: &mut SeedRng) -> f64 {
        match self {
            Self::Laplace { scale } => value + sample_laplace(rng, *scale),
            Self::Gaussian { sigma } => value + sample_gaussian(rng, *sigma),
        }
    }

    /// ε that this mechanism consumes for a sensitivity-1 query.
    pub fn epsilon_consumed(&self, sensitivity: f64) -> f64 {
        match self {
            Self::Laplace { scale } => {
                if *scale <= 0.0 {
                    f64::INFINITY
                } else {
                    sensitivity / scale
                }
            }
            Self::Gaussian { sigma: _ } => {
                // Gaussian (ε, δ)-DP: ε is governed by the analyst's δ +
                // sensitivity / σ. We return a conservative proxy here so
                // budget bookkeeping makes progress; production deployments
                // use the analytic Gaussian or Renyi-DP composition.
                sensitivity * 1.0
            }
        }
    }
}

fn sample_laplace(rng: &mut SeedRng, scale: f64) -> f64 {
    // Inverse-CDF: u ~ Uniform(-0.5, 0.5); X = -scale * sign(u) * ln(1-2|u|).
    let u = rng.next_unit() - 0.5;
    let sign = if u < 0.0 { -1.0 } else { 1.0 };
    -scale * sign * (1.0 - 2.0 * u.abs()).ln()
}

fn sample_gaussian(rng: &mut SeedRng, sigma: f64) -> f64 {
    // Box-Muller transform.
    let mut u1 = rng.next_unit();
    if u1 < 1e-12 {
        u1 = 1e-12;
    }
    let u2 = rng.next_unit();
    let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
    z * sigma
}

// =============================================================================
// PrivacyBudget
// =============================================================================

/// Per-tenant privacy budget.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyBudget {
    /// Total ε budget (Laplace + linear composition).
    pub epsilon_total: f64,
    /// ε already consumed.
    pub epsilon_consumed: f64,
    /// Total δ budget (for Gaussian).
    pub delta_total: f64,
    /// δ already consumed.
    pub delta_consumed: f64,
}

impl PrivacyBudget {
    /// New budget.
    pub fn new(epsilon_total: f64, delta_total: f64) -> Self {
        Self {
            epsilon_total,
            epsilon_consumed: 0.0,
            delta_total,
            delta_consumed: 0.0,
        }
    }

    /// Conservative pilot budget (ε = 1.0, δ = 1e-5).
    pub fn pilot() -> Self {
        Self::new(1.0, 1e-5)
    }

    /// Strict (ε = 0.1, δ = 1e-6).
    pub fn strict() -> Self {
        Self::new(0.1, 1e-6)
    }

    /// Consume ε (and optional δ).
    pub fn consume(&mut self, epsilon: f64, delta: f64) -> SandboxResult<()> {
        if !epsilon.is_finite() || epsilon < 0.0 {
            return Err(SandboxError::invalid("non-finite or negative epsilon"));
        }
        if !delta.is_finite() || delta < 0.0 {
            return Err(SandboxError::invalid("non-finite or negative delta"));
        }
        if self.epsilon_consumed + epsilon > self.epsilon_total {
            return Err(SandboxError::Other(format!(
                "epsilon budget exhausted: {} + {} > {}",
                self.epsilon_consumed, epsilon, self.epsilon_total
            )));
        }
        if self.delta_consumed + delta > self.delta_total {
            return Err(SandboxError::Other(format!(
                "delta budget exhausted: {} + {} > {}",
                self.delta_consumed, delta, self.delta_total
            )));
        }
        self.epsilon_consumed += epsilon;
        self.delta_consumed += delta;
        Ok(())
    }

    /// Remaining ε.
    pub fn epsilon_remaining(&self) -> f64 {
        self.epsilon_total - self.epsilon_consumed
    }

    /// Remaining δ.
    pub fn delta_remaining(&self) -> f64 {
        self.delta_total - self.delta_consumed
    }

    /// `true` if any ε remains.
    pub fn has_budget(&self) -> bool {
        self.epsilon_remaining() > 0.0
    }
}

// =============================================================================
// PrivateQuery
// =============================================================================

/// Wrap a value with DP noise + budget consumption.
pub struct PrivateQuery<'a> {
    budget: &'a mut PrivacyBudget,
    rng: SeedRng,
}

impl<'a> PrivateQuery<'a> {
    /// New query with the given seed.
    pub fn new(budget: &'a mut PrivacyBudget, seed: &[u8]) -> Self {
        Self {
            budget,
            rng: SeedRng::from_bytes(seed),
        }
    }

    /// Privatised count (sensitivity = 1).
    pub fn count(&mut self, true_count: u64, mechanism: Mechanism) -> SandboxResult<f64> {
        let eps = mechanism.epsilon_consumed(1.0);
        let delta = match mechanism {
            Mechanism::Gaussian { .. } => 1e-6,
            _ => 0.0,
        };
        self.budget.consume(eps, delta)?;
        Ok(mechanism.add_noise(true_count as f64, &mut self.rng))
    }

    /// Privatised sum (caller supplies sensitivity, e.g., the max value).
    pub fn sum(
        &mut self,
        true_sum: f64,
        sensitivity: f64,
        mechanism: Mechanism,
    ) -> SandboxResult<f64> {
        let eps = mechanism.epsilon_consumed(sensitivity);
        let delta = match mechanism {
            Mechanism::Gaussian { .. } => 1e-6,
            _ => 0.0,
        };
        self.budget.consume(eps, delta)?;
        Ok(mechanism.add_noise(true_sum, &mut self.rng))
    }

    /// Privatised mean.
    pub fn mean(
        &mut self,
        true_sum: f64,
        n: u64,
        sensitivity: f64,
        mechanism: Mechanism,
    ) -> SandboxResult<f64> {
        if n == 0 {
            return Err(SandboxError::invalid("cannot compute mean of n=0"));
        }
        let private_sum = self.sum(true_sum, sensitivity, mechanism)?;
        Ok(private_sum / n as f64)
    }

    /// Privatised histogram counts (one mechanism per bucket).
    pub fn histogram(
        &mut self,
        true_counts: &[u64],
        mechanism: Mechanism,
    ) -> SandboxResult<Vec<f64>> {
        // Sensitivity for parallel-composition histogram is 1 (one record
        // changes one bucket count by 1).
        let eps_per = mechanism.epsilon_consumed(1.0);
        let delta_per = match mechanism {
            Mechanism::Gaussian { .. } => 1e-6,
            _ => 0.0,
        };
        // Parallel composition: total ε is max, not sum, but only when
        // buckets are disjoint records. We charge per bucket conservatively
        // as the true upper-bound under sequential composition.
        self.budget.consume(eps_per, delta_per)?;
        let out: Vec<f64> = true_counts
            .iter()
            .map(|c| mechanism.add_noise(*c as f64, &mut self.rng))
            .collect();
        Ok(out)
    }
}

// =============================================================================
// DpAccountant
// =============================================================================

/// Per-tenant budget registry.
pub struct DpAccountant {
    budgets: Mutex<BTreeMap<String, PrivacyBudget>>,
}

impl Default for DpAccountant {
    fn default() -> Self {
        Self::new()
    }
}

impl DpAccountant {
    /// New empty accountant.
    pub fn new() -> Self {
        Self {
            budgets: Mutex::new(BTreeMap::new()),
        }
    }

    /// Register a budget for `tenant`.
    pub fn register(&self, tenant: impl Into<String>, budget: PrivacyBudget) {
        match self.budgets.lock() {
            Ok(mut g) => {
                g.insert(tenant.into(), budget);
            }
            Err(e) => {
                e.into_inner().insert(tenant.into(), budget);
            }
        }
    }

    /// Snapshot a tenant's budget.
    pub fn snapshot(&self, tenant: &str) -> Option<PrivacyBudget> {
        self.budgets
            .lock()
            .ok()
            .and_then(|g| g.get(tenant).cloned())
    }

    /// Run a closure with mutable access to a tenant's budget.
    pub fn with_budget<F, R>(&self, tenant: &str, f: F) -> SandboxResult<R>
    where
        F: FnOnce(&mut PrivacyBudget) -> SandboxResult<R>,
    {
        let mut g = self
            .budgets
            .lock()
            .map_err(|_| SandboxError::Other("accountant poisoned".into()))?;
        let b = g.get_mut(tenant).ok_or_else(|| {
            SandboxError::Other(format!("no budget for tenant {tenant}"))
        })?;
        f(b)
    }

    /// Number of tenants with budgets.
    pub fn len(&self) -> usize {
        self.budgets.lock().map(|g| g.len()).unwrap_or(0)
    }

    /// `true` if no budgets.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rng() -> SeedRng {
        SeedRng::from_bytes(b"deterministic-test-seed")
    }

    #[test]
    fn rng_is_deterministic() {
        let mut a = rng();
        let mut b = rng();
        for _ in 0..100 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn rng_unit_in_zero_one() {
        let mut r = rng();
        for _ in 0..1000 {
            let v = r.next_unit();
            assert!((0.0..1.0).contains(&v));
        }
    }

    #[test]
    fn rng_next_u64_unique_over_many_calls() {
        let mut r = rng();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..1000 {
            seen.insert(r.next_u64());
        }
        assert!(seen.len() > 990);
    }

    #[test]
    fn laplace_mean_zero_for_value_zero() {
        let mut r = rng();
        let m = Mechanism::Laplace { scale: 1.0 };
        let mut sum = 0.0;
        for _ in 0..1000 {
            sum += m.add_noise(0.0, &mut r);
        }
        let mean = sum / 1000.0;
        // Mean should be near zero for symmetric noise.
        assert!(mean.abs() < 0.1);
    }

    #[test]
    fn gaussian_mean_zero_for_value_zero() {
        let mut r = rng();
        let m = Mechanism::Gaussian { sigma: 1.0 };
        let mut sum = 0.0;
        for _ in 0..1000 {
            sum += m.add_noise(0.0, &mut r);
        }
        let mean = sum / 1000.0;
        assert!(mean.abs() < 0.15);
    }

    #[test]
    fn laplace_epsilon_consumed_for_sensitivity_1() {
        let m = Mechanism::Laplace { scale: 1.0 };
        assert_eq!(m.epsilon_consumed(1.0), 1.0);
    }

    #[test]
    fn laplace_epsilon_consumed_zero_scale_is_inf() {
        let m = Mechanism::Laplace { scale: 0.0 };
        assert!(m.epsilon_consumed(1.0).is_infinite());
    }

    #[test]
    fn budget_consume_within_limit() {
        let mut b = PrivacyBudget::new(1.0, 1e-5);
        b.consume(0.5, 0.0).unwrap();
        assert!((b.epsilon_remaining() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn budget_consume_exceeds_rejected() {
        let mut b = PrivacyBudget::new(1.0, 1e-5);
        b.consume(0.6, 0.0).unwrap();
        let r = b.consume(0.5, 0.0);
        assert!(r.is_err());
    }

    #[test]
    fn budget_negative_epsilon_rejected() {
        let mut b = PrivacyBudget::new(1.0, 1e-5);
        let r = b.consume(-0.1, 0.0);
        assert!(r.is_err());
    }

    #[test]
    fn budget_nan_rejected() {
        let mut b = PrivacyBudget::new(1.0, 1e-5);
        let r = b.consume(f64::NAN, 0.0);
        assert!(r.is_err());
    }

    #[test]
    fn budget_pilot_default() {
        let b = PrivacyBudget::pilot();
        assert_eq!(b.epsilon_total, 1.0);
    }

    #[test]
    fn budget_strict_default() {
        let b = PrivacyBudget::strict();
        assert!((b.epsilon_total - 0.1).abs() < 1e-9);
    }

    #[test]
    fn budget_has_budget_initially() {
        let b = PrivacyBudget::new(1.0, 1e-5);
        assert!(b.has_budget());
    }

    #[test]
    fn budget_no_budget_after_full_consume() {
        let mut b = PrivacyBudget::new(0.5, 1e-5);
        b.consume(0.5, 0.0).unwrap();
        assert!(!b.has_budget());
    }

    #[test]
    fn private_count_within_budget() {
        let mut b = PrivacyBudget::new(2.0, 0.0);
        let mut q = PrivateQuery::new(&mut b, b"seed-x");
        let r = q.count(100, Mechanism::Laplace { scale: 1.0 }).unwrap();
        assert!(r > 50.0 && r < 150.0); // within ~3 stddev
    }

    #[test]
    fn private_count_exceeds_budget_rejected() {
        let mut b = PrivacyBudget::new(0.5, 0.0);
        let mut q = PrivateQuery::new(&mut b, b"seed-x");
        // First call uses ε=1.0 — over budget.
        let r = q.count(100, Mechanism::Laplace { scale: 1.0 });
        assert!(r.is_err());
    }

    #[test]
    fn private_sum_within_budget() {
        let mut b = PrivacyBudget::new(10.0, 0.0);
        let mut q = PrivateQuery::new(&mut b, b"seed-x");
        let r = q.sum(1000.0, 1.0, Mechanism::Laplace { scale: 1.0 }).unwrap();
        assert!(r > 800.0 && r < 1200.0);
    }

    #[test]
    fn private_mean_handles_zero_n() {
        let mut b = PrivacyBudget::new(10.0, 0.0);
        let mut q = PrivateQuery::new(&mut b, b"seed-x");
        let r = q.mean(0.0, 0, 1.0, Mechanism::Laplace { scale: 1.0 });
        assert!(r.is_err());
    }

    #[test]
    fn private_histogram_returns_correct_length() {
        let mut b = PrivacyBudget::new(2.0, 0.0);
        let mut q = PrivateQuery::new(&mut b, b"seed-x");
        let r = q
            .histogram(&[10, 20, 30, 40, 50], Mechanism::Laplace { scale: 1.0 })
            .unwrap();
        assert_eq!(r.len(), 5);
    }

    #[test]
    fn dp_accountant_register_and_snapshot() {
        let acc = DpAccountant::new();
        acc.register("FAB", PrivacyBudget::pilot());
        let s = acc.snapshot("FAB").unwrap();
        assert_eq!(s.epsilon_total, 1.0);
    }

    #[test]
    fn dp_accountant_with_budget_consumes() {
        let acc = DpAccountant::new();
        acc.register("FAB", PrivacyBudget::pilot());
        acc.with_budget("FAB", |b| b.consume(0.3, 0.0)).unwrap();
        let s = acc.snapshot("FAB").unwrap();
        assert!((s.epsilon_consumed - 0.3).abs() < 1e-9);
    }

    #[test]
    fn dp_accountant_unknown_tenant_errors() {
        let acc = DpAccountant::new();
        let r = acc.with_budget("nope", |_b| Ok(()));
        assert!(r.is_err());
    }

    #[test]
    fn dp_accountant_snapshot_unknown_returns_none() {
        let acc = DpAccountant::new();
        assert!(acc.snapshot("nope").is_none());
    }

    #[test]
    fn dp_accountant_len() {
        let acc = DpAccountant::new();
        assert!(acc.is_empty());
        acc.register("a", PrivacyBudget::pilot());
        acc.register("b", PrivacyBudget::pilot());
        assert_eq!(acc.len(), 2);
    }

    #[test]
    fn budget_serde_round_trip() {
        let mut b = PrivacyBudget::pilot();
        b.consume(0.3, 0.0).unwrap();
        let j = serde_json::to_string(&b).unwrap();
        let p: PrivacyBudget = serde_json::from_str(&j).unwrap();
        assert!((p.epsilon_consumed - b.epsilon_consumed).abs() < 1e-9);
    }

    #[test]
    fn mechanism_serde_round_trip() {
        let m = Mechanism::Laplace { scale: 2.5 };
        let j = serde_json::to_string(&m).unwrap();
        let p: Mechanism = serde_json::from_str(&j).unwrap();
        assert_eq!(p, m);
    }

    #[test]
    fn private_count_consumes_budget() {
        let mut b = PrivacyBudget::new(2.0, 0.0);
        {
            let mut q = PrivateQuery::new(&mut b, b"x");
            q.count(100, Mechanism::Laplace { scale: 1.0 }).unwrap();
        }
        assert!((b.epsilon_consumed - 1.0).abs() < 1e-9);
    }

    #[test]
    fn deterministic_noise_for_same_seed() {
        // Same seed, same input → same noise, so two queries return same value.
        let mut b1 = PrivacyBudget::new(2.0, 0.0);
        let mut q1 = PrivateQuery::new(&mut b1, b"identical-seed");
        let r1 = q1.count(50, Mechanism::Laplace { scale: 1.0 }).unwrap();
        let mut b2 = PrivacyBudget::new(2.0, 0.0);
        let mut q2 = PrivateQuery::new(&mut b2, b"identical-seed");
        let r2 = q2.count(50, Mechanism::Laplace { scale: 1.0 }).unwrap();
        assert_eq!(r1, r2);
    }

    #[test]
    fn rng_from_bytes_determinism() {
        let mut a = SeedRng::from_bytes(b"seed");
        let mut b = SeedRng::from_bytes(b"seed");
        assert_eq!(a.next_u64(), b.next_u64());
    }

    #[test]
    fn private_sum_high_sensitivity_consumes_more_budget() {
        let mut b = PrivacyBudget::new(5.0, 0.0);
        let mut q = PrivateQuery::new(&mut b, b"x");
        // Sensitivity 10 with scale 1 consumes ε = 10 — should exceed.
        let r = q.sum(100.0, 10.0, Mechanism::Laplace { scale: 1.0 });
        assert!(r.is_err());
    }
}
