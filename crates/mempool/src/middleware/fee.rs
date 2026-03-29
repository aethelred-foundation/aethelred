//! Fee Validation Middleware
//!
//! Validates transaction fees and gas parameters.
//!
//! # Checks
//!
//! - Minimum gas price
//! - Maximum gas limit
//! - Fee calculation
//! - Priority fee handling

use super::{Middleware, MiddlewareAction, MiddlewareContext, MiddlewareResult};

/// Fee validation middleware
pub struct FeeMiddleware {
    /// Minimum gas price (can be updated dynamically)
    min_gas_price: u64,
    /// Maximum gas limit per transaction
    max_gas_limit: u64,
    /// Base gas for different transaction types
    base_gas: std::collections::HashMap<u8, u64>,
}

impl FeeMiddleware {
    /// Create new fee middleware
    pub fn new() -> Self {
        let mut base_gas = std::collections::HashMap::new();
        base_gas.insert(0x01, 21_000); // Transfer
        base_gas.insert(0x02, 100_000); // ComputeJob
        base_gas.insert(0x03, 50_000); // Seal
        base_gas.insert(0x04, 30_000); // Stake
        base_gas.insert(0x05, 30_000); // Unstake
        base_gas.insert(0x06, 200_000); // Propose
        base_gas.insert(0x07, 25_000); // Vote
        base_gas.insert(0x08, 50_000); // OracleUpdate
        base_gas.insert(0x09, 500_000); // Deploy
        base_gas.insert(0x0A, 21_000); // Call

        Self {
            min_gas_price: 1,
            max_gas_limit: 10_000_000,
            base_gas,
        }
    }

    /// Set minimum gas price
    pub fn with_min_gas_price(mut self, price: u64) -> Self {
        self.min_gas_price = price;
        self
    }

    /// Set maximum gas limit
    pub fn with_max_gas_limit(mut self, limit: u64) -> Self {
        self.max_gas_limit = limit;
        self
    }

    /// Get base gas for transaction type
    fn get_base_gas(&self, tx_type: u8) -> u64 {
        *self.base_gas.get(&tx_type).unwrap_or(&21_000)
    }

    /// Calculate minimum required fee
    fn calculate_min_fee(&self, tx_type: u8, data_size: usize) -> u128 {
        let base = self.get_base_gas(tx_type) as u128;
        let data_gas = (data_size as u128) * 16; // 16 gas per byte
        (base + data_gas) * (self.min_gas_price as u128)
    }

    /// Estimate gas for transaction
    fn estimate_gas(&self, tx_type: u8, data_size: usize) -> u64 {
        let base = self.get_base_gas(tx_type);
        let data_gas = (data_size as u64) * 16;
        base + data_gas
    }
}

impl Default for FeeMiddleware {
    fn default() -> Self {
        Self::new()
    }
}

impl Middleware for FeeMiddleware {
    fn process(&self, ctx: &mut MiddlewareContext) -> MiddlewareResult<MiddlewareAction> {
        // Get parsed transaction
        let (tx_type, gas_price, gas_limit, size) = match &ctx.parsed_tx {
            Some(p) => (p.tx_type, p.gas_price, p.gas_limit, p.size),
            None => return Ok(MiddlewareAction::Continue),
        };

        // 1. Check minimum gas price
        let min_gas_price = ctx.config.min_gas_price.max(self.min_gas_price);
        if gas_price < min_gas_price {
            return Ok(MiddlewareAction::Reject(format!(
                "Gas price {} below minimum {}",
                gas_price, min_gas_price
            )));
        }

        // 2. Check gas limit bounds
        let base_gas = self.get_base_gas(tx_type);
        if gas_limit < base_gas {
            return Ok(MiddlewareAction::Reject(format!(
                "Gas limit {} below minimum {} for transaction type {}",
                gas_limit, base_gas, tx_type
            )));
        }

        if gas_limit > self.max_gas_limit {
            return Ok(MiddlewareAction::Reject(format!(
                "Gas limit {} exceeds maximum {}",
                gas_limit, self.max_gas_limit
            )));
        }

        // 3. Calculate and validate fee
        let estimated_gas = self.estimate_gas(tx_type, size);
        let provided_gas = gas_limit;

        if provided_gas < estimated_gas {
            ctx.metadata.warnings.push(format!(
                "Gas limit {} may be insufficient (estimated: {})",
                provided_gas, estimated_gas
            ));
        }

        // 4. Calculate and enforce minimum fee
        let total_fee = (gas_price as u128) * (gas_limit as u128);
        let min_required_fee = self.calculate_min_fee(tx_type, size);
        if total_fee < min_required_fee {
            return Ok(MiddlewareAction::Reject(format!(
                "Total fee {} below minimum required {}",
                total_fee, min_required_fee
            )));
        }

        // 5. Add fee information to context
        ctx.add_tag("gas_price", gas_price.to_string());
        ctx.add_tag("gas_limit", gas_limit.to_string());
        ctx.add_tag("total_fee", total_fee.to_string());
        ctx.add_tag("estimated_gas", estimated_gas.to_string());
        ctx.add_tag("min_required_fee", min_required_fee.to_string());

        // 6. Calculate priority score (for mempool ordering)
        let priority_score = calculate_priority_score(gas_price, gas_limit, size);
        ctx.add_tag("priority_score", priority_score.to_string());

        Ok(MiddlewareAction::Continue)
    }

    fn name(&self) -> &'static str {
        "fee"
    }

    fn priority(&self) -> u32 {
        40 // After rate limiting (30)
    }
}

/// Calculate priority score for mempool ordering
///
/// Higher score = higher priority
fn calculate_priority_score(gas_price: u64, _gas_limit: u64, size: usize) -> u64 {
    // Priority based on:
    // 1. Gas price (higher = better)
    // 2. Efficiency (gas_price / size ratio)

    let base_score = gas_price;
    let efficiency_bonus = if size > 0 {
        (gas_price * 100) / (size as u64)
    } else {
        0
    };

    base_score.saturating_add(efficiency_bonus)
}

/// Fee estimator for clients
pub struct FeeEstimator {
    /// Recent gas prices (for estimation)
    recent_prices: Vec<u64>,
    /// Maximum samples to keep
    max_samples: usize,
    /// Base fee per type
    base_fees: std::collections::HashMap<u8, u64>,
}

impl FeeEstimator {
    /// Create new fee estimator
    pub fn new() -> Self {
        Self {
            recent_prices: Vec::new(),
            max_samples: 100,
            base_fees: std::collections::HashMap::new(),
        }
    }

    /// Record a gas price from a confirmed transaction
    pub fn record_gas_price(&mut self, price: u64) {
        self.recent_prices.push(price);
        if self.recent_prices.len() > self.max_samples {
            self.recent_prices.remove(0);
        }
    }

    /// Get suggested gas price (percentile-based)
    pub fn suggest_gas_price(&self, percentile: f64) -> u64 {
        if self.recent_prices.is_empty() {
            return 1; // Default minimum
        }

        let mut sorted = self.recent_prices.clone();
        sorted.sort();

        let index = ((sorted.len() as f64) * percentile / 100.0) as usize;
        let index = index.min(sorted.len() - 1);

        sorted[index]
    }

    /// Get slow/medium/fast gas prices
    pub fn get_gas_price_tiers(&self) -> GasPriceTiers {
        GasPriceTiers {
            slow: self.suggest_gas_price(25.0),
            medium: self.suggest_gas_price(50.0),
            fast: self.suggest_gas_price(75.0),
            instant: self.suggest_gas_price(95.0),
        }
    }

    /// Estimate total fee for transaction
    pub fn estimate_fee(&self, tx_type: u8, data_size: usize, speed: FeeSpeed) -> FeeEstimate {
        let tiers = self.get_gas_price_tiers();
        let gas_price = match speed {
            FeeSpeed::Slow => tiers.slow,
            FeeSpeed::Medium => tiers.medium,
            FeeSpeed::Fast => tiers.fast,
            FeeSpeed::Instant => tiers.instant,
        };

        let base_gas = *self.base_fees.get(&tx_type).unwrap_or(&21_000);
        let data_gas = (data_size as u64) * 16;
        let gas_limit = base_gas + data_gas;

        FeeEstimate {
            gas_price,
            gas_limit,
            total_fee: (gas_price as u128) * (gas_limit as u128),
            estimated_wait: match speed {
                FeeSpeed::Slow => "~10 blocks",
                FeeSpeed::Medium => "~5 blocks",
                FeeSpeed::Fast => "~2 blocks",
                FeeSpeed::Instant => "Next block",
            },
        }
    }
}

impl Default for FeeEstimator {
    fn default() -> Self {
        Self::new()
    }
}

/// Gas price tiers
#[derive(Debug, Clone)]
pub struct GasPriceTiers {
    pub slow: u64,
    pub medium: u64,
    pub fast: u64,
    pub instant: u64,
}

/// Fee speed options
#[derive(Debug, Clone, Copy)]
pub enum FeeSpeed {
    Slow,
    Medium,
    Fast,
    Instant,
}

/// Fee estimate result
#[derive(Debug, Clone)]
pub struct FeeEstimate {
    pub gas_price: u64,
    pub gas_limit: u64,
    pub total_fee: u128,
    pub estimated_wait: &'static str,
}

/// EIP-1559 style fee configuration (for future use)
#[derive(Debug, Clone)]
pub struct Eip1559Config {
    /// Base fee (protocol-set)
    pub base_fee: u64,
    /// Maximum fee per gas
    pub max_fee_per_gas: u64,
    /// Maximum priority fee (tip)
    pub max_priority_fee: u64,
}

impl Eip1559Config {
    /// Calculate effective gas price
    pub fn effective_gas_price(&self) -> u64 {
        let priority_fee = self
            .max_priority_fee
            .min(self.max_fee_per_gas.saturating_sub(self.base_fee));
        self.base_fee.saturating_add(priority_fee)
    }

    /// Check if fee is sufficient
    pub fn is_sufficient(&self) -> bool {
        self.max_fee_per_gas >= self.base_fee
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn create_test_context() -> super::super::MiddlewareContext {
        let config = Arc::new(super::super::MiddlewareConfig::default());
        let mut ctx = super::super::MiddlewareContext::new(vec![0; 100], config);

        ctx.parsed_tx = Some(super::super::ParsedTransaction {
            tx_id: [0; 32],
            sender: [0; 21],
            tx_type: 0x01, // Transfer
            nonce: 0,
            gas_price: 1,
            gas_limit: 23_000,
            chain_id: 1,
            size: 100,
            signature_valid: true,
            compliance_metadata: None,
        });

        ctx
    }

    #[test]
    fn test_fee_middleware() {
        let middleware = FeeMiddleware::new();
        let mut ctx = create_test_context();

        let action = middleware.process(&mut ctx).unwrap();
        assert_eq!(action, MiddlewareAction::Continue);
        assert!(ctx.has_tag("total_fee"));
    }

    #[test]
    fn test_reject_low_gas_price() {
        let middleware = FeeMiddleware::new().with_min_gas_price(10);
        let mut ctx = create_test_context();

        // Set gas price below minimum
        if let Some(ref mut parsed) = ctx.parsed_tx {
            parsed.gas_price = 1;
        }

        let action = middleware.process(&mut ctx).unwrap();
        assert!(matches!(action, MiddlewareAction::Reject(_)));
    }

    #[test]
    fn test_reject_low_gas_limit() {
        let middleware = FeeMiddleware::new();
        let mut ctx = create_test_context();

        // Set gas limit below base
        if let Some(ref mut parsed) = ctx.parsed_tx {
            parsed.gas_limit = 1000; // Below 21000 for transfer
        }

        let action = middleware.process(&mut ctx).unwrap();
        assert!(matches!(action, MiddlewareAction::Reject(_)));
    }

    #[test]
    fn test_fee_estimator() {
        let mut estimator = FeeEstimator::new();

        // Record some prices
        for i in 1..=10 {
            estimator.record_gas_price(i);
        }

        let tiers = estimator.get_gas_price_tiers();
        assert!(tiers.slow <= tiers.medium);
        assert!(tiers.medium <= tiers.fast);
        assert!(tiers.fast <= tiers.instant);
    }

    #[test]
    fn test_priority_score() {
        // Higher gas price = higher priority
        let score1 = calculate_priority_score(1, 21000, 100);
        let score2 = calculate_priority_score(10, 21000, 100);
        assert!(score2 > score1);
    }

    #[test]
    fn test_eip1559() {
        let config = Eip1559Config {
            base_fee: 10,
            max_fee_per_gas: 20,
            max_priority_fee: 5,
        };

        assert!(config.is_sufficient());
        assert_eq!(config.effective_gas_price(), 15); // 10 + 5
    }
}
