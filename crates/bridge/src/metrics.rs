//! Bridge Metrics
//!
//! Prometheus metrics for bridge monitoring.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use crate::error::Result;

/// Bridge metrics collector
pub struct BridgeMetrics {
    /// Service start time
    start_time: Instant,

    /// Ethereum deposits processed
    eth_deposits: AtomicU64,

    /// Ethereum withdrawals processed
    eth_withdrawals: AtomicU64,

    /// Aethelred mints processed
    aethelred_mints: AtomicU64,

    /// Aethelred burns processed
    aethelred_burns: AtomicU64,

    /// Consensus rounds completed
    consensus_rounds: AtomicU64,

    /// Failed transactions
    failed_txs: AtomicU64,
}

impl BridgeMetrics {
    /// Create a new metrics collector
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            eth_deposits: AtomicU64::new(0),
            eth_withdrawals: AtomicU64::new(0),
            aethelred_mints: AtomicU64::new(0),
            aethelred_burns: AtomicU64::new(0),
            consensus_rounds: AtomicU64::new(0),
            failed_txs: AtomicU64::new(0),
        }
    }

    /// Get uptime in seconds
    pub fn uptime_seconds(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }

    /// Get Ethereum deposits processed
    pub fn eth_deposits_processed(&self) -> u64 {
        self.eth_deposits.load(Ordering::Relaxed)
    }

    /// Increment Ethereum deposits
    pub fn increment_eth_deposits(&self) {
        self.eth_deposits.fetch_add(1, Ordering::Relaxed);
    }

    /// Get Ethereum withdrawals processed
    pub fn eth_withdrawals_processed(&self) -> u64 {
        self.eth_withdrawals.load(Ordering::Relaxed)
    }

    /// Increment Ethereum withdrawals
    pub fn increment_eth_withdrawals(&self) {
        self.eth_withdrawals.fetch_add(1, Ordering::Relaxed);
    }

    /// Get Aethelred mints processed
    pub fn aethelred_mints_processed(&self) -> u64 {
        self.aethelred_mints.load(Ordering::Relaxed)
    }

    /// Increment Aethelred mints
    pub fn increment_aethelred_mints(&self) {
        self.aethelred_mints.fetch_add(1, Ordering::Relaxed);
    }

    /// Get Aethelred burns processed
    pub fn aethelred_burns_processed(&self) -> u64 {
        self.aethelred_burns.load(Ordering::Relaxed)
    }

    /// Increment Aethelred burns
    pub fn increment_aethelred_burns(&self) {
        self.aethelred_burns.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment consensus rounds
    pub fn increment_consensus_rounds(&self) {
        self.consensus_rounds.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment failed transactions
    pub fn increment_failed_txs(&self) {
        self.failed_txs.fetch_add(1, Ordering::Relaxed);
    }

    /// Start the metrics HTTP server
    pub async fn serve(&self, port: u16) -> Result<()> {
        // In production, use prometheus::Encoder and hyper/actix-web
        tracing::info!("Metrics server would start on port {}", port);

        // Keep running
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
        }
    }

    /// Export metrics in Prometheus format
    pub fn export_prometheus(&self) -> String {
        format!(
            r#"# HELP aethelred_bridge_uptime_seconds Bridge relayer uptime in seconds
# TYPE aethelred_bridge_uptime_seconds counter
aethelred_bridge_uptime_seconds {}

# HELP aethelred_bridge_eth_deposits_total Total Ethereum deposits processed
# TYPE aethelred_bridge_eth_deposits_total counter
aethelred_bridge_eth_deposits_total {}

# HELP aethelred_bridge_eth_withdrawals_total Total Ethereum withdrawals processed
# TYPE aethelred_bridge_eth_withdrawals_total counter
aethelred_bridge_eth_withdrawals_total {}

# HELP aethelred_bridge_aethelred_mints_total Total Aethelred mints processed
# TYPE aethelred_bridge_aethelred_mints_total counter
aethelred_bridge_aethelred_mints_total {}

# HELP aethelred_bridge_aethelred_burns_total Total Aethelred burns processed
# TYPE aethelred_bridge_aethelred_burns_total counter
aethelred_bridge_aethelred_burns_total {}

# HELP aethelred_bridge_consensus_rounds_total Total consensus rounds completed
# TYPE aethelred_bridge_consensus_rounds_total counter
aethelred_bridge_consensus_rounds_total {}

# HELP aethelred_bridge_failed_txs_total Total failed transactions
# TYPE aethelred_bridge_failed_txs_total counter
aethelred_bridge_failed_txs_total {}
"#,
            self.uptime_seconds(),
            self.eth_deposits_processed(),
            self.eth_withdrawals_processed(),
            self.aethelred_mints_processed(),
            self.aethelred_burns_processed(),
            self.consensus_rounds.load(Ordering::Relaxed),
            self.failed_txs.load(Ordering::Relaxed),
        )
    }
}

impl Default for BridgeMetrics {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_increment() {
        let metrics = BridgeMetrics::new();

        assert_eq!(metrics.eth_deposits_processed(), 0);
        metrics.increment_eth_deposits();
        metrics.increment_eth_deposits();
        assert_eq!(metrics.eth_deposits_processed(), 2);
    }

    #[test]
    fn test_prometheus_export() {
        let metrics = BridgeMetrics::new();
        metrics.increment_eth_deposits();

        let output = metrics.export_prometheus();
        assert!(output.contains("aethelred_bridge_eth_deposits_total 1"));
    }
}
