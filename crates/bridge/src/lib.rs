//! Aethelred Bridge Relayer
//!
//! Enterprise-grade bridge relayer for Ethereum <-> Aethelred token transfers.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────────────┐
//! │                         BRIDGE RELAYER SERVICE                                   │
//! ├─────────────────────────────────────────────────────────────────────────────────┤
//! │                                                                                  │
//! │   ┌─────────────────────────────────────────────────────────────────────────┐   │
//! │   │                      EVENT LISTENERS                                     │   │
//! │   │                                                                          │   │
//! │   │   ┌─────────────────────┐    ┌─────────────────────┐                    │   │
//! │   │   │  Ethereum Listener  │    │  Aethelred Listener │                    │   │
//! │   │   │                     │    │                     │                    │   │
//! │   │   │  • Deposit Events   │    │  • Burn Events      │                    │   │
//! │   │   │  • Block Finality   │    │  • Mint Confirms    │                    │   │
//! │   │   │  • Reorg Detection  │    │  • State Sync       │                    │   │
//! │   │   └─────────┬───────────┘    └─────────┬───────────┘                    │   │
//! │   │             │                          │                                 │   │
//! │   └─────────────┼──────────────────────────┼─────────────────────────────────┘   │
//! │                 │                          │                                     │
//! │                 ▼                          ▼                                     │
//! │   ┌─────────────────────────────────────────────────────────────────────────┐   │
//! │   │                        EVENT PROCESSOR                                   │   │
//! │   │                                                                          │   │
//! │   │   ┌────────────────┐  ┌────────────────┐  ┌────────────────┐            │   │
//! │   │   │  Validation    │  │  Deduplication │  │  Rate Limiting │            │   │
//! │   │   └───────┬────────┘  └───────┬────────┘  └───────┬────────┘            │   │
//! │   │           │                   │                   │                      │   │
//! │   └───────────┼───────────────────┼───────────────────┼──────────────────────┘   │
//! │               │                   │                   │                          │
//! │               ▼                   ▼                   ▼                          │
//! │   ┌─────────────────────────────────────────────────────────────────────────┐   │
//! │   │                         CONSENSUS ENGINE                                 │   │
//! │   │                                                                          │   │
//! │   │   • Collect votes from peer relayers                                    │   │
//! │   │   • Reach 67% consensus threshold                                       │   │
//! │   │   • Submit aggregated proof                                             │   │
//! │   │                                                                          │   │
//! │   └───────────────────────────────────┬─────────────────────────────────────┘   │
//! │                                       │                                          │
//! │                                       ▼                                          │
//! │   ┌─────────────────────────────────────────────────────────────────────────┐   │
//! │   │                         TRANSACTION SUBMITTER                            │   │
//! │   │                                                                          │   │
//! │   │   ┌─────────────────────┐    ┌─────────────────────┐                    │   │
//! │   │   │  To Aethelred       │    │  To Ethereum        │                    │   │
//! │   │   │  (Mint Proposals)   │    │  (Withdrawal Votes) │                    │   │
//! │   │   └─────────────────────┘    └─────────────────────┘                    │   │
//! │   │                                                                          │   │
//! │   └─────────────────────────────────────────────────────────────────────────┘   │
//! │                                                                                  │
//! └─────────────────────────────────────────────────────────────────────────────────┘
//! ```

pub mod config;
pub mod error;
pub mod ethereum;
pub mod aethelred;
pub mod processor;
pub mod consensus;
pub mod storage;
pub mod metrics;
pub mod types;

pub use config::BridgeConfig;
pub use error::{BridgeError, Result};
pub use types::*;

use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn, error};

/// Bridge relayer service
pub struct BridgeRelayer {
    /// Configuration
    config: BridgeConfig,

    /// Ethereum event listener
    eth_listener: Arc<ethereum::EthereumListener>,

    /// Aethelred event listener
    aethelred_listener: Arc<aethelred::AethelredListener>,

    /// Event processor
    processor: Arc<processor::EventProcessor>,

    /// Consensus engine
    consensus: Arc<consensus::ConsensusEngine>,

    /// Persistent storage
    storage: Arc<storage::BridgeStorage>,

    /// Metrics collector
    metrics: Arc<metrics::BridgeMetrics>,

    /// Running state
    running: Arc<RwLock<bool>>,
}

impl BridgeRelayer {
    /// Create a new bridge relayer
    pub async fn new(config: BridgeConfig) -> Result<Self> {
        info!("Initializing Aethelred Bridge Relayer");

        // Initialize storage
        let storage = Arc::new(storage::BridgeStorage::open(&config.storage_path)?);

        // Initialize metrics
        let metrics = Arc::new(metrics::BridgeMetrics::new());

        // Initialize Ethereum listener
        let eth_listener = Arc::new(
            ethereum::EthereumListener::new(
                &config.ethereum,
                storage.clone(),
                metrics.clone(),
            ).await?
        );

        // Initialize Aethelred listener
        let aethelred_listener = Arc::new(
            aethelred::AethelredListener::new(
                &config.aethelred,
                storage.clone(),
                metrics.clone(),
            ).await?
        );

        // Initialize event processor
        let processor = Arc::new(
            processor::EventProcessor::new(
                config.clone(),
                storage.clone(),
                metrics.clone(),
            )
        );

        // Initialize consensus engine
        let consensus = Arc::new(
            consensus::ConsensusEngine::new(
                config.clone(),
                storage.clone(),
                metrics.clone(),
            )
        );

        Ok(Self {
            config,
            eth_listener,
            aethelred_listener,
            processor,
            consensus,
            storage,
            metrics,
            running: Arc::new(RwLock::new(false)),
        })
    }

    /// Start the bridge relayer
    pub async fn start(&self) -> Result<()> {
        info!("Starting Bridge Relayer");

        {
            let mut running = self.running.write().await;
            if *running {
                warn!("Bridge relayer already running");
                return Ok(());
            }
            *running = true;
        }

        // Spawn Ethereum listener task
        let eth_listener = self.eth_listener.clone();
        let processor = self.processor.clone();
        let running = self.running.clone();

        tokio::spawn(async move {
            info!("Starting Ethereum event listener");
            if let Err(e) = Self::run_eth_listener(eth_listener, processor, running).await {
                error!("Ethereum listener error: {}", e);
            }
        });

        // Spawn Aethelred listener task
        let aethelred_listener = self.aethelred_listener.clone();
        let processor = self.processor.clone();
        let running = self.running.clone();

        tokio::spawn(async move {
            info!("Starting Aethelred event listener");
            if let Err(e) = Self::run_aethelred_listener(aethelred_listener, processor, running).await {
                error!("Aethelred listener error: {}", e);
            }
        });

        // Spawn consensus engine task
        let consensus = self.consensus.clone();
        let running = self.running.clone();

        tokio::spawn(async move {
            info!("Starting consensus engine");
            if let Err(e) = Self::run_consensus(consensus, running).await {
                error!("Consensus engine error: {}", e);
            }
        });

        // Spawn metrics server if enabled
        if self.config.metrics_enabled {
            let metrics = self.metrics.clone();
            let metrics_port = self.config.metrics_port;

            tokio::spawn(async move {
                info!("Starting metrics server on port {}", metrics_port);
                if let Err(e) = metrics.serve(metrics_port).await {
                    error!("Metrics server error: {}", e);
                }
            });
        }

        info!("Bridge Relayer started successfully");
        Ok(())
    }

    /// Stop the bridge relayer
    pub async fn stop(&self) -> Result<()> {
        info!("Stopping Bridge Relayer");

        {
            let mut running = self.running.write().await;
            *running = false;
        }

        // Allow time for graceful shutdown
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        info!("Bridge Relayer stopped");
        Ok(())
    }

    /// Run Ethereum event listener loop
    async fn run_eth_listener(
        listener: Arc<ethereum::EthereumListener>,
        processor: Arc<processor::EventProcessor>,
        running: Arc<RwLock<bool>>,
    ) -> Result<()> {
        let mut event_stream = listener.subscribe().await?;

        loop {
            // Check if still running
            if !*running.read().await {
                break;
            }

            tokio::select! {
                event = event_stream.recv() => {
                    match event {
                        Ok(eth_event) => {
                            if let Err(e) = processor.process_ethereum_event(eth_event).await {
                                warn!("Failed to process Ethereum event: {}", e);
                            }
                        }
                        Err(e) => {
                            error!("Ethereum event stream error: {}", e);
                            break;
                        }
                    }
                }
                _ = tokio::time::sleep(tokio::time::Duration::from_secs(1)) => {
                    // Heartbeat
                }
            }
        }

        Ok(())
    }

    /// Run Aethelred event listener loop
    async fn run_aethelred_listener(
        listener: Arc<aethelred::AethelredListener>,
        processor: Arc<processor::EventProcessor>,
        running: Arc<RwLock<bool>>,
    ) -> Result<()> {
        let mut event_stream = listener.subscribe().await?;

        loop {
            // Check if still running
            if !*running.read().await {
                break;
            }

            tokio::select! {
                event = event_stream.recv() => {
                    match event {
                        Ok(aethel_event) => {
                            if let Err(e) = processor.process_aethelred_event(aethel_event).await {
                                warn!("Failed to process Aethelred event: {}", e);
                            }
                        }
                        Err(e) => {
                            error!("Aethelred event stream error: {}", e);
                            break;
                        }
                    }
                }
                _ = tokio::time::sleep(tokio::time::Duration::from_secs(1)) => {
                    // Heartbeat
                }
            }
        }

        Ok(())
    }

    /// Run consensus engine loop
    async fn run_consensus(
        consensus: Arc<consensus::ConsensusEngine>,
        running: Arc<RwLock<bool>>,
    ) -> Result<()> {
        loop {
            // Check if still running
            if !*running.read().await {
                break;
            }

            // Process pending proposals
            if let Err(e) = consensus.process_pending().await {
                warn!("Consensus processing error: {}", e);
            }

            // Check for timeout proposals
            if let Err(e) = consensus.check_timeouts().await {
                warn!("Timeout check error: {}", e);
            }

            // Sleep before next iteration
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        }

        Ok(())
    }

    /// Get bridge statistics
    pub async fn statistics(&self) -> BridgeStatistics {
        BridgeStatistics {
            eth_deposits_processed: self.metrics.eth_deposits_processed(),
            eth_withdrawals_processed: self.metrics.eth_withdrawals_processed(),
            aethelred_mints_processed: self.metrics.aethelred_mints_processed(),
            aethelred_burns_processed: self.metrics.aethelred_burns_processed(),
            pending_deposits: self.storage.pending_deposit_count().unwrap_or(0),
            pending_withdrawals: self.storage.pending_withdrawal_count().unwrap_or(0),
            last_eth_block: self.eth_listener.last_processed_block().await,
            last_aethelred_block: self.aethelred_listener.last_processed_block().await,
            consensus_participants: self.consensus.participant_count().await,
            uptime_seconds: self.metrics.uptime_seconds(),
        }
    }
}

/// Bridge statistics
#[derive(Debug, Clone)]
pub struct BridgeStatistics {
    /// Total Ethereum deposits processed
    pub eth_deposits_processed: u64,
    /// Total Ethereum withdrawals processed
    pub eth_withdrawals_processed: u64,
    /// Total Aethelred mints processed
    pub aethelred_mints_processed: u64,
    /// Total Aethelred burns processed
    pub aethelred_burns_processed: u64,
    /// Pending deposits
    pub pending_deposits: usize,
    /// Pending withdrawals
    pub pending_withdrawals: usize,
    /// Last processed Ethereum block
    pub last_eth_block: u64,
    /// Last processed Aethelred block
    pub last_aethelred_block: u64,
    /// Number of consensus participants
    pub consensus_participants: usize,
    /// Service uptime in seconds
    pub uptime_seconds: u64,
}
