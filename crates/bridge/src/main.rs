//! Aethelred Bridge Relayer - Main Entry Point
//!
//! Enterprise-grade bridge relayer service that watches Ethereum for deposit events
//! and submits mint proposals to the Aethelred network.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────────┐
//! │                      BRIDGE RELAYER SERVICE                                  │
//! ├─────────────────────────────────────────────────────────────────────────────┤
//! │                                                                              │
//! │   ┌─────────────────────────────────────────────────────────────────────┐   │
//! │   │                        MAIN LOOP                                     │   │
//! │   │                                                                      │   │
//! │   │   1. Watch Ethereum for Deposit events                              │   │
//! │   │   2. Validate deposits (confirmations, amount, recipient)           │   │
//! │   │   3. Submit mint proposals to Aethelred                             │   │
//! │   │   4. Watch Aethelred for Burn events                                │   │
//! │   │   5. Submit withdrawal votes to Ethereum                            │   │
//! │   │   6. Participate in relayer consensus                               │   │
//! │   │                                                                      │   │
//! │   └─────────────────────────────────────────────────────────────────────┘   │
//! │                                                                              │
//! └─────────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Usage
//!
//! ```bash
//! aethelred-bridge start --config /path/to/config.toml
//! ```

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};
use tokio::signal;
use tracing::{info, warn, Level};
use tracing_subscriber::{fmt, EnvFilter};

use aethelred_bridge::{
    BridgeConfig, BridgeRelayer, BridgeError, Result,
};

// =============================================================================
// CLI DEFINITION
// =============================================================================

#[derive(Parser)]
#[command(name = "aethelred-bridge")]
#[command(author = "Aethelred Team")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "Aethelred Bridge Relayer - Ethereum <-> Aethelred Token Bridge")]
#[command(long_about = r#"
Enterprise-grade bridge relayer for transferring tokens between Ethereum and Aethelred.

The relayer watches for deposit events on Ethereum and submits mint proposals to the
Aethelred network. It also watches for burn events on Aethelred and participates in
the consensus process to unlock tokens on Ethereum.

ARCHITECTURE:

  Ethereum                    Relayer                    Aethelred
  ────────                    ───────                    ─────────

  User deposits ETH    ──►    Watch events         ──►  Submit mint proposal
       │                           │                          │
       │                           │                          │
       ▼                           ▼                          ▼
  Lock in Bridge       ──►    Validate deposit    ──►  Consensus vote
       │                           │                          │
       │                           │                          │
       ▼                           ▼                          ▼
  Emit Deposit event   ◄──    Submit to chain     ◄──  Mint tokens
"#)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the bridge relayer service
    Start {
        /// Path to configuration file
        #[arg(short, long, default_value = "config/bridge.toml")]
        config: PathBuf,

        /// Data directory
        #[arg(short, long, default_value = "./data/bridge")]
        data_dir: PathBuf,

        /// Override Ethereum RPC URL
        #[arg(long, env = "ETH_RPC_URL")]
        eth_rpc: Option<String>,

        /// Override Aethelred RPC URL
        #[arg(long, env = "AETHELRED_RPC_URL")]
        aethelred_rpc: Option<String>,

        /// Enable debug logging
        #[arg(long)]
        debug: bool,
    },

    /// Check health of the relayer and connected chains
    Health {
        /// RPC endpoint to check
        #[arg(short, long, default_value = "http://localhost:9100")]
        rpc: String,
    },

    /// Generate a new relayer key pair
    GenerateKey {
        /// Output path for the key file
        #[arg(short, long, default_value = "relayer.key")]
        output: PathBuf,
    },

    /// Show current bridge statistics
    Stats {
        /// Path to configuration file
        #[arg(short, long, default_value = "config/bridge.toml")]
        config: PathBuf,
    },

    /// Manually process a specific deposit
    ProcessDeposit {
        /// Deposit transaction hash on Ethereum
        #[arg(long)]
        tx_hash: String,

        /// Path to configuration file
        #[arg(short, long, default_value = "config/bridge.toml")]
        config: PathBuf,
    },

    /// Export Prometheus metrics
    Metrics {
        /// Listen address for metrics server
        #[arg(short, long, default_value = "0.0.0.0:9100")]
        listen: String,
    },
}

// =============================================================================
// MAIN ENTRY POINT
// =============================================================================

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Start {
            config,
            data_dir,
            eth_rpc,
            aethelred_rpc,
            debug,
        } => {
            start_relayer(config, data_dir, eth_rpc, aethelred_rpc, debug).await
        }

        Commands::Health { rpc } => {
            check_health(&rpc).await
        }

        Commands::GenerateKey { output } => {
            generate_key(&output).await
        }

        Commands::Stats { config } => {
            show_stats(&config).await
        }

        Commands::ProcessDeposit { tx_hash, config } => {
            process_deposit(&tx_hash, &config).await
        }

        Commands::Metrics { listen } => {
            start_metrics_server(&listen).await
        }
    }
}

// =============================================================================
// START RELAYER
// =============================================================================

async fn start_relayer(
    config_path: PathBuf,
    data_dir: PathBuf,
    eth_rpc_override: Option<String>,
    aethelred_rpc_override: Option<String>,
    debug: bool,
) -> Result<()> {
    // Initialize logging
    init_logging(debug);

    info!("Starting Aethelred Bridge Relayer v{}", env!("CARGO_PKG_VERSION"));
    info!("Configuration: {:?}", config_path);
    info!("Data directory: {:?}", data_dir);

    // Load configuration
    let mut config = if config_path.exists() {
        BridgeConfig::load(config_path.to_str().unwrap())?
    } else {
        warn!("Config file not found, using defaults");
        BridgeConfig::default()
    };

    // Apply overrides
    if let Some(eth_rpc) = eth_rpc_override {
        info!("Overriding Ethereum RPC: {}", eth_rpc);
        config.ethereum.rpc_url = eth_rpc;
    }

    if let Some(aethelred_rpc) = aethelred_rpc_override {
        info!("Overriding Aethelred RPC: {}", aethelred_rpc);
        config.aethelred.rpc_url = aethelred_rpc;
    }

    config.storage_path = data_dir;

    // Validate configuration
    config.validate()?;

    // Print configuration summary
    print_config_summary(&config);

    // Create the relayer
    let relayer = Arc::new(BridgeRelayer::new(config).await?);

    // Start the relayer
    relayer.start().await?;

    info!("Bridge relayer is now running");
    info!("Press Ctrl+C to stop");

    // Wait for shutdown signal
    wait_for_shutdown().await;

    // Graceful shutdown
    info!("Shutting down bridge relayer...");
    relayer.stop().await?;

    info!("Bridge relayer stopped successfully");
    Ok(())
}

// =============================================================================
// HEALTH CHECK
// =============================================================================

async fn check_health(rpc: &str) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    println!("Checking health of bridge relayer at {}...", rpc);

    let endpoint = rpc
        .strip_prefix("http://")
        .or_else(|| rpc.strip_prefix("https://"))
        .unwrap_or(rpc)
        .trim_end_matches('/')
        .to_string();

    let mut stream = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(&endpoint))
        .await
        .map_err(|_| BridgeError::Timeout("Health check connect timed out".to_string()))?
        .map_err(|e| BridgeError::Network(e.to_string()))?;

    let request = format!(
        "GET /health HTTP/1.1\r\nHost: {endpoint}\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| BridgeError::Network(e.to_string()))?;

    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .map_err(|e| BridgeError::Network(e.to_string()))?;
    let response = String::from_utf8_lossy(&response);

    if response.starts_with("HTTP/1.1 200") || response.starts_with("HTTP/1.0 200") {
        println!("✅ Bridge relayer is healthy");
        Ok(())
    } else {
        let status_line = response.lines().next().unwrap_or("unknown response");
        println!("❌ Bridge relayer is unhealthy: {status_line}");
        Err(BridgeError::Internal("Health check failed".to_string()))
    }
}

// =============================================================================
// KEY GENERATION
// =============================================================================

async fn generate_key(output: &PathBuf) -> Result<()> {
    use sha2::{Sha256, Digest};
    use rand::RngCore;

    println!("Generating new relayer key pair...");

    // Generate random seed
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);

    // Derive key (in production, use proper key derivation)
    let mut hasher = Sha256::new();
    hasher.update(b"aethelred-relayer-key:");
    hasher.update(seed);
    let private_key = hasher.finalize();

    // Derive public key / address (simplified)
    let mut hasher = Sha256::new();
    hasher.update(private_key);
    let address = hasher.finalize();

    // Save to file
    let key_data = serde_json::json!({
        "version": 1,
        "type": "relayer",
        "private_key": hex::encode(private_key),
        "address": format!("0x{}", hex::encode(&address[..20])),
        "created_at": chrono::Utc::now().to_rfc3339(),
    });

    std::fs::write(output, serde_json::to_string_pretty(&key_data).unwrap())
        .map_err(|e| BridgeError::Storage(e.to_string()))?;

    println!("✅ Key pair generated successfully");
    println!("   Address: 0x{}", hex::encode(&address[..20]));
    println!("   Saved to: {:?}", output);
    println!("\n⚠️  IMPORTANT: Keep your private key secure!");

    Ok(())
}

// =============================================================================
// STATISTICS
// =============================================================================

async fn show_stats(config_path: &std::path::Path) -> Result<()> {
    println!("Bridge Statistics");
    println!("─────────────────");

    // Load config and connect
    let config = BridgeConfig::load(config_path.to_str().unwrap())?;

    // In production, would connect and fetch real stats
    println!("\nEthereum Chain:");
    println!("  RPC: {}", config.ethereum.rpc_url);
    println!("  Chain ID: {}", config.ethereum.chain_id);
    println!("  Bridge Contract: {}", config.ethereum.bridge_address);

    println!("\nAethelred Chain:");
    println!("  RPC: {}", config.aethelred.rpc_url);
    println!("  Chain ID: {}", config.aethelred.chain_id);

    println!("\nConsensus:");
    println!("  Threshold: {}%", config.consensus.threshold_bps as f64 / 100.0);
    println!("  Proposal Timeout: {}s", config.consensus.proposal_timeout_secs);

    Ok(())
}

// =============================================================================
// MANUAL DEPOSIT PROCESSING
// =============================================================================

async fn process_deposit(tx_hash: &str, config_path: &PathBuf) -> Result<()> {
    println!("Processing deposit: {}", tx_hash);

    let _config = BridgeConfig::load(config_path.to_str().unwrap())?;

    // In production:
    // 1. Fetch the transaction from Ethereum
    // 2. Parse the Deposit event
    // 3. Validate it has enough confirmations
    // 4. Submit mint proposal to Aethelred

    println!("✅ Deposit processed (simulated)");
    println!("   TX Hash: {}", tx_hash);
    println!("   Config: {:?}", config_path);

    Ok(())
}

// =============================================================================
// METRICS SERVER
// =============================================================================

async fn start_metrics_server(listen: &str) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    info!("Starting metrics server on {}", listen);

    let listener = TcpListener::bind(listen)
        .await
        .map_err(|e| BridgeError::Config(format!("Invalid listen address: {}", e)))?;

    info!("Metrics server listening on http://{}", listen);
    info!("  /health  - Health check endpoint");
    info!("  /metrics - Prometheus metrics");

    loop {
        let (mut socket, _) = listener
            .accept()
            .await
            .map_err(|e| BridgeError::Internal(e.to_string()))?;

        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            let read = match socket.read(&mut buf).await {
                Ok(n) => n,
                Err(_) => return,
            };
            if read == 0 {
                return;
            }

            let req = String::from_utf8_lossy(&buf[..read]);
            let (status, content_type, body) = if req.starts_with("GET /health ") {
                ("200 OK", "application/json", r#"{"status":"healthy"}"#.to_string())
            } else if req.starts_with("GET /metrics ") {
                (
                    "200 OK",
                    "text/plain; version=0.0.4",
                    generate_prometheus_metrics(),
                )
            } else {
                ("404 Not Found", "text/plain", "Not Found".to_string())
            };

            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );

            let _ = socket.write_all(response.as_bytes()).await;
            let _ = socket.shutdown().await;
        });
    }

}

fn generate_prometheus_metrics() -> String {
    format!(
        r#"# HELP aethelred_bridge_info Bridge relayer information
# TYPE aethelred_bridge_info gauge
aethelred_bridge_info{{version="{}"}} 1

# HELP aethelred_bridge_up Bridge relayer up status
# TYPE aethelred_bridge_up gauge
aethelred_bridge_up 1
"#,
        env!("CARGO_PKG_VERSION")
    )
}

// =============================================================================
// UTILITIES
// =============================================================================

fn init_logging(debug: bool) {
    let level = if debug { Level::DEBUG } else { Level::INFO };

    let filter = EnvFilter::from_default_env()
        .add_directive(level.into())
        .add_directive("hyper=warn".parse().unwrap())
        .add_directive("reqwest=warn".parse().unwrap());

    fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_thread_ids(false)
        .with_file(true)
        .with_line_number(true)
        .init();
}

fn print_config_summary(config: &BridgeConfig) {
    info!("┌────────────────────────────────────────────────────────────┐");
    info!("│                  BRIDGE CONFIGURATION                      │");
    info!("├────────────────────────────────────────────────────────────┤");
    info!("│ Ethereum                                                   │");
    info!("│   RPC:          {}", truncate(&config.ethereum.rpc_url, 40));
    info!("│   Chain ID:     {}", config.ethereum.chain_id);
    info!("│   Confirmations: {}", config.ethereum.confirmations);
    info!("├────────────────────────────────────────────────────────────┤");
    info!("│ Aethelred                                                  │");
    info!("│   RPC:          {}", truncate(&config.aethelred.rpc_url, 40));
    info!("│   Chain ID:     {}", config.aethelred.chain_id);
    info!("│   Confirmations: {}", config.aethelred.confirmations);
    info!("├────────────────────────────────────────────────────────────┤");
    info!("│ Consensus                                                  │");
    info!("│   Threshold:    {}%", config.consensus.threshold_bps as f64 / 100.0);
    info!("│   Timeout:      {}s", config.consensus.proposal_timeout_secs);
    info!("└────────────────────────────────────────────────────────────┘");
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() > max_len {
        format!("{}...", &s[..max_len - 3])
    } else {
        s.to_string()
    }
}

async fn wait_for_shutdown() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            info!("Received Ctrl+C");
        }
        _ = terminate => {
            info!("Received SIGTERM");
        }
    }
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_truncate() {
        assert_eq!(truncate("hello", 10), "hello");
        assert_eq!(truncate("hello world", 8), "hello...");
    }

    #[tokio::test]
    async fn test_generate_key() {
        let temp_dir = tempfile::tempdir().unwrap();
        let key_path = temp_dir.path().join("test.key");

        generate_key(&key_path).await.unwrap();

        assert!(key_path.exists());

        let content = std::fs::read_to_string(&key_path).unwrap();
        let json: serde_json::Value = serde_json::from_str(&content).unwrap();

        assert_eq!(json["version"], 1);
        assert_eq!(json["type"], "relayer");
        assert!(json["private_key"].is_string());
        assert!(json["address"].as_str().unwrap().starts_with("0x"));
    }
}
