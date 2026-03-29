//! Aethelred CLI - Advanced Command Line Interface
//!
//! A comprehensive CLI for interacting with the Aethelred AI Blockchain.
//! Features interactive mode, model management, job submission, and more.

use clap::{Args, Parser, Subcommand};
use colored::*;
use dialoguer::{theme::ColorfulTheme, Confirm, Input, MultiSelect, Password, Select};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use prettytable::{format, Cell, Row, Table};
use rustyline::error::ReadlineError;
use rustyline::Editor;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tokio::time::sleep;

mod commands;
mod config;
mod interactive;
mod utils;

/// Aethelred CLI - The Most Advanced AI Blockchain Interface
#[derive(Parser)]
#[command(name = "aethelred")]
#[command(author = "Aethelred Team")]
#[command(version = "2.0.0")]
#[command(about = "Advanced CLI for Aethelred AI Blockchain", long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    /// Configuration file path
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    /// Network to connect to (mainnet, testnet, devnet, local)
    #[arg(short, long, global = true, default_value = "testnet")]
    network: String,

    /// Output format (text, json, yaml, table)
    #[arg(short, long, global = true, default_value = "text")]
    output: String,

    /// Enable verbose output
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Disable colored output
    #[arg(long, global = true)]
    no_color: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start interactive mode
    Interactive,

    /// Initialize a new Aethelred project
    Init(InitArgs),

    /// Manage models
    #[command(subcommand)]
    Model(ModelCommands),

    /// Manage compute jobs
    #[command(subcommand)]
    Job(JobCommands),

    /// Manage digital seals
    #[command(subcommand)]
    Seal(SealCommands),

    /// Validator operations
    #[command(subcommand)]
    Validator(ValidatorCommands),

    /// Account and wallet management
    #[command(subcommand)]
    Account(AccountCommands),

    /// Network information and status
    #[command(subcommand)]
    Network(NetworkCommands),

    /// Development tools
    #[command(subcommand)]
    Dev(DevCommands),

    /// Run benchmarks
    #[command(subcommand)]
    Bench(BenchCommands),

    /// Configuration management
    #[command(subcommand)]
    Config(ConfigCommands),

    /// Start local development node
    Node(NodeArgs),

    /// Deploy model or contract
    Deploy(DeployArgs),

    /// Query blockchain state
    Query(QueryArgs),

    /// Transaction operations
    Tx(TxArgs),

    /// Compliance checking and legal linting
    #[command(subcommand)]
    Compliance(commands::compliance::ComplianceCommands),

    /// Hardware detection and simulation
    #[command(subcommand)]
    Hardware(commands::hardware::HardwareCommands),

    /// Show SDK and CLI version info
    Version,
}

// ============ Init Command ============

#[derive(Args)]
struct InitArgs {
    /// Project name
    #[arg(short, long)]
    name: Option<String>,

    /// Project template (minimal, standard, advanced)
    #[arg(short, long, default_value = "standard")]
    template: String,

    /// Target directory
    #[arg(short, long)]
    dir: Option<PathBuf>,

    /// Programming language (python, typescript, rust, go)
    #[arg(short, long, default_value = "python")]
    lang: String,

    /// Skip prompts and use defaults
    #[arg(long)]
    yes: bool,
}

// ============ Model Commands ============

#[derive(Subcommand)]
enum ModelCommands {
    /// List registered models
    List(ModelListArgs),

    /// Register a new model
    Register(ModelRegisterArgs),

    /// Get model details
    Get {
        /// Model ID or name
        model: String,
    },

    /// Deploy model to validators
    Deploy(ModelDeployArgs),

    /// Update model metadata
    Update(ModelUpdateArgs),

    /// Export model for deployment
    Export(ModelExportArgs),

    /// Quantize model
    Quantize(ModelQuantizeArgs),

    /// Benchmark model performance
    Benchmark(ModelBenchmarkArgs),

    /// Verify model integrity
    Verify {
        /// Model ID
        model: String,
    },
}

#[derive(Args)]
struct ModelListArgs {
    /// Filter by owner
    #[arg(long)]
    owner: Option<String>,

    /// Filter by status
    #[arg(long)]
    status: Option<String>,

    /// Maximum results
    #[arg(long, default_value = "20")]
    limit: usize,

    /// Skip results
    #[arg(long, default_value = "0")]
    offset: usize,
}

#[derive(Args)]
struct ModelRegisterArgs {
    /// Model file path
    #[arg(short, long)]
    file: PathBuf,

    /// Model name
    #[arg(short, long)]
    name: String,

    /// Model version
    #[arg(short, long, default_value = "1.0.0")]
    version: String,

    /// Model description
    #[arg(short, long)]
    description: Option<String>,

    /// Model tags
    #[arg(short, long)]
    tags: Vec<String>,

    /// Require TEE execution
    #[arg(long)]
    require_tee: bool,

    /// Enable zkML proofs
    #[arg(long)]
    enable_zkml: bool,
}

#[derive(Args)]
struct ModelDeployArgs {
    /// Model ID
    model: String,

    /// Target validators (comma-separated)
    #[arg(short, long)]
    validators: Option<String>,

    /// Number of replicas
    #[arg(short, long, default_value = "3")]
    replicas: u32,

    /// Wait for deployment
    #[arg(long)]
    wait: bool,
}

#[derive(Args)]
struct ModelUpdateArgs {
    /// Model ID
    model: String,

    /// New name
    #[arg(long)]
    name: Option<String>,

    /// New description
    #[arg(long)]
    description: Option<String>,

    /// Add tags
    #[arg(long)]
    add_tags: Vec<String>,

    /// Remove tags
    #[arg(long)]
    remove_tags: Vec<String>,
}

#[derive(Args)]
struct ModelExportArgs {
    /// Model ID
    model: String,

    /// Output path
    #[arg(short, long)]
    output: PathBuf,

    /// Export format (onnx, safetensors, pytorch, tflite)
    #[arg(short, long, default_value = "onnx")]
    format: String,

    /// Include weights
    #[arg(long, default_value = "true")]
    include_weights: bool,
}

#[derive(Args)]
struct ModelQuantizeArgs {
    /// Model ID or path
    model: String,

    /// Quantization type (int8, int4, fp16, bf16, fp8)
    #[arg(short, long, default_value = "int8")]
    dtype: String,

    /// Calibration data path
    #[arg(short, long)]
    calibration: Option<PathBuf>,

    /// Output path
    #[arg(short, long)]
    output: PathBuf,

    /// Quantization method (ptq, qat, gptq, awq)
    #[arg(long, default_value = "ptq")]
    method: String,
}

#[derive(Args)]
struct ModelBenchmarkArgs {
    /// Model ID or path
    model: String,

    /// Batch sizes to test
    #[arg(short, long, default_value = "1,8,32")]
    batch_sizes: String,

    /// Number of warmup iterations
    #[arg(long, default_value = "10")]
    warmup: usize,

    /// Number of iterations
    #[arg(short, long, default_value = "100")]
    iterations: usize,

    /// Enable profiling
    #[arg(long)]
    profile: bool,
}

// ============ Job Commands ============

#[derive(Subcommand)]
enum JobCommands {
    /// Submit a compute job
    Submit(JobSubmitArgs),

    /// List jobs
    List(JobListArgs),

    /// Get job details
    Get {
        /// Job ID
        job_id: String,
    },

    /// Wait for job completion
    Wait {
        /// Job ID
        job_id: String,

        /// Timeout in seconds
        #[arg(short, long, default_value = "300")]
        timeout: u64,
    },

    /// Cancel a job
    Cancel {
        /// Job ID
        job_id: String,
    },

    /// Get job logs
    Logs {
        /// Job ID
        job_id: String,

        /// Follow logs
        #[arg(short, long)]
        follow: bool,
    },

    /// Retry a failed job
    Retry {
        /// Job ID
        job_id: String,
    },
}

#[derive(Args)]
struct JobSubmitArgs {
    /// Model ID
    #[arg(short, long)]
    model: String,

    /// Input data file
    #[arg(short, long)]
    input: PathBuf,

    /// Job priority (low, normal, high, urgent)
    #[arg(short, long, default_value = "normal")]
    priority: String,

    /// Maximum execution time (seconds)
    #[arg(long, default_value = "3600")]
    timeout: u64,

    /// Require TEE execution
    #[arg(long)]
    require_tee: bool,

    /// Generate zkML proof
    #[arg(long)]
    generate_proof: bool,

    /// Wait for completion
    #[arg(long)]
    wait: bool,
}

#[derive(Args)]
struct JobListArgs {
    /// Filter by status
    #[arg(long)]
    status: Option<String>,

    /// Filter by model
    #[arg(long)]
    model: Option<String>,

    /// Show only my jobs
    #[arg(long)]
    mine: bool,

    /// Maximum results
    #[arg(long, default_value = "20")]
    limit: usize,
}

// ============ Seal Commands ============

#[derive(Subcommand)]
enum SealCommands {
    /// Create a digital seal
    Create(SealCreateArgs),

    /// Verify a seal
    Verify {
        /// Seal ID
        seal_id: String,
    },

    /// Get seal details
    Get {
        /// Seal ID
        seal_id: String,
    },

    /// List seals
    List(SealListArgs),

    /// Export seal for external verification
    Export {
        /// Seal ID
        seal_id: String,

        /// Output path
        #[arg(short, long)]
        output: PathBuf,

        /// Export format (json, pdf, xml)
        #[arg(short, long, default_value = "json")]
        format: String,
    },
}

#[derive(Args)]
struct SealCreateArgs {
    /// Model hash
    #[arg(short, long)]
    model: String,

    /// Input hash
    #[arg(short, long)]
    input: String,

    /// Output hash
    #[arg(short, long)]
    output: String,

    /// Include TEE attestation
    #[arg(long)]
    with_attestation: bool,

    /// Include zkML proof
    #[arg(long)]
    with_proof: bool,
}

#[derive(Args)]
struct SealListArgs {
    /// Filter by model
    #[arg(long)]
    model: Option<String>,

    /// Filter by creator
    #[arg(long)]
    creator: Option<String>,

    /// Start date
    #[arg(long)]
    from: Option<String>,

    /// End date
    #[arg(long)]
    to: Option<String>,

    /// Maximum results
    #[arg(long, default_value = "20")]
    limit: usize,
}

// ============ Validator Commands ============

#[derive(Subcommand)]
enum ValidatorCommands {
    /// List validators
    List(ValidatorListArgs),

    /// Get validator details
    Get {
        /// Validator address
        address: String,
    },

    /// Register as validator
    Register(ValidatorRegisterArgs),

    /// Update validator info
    Update(ValidatorUpdateArgs),

    /// Stake tokens
    Stake {
        /// Amount to stake
        amount: String,
    },

    /// Unstake tokens
    Unstake {
        /// Amount to unstake
        amount: String,
    },

    /// Check validator status
    Status,
}

#[derive(Args)]
struct ValidatorListArgs {
    /// Filter by status (active, inactive, jailed)
    #[arg(long)]
    status: Option<String>,

    /// Sort by (power, sla, name)
    #[arg(long, default_value = "power")]
    sort: String,

    /// Maximum results
    #[arg(long, default_value = "50")]
    limit: usize,
}

#[derive(Args)]
struct ValidatorRegisterArgs {
    /// Validator moniker
    #[arg(short, long)]
    moniker: String,

    /// Commission rate (0-100)
    #[arg(short, long, default_value = "10")]
    commission: u8,

    /// Website URL
    #[arg(long)]
    website: Option<String>,

    /// Description
    #[arg(short, long)]
    description: Option<String>,

    /// Initial stake amount
    #[arg(long)]
    stake: String,
}

#[derive(Args)]
struct ValidatorUpdateArgs {
    /// New moniker
    #[arg(long)]
    moniker: Option<String>,

    /// New commission rate
    #[arg(long)]
    commission: Option<u8>,

    /// New website
    #[arg(long)]
    website: Option<String>,

    /// New description
    #[arg(long)]
    description: Option<String>,
}

// ============ Account Commands ============

#[derive(Subcommand)]
enum AccountCommands {
    /// Create new account
    Create {
        /// Account name
        #[arg(short, long)]
        name: String,
    },

    /// Import account from mnemonic
    Import {
        /// Account name
        #[arg(short, long)]
        name: String,
    },

    /// Export account
    Export {
        /// Account name
        name: String,

        /// Output path
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// List accounts
    List,

    /// Get account balance
    Balance {
        /// Account address (default: current)
        address: Option<String>,
    },

    /// Send tokens
    Send {
        /// Recipient address
        to: String,

        /// Amount
        amount: String,

        /// Token denomination
        #[arg(short, long, default_value = "uaethel")]
        denom: String,
    },

    /// Set default account
    Use {
        /// Account name
        name: String,
    },
}

// ============ Network Commands ============

#[derive(Subcommand)]
enum NetworkCommands {
    /// Show network status
    Status,

    /// Show network info
    Info,

    /// List available networks
    List,

    /// Switch network
    Switch {
        /// Network name
        network: String,
    },

    /// Show chain parameters
    Params,

    /// Show recent blocks
    Blocks {
        /// Number of blocks
        #[arg(short, long, default_value = "10")]
        count: usize,
    },

    /// Show pending transactions
    Pending,
}

// ============ Dev Commands ============

#[derive(Subcommand)]
enum DevCommands {
    /// Start development server
    Serve {
        /// Port number
        #[arg(short, long, default_value = "8080")]
        port: u16,

        /// Enable hot reload
        #[arg(long)]
        hot_reload: bool,
    },

    /// Run tests
    Test {
        /// Test pattern
        pattern: Option<String>,

        /// Verbose output
        #[arg(short, long)]
        verbose: bool,
    },

    /// Generate types from contract
    Codegen {
        /// Contract path
        contract: PathBuf,

        /// Output directory
        #[arg(short, long)]
        output: PathBuf,

        /// Target language
        #[arg(short, long, default_value = "typescript")]
        lang: String,
    },

    /// Format code
    Fmt {
        /// Files to format
        files: Vec<PathBuf>,

        /// Check only (don't write)
        #[arg(long)]
        check: bool,
    },

    /// Lint code
    Lint {
        /// Files to lint
        files: Vec<PathBuf>,

        /// Auto-fix issues
        #[arg(long)]
        fix: bool,
    },

    /// Profile execution
    Profile {
        /// Command to profile
        command: Vec<String>,

        /// Output file
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Debug model
    Debug {
        /// Model path
        model: PathBuf,

        /// Input data
        #[arg(short, long)]
        input: Option<PathBuf>,
    },
}

// ============ Bench Commands ============

#[derive(Subcommand)]
enum BenchCommands {
    /// Run inference benchmark
    Inference(BenchInferenceArgs),

    /// Run training benchmark
    Training(BenchTrainingArgs),

    /// Run network benchmark
    Network(BenchNetworkArgs),

    /// Run memory benchmark
    Memory(BenchMemoryArgs),

    /// Run comprehensive benchmark suite
    All {
        /// Output report path
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Compare benchmark results
    Compare {
        /// First result file
        first: PathBuf,

        /// Second result file
        second: PathBuf,
    },
}

#[derive(Args)]
struct BenchInferenceArgs {
    /// Model to benchmark
    #[arg(short, long)]
    model: Option<String>,

    /// Batch sizes
    #[arg(short, long, default_value = "1,2,4,8,16,32")]
    batch_sizes: String,

    /// Sequence lengths (for transformers)
    #[arg(short, long, default_value = "128,512,2048")]
    seq_lengths: String,

    /// Number of iterations
    #[arg(short, long, default_value = "100")]
    iterations: usize,

    /// Warmup iterations
    #[arg(long, default_value = "10")]
    warmup: usize,

    /// Output file
    #[arg(short, long)]
    output: Option<PathBuf>,
}

#[derive(Args)]
struct BenchTrainingArgs {
    /// Model to benchmark
    #[arg(short, long)]
    model: Option<String>,

    /// Batch sizes
    #[arg(short, long, default_value = "8,16,32")]
    batch_sizes: String,

    /// Number of steps
    #[arg(short, long, default_value = "100")]
    steps: usize,

    /// Enable gradient checkpointing
    #[arg(long)]
    gradient_checkpointing: bool,

    /// Enable mixed precision
    #[arg(long)]
    mixed_precision: bool,
}

#[derive(Args)]
struct BenchNetworkArgs {
    /// Target endpoint
    #[arg(short, long)]
    endpoint: Option<String>,

    /// Number of requests
    #[arg(short, long, default_value = "1000")]
    requests: usize,

    /// Concurrent connections
    #[arg(short, long, default_value = "10")]
    concurrency: usize,
}

#[derive(Args)]
struct BenchMemoryArgs {
    /// Model to profile
    #[arg(short, long)]
    model: Option<String>,

    /// Batch size
    #[arg(short, long, default_value = "1")]
    batch_size: usize,

    /// Track allocations
    #[arg(long)]
    track_allocations: bool,
}

// ============ Config Commands ============

#[derive(Subcommand)]
enum ConfigCommands {
    /// Show current config
    Show,

    /// Set config value
    Set {
        /// Key
        key: String,

        /// Value
        value: String,
    },

    /// Get config value
    Get {
        /// Key
        key: String,
    },

    /// Reset config to defaults
    Reset {
        /// Reset only specific key
        key: Option<String>,
    },

    /// Open config in editor
    Edit,

    /// Export config
    Export {
        /// Output path
        output: PathBuf,
    },

    /// Import config
    Import {
        /// Input path
        input: PathBuf,
    },
}

// ============ Node Command ============

#[derive(Args)]
struct NodeArgs {
    /// Node type (full, validator, light)
    #[arg(short, long, default_value = "full")]
    node_type: String,

    /// Data directory
    #[arg(short, long)]
    data_dir: Option<PathBuf>,

    /// RPC port
    #[arg(long, default_value = "26657")]
    rpc_port: u16,

    /// P2P port
    #[arg(long, default_value = "26656")]
    p2p_port: u16,

    /// gRPC port
    #[arg(long, default_value = "9090")]
    grpc_port: u16,

    /// Enable API
    #[arg(long)]
    enable_api: bool,

    /// Pruning strategy (nothing, default, everything)
    #[arg(long, default_value = "default")]
    pruning: String,
}

// ============ Deploy Command ============

#[derive(Args)]
struct DeployArgs {
    /// Artifact to deploy (model, contract)
    artifact: PathBuf,

    /// Deployment name
    #[arg(short, long)]
    name: Option<String>,

    /// Target network
    #[arg(short, long)]
    network: Option<String>,

    /// Gas limit
    #[arg(long)]
    gas_limit: Option<u64>,

    /// Skip confirmation
    #[arg(long)]
    yes: bool,
}

// ============ Query Command ============

#[derive(Args)]
struct QueryArgs {
    /// Query type (block, tx, account, model, seal, job)
    query_type: String,

    /// Query parameters
    params: Vec<String>,

    /// Output raw response
    #[arg(long)]
    raw: bool,
}

// ============ Tx Command ============

#[derive(Args)]
struct TxArgs {
    /// Transaction type
    tx_type: String,

    /// Transaction parameters (key=value)
    params: Vec<String>,

    /// Gas limit
    #[arg(long)]
    gas: Option<u64>,

    /// Fee amount
    #[arg(long)]
    fee: Option<String>,

    /// Skip confirmation
    #[arg(long)]
    yes: bool,

    /// Wait for confirmation
    #[arg(long)]
    wait: bool,
}

// ============ Main ============

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Setup logging
    if cli.verbose {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .init();
    }

    // Disable colors if requested
    if cli.no_color {
        colored::control::set_override(false);
    }

    // Load configuration
    let config = config::Config::load(cli.config.as_ref())?;

    match cli.command {
        Some(Commands::Interactive) => {
            interactive::run_interactive(&config).await?;
        }
        Some(Commands::Init(args)) => {
            commands::init::run(args, &config).await?;
        }
        Some(Commands::Model(cmd)) => {
            commands::model::run(cmd, &config).await?;
        }
        Some(Commands::Job(cmd)) => {
            commands::job::run(cmd, &config).await?;
        }
        Some(Commands::Seal(cmd)) => {
            commands::seal::run(cmd, &config).await?;
        }
        Some(Commands::Validator(cmd)) => {
            commands::validator::run(cmd, &config).await?;
        }
        Some(Commands::Account(cmd)) => {
            commands::account::run(cmd, &config).await?;
        }
        Some(Commands::Network(cmd)) => {
            commands::network::run(cmd, &config).await?;
        }
        Some(Commands::Dev(cmd)) => {
            commands::dev::run(cmd, &config).await?;
        }
        Some(Commands::Bench(cmd)) => {
            commands::bench::run(cmd, &config).await?;
        }
        Some(Commands::Config(cmd)) => {
            commands::config_cmd::run(cmd, &config).await?;
        }
        Some(Commands::Node(args)) => {
            commands::node::run(args, &config).await?;
        }
        Some(Commands::Deploy(args)) => {
            commands::deploy::run(args, &config).await?;
        }
        Some(Commands::Query(args)) => {
            commands::query::run(args, &config).await?;
        }
        Some(Commands::Tx(args)) => {
            commands::tx::run(args, &config).await?;
        }
        Some(Commands::Compliance(cmd)) => {
            commands::compliance::run(cmd, &config).await?;
        }
        Some(Commands::Hardware(cmd)) => {
            commands::hardware::run(cmd, &config).await?;
        }
        Some(Commands::Version) => {
            print_version();
        }
        None => {
            // No command provided, show help or start interactive mode
            println!("{}", BANNER.cyan());
            println!();
            println!(
                "Use {} for help or {} for interactive mode.",
                "aethelred --help".green(),
                "aethelred interactive".green()
            );
        }
    }

    Ok(())
}

const BANNER: &str = r#"
    _         _   _          _              _
   / \   ___| |_| |__   ___| |_ __ ___  __| |
  / _ \ / _ \ __| '_ \ / _ \ | '__/ _ \/ _` |
 / ___ \  __/ |_| | | |  __/ | | |  __/ (_| |
/_/   \_\___|\__|_| |_|\___|_|_|  \___|\__,_|

The Most Advanced AI Blockchain Platform
"#;

fn print_version() {
    let sdk_version = read_sdk_version_from_matrix().unwrap_or_else(|| "unknown".to_string());
    let git_sha = option_env!("VERGEN_GIT_SHA").unwrap_or("unknown");
    let rust_semver = option_env!("VERGEN_RUSTC_SEMVER").unwrap_or(env!("CARGO_PKG_VERSION"));

    println!("{}", BANNER.cyan());
    println!();
    println!("  {} {}", "CLI Version:".bold(), env!("CARGO_PKG_VERSION"));
    println!("  {} {}", "SDK Version:".bold(), sdk_version);
    println!("  {} {}", "API Version:".bold(), "v1");
    println!("  {} {}", "Build:".bold(), git_sha);
    println!("  {} {}", "Rust:".bold(), rust_semver);
    println!();
    println!("  {} https://aethelred.io", "Website:".bold());
    println!("  {} https://docs.aethelred.io", "Docs:".bold());
    println!("  {} https://github.com/aethelred", "GitHub:".bold());
}

#[derive(Deserialize)]
struct VersionMatrix {
    packages: VersionPackages,
}

#[derive(Deserialize)]
struct VersionPackages {
    go: VersionEntry,
}

#[derive(Deserialize)]
struct VersionEntry {
    version: String,
}

fn read_sdk_version_from_matrix() -> Option<String> {
    let raw = include_str!("../../sdk/version-matrix.json");
    let matrix: VersionMatrix = serde_json::from_str(raw).ok()?;
    Some(matrix.packages.go.version)
}
