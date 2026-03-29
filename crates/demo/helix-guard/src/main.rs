//! # Project Helix-Guard: Demo Runner
//!
//! Command-line interface for running the Blind Drug Discovery Protocol demo.
//!
//! ## Usage
//!
//! ```bash
//! # Run with default settings
//! cargo run --bin helix-guard
//!
//! # Run with verbose output
//! cargo run --bin helix-guard -- --verbose
//!
//! # Run without delays (faster for testing)
//! cargo run --bin helix-guard -- --no-delays
//!
//! # Run with specific number of drug candidates
//! cargo run --bin helix-guard -- --candidates 5
//! ```

use std::process::ExitCode;

use clap::{Parser, Subcommand};

use helix_guard::{print_banner, version_info, DemoConfig, DemoStatus, HelixGuardDemo};

/// Helix-Guard: Sovereign Genomics Collaboration Platform
#[derive(Parser, Debug)]
#[command(name = "helix-guard")]
#[command(author = "Aethelred Team")]
#[command(version)]
#[command(about = "Project Helix-Guard: The Blind Drug Discovery Protocol")]
#[command(long_about = r#"
Project Helix-Guard demonstrates sovereign genomics collaboration between
M42 Health (UAE) and pharmaceutical partners using Aethelred's TEE-based
verification infrastructure.

The demo showcases:
  • M42's Emirati Genome Program (100,000+ genomes)
  • AstraZeneca drug candidate analysis
  • Blind computation in NVIDIA H100 TEE enclaves
  • Automatic royalty settlement in AETHEL tokens

Key guarantee: "Where Data Stays, Truth Travels"
"#)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Enable verbose output
    #[arg(short, long, default_value_t = true)]
    verbose: bool,

    /// Disable simulated delays (faster execution)
    #[arg(long)]
    no_delays: bool,

    /// Show ASCII visualizations
    #[arg(long, default_value_t = true)]
    visualizations: bool,

    /// Number of drug candidates to analyze
    #[arg(short, long, default_value_t = 3)]
    candidates: u32,

    /// Enable zkML proofs
    #[arg(long, default_value_t = true)]
    zkml: bool,

    /// Output format (text, json)
    #[arg(short, long, default_value = "text")]
    format: String,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run the full demo
    Run {
        /// Enable verbose output
        #[arg(short, long)]
        verbose: bool,

        /// Disable simulated delays
        #[arg(long)]
        no_delays: bool,
    },

    /// Display version information
    Version,

    /// Display the demo banner
    Banner,

    /// Show demo configuration
    Config,
}

#[tokio::main]
async fn main() -> ExitCode {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("helix_guard=info".parse().unwrap()),
        )
        .with_target(false)
        .init();

    let cli = Cli::parse();

    match &cli.command {
        Some(Commands::Version) => {
            println!("{}", version_info());
            println!();
            println!("The Blind Drug Discovery Protocol");
            println!("M42 Health (UAE) ←→ AstraZeneca (UK)");
            println!();
            println!("Powered by Aethelred: Where Data Stays, Truth Travels");
            ExitCode::SUCCESS
        }

        Some(Commands::Banner) => {
            print_banner();
            ExitCode::SUCCESS
        }

        Some(Commands::Config) => {
            let config = DemoConfig::default();
            println!("Helix-Guard Demo Configuration");
            println!("==============================");
            println!();
            println!("General:");
            println!("  Verbose:           {}", config.verbose);
            println!("  Simulate Delays:   {}", config.simulate_delays);
            println!("  Visualizations:    {}", config.show_visualizations);
            println!("  zkML Enabled:      {}", config.zkml_enabled);
            println!("  Drug Candidates:   {}", config.drug_candidate_count);
            println!();
            println!("Discovery Protocol:");
            println!(
                "  Strict Sovereignty:    {}",
                config.discovery_config.strict_sovereignty
            );
            println!(
                "  Require Ethics:        {}",
                config.discovery_config.require_ethics_approval
            );
            println!(
                "  Require DoH:           {}",
                config.discovery_config.require_doh_approval
            );
            println!(
                "  Auto Royalty:          {}",
                config.discovery_config.auto_royalty_payment
            );
            println!(
                "  Session Timeout:       {} hours",
                config.discovery_config.session_timeout_hours
            );
            println!();
            println!("Royalty Engine:");
            println!(
                "  Base Fee:          ${}",
                config.royalty_config.base_fee_usd
            );
            println!(
                "  Auto Settlement:   {}",
                config.royalty_config.auto_settlement
            );
            println!(
                "  Escrow Enabled:    {}",
                config.royalty_config.escrow_enabled
            );
            println!(
                "  Escrow Threshold:  ${}",
                config.royalty_config.escrow_threshold_usd
            );
            ExitCode::SUCCESS
        }

        Some(Commands::Run { verbose, no_delays }) => {
            run_demo(*verbose, *no_delays, cli.candidates, cli.zkml, &cli.format).await
        }

        None => {
            // Default: run demo with CLI args
            run_demo(
                cli.verbose,
                cli.no_delays,
                cli.candidates,
                cli.zkml,
                &cli.format,
            )
            .await
        }
    }
}

async fn run_demo(
    verbose: bool,
    no_delays: bool,
    candidates: u32,
    zkml: bool,
    format: &str,
) -> ExitCode {
    let config = DemoConfig {
        verbose,
        simulate_delays: !no_delays,
        show_visualizations: verbose,
        zkml_enabled: zkml,
        drug_candidate_count: candidates,
        ..Default::default()
    };

    let demo = HelixGuardDemo::new(config);

    match demo.run().await {
        Ok(output) => {
            match format {
                "json" => match serde_json::to_string_pretty(&output) {
                    Ok(json) => println!("{}", json),
                    Err(e) => {
                        eprintln!("Error serializing output: {}", e);
                        return ExitCode::FAILURE;
                    }
                },
                _ => {
                    // Text output is already printed by the demo
                    if output.status != DemoStatus::Completed {
                        eprintln!("Demo did not complete successfully");
                        return ExitCode::FAILURE;
                    }
                }
            }

            if output.status == DemoStatus::Completed {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(e) => {
            eprintln!("Demo failed: {}", e);
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_parsing() {
        let cli = Cli::parse_from(["helix-guard"]);
        assert!(cli.verbose);
        assert!(!cli.no_delays);
    }

    #[test]
    fn test_cli_with_args() {
        let cli = Cli::parse_from(["helix-guard", "--no-delays", "--candidates", "5"]);
        assert!(cli.no_delays);
        assert_eq!(cli.candidates, 5);
    }
}
