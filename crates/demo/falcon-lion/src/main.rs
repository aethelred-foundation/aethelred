#![allow(clippy::panicking_unwrap)]
#![allow(clippy::await_holding_lock)]
#![allow(clippy::only_used_in_recursion)]
#![allow(clippy::if_same_then_else)]
#![allow(clippy::match_like_matches_macro)]
#![allow(unused_doc_comments)]
#![allow(unexpected_cfgs)]
#![allow(ambiguous_glob_reexports)]
#![allow(clippy::upper_case_acronyms)]
#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(clippy::type_complexity)]
#![allow(clippy::result_large_err)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::inconsistent_digit_grouping)]
#![allow(clippy::neg_cmp_op_on_partial_ord)]
#![allow(clippy::should_implement_trait)]
#![allow(clippy::doc_lazy_continuation)]
#![allow(non_camel_case_types)]
//! # Project Falcon-Lion Demo Runner
//!
//! Command-line interface for running the Zero-Knowledge Letter of Credit demo
//! between FAB (First Abu Dhabi Bank, UAE) and DBS (Development Bank of Singapore).
//!
//! ## Usage
//!
//! ```bash
//! # Run with default settings (verbose, with simulated delays)
//! cargo run --bin falcon-lion
//!
//! # Run in quiet mode
//! cargo run --bin falcon-lion -- --quiet
//!
//! # Run without delays (fast mode)
//! cargo run --bin falcon-lion -- --fast
//!
//! # Export results to JSON
//! cargo run --bin falcon-lion -- --output results.json
//!
//! # Show version
//! cargo run --bin falcon-lion -- --version
//! ```

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

use falcon_lion::{
    print_banner, version_info, DemoConfig, DemoMode, DemoOutput, FalconLionDemo, FalconLionError,
    FalconLionResult,
};

// =============================================================================
// CLI ARGUMENTS
// =============================================================================

/// Command-line arguments for the demo
struct CliArgs {
    /// Run in verbose mode (default: true)
    verbose: bool,
    /// Simulate realistic delays (default: true)
    simulate_delays: bool,
    /// Output file path for JSON results
    output_path: Option<PathBuf>,
    /// Show version and exit
    show_version: bool,
    /// Show help and exit
    show_help: bool,
}

impl Default for CliArgs {
    fn default() -> Self {
        Self {
            verbose: true,
            simulate_delays: true,
            output_path: None,
            show_version: false,
            show_help: false,
        }
    }
}

impl CliArgs {
    /// Parse command-line arguments
    fn parse() -> Self {
        let args: Vec<String> = std::env::args().collect();
        let mut cli = CliArgs::default();

        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "--quiet" | "-q" => cli.verbose = false,
                "--fast" | "-f" => cli.simulate_delays = false,
                "--version" | "-V" => cli.show_version = true,
                "--help" | "-h" => cli.show_help = true,
                "--output" | "-o" => {
                    i += 1;
                    if i < args.len() {
                        cli.output_path = Some(PathBuf::from(&args[i]));
                    }
                }
                arg if arg.starts_with("--output=") => {
                    let path = arg.strip_prefix("--output=").unwrap();
                    cli.output_path = Some(PathBuf::from(path));
                }
                _ => {
                    // Unknown argument, ignore
                }
            }
            i += 1;
        }

        cli
    }
}

// =============================================================================
// HELP TEXT
// =============================================================================

fn print_help() {
    println!(
        r#"
Project Falcon-Lion: Zero-Knowledge Letter of Credit Demo

USAGE:
    falcon-lion [OPTIONS]

OPTIONS:
    -q, --quiet         Run in quiet mode (minimal output)
    -f, --fast          Skip simulated delays (fast execution)
    -o, --output FILE   Export results to JSON file
    -V, --version       Print version information
    -h, --help          Print this help message

DESCRIPTION:
    This demo showcases a cross-border trade finance transaction between:

    • FAB (First Abu Dhabi Bank, UAE) - Advising Bank
    • DBS (Development Bank of Singapore) - Issuing Bank

    The demo demonstrates how Aethelred enables Zero-Knowledge Letter of Credit
    verification while preserving data sovereignty:

    1. UAE Solar Manufacturer exports $5M in solar panels
    2. Singapore Construction Firm imports for a green building project
    3. Neither bank can share private financial records
    4. Aethelred verifies compliance without exposing data
    5. Verifiable Letter of Credit is minted on-chain

KEY INSIGHT:
    "FAB's data stayed in the UAE node. DBS's data stayed in the Singapore node.
     Aethelred only moved the TRUTH, not the DATA."

EXAMPLES:
    # Standard demo run
    falcon-lion

    # Quick demo without delays
    falcon-lion --fast

    # Export results for integration testing
    falcon-lion --output demo_results.json

    # Minimal output for CI/CD
    falcon-lion --quiet --fast --output results.json

For more information, visit: https://aethelred.io/falcon-lion
"#
    );
}

// =============================================================================
// OUTPUT FORMATTING
// =============================================================================

/// Print execution summary
fn print_summary(output: &DemoOutput, duration: std::time::Duration) {
    println!();
    println!("╔══════════════════════════════════════════════════════════════════════════════╗");
    println!("║                           EXECUTION SUMMARY                                  ║");
    println!("╠══════════════════════════════════════════════════════════════════════════════╣");
    println!("║                                                                              ║");
    println!(
        "║  Demo ID: {:<63} ║",
        truncate(&output.demo_id.to_string(), 63)
    );
    println!("║  Status: {:<64} ║", format!("{:?}", output.status));
    println!("║                                                                              ║");
    println!("║  Trade Deal:                                                                 ║");
    println!(
        "║    Reference: {:<59} ║",
        truncate(&output.deal_reference, 59)
    );
    println!("║                                                                              ║");
    println!("║  Letter of Credit:                                                           ║");
    println!(
        "║    Reference: {:<59} ║",
        output.lc_reference.as_deref().unwrap_or("-")
    );
    println!(
        "║    On-Chain ID: {:<57} ║",
        truncate(output.lc_id.as_deref().unwrap_or("-"), 57)
    );
    println!("║                                                                              ║");
    println!("║  Settlement:                                                                 ║");
    println!(
        "║    TX Hash: {:<61} ║",
        truncate(output.settlement_tx_hash.as_deref().unwrap_or("-"), 61)
    );
    println!("║                                                                              ║");
    println!("║  Performance:                                                                ║");
    println!(
        "║    Total Time: {:<55} ║",
        format!("{}ms", output.total_time_ms)
    );
    println!(
        "║    Data Transferred: {:<49} ║",
        format!(
            "{} bytes (proofs only)",
            output.metrics.data_transferred_bytes
        )
    );
    println!(
        "║    Sensitive Data Exposed: {:<43} ║",
        if output.metrics.sensitive_data_exposed {
            "YES ⚠️"
        } else {
            "NONE ✅"
        }
    );
    println!("║                                                                              ║");
    println!("║  Explorer URL:                                                               ║");
    println!(
        "║    {:<69} ║",
        truncate(output.explorer_url.as_deref().unwrap_or("-"), 69)
    );
    println!("║                                                                              ║");
    println!(
        "║  Execution Time: {:<55} ║",
        format!("{:.2}s", duration.as_secs_f64())
    );
    println!("║                                                                              ║");
    println!("╚══════════════════════════════════════════════════════════════════════════════╝");
}

/// Print the key insight box
fn print_key_insight() {
    println!();
    println!("┌──────────────────────────────────────────────────────────────────────────────┐");
    println!("│                              💡 KEY INSIGHT                                  │");
    println!("├──────────────────────────────────────────────────────────────────────────────┤");
    println!("│                                                                              │");
    println!("│   FAB's data stayed in the UAE node.                                        │");
    println!("│   DBS's data stayed in the Singapore node.                                  │");
    println!("│                                                                              │");
    println!("│   Aethelred only moved the TRUTH, not the DATA.                             │");
    println!("│                                                                              │");
    println!("│   ┌─────────────────────────────────────────────────────────────────────┐   │");
    println!("│   │  UAE Data    →  [TEE Enclave]  →  ZK Proof  ─┐                      │   │");
    println!("│   │                                               ├→  Settlement Chain  │   │");
    println!("│   │  SG Data     →  [TEE Enclave]  →  ZK Proof  ─┘                      │   │");
    println!("│   └─────────────────────────────────────────────────────────────────────┘   │");
    println!("│                                                                              │");
    println!("│   This is the future of privacy-preserving cross-border finance.            │");
    println!("│                                                                              │");
    println!("└──────────────────────────────────────────────────────────────────────────────┘");
}

/// Helper to truncate strings
fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}

/// Format whole numbers with thousands separators for CLI output.
fn format_number(value: u64) -> String {
    let digits = value.to_string();
    let mut output = String::with_capacity(digits.len() + digits.len() / 3);

    for (index, ch) in digits.chars().rev().enumerate() {
        if index > 0 && index % 3 == 0 {
            output.push(',');
        }
        output.push(ch);
    }

    output.chars().rev().collect()
}

// =============================================================================
// JSON EXPORT
// =============================================================================

/// Export results to JSON file
fn export_to_json(output: &DemoOutput, path: &PathBuf) -> FalconLionResult<()> {
    use std::fs::File;
    use std::io::Write;

    let json = serde_json::json!({
        "project": "Falcon-Lion",
        "version": falcon_lion::VERSION,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "demo_id": output.demo_id.to_string(),
        "status": format!("{:?}", output.status),
        "deal_reference": output.deal_reference,
        "letter_of_credit": {
            "reference": output.lc_reference,
            "on_chain_id": output.lc_id,
        },
        "settlement": {
            "tx_hash": output.settlement_tx_hash,
            "explorer_url": output.explorer_url,
        },
        "metrics": {
            "total_time_ms": output.total_time_ms,
            "data_transferred_bytes": output.metrics.data_transferred_bytes,
            "sensitive_data_exposed": output.metrics.sensitive_data_exposed,
        },
        "audit_trail_entries": output.audit_trail.len(),
    });

    let mut file = File::create(path).map_err(|e| FalconLionError::IoError(e.to_string()))?;

    let json_string = serde_json::to_string_pretty(&json)
        .map_err(|e| FalconLionError::SerializationError(e.to_string()))?;

    file.write_all(json_string.as_bytes())
        .map_err(|e| FalconLionError::IoError(e.to_string()))?;

    println!("Results exported to: {}", path.display());

    Ok(())
}

// =============================================================================
// MAIN ENTRY POINT
// =============================================================================

#[tokio::main]
async fn main() -> ExitCode {
    // Parse command-line arguments
    let args = CliArgs::parse();

    // Handle --version
    if args.show_version {
        println!("{}", version_info());
        return ExitCode::SUCCESS;
    }

    // Handle --help
    if args.show_help {
        print_help();
        return ExitCode::SUCCESS;
    }

    // Print banner
    if args.verbose {
        print_banner();
    }

    // Configure demo
    let config = DemoConfig {
        verbose: args.verbose,
        simulate_delays: args.simulate_delays,
        mode: if args.simulate_delays {
            DemoMode::Presentation
        } else {
            DemoMode::Fast
        },
        deal_amount: None,
        goods_description: None,
    };

    // Create and run demo
    let demo = FalconLionDemo::new(config);

    if args.verbose {
        println!("Starting Project Falcon-Lion Demo...\n");
    }

    let start_time = Instant::now();

    match demo.run().await {
        Ok(output) => {
            let duration = start_time.elapsed();

            // Print summary
            if args.verbose {
                print_summary(&output, duration);
                print_key_insight();
            }

            // Export to JSON if requested
            if let Some(ref path) = args.output_path {
                if let Err(e) = export_to_json(&output, path) {
                    eprintln!("Failed to export results: {}", e);
                    return ExitCode::FAILURE;
                }
            }

            // Print success message
            if args.verbose {
                println!();
                println!("✅ Demo completed successfully!");
                println!();
                println!("Next steps:");
                println!("  • Review the Verifiable Letter of Credit on-chain");
                println!("  • Export audit trail for regulatory compliance");
                println!("  • Integrate with your trade finance system via SDK");
                println!();
                println!("Learn more: https://aethelred.io/docs/falcon-lion");
            }

            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!();
            eprintln!(
                "╔══════════════════════════════════════════════════════════════════════════════╗"
            );
            eprintln!(
                "║                              ❌ DEMO FAILED                                  ║"
            );
            eprintln!(
                "╠══════════════════════════════════════════════════════════════════════════════╣"
            );
            eprintln!(
                "║                                                                              ║"
            );
            eprintln!("║  Error: {:<65} ║", truncate(&e.to_string(), 65));
            eprintln!(
                "║                                                                              ║"
            );
            eprintln!("║  Error Code: {:<60} ║", e.error_code());
            eprintln!(
                "║  Recoverable: {:<59} ║",
                if e.is_recoverable() { "Yes" } else { "No" }
            );
            eprintln!(
                "║  Blocking: {:<62} ║",
                if e.is_blocking() { "Yes" } else { "No" }
            );
            eprintln!(
                "║                                                                              ║"
            );
            eprintln!(
                "╚══════════════════════════════════════════════════════════════════════════════╝"
            );
            eprintln!();
            eprintln!("For troubleshooting, see: https://aethelred.io/docs/troubleshooting");

            ExitCode::FAILURE
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
    fn test_cli_args_default() {
        let args = CliArgs::default();
        assert!(args.verbose);
        assert!(args.simulate_delays);
        assert!(args.output_path.is_none());
        assert!(!args.show_version);
        assert!(!args.show_help);
    }

    #[test]
    fn test_truncate_short_string() {
        assert_eq!(truncate("hello", 10), "hello");
    }

    #[test]
    fn test_truncate_long_string() {
        assert_eq!(truncate("hello world", 8), "hello...");
    }

    #[test]
    fn test_format_number() {
        assert_eq!(format_number(1000), "1,000");
        assert_eq!(format_number(1000000), "1,000,000");
        assert_eq!(format_number(5000000), "5,000,000");
    }

    #[test]
    fn test_format_number_small() {
        assert_eq!(format_number(1), "1");
        assert_eq!(format_number(12), "12");
        assert_eq!(format_number(123), "123");
    }
}
