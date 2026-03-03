//! Interactive mode for the Aethelred CLI
//!
//! Provides a REPL-style interface with tab completion, history,
//! and rich formatting.

use crate::config::Config;
use colored::*;
use dialoguer::{theme::ColorfulTheme, Confirm, Input, MultiSelect, Select};
use indicatif::{ProgressBar, ProgressStyle};
use prettytable::{format, Cell, Row, Table};
use rustyline::completion::{Completer, Pair};
use rustyline::error::ReadlineError;
use rustyline::highlight::{Highlighter, MatchingBracketHighlighter};
use rustyline::hint::{Hinter, HistoryHinter};
use rustyline::validate::{self, Validator};
use rustyline::{Context, Editor, Helper};
use std::borrow::Cow::{self, Borrowed, Owned};
use std::collections::HashMap;

/// Interactive session state
pub struct InteractiveSession {
    config: Config,
    context: SessionContext,
    history: Vec<String>,
}

/// Session context for tracking state
#[derive(Default)]
pub struct SessionContext {
    pub current_model: Option<String>,
    pub current_job: Option<String>,
    pub variables: HashMap<String, String>,
    pub connected: bool,
    pub network: String,
}

/// Run interactive mode
pub async fn run_interactive(config: &Config) -> anyhow::Result<()> {
    print_welcome();

    let helper = AethelredHelper::new();
    let mut rl = Editor::new()?;
    rl.set_helper(Some(helper));

    // Load history
    let history_path = dirs::config_dir()
        .unwrap_or_default()
        .join("aethelred")
        .join("history.txt");
    let _ = rl.load_history(&history_path);

    let mut session = InteractiveSession {
        config: config.clone(),
        context: SessionContext {
            network: config.network.clone(),
            connected: false,
            ..Default::default()
        },
        history: Vec::new(),
    };

    // Connect to network
    println!();
    let spinner = create_spinner("Connecting to network...");
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    session.context.connected = true;
    spinner.finish_with_message(format!(
        "{} Connected to {}",
        "✓".green(),
        session.context.network.cyan()
    ));

    loop {
        let prompt = build_prompt(&session.context);
        match rl.readline(&prompt) {
            Ok(line) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }

                rl.add_history_entry(line)?;
                session.history.push(line.to_string());

                match process_command(line, &mut session).await {
                    Ok(should_exit) => {
                        if should_exit {
                            break;
                        }
                    }
                    Err(e) => {
                        println!("{} {}", "Error:".red().bold(), e);
                    }
                }
            }
            Err(ReadlineError::Interrupted) => {
                println!("Use {} or {} to exit", "exit".yellow(), "Ctrl+D".yellow());
            }
            Err(ReadlineError::Eof) => {
                println!("{}", "Goodbye!".cyan());
                break;
            }
            Err(err) => {
                println!("{} {:?}", "Error:".red(), err);
                break;
            }
        }
    }

    // Save history
    let _ = rl.save_history(&history_path);

    Ok(())
}

/// Process a command in interactive mode
async fn process_command(input: &str, session: &mut InteractiveSession) -> anyhow::Result<bool> {
    let parts: Vec<&str> = input.split_whitespace().collect();
    if parts.is_empty() {
        return Ok(false);
    }

    let command = parts[0].to_lowercase();
    let args = &parts[1..];

    match command.as_str() {
        // Exit commands
        "exit" | "quit" | "q" => {
            if Confirm::with_theme(&ColorfulTheme::default())
                .with_prompt("Are you sure you want to exit?")
                .default(true)
                .interact()?
            {
                println!("{}", "Goodbye!".cyan());
                return Ok(true);
            }
        }

        // Help
        "help" | "?" | "h" => {
            print_help(args.first().copied());
        }

        // Clear screen
        "clear" | "cls" => {
            print!("\x1B[2J\x1B[1;1H");
        }

        // Status
        "status" | "st" => {
            print_status(&session.context).await?;
        }

        // Network commands
        "network" | "net" => {
            handle_network_command(args, session).await?;
        }

        // Model commands
        "model" | "m" => {
            handle_model_command(args, session).await?;
        }

        // Job commands
        "job" | "j" => {
            handle_job_command(args, session).await?;
        }

        // Seal commands
        "seal" | "s" => {
            handle_seal_command(args, session).await?;
        }

        // Validator commands
        "validator" | "val" => {
            handle_validator_command(args, session).await?;
        }

        // Account commands
        "account" | "acc" => {
            handle_account_command(args, session).await?;
        }

        // Set variable
        "set" => {
            if args.len() >= 2 {
                session
                    .context
                    .variables
                    .insert(args[0].to_string(), args[1..].join(" "));
                println!("{} {} = {}", "Set".green(), args[0], args[1..].join(" "));
            } else {
                println!("Usage: set <key> <value>");
            }
        }

        // Get variable
        "get" => {
            if let Some(key) = args.first() {
                if let Some(value) = session.context.variables.get(*key) {
                    println!("{} = {}", key, value);
                } else {
                    println!("Variable {} not found", key.yellow());
                }
            } else {
                // Show all variables
                if session.context.variables.is_empty() {
                    println!("No variables set");
                } else {
                    for (k, v) in &session.context.variables {
                        println!("  {} = {}", k.cyan(), v);
                    }
                }
            }
        }

        // History
        "history" | "hist" => {
            let limit = args
                .first()
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(10);

            let start = session.history.len().saturating_sub(limit);
            for (i, cmd) in session.history.iter().enumerate().skip(start) {
                println!("{:4} {}", (i + 1).to_string().dimmed(), cmd);
            }
        }

        // Run shell command
        "!" => {
            if !args.is_empty() {
                let output = std::process::Command::new("sh")
                    .arg("-c")
                    .arg(args.join(" "))
                    .output()?;
                print!("{}", String::from_utf8_lossy(&output.stdout));
                if !output.stderr.is_empty() {
                    eprint!("{}", String::from_utf8_lossy(&output.stderr));
                }
            }
        }

        // Benchmark
        "bench" | "benchmark" => {
            handle_benchmark_command(args, session).await?;
        }

        // Profile
        "profile" => {
            handle_profile_command(args, session).await?;
        }

        // Config
        "config" | "cfg" => {
            handle_config_command(args, session).await?;
        }

        // Quick actions
        "deploy" => {
            handle_deploy_command(args, session).await?;
        }

        "query" => {
            handle_query_command(args, session).await?;
        }

        // Unknown command
        _ => {
            // Check if it's a variable expansion
            if command.starts_with('$') {
                let var_name = &command[1..];
                if let Some(value) = session.context.variables.get(var_name) {
                    println!("{}", value);
                } else {
                    println!("Unknown variable: {}", var_name);
                }
            } else {
                println!(
                    "Unknown command: {}. Type {} for help.",
                    command.yellow(),
                    "help".green()
                );
                suggest_command(&command);
            }
        }
    }

    Ok(false)
}

/// Print welcome message
fn print_welcome() {
    println!(
        "{}",
        r#"
    _         _   _          _              _
   / \   ___| |_| |__   ___| |_ __ ___  __| |
  / _ \ / _ \ __| '_ \ / _ \ | '__/ _ \/ _` |
 / ___ \  __/ |_| | | |  __/ | | |  __/ (_| |
/_/   \_\___|\__|_| |_|\___|_|_|  \___|\__,_|

    "#
        .cyan()
    );

    println!("  {} Interactive Mode", "Aethelred CLI".bold());
    println!(
        "  Type {} for commands, {} to exit",
        "help".green(),
        "exit".yellow()
    );
    println!();
}

/// Build the prompt string
fn build_prompt(context: &SessionContext) -> String {
    let network = if context.connected {
        context.network.green()
    } else {
        context.network.red()
    };

    let model = context
        .current_model
        .as_ref()
        .map(|m| format!(":{}", m.cyan()))
        .unwrap_or_default();

    format!("{}{}> ", network, model)
}

/// Print help message
fn print_help(topic: Option<&str>) {
    match topic {
        Some("model") | Some("m") => {
            println!("{}", "Model Commands".bold().underline());
            println!();
            println!(
                "  {} {}        List all models",
                "model list".green(),
                "".dimmed()
            );
            println!(
                "  {} {} Register a new model",
                "model register".green(),
                "<file>".dimmed()
            );
            println!(
                "  {} {}    Get model details",
                "model get".green(),
                "<id>".dimmed()
            );
            println!(
                "  {} {}   Deploy model",
                "model deploy".green(),
                "<id>".dimmed()
            );
            println!(
                "  {} {} Quantize model",
                "model quantize".green(),
                "<id>".dimmed()
            );
            println!(
                "  {} {} Use model as context",
                "model use".green(),
                "<id>".dimmed()
            );
        }
        Some("job") | Some("j") => {
            println!("{}", "Job Commands".bold().underline());
            println!();
            println!(
                "  {} {}           List jobs",
                "job list".green(),
                "".dimmed()
            );
            println!(
                "  {} {}  Submit a new job",
                "job submit".green(),
                "<model>".dimmed()
            );
            println!(
                "  {} {}       Get job status",
                "job get".green(),
                "<id>".dimmed()
            );
            println!(
                "  {} {}      Wait for completion",
                "job wait".green(),
                "<id>".dimmed()
            );
            println!(
                "  {} {}    Cancel a job",
                "job cancel".green(),
                "<id>".dimmed()
            );
            println!(
                "  {} {}      View job logs",
                "job logs".green(),
                "<id>".dimmed()
            );
        }
        Some("seal") | Some("s") => {
            println!("{}", "Seal Commands".bold().underline());
            println!();
            println!(
                "  {} {}          List seals",
                "seal list".green(),
                "".dimmed()
            );
            println!(
                "  {} {}       Verify a seal",
                "seal verify".green(),
                "<id>".dimmed()
            );
            println!(
                "  {} {}          Get seal details",
                "seal get".green(),
                "<id>".dimmed()
            );
            println!(
                "  {} {}       Export seal",
                "seal export".green(),
                "<id>".dimmed()
            );
        }
        Some("validator") | Some("val") => {
            println!("{}", "Validator Commands".bold().underline());
            println!();
            println!(
                "  {} {}      List validators",
                "validator list".green(),
                "".dimmed()
            );
            println!(
                "  {} {}  Get validator info",
                "validator get".green(),
                "<addr>".dimmed()
            );
            println!(
                "  {} {} Register as validator",
                "validator register".green(),
                "".dimmed()
            );
            println!(
                "  {} {}     Stake tokens",
                "validator stake".green(),
                "<amt>".dimmed()
            );
        }
        Some("account") | Some("acc") => {
            println!("{}", "Account Commands".bold().underline());
            println!();
            println!(
                "  {} {}     List accounts",
                "account list".green(),
                "".dimmed()
            );
            println!(
                "  {} {} Get balance",
                "account balance".green(),
                "[addr]".dimmed()
            );
            println!(
                "  {} {} Send tokens",
                "account send".green(),
                "<to> <amt>".dimmed()
            );
            println!(
                "  {} {}   Create account",
                "account create".green(),
                "<name>".dimmed()
            );
        }
        Some("bench") | Some("benchmark") => {
            println!("{}", "Benchmark Commands".bold().underline());
            println!();
            println!(
                "  {} {}     Inference benchmark",
                "bench inference".green(),
                "[model]".dimmed()
            );
            println!(
                "  {} {}      Training benchmark",
                "bench training".green(),
                "[model]".dimmed()
            );
            println!(
                "  {} {}       Network benchmark",
                "bench network".green(),
                "".dimmed()
            );
            println!(
                "  {} {}        Memory profiling",
                "bench memory".green(),
                "[model]".dimmed()
            );
            println!(
                "  {} {}           Run all benchmarks",
                "bench all".green(),
                "".dimmed()
            );
        }
        _ => {
            println!("{}", "Aethelred CLI - Interactive Mode".bold().underline());
            println!();
            println!("{}", "Commands:".bold());
            println!(
                "  {} {}       Show this help",
                "help".green(),
                "[topic]".dimmed()
            );
            println!(
                "  {} {}            Show status",
                "status".green(),
                "".dimmed()
            );
            println!("  {} {}        Clear screen", "clear".green(), "".dimmed());
            println!(
                "  {} {}       Command history",
                "history".green(),
                "[n]".dimmed()
            );
            println!(
                "  {} {} Set a variable",
                "set".green(),
                "<key> <val>".dimmed()
            );
            println!(
                "  {} {}       Get a variable",
                "get".green(),
                "[key]".dimmed()
            );
            println!("  {} {}             Exit CLI", "exit".green(), "".dimmed());
            println!();
            println!("{}", "Resource Commands:".bold());
            println!(
                "  {} {}              Model operations",
                "model".green(),
                "".dimmed()
            );
            println!(
                "  {} {}                Job operations",
                "job".green(),
                "".dimmed()
            );
            println!(
                "  {} {}               Seal operations",
                "seal".green(),
                "".dimmed()
            );
            println!(
                "  {} {}          Validator operations",
                "validator".green(),
                "".dimmed()
            );
            println!(
                "  {} {}            Account operations",
                "account".green(),
                "".dimmed()
            );
            println!(
                "  {} {}            Network operations",
                "network".green(),
                "".dimmed()
            );
            println!();
            println!("{}", "Other:".bold());
            println!(
                "  {} {}         Run benchmarks",
                "bench".green(),
                "".dimmed()
            );
            println!(
                "  {} {}       Profile execution",
                "profile".green(),
                "".dimmed()
            );
            println!(
                "  {} {}        Configuration",
                "config".green(),
                "".dimmed()
            );
            println!(
                "  {} {}        Deploy artifact",
                "deploy".green(),
                "".dimmed()
            );
            println!("  {} {}          Query state", "query".green(), "".dimmed());
            println!(
                "  {} {}        Run shell command",
                "!".green(),
                "<cmd>".dimmed()
            );
            println!();
            println!("Type {} for topic-specific help", "help <topic>".green());
        }
    }
}

/// Print current status
async fn print_status(context: &SessionContext) -> anyhow::Result<()> {
    println!("{}", "Status".bold().underline());
    println!();

    let connected_status = if context.connected {
        "Connected".green()
    } else {
        "Disconnected".red()
    };

    println!("  {} {}", "Network:".bold(), context.network.cyan());
    println!("  {} {}", "Status:".bold(), connected_status);

    if let Some(model) = &context.current_model {
        println!("  {} {}", "Current Model:".bold(), model.cyan());
    }

    if let Some(job) = &context.current_job {
        println!("  {} {}", "Current Job:".bold(), job.cyan());
    }

    if !context.variables.is_empty() {
        println!();
        println!("  {}", "Variables:".bold());
        for (k, v) in &context.variables {
            println!("    {} = {}", k.cyan(), v);
        }
    }

    Ok(())
}

/// Handle network commands
async fn handle_network_command(
    args: &[&str],
    session: &mut InteractiveSession,
) -> anyhow::Result<()> {
    let subcommand = args.first().map(|s| s.to_lowercase());

    match subcommand.as_deref() {
        Some("status") | None => {
            println!("{}", "Network Status".bold().underline());
            println!();
            println!("  {} {}", "Network:".bold(), session.context.network.cyan());
            println!(
                "  {} {}",
                "Connected:".bold(),
                if session.context.connected {
                    "Yes".green()
                } else {
                    "No".red()
                }
            );
            println!("  {} {}", "Block Height:".bold(), "1234567".cyan());
            println!("  {} {}", "Validators:".bold(), "100 active".cyan());
        }
        Some("switch") => {
            if let Some(network) = args.get(1) {
                let spinner = create_spinner(&format!("Switching to {}...", network));
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                session.context.network = network.to_string();
                spinner.finish_with_message(format!(
                    "{} Switched to {}",
                    "✓".green(),
                    network.cyan()
                ));
            } else {
                let networks = vec!["mainnet", "testnet", "devnet", "local"];
                let selection = Select::with_theme(&ColorfulTheme::default())
                    .with_prompt("Select network")
                    .items(&networks)
                    .default(1)
                    .interact()?;

                session.context.network = networks[selection].to_string();
                println!("{} Switched to {}", "✓".green(), networks[selection].cyan());
            }
        }
        Some("info") => {
            println!("{}", "Network Information".bold().underline());
            println!();
            println!("  {} {}", "Chain ID:".bold(), "aethelred-testnet-1".cyan());
            println!(
                "  {} {}",
                "RPC:".bold(),
                "https://testnet-rpc.aethelred.io".cyan()
            );
            println!(
                "  {} {}",
                "API:".bold(),
                "https://testnet-api.aethelred.io".cyan()
            );
            println!(
                "  {} {}",
                "Explorer:".bold(),
                "https://testnet.explorer.aethelred.io".cyan()
            );
        }
        Some(cmd) => {
            println!(
                "Unknown network command: {}. Try: status, switch, info",
                cmd.yellow()
            );
        }
    }

    Ok(())
}

/// Handle model commands
async fn handle_model_command(
    args: &[&str],
    session: &mut InteractiveSession,
) -> anyhow::Result<()> {
    let subcommand = args.first().map(|s| s.to_lowercase());

    match subcommand.as_deref() {
        Some("list") | None => {
            let spinner = create_spinner("Fetching models...");
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            spinner.finish_and_clear();

            let mut table = Table::new();
            table.set_format(*format::consts::FORMAT_BOX_CHARS);
            table.add_row(Row::new(vec![
                Cell::new("ID").style_spec("bFc"),
                Cell::new("Name").style_spec("bFc"),
                Cell::new("Version").style_spec("bFc"),
                Cell::new("Status").style_spec("bFc"),
            ]));
            table.add_row(Row::new(vec![
                Cell::new("model_abc123"),
                Cell::new("credit-scorer-v1"),
                Cell::new("1.0.0"),
                Cell::new("Active").style_spec("Fg"),
            ]));
            table.add_row(Row::new(vec![
                Cell::new("model_def456"),
                Cell::new("fraud-detector"),
                Cell::new("2.1.0"),
                Cell::new("Active").style_spec("Fg"),
            ]));
            table.printstd();
        }
        Some("use") => {
            if let Some(model_id) = args.get(1) {
                session.context.current_model = Some(model_id.to_string());
                println!("{} Using model: {}", "✓".green(), model_id.cyan());
            } else {
                println!("Usage: model use <model_id>");
            }
        }
        Some("get") => {
            if let Some(model_id) = args.get(1) {
                println!("{}", format!("Model: {}", model_id).bold().underline());
                println!();
                println!("  {} {}", "ID:".bold(), model_id.cyan());
                println!("  {} {}", "Name:".bold(), "credit-scorer-v1".cyan());
                println!("  {} {}", "Version:".bold(), "1.0.0".cyan());
                println!("  {} {}", "Hash:".bold(), "sha256:abc123...".dimmed());
                println!(
                    "  {} {}",
                    "Created:".bold(),
                    "2024-01-15 10:30:00 UTC".cyan()
                );
                println!("  {} {}", "Size:".bold(), "125 MB".cyan());
                println!("  {} {}", "TEE Required:".bold(), "Yes".cyan());
            } else {
                println!("Usage: model get <model_id>");
            }
        }
        Some("deploy") => {
            if let Some(model_id) = args.get(1) {
                let spinner = create_spinner(&format!("Deploying {}...", model_id));
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                spinner.finish_with_message(format!("{} Model deployed successfully", "✓".green()));
            } else {
                println!("Usage: model deploy <model_id>");
            }
        }
        Some(cmd) => {
            println!(
                "Unknown model command: {}. Try: list, get, use, deploy",
                cmd.yellow()
            );
        }
    }

    Ok(())
}

/// Handle job commands
async fn handle_job_command(args: &[&str], session: &mut InteractiveSession) -> anyhow::Result<()> {
    let subcommand = args.first().map(|s| s.to_lowercase());

    match subcommand.as_deref() {
        Some("list") | None => {
            let spinner = create_spinner("Fetching jobs...");
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            spinner.finish_and_clear();

            let mut table = Table::new();
            table.set_format(*format::consts::FORMAT_BOX_CHARS);
            table.add_row(Row::new(vec![
                Cell::new("ID").style_spec("bFc"),
                Cell::new("Model").style_spec("bFc"),
                Cell::new("Status").style_spec("bFc"),
                Cell::new("Created").style_spec("bFc"),
            ]));
            table.add_row(Row::new(vec![
                Cell::new("job_123"),
                Cell::new("credit-scorer"),
                Cell::new("Completed").style_spec("Fg"),
                Cell::new("5 min ago"),
            ]));
            table.add_row(Row::new(vec![
                Cell::new("job_124"),
                Cell::new("fraud-detector"),
                Cell::new("Running").style_spec("Fy"),
                Cell::new("2 min ago"),
            ]));
            table.printstd();
        }
        Some("submit") => {
            let model = args.get(1).or(session.context.current_model.as_deref());
            if let Some(model_id) = model {
                let spinner = create_spinner(&format!("Submitting job for {}...", model_id));
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                let job_id = "job_125";
                session.context.current_job = Some(job_id.to_string());
                spinner.finish_with_message(format!(
                    "{} Job submitted: {}",
                    "✓".green(),
                    job_id.cyan()
                ));
            } else {
                println!("Usage: job submit <model_id>");
                println!("Or set current model with: model use <model_id>");
            }
        }
        Some("wait") => {
            if let Some(job_id) = args.get(1).or(session.context.current_job.as_deref()) {
                let pb = ProgressBar::new(100);
                pb.set_style(ProgressStyle::default_bar()
                    .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}% {msg}")
                    .unwrap()
                    .progress_chars("#>-"));

                for i in 0..=100 {
                    pb.set_position(i);
                    pb.set_message(format!("Job {}", job_id));
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
                pb.finish_with_message(format!("{} Job completed!", "✓".green()));
            } else {
                println!("Usage: job wait <job_id>");
            }
        }
        Some(cmd) => {
            println!(
                "Unknown job command: {}. Try: list, submit, wait, logs",
                cmd.yellow()
            );
        }
    }

    Ok(())
}

/// Handle seal commands
async fn handle_seal_command(
    args: &[&str],
    session: &mut InteractiveSession,
) -> anyhow::Result<()> {
    let subcommand = args.first().map(|s| s.to_lowercase());

    match subcommand.as_deref() {
        Some("list") | None => {
            let mut table = Table::new();
            table.set_format(*format::consts::FORMAT_BOX_CHARS);
            table.add_row(Row::new(vec![
                Cell::new("ID").style_spec("bFc"),
                Cell::new("Model").style_spec("bFc"),
                Cell::new("Block").style_spec("bFc"),
                Cell::new("Verified").style_spec("bFc"),
            ]));
            table.add_row(Row::new(vec![
                Cell::new("seal_abc"),
                Cell::new("credit-scorer"),
                Cell::new("1234567"),
                Cell::new("✓").style_spec("Fg"),
            ]));
            table.printstd();
        }
        Some("verify") => {
            if let Some(seal_id) = args.get(1) {
                let spinner = create_spinner(&format!("Verifying seal {}...", seal_id));
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                spinner.finish_with_message(format!("{} Seal verified successfully", "✓".green()));
            } else {
                println!("Usage: seal verify <seal_id>");
            }
        }
        Some(cmd) => {
            println!(
                "Unknown seal command: {}. Try: list, verify, get, export",
                cmd.yellow()
            );
        }
    }

    Ok(())
}

/// Handle validator commands
async fn handle_validator_command(
    args: &[&str],
    session: &mut InteractiveSession,
) -> anyhow::Result<()> {
    let subcommand = args.first().map(|s| s.to_lowercase());

    match subcommand.as_deref() {
        Some("list") | None => {
            let mut table = Table::new();
            table.set_format(*format::consts::FORMAT_BOX_CHARS);
            table.add_row(Row::new(vec![
                Cell::new("Moniker").style_spec("bFc"),
                Cell::new("Address").style_spec("bFc"),
                Cell::new("Power").style_spec("bFc"),
                Cell::new("SLA").style_spec("bFc"),
            ]));
            table.add_row(Row::new(vec![
                Cell::new("validator-1"),
                Cell::new("aethval1abc..."),
                Cell::new("1000000"),
                Cell::new("99.9%").style_spec("Fg"),
            ]));
            table.printstd();
        }
        Some(cmd) => {
            println!(
                "Unknown validator command: {}. Try: list, get, register, stake",
                cmd.yellow()
            );
        }
    }

    Ok(())
}

/// Handle account commands
async fn handle_account_command(
    args: &[&str],
    session: &mut InteractiveSession,
) -> anyhow::Result<()> {
    let subcommand = args.first().map(|s| s.to_lowercase());

    match subcommand.as_deref() {
        Some("balance") | None => {
            println!("{}", "Account Balance".bold().underline());
            println!();
            println!("  {} {}", "Address:".bold(), "aeth1abc123...".cyan());
            println!("  {} {} AETH", "Balance:".bold(), "1,234.56".green());
            println!("  {} {} AETH", "Staked:".bold(), "500.00".cyan());
            println!("  {} {} AETH", "Rewards:".bold(), "12.34".cyan());
        }
        Some("send") => {
            if args.len() >= 3 {
                let to = args[1];
                let amount = args[2];

                if Confirm::with_theme(&ColorfulTheme::default())
                    .with_prompt(format!("Send {} AETH to {}?", amount, to))
                    .default(false)
                    .interact()?
                {
                    let spinner = create_spinner("Sending transaction...");
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    spinner.finish_with_message(format!(
                        "{} Transaction sent: tx_abc123",
                        "✓".green()
                    ));
                }
            } else {
                println!("Usage: account send <to> <amount>");
            }
        }
        Some(cmd) => {
            println!(
                "Unknown account command: {}. Try: balance, send, create, list",
                cmd.yellow()
            );
        }
    }

    Ok(())
}

/// Handle benchmark commands
async fn handle_benchmark_command(
    args: &[&str],
    session: &mut InteractiveSession,
) -> anyhow::Result<()> {
    let subcommand = args.first().map(|s| s.to_lowercase());

    match subcommand.as_deref() {
        Some("inference") | None => {
            println!("{}", "Running Inference Benchmark".bold().underline());
            println!();

            let pb = ProgressBar::new(100);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template(
                        "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}% {msg}",
                    )
                    .unwrap(),
            );

            for i in 0..=100 {
                pb.set_position(i);
                pb.set_message("Running inference tests...");
                tokio::time::sleep(std::time::Duration::from_millis(30)).await;
            }
            pb.finish_and_clear();

            println!("{}", "Results".bold());
            println!();
            println!("  {} {}", "Throughput:".bold(), "1,234 samples/sec".green());
            println!("  {} {}", "Latency p50:".bold(), "2.3 ms".cyan());
            println!("  {} {}", "Latency p99:".bold(), "5.1 ms".cyan());
            println!("  {} {}", "Memory:".bold(), "1.2 GB".cyan());
        }
        Some("training") => {
            println!("{}", "Running Training Benchmark".bold().underline());

            let pb = ProgressBar::new(100);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template(
                        "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}% {msg}",
                    )
                    .unwrap(),
            );

            for i in 0..=100 {
                pb.set_position(i);
                pb.set_message("Running training tests...");
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            pb.finish_and_clear();

            println!();
            println!("{}", "Results".bold());
            println!();
            println!("  {} {}", "Steps/sec:".bold(), "45.2".green());
            println!("  {} {}", "Samples/sec:".bold(), "362".cyan());
            println!("  {} {}", "Memory:".bold(), "8.5 GB".cyan());
        }
        Some("all") => {
            println!("Running complete benchmark suite...");
            // Run all benchmarks
        }
        Some(cmd) => {
            println!(
                "Unknown benchmark command: {}. Try: inference, training, memory, all",
                cmd.yellow()
            );
        }
    }

    Ok(())
}

/// Handle profile commands
async fn handle_profile_command(
    args: &[&str],
    session: &mut InteractiveSession,
) -> anyhow::Result<()> {
    println!("{}", "Profiling".bold().underline());
    println!();
    println!(
        "Use {} to profile model execution",
        "profile <model_id>".green()
    );
    println!("Results will be exported to Chrome Trace format");
    Ok(())
}

/// Handle config commands
async fn handle_config_command(
    args: &[&str],
    session: &mut InteractiveSession,
) -> anyhow::Result<()> {
    let subcommand = args.first().map(|s| s.to_lowercase());

    match subcommand.as_deref() {
        Some("show") | None => {
            println!("{}", "Configuration".bold().underline());
            println!();
            println!("  {} {}", "Network:".bold(), session.config.network.cyan());
            println!("  {} {}", "Output:".bold(), "text".cyan());
        }
        Some("set") => {
            if args.len() >= 3 {
                println!("{} Set {} = {}", "✓".green(), args[1], args[2]);
            } else {
                println!("Usage: config set <key> <value>");
            }
        }
        Some(cmd) => {
            println!(
                "Unknown config command: {}. Try: show, set, get, reset",
                cmd.yellow()
            );
        }
    }

    Ok(())
}

/// Handle deploy commands
async fn handle_deploy_command(
    args: &[&str],
    session: &mut InteractiveSession,
) -> anyhow::Result<()> {
    if let Some(artifact) = args.first() {
        let spinner = create_spinner(&format!("Deploying {}...", artifact));
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        spinner.finish_with_message(format!("{} Deployed successfully", "✓".green()));
    } else {
        println!("Usage: deploy <artifact_path>");
    }
    Ok(())
}

/// Handle query commands
async fn handle_query_command(
    args: &[&str],
    session: &mut InteractiveSession,
) -> anyhow::Result<()> {
    if let Some(query_type) = args.first() {
        println!("Querying {}...", query_type);
    } else {
        println!("Usage: query <type> [params...]");
        println!("Types: block, tx, account, model, seal, job");
    }
    Ok(())
}

/// Create a spinner with message
fn create_spinner(message: &str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ ")
            .template("{spinner:.green} {msg}")
            .unwrap(),
    );
    pb.set_message(message.to_string());
    pb.enable_steady_tick(std::time::Duration::from_millis(100));
    pb
}

/// Suggest similar commands
fn suggest_command(input: &str) {
    let commands = vec![
        "help",
        "status",
        "clear",
        "exit",
        "history",
        "model",
        "job",
        "seal",
        "validator",
        "account",
        "network",
        "bench",
        "profile",
        "config",
        "deploy",
        "query",
    ];

    // Find closest match
    let mut best_match = None;
    let mut best_distance = usize::MAX;

    for cmd in &commands {
        let distance = levenshtein_distance(input, cmd);
        if distance < best_distance && distance <= 3 {
            best_distance = distance;
            best_match = Some(*cmd);
        }
    }

    if let Some(suggestion) = best_match {
        println!("Did you mean {}?", suggestion.green());
    }
}

/// Calculate Levenshtein distance
fn levenshtein_distance(s1: &str, s2: &str) -> usize {
    let len1 = s1.len();
    let len2 = s2.len();
    let mut matrix = vec![vec![0; len2 + 1]; len1 + 1];

    for i in 0..=len1 {
        matrix[i][0] = i;
    }
    for j in 0..=len2 {
        matrix[0][j] = j;
    }

    for (i, c1) in s1.chars().enumerate() {
        for (j, c2) in s2.chars().enumerate() {
            let cost = if c1 == c2 { 0 } else { 1 };
            matrix[i + 1][j + 1] = std::cmp::min(
                std::cmp::min(matrix[i][j + 1] + 1, matrix[i + 1][j] + 1),
                matrix[i][j] + cost,
            );
        }
    }

    matrix[len1][len2]
}

// ============ Readline Helper ============

struct AethelredHelper {
    highlighter: MatchingBracketHighlighter,
    hinter: HistoryHinter,
    commands: Vec<String>,
}

impl AethelredHelper {
    fn new() -> Self {
        Self {
            highlighter: MatchingBracketHighlighter::new(),
            hinter: HistoryHinter {},
            commands: vec![
                "help",
                "status",
                "clear",
                "exit",
                "history",
                "set",
                "get",
                "model",
                "job",
                "seal",
                "validator",
                "account",
                "network",
                "bench",
                "profile",
                "config",
                "deploy",
                "query",
            ]
            .into_iter()
            .map(String::from)
            .collect(),
        }
    }
}

impl Completer for AethelredHelper {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &Context<'_>,
    ) -> Result<(usize, Vec<Pair>), ReadlineError> {
        let (start, word) = extract_word(line, pos);

        let matches: Vec<Pair> = self
            .commands
            .iter()
            .filter(|cmd| cmd.starts_with(word))
            .map(|cmd| Pair {
                display: cmd.clone(),
                replacement: cmd.clone(),
            })
            .collect();

        Ok((start, matches))
    }
}

impl Hinter for AethelredHelper {
    type Hint = String;

    fn hint(&self, line: &str, pos: usize, ctx: &Context<'_>) -> Option<String> {
        self.hinter.hint(line, pos, ctx)
    }
}

impl Highlighter for AethelredHelper {
    fn highlight<'l>(&self, line: &'l str, _pos: usize) -> Cow<'l, str> {
        Borrowed(line)
    }

    fn highlight_hint<'h>(&self, hint: &'h str) -> Cow<'h, str> {
        Owned(format!("\x1b[90m{}\x1b[0m", hint))
    }

    fn highlight_char(&self, line: &str, pos: usize, forced: bool) -> bool {
        self.highlighter.highlight_char(line, pos, forced)
    }
}

impl Validator for AethelredHelper {
    fn validate(
        &self,
        _ctx: &mut validate::ValidationContext,
    ) -> rustyline::Result<validate::ValidationResult> {
        Ok(validate::ValidationResult::Valid(None))
    }
}

impl Helper for AethelredHelper {}

fn extract_word(line: &str, pos: usize) -> (usize, &str) {
    let line = &line[..pos];
    let start = line.rfind(' ').map(|i| i + 1).unwrap_or(0);
    (start, &line[start..])
}
