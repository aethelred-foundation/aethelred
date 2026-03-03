//! Development commands.

use anyhow::{anyhow, Context, Result};
use std::path::PathBuf;
use std::process::Command;

use crate::config::Config;
use crate::DevCommands;

pub async fn run(cmd: DevCommands, _config: &Config) -> Result<()> {
    match cmd {
        DevCommands::Serve { port, hot_reload } => {
            let mut command = Command::new("go");
            command.arg("run").arg("./cmd/aethelredd");
            command.arg(format!("--rpc.laddr=tcp://0.0.0.0:{port}"));
            if hot_reload {
                println!(
                    "Hot reload requested: run with external watcher (e.g. air) for full support."
                );
            }
            run_command(command, "development server")
        }
        DevCommands::Test { pattern, verbose } => {
            let mut command = Command::new("go");
            command.arg("test");
            if verbose {
                command.arg("-v");
            }
            if let Some(pattern) = pattern {
                command.arg(format!("-run={pattern}"));
            }
            command.arg("./...");
            run_command(command, "go tests")
        }
        DevCommands::Codegen {
            contract,
            output,
            lang,
        } => {
            let mut command = Command::new("go");
            command
                .arg("run")
                .arg("./scripts/openapi_to_sdk_stub.go")
                .arg("--input")
                .arg(contract)
                .arg("--output")
                .arg(output)
                .arg("--lang")
                .arg(lang);
            run_command(command, "code generation")
        }
        DevCommands::Fmt { files, check } => {
            if files.is_empty() {
                return run_command(
                    command_for("go", vec!["fmt".into(), "./...".into()]),
                    "formatting",
                );
            }
            for file in files {
                let mut command = command_for("gofmt", vec![]);
                if check {
                    command.arg("-d");
                } else {
                    command.arg("-w");
                }
                command.arg(file);
                run_command(command, "formatting")?;
            }
            Ok(())
        }
        DevCommands::Lint { files, fix } => {
            let mut command = Command::new("golangci-lint");
            command.arg("run");
            if fix {
                command.arg("--fix");
            }
            if !files.is_empty() {
                for file in files {
                    command.arg(file);
                }
            }
            run_command(command, "lint")
        }
        DevCommands::Profile { command, output } => {
            if command.is_empty() {
                return Err(anyhow!("profile command requires a subcommand to execute"));
            }
            let mut pprof = Command::new("go");
            pprof.arg("tool").arg("pprof");
            if let Some(output_path) = output {
                pprof.arg("-output").arg(output_path);
            }
            for part in command {
                pprof.arg(part);
            }
            run_command(pprof, "profiling")
        }
        DevCommands::Debug { model, input } => debug_model(model, input),
    }
}

fn debug_model(model: PathBuf, input: Option<PathBuf>) -> Result<()> {
    if !model.exists() {
        return Err(anyhow!("model does not exist: {}", model.display()));
    }
    println!("Debug model: {}", model.display());
    if let Some(input_file) = input {
        if !input_file.exists() {
            return Err(anyhow!("input does not exist: {}", input_file.display()));
        }
        println!("Input: {}", input_file.display());
    }
    println!("Tip: use `aethelred model benchmark` for runtime-level diagnostics.");
    Ok(())
}

fn command_for(binary: &str, args: Vec<String>) -> Command {
    let mut command = Command::new(binary);
    for arg in args {
        command.arg(arg);
    }
    command
}

fn run_command(mut command: Command, task: &str) -> Result<()> {
    let status = command
        .status()
        .with_context(|| format!("failed to start process for {task}"))?;
    if !status.success() {
        return Err(anyhow!("{task} failed with status {status}"));
    }
    Ok(())
}
