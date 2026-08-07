use aethelred_testnet::{Testnet, TestnetConfig};
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "aethelred-testnet",
    about = "Inspect the local Aethelred testnet showcase configuration"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Print the current synthesized testnet status document.
    Status,
    /// Print the developer-facing connection details.
    ConnectionInfo,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let testnet = Testnet::new(TestnetConfig::default());

    match cli.command.unwrap_or(Command::Status) {
        Command::Status => println!("{}", serde_json::to_string_pretty(&testnet.status())?),
        Command::ConnectionInfo => println!(
            "{}",
            serde_json::to_string_pretty(&testnet.connection_info())?
        ),
    }

    Ok(())
}
