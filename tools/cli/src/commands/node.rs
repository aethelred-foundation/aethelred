//! Node commands.

use anyhow::{anyhow, Context, Result};
use std::process::Command;

use crate::config::Config;
use crate::NodeArgs;

pub async fn run(args: NodeArgs, _config: &Config) -> Result<()> {
    let binary = std::env::var("AETH_NODE_BINARY").unwrap_or_else(|_| "aethelredd".to_string());
    let mut command = Command::new(&binary);

    command.arg("start");
    command.arg("--rpc.laddr");
    command.arg(format!("tcp://0.0.0.0:{}", args.rpc_port));
    command.arg("--p2p.laddr");
    command.arg(format!("tcp://0.0.0.0:{}", args.p2p_port));
    command.arg("--grpc.address");
    command.arg(format!("0.0.0.0:{}", args.grpc_port));
    command.arg("--pruning");
    command.arg(args.pruning);

    if args.enable_api {
        command.arg("--api.enable");
    }

    if let Some(data_dir) = args.data_dir {
        command.arg("--home");
        command.arg(data_dir);
    }

    println!("Launching {} {} node...", binary, args.node_type);
    let status = command
        .status()
        .with_context(|| format!("failed to execute node binary '{binary}'"))?;

    if !status.success() {
        return Err(anyhow!("node process exited with status {status}"));
    }

    Ok(())
}
