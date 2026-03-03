//! Network commands.

use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};

use crate::commands::api::{print_value, ApiClient};
use crate::config::{Config, NetworkPreset};
use crate::NetworkCommands;

pub async fn run(cmd: NetworkCommands, config: &Config) -> Result<()> {
    match cmd {
        NetworkCommands::Status => status(config).await,
        NetworkCommands::Info => info(config),
        NetworkCommands::List => list(config),
        NetworkCommands::Switch { network } => switch_network(config, &network),
        NetworkCommands::Params => params(config).await,
        NetworkCommands::Blocks { count } => blocks(config, count).await,
        NetworkCommands::Pending => pending(config).await,
    }
}

async fn status(config: &Config) -> Result<()> {
    let client = ApiClient::new(config)?;
    let api_status = client
        .get_api("/v1/status", &[])
        .await
        .unwrap_or_else(|err| {
            json!({
                "status": "unreachable",
                "error": err.to_string()
            })
        });
    let rpc_status = client.get_rpc("/status", &[]).await.unwrap_or_else(|err| {
        json!({
            "status": "unreachable",
            "error": err.to_string()
        })
    });

    let output = json!({
        "network": config.network,
        "chain_id": config.chain_id,
        "api_endpoint": config.api_endpoint,
        "rpc_endpoint": config.rpc_endpoint,
        "api_status": api_status,
        "rpc_status": rpc_status
    });
    print_value(&output, &config.output_format)
}

fn info(config: &Config) -> Result<()> {
    let info = json!({
        "network": config.network,
        "chain_id": config.chain_id,
        "api_endpoint": config.api_endpoint,
        "rpc_endpoint": config.rpc_endpoint,
        "keyring_backend": config.keyring_backend,
        "default_account": config.default_account,
        "gas": {
            "limit": config.gas.limit,
            "price": config.gas.price,
            "adjustment": config.gas.adjustment
        }
    });
    print_value(&info, &config.output_format)
}

fn list(config: &Config) -> Result<()> {
    let presets: Vec<Value> = NetworkPreset::all()
        .into_iter()
        .map(|preset| {
            json!({
                "name": preset.name,
                "rpc": preset.rpc,
                "api": preset.api,
                "chain_id": preset.chain_id,
                "explorer": preset.explorer,
                "faucet": preset.faucet
            })
        })
        .collect();

    print_value(&json!({ "networks": presets }), &config.output_format)
}

fn switch_network(config: &Config, network: &str) -> Result<()> {
    if !["mainnet", "testnet", "devnet", "local"].contains(&network) {
        return Err(anyhow!(
            "unsupported network '{network}', expected one of: mainnet, testnet, devnet, local"
        ));
    }

    let mut updated = config.clone();
    updated.set_network(network);
    updated
        .save(None)
        .with_context(|| format!("failed to persist network switch to '{network}'"))?;

    println!("Switched network to '{network}'");
    println!("RPC: {}", updated.rpc_endpoint);
    println!("API: {}", updated.api_endpoint);
    println!("Chain ID: {}", updated.chain_id);
    Ok(())
}

async fn params(config: &Config) -> Result<()> {
    let client = ApiClient::new(config)?;
    let value = client
        .get_api("/cosmos/base/tendermint/v1beta1/node_info", &[])
        .await
        .or_else(|_| client.get_api("/v1/status", &[]).await)
        .context("failed to fetch chain parameters")?;
    print_value(&value, &config.output_format)
}

async fn blocks(config: &Config, count: usize) -> Result<()> {
    let client = ApiClient::new(config)?;
    let latest = client
        .get_api("/cosmos/base/tendermint/v1beta1/blocks/latest", &[])
        .await
        .context("failed to fetch latest block")?;

    if count <= 1 {
        return print_value(&latest, &config.output_format);
    }

    let mut blocks = vec![latest];
    let height = blocks[0]
        .pointer("/block/header/height")
        .and_then(Value::as_str)
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or_default();

    for offset in 1..count {
        let target = height - offset as i64;
        if target <= 0 {
            break;
        }
        let response = client
            .get_api(
                "/cosmos/base/tendermint/v1beta1/blocks/latest",
                &[("height", target.to_string())],
            )
            .await
            .unwrap_or_else(|err| json!({ "height": target, "error": err.to_string() }));
        blocks.push(response);
    }

    print_value(&json!({ "blocks": blocks }), &config.output_format)
}

async fn pending(config: &Config) -> Result<()> {
    let client = ApiClient::new(config)?;
    let value = client
        .get_rpc("/unconfirmed_txs", &[])
        .await
        .or_else(|_| client.get_api("/v1/transactions?status=pending", &[]).await)
        .context("failed to fetch pending transactions")?;
    print_value(&value, &config.output_format)
}
