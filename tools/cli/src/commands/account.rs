//! Account commands.

use anyhow::{anyhow, Context, Result};
use dialoguer::Input;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

use crate::commands::api::{parse_key_value_params, print_value, ApiClient};
use crate::config::Config;
use crate::AccountCommands;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AccountStore {
    accounts: Vec<StoredAccount>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredAccount {
    name: String,
    address: String,
    mnemonic: Option<String>,
}

pub async fn run(cmd: AccountCommands, config: &Config) -> Result<()> {
    match cmd {
        AccountCommands::Create { name } => create_account(config, &name),
        AccountCommands::Import { name } => import_account(config, &name),
        AccountCommands::Export { name, output } => export_account(config, &name, output),
        AccountCommands::List => list_accounts(config),
        AccountCommands::Balance { address } => balance(config, address).await,
        AccountCommands::Send { to, amount, denom } => send(config, &to, &amount, &denom).await,
        AccountCommands::Use { name } => use_account(config, &name),
    }
}

fn create_account(config: &Config, name: &str) -> Result<()> {
    let mut store = load_store()?;
    if store.accounts.iter().any(|account| account.name == name) {
        return Err(anyhow!("account '{name}' already exists"));
    }

    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let mut hasher = Sha256::new();
    hasher.update(seed);
    let digest = hasher.finalize();
    let address = format!("aeth1{}", hex::encode(&digest[..20]));

    store.accounts.push(StoredAccount {
        name: name.to_string(),
        address: address.clone(),
        mnemonic: None,
    });
    save_store(&store)?;

    if config.default_account.is_none() {
        let mut updated = config.clone();
        updated.default_account = Some(name.to_string());
        updated.save(None)?;
    }

    println!("Account created");
    println!("  name: {name}");
    println!("  address: {address}");
    Ok(())
}

fn import_account(config: &Config, name: &str) -> Result<()> {
    let mut store = load_store()?;
    if store.accounts.iter().any(|account| account.name == name) {
        return Err(anyhow!("account '{name}' already exists"));
    }

    let mnemonic = std::env::var("AETH_MNEMONIC").unwrap_or_else(|_| {
        Input::<String>::new()
            .with_prompt("Enter mnemonic")
            .interact_text()
            .unwrap_or_default()
    });
    if mnemonic.trim().is_empty() {
        return Err(anyhow!("mnemonic input is empty"));
    }

    let mut hasher = Sha256::new();
    hasher.update(mnemonic.as_bytes());
    let digest = hasher.finalize();
    let address = format!("aeth1{}", hex::encode(&digest[..20]));

    store.accounts.push(StoredAccount {
        name: name.to_string(),
        address: address.clone(),
        mnemonic: Some(mnemonic),
    });
    save_store(&store)?;

    if config.default_account.is_none() {
        let mut updated = config.clone();
        updated.default_account = Some(name.to_string());
        updated.save(None)?;
    }

    println!("Account imported");
    println!("  name: {name}");
    println!("  address: {address}");
    Ok(())
}

fn export_account(_config: &Config, name: &str, output: Option<PathBuf>) -> Result<()> {
    let store = load_store()?;
    let account = store
        .accounts
        .iter()
        .find(|account| account.name == name)
        .ok_or_else(|| anyhow!("account '{name}' not found"))?;

    let payload = serde_json::to_vec_pretty(account)?;
    match output {
        Some(path) => {
            fs::write(&path, payload)
                .with_context(|| format!("failed to write {}", path.display()))?;
            println!("Exported account '{name}' to {}", path.display());
        }
        None => {
            println!("{}", serde_json::to_string_pretty(account)?);
        }
    }
    Ok(())
}

fn list_accounts(config: &Config) -> Result<()> {
    let store = load_store()?;
    let values = store
        .accounts
        .iter()
        .map(|account| {
            json!({
                "name": account.name,
                "address": account.address,
                "default": config.default_account.as_deref() == Some(account.name.as_str())
            })
        })
        .collect::<Vec<_>>();
    print_value(&json!({ "accounts": values }), &config.output_format)
}

async fn balance(config: &Config, explicit_address: Option<String>) -> Result<()> {
    let store = load_store()?;
    let target_address = if let Some(address) = explicit_address {
        address
    } else {
        let default_name = config
            .default_account
            .as_ref()
            .ok_or_else(|| anyhow!("no address provided and no default account is configured"))?;
        store
            .accounts
            .iter()
            .find(|account| account.name == *default_name)
            .map(|account| account.address.clone())
            .ok_or_else(|| anyhow!("default account '{default_name}' not found in local store"))?
    };

    let client = ApiClient::new(config)?;
    let response = client
        .get_api(&format!("/v1/accounts/{target_address}"), &[])
        .await
        .or_else(|_| {
            client
                .get_api(
                    "/cosmos/bank/v1beta1/balances",
                    &[("address", target_address.clone())],
                )
                .await
        })
        .with_context(|| format!("failed to fetch balance for {target_address}"))?;

    print_value(&response, &config.output_format)
}

async fn send(config: &Config, to: &str, amount: &str, denom: &str) -> Result<()> {
    let store = load_store()?;
    let from = resolve_default_address(config, &store)?;

    let payload = json!({
        "from": from,
        "to": to,
        "amount": amount,
        "denom": denom
    });
    let client = ApiClient::new(config)?;
    let response = client
        .post_api("/v1/transactions/send", &payload)
        .await
        .or_else(|_| {
            client
                .post_api(
                    "/cosmos/tx/v1beta1/txs",
                    &json!({
                        "body": parse_key_value_params(&[
                            format!("from={from}"),
                            format!("to={to}"),
                            format!("amount={amount}{denom}"),
                        ])?
                    }),
                )
                .await
        })
        .context("failed to submit send transaction")?;

    print_value(&response, &config.output_format)
}

fn use_account(config: &Config, name: &str) -> Result<()> {
    let store = load_store()?;
    if !store.accounts.iter().any(|account| account.name == name) {
        return Err(anyhow!("account '{name}' not found"));
    }

    let mut updated = config.clone();
    updated.default_account = Some(name.to_string());
    updated.save(None)?;
    println!("Default account set to '{name}'");
    Ok(())
}

fn resolve_default_address(config: &Config, store: &AccountStore) -> Result<String> {
    let default_name = config
        .default_account
        .as_ref()
        .ok_or_else(|| anyhow!("default account not configured"))?;
    store
        .accounts
        .iter()
        .find(|account| account.name == *default_name)
        .map(|account| account.address.clone())
        .ok_or_else(|| anyhow!("default account '{default_name}' not found"))
}

fn load_store() -> Result<AccountStore> {
    let path = account_store_path()?;
    if !path.exists() {
        return Ok(AccountStore { accounts: vec![] });
    }

    let data =
        fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?;
    let store: AccountStore = serde_json::from_str(&data)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    Ok(store)
}

fn save_store(store: &AccountStore) -> Result<()> {
    let path = account_store_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    fs::write(&path, serde_json::to_vec_pretty(store)?)
        .with_context(|| format!("failed to write {}", path.display()))
}

fn account_store_path() -> Result<PathBuf> {
    let base = dirs::config_dir().ok_or_else(|| anyhow!("cannot determine config directory"))?;
    Ok(base.join("aethelred").join("accounts.json"))
}

#[allow(dead_code)]
fn _ensure_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    Ok(())
}
