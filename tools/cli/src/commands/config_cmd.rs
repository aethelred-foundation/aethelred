//! Configuration commands.

use anyhow::{anyhow, Context, Result};
use serde_json::json;
use std::fs;
use std::process::Command;

use crate::commands::api::print_value;
use crate::config::Config;
use crate::ConfigCommands;

pub async fn run(cmd: ConfigCommands, config: &Config) -> Result<()> {
    match cmd {
        ConfigCommands::Show => show(config),
        ConfigCommands::Set { key, value } => set_value(config, &key, &value),
        ConfigCommands::Get { key } => get_value(config, &key),
        ConfigCommands::Reset { key } => reset(config, key),
        ConfigCommands::Edit => edit(config),
        ConfigCommands::Export { output } => export_config(config, &output),
        ConfigCommands::Import { input } => import_config(&input),
    }
}

fn show(config: &Config) -> Result<()> {
    let custom: serde_json::Map<String, serde_json::Value> = config
        .custom
        .iter()
        .map(|(key, value)| (key.clone(), json!(display_value(key, value))))
        .collect();
    let payload = json!({
        "network": config.network,
        "rpc_endpoint": config.rpc_endpoint,
        "api_endpoint": config.api_endpoint,
        "chain_id": config.chain_id,
        "output_format": config.output_format,
        "keyring_backend": config.keyring_backend,
        "default_account": config.default_account,
        "gas": {
            "limit": config.gas.limit,
            "price": config.gas.price,
            "adjustment": config.gas.adjustment
        },
        "custom": custom
    });
    print_value(&payload, &config.output_format)
}

fn set_value(config: &Config, key: &str, value: &str) -> Result<()> {
    let mut updated = config.clone();
    updated
        .set(key, value)
        .with_context(|| format!("failed to set '{key}'"))?;
    updated.save(None).context("failed to save config")?;
    if is_sensitive_key(key) {
        println!("Set {key} = [REDACTED]");
    } else {
        println!("Set {key} = {value}");
    }
    Ok(())
}

fn get_value(config: &Config, key: &str) -> Result<()> {
    let value = config
        .get(key)
        .ok_or_else(|| anyhow!("key '{key}' not found"))?;
    println!("{}", display_value(key, &value));
    Ok(())
}

fn display_value(key: &str, value: &str) -> String {
    if is_sensitive_key(key) {
        "[REDACTED]".to_string()
    } else {
        value.to_string()
    }
}

fn is_sensitive_key(key: &str) -> bool {
    let normalized = key.to_ascii_lowercase().replace(['-', '.'], "_");
    [
        "secret",
        "token",
        "password",
        "private",
        "mnemonic",
        "seed",
        "apikey",
        "api_key",
        "access_key",
        "client_secret",
        "secret_key",
        "signing_key",
        "seed_phrase",
        "auth",
        "credential",
    ]
    .iter()
    .any(|needle| normalized.contains(needle))
}

fn reset(config: &Config, key: Option<String>) -> Result<()> {
    let mut updated = config.clone();
    match key {
        Some(key_name) => {
            let default = Config::default();
            if let Some(default_value) = default.get(&key_name) {
                updated.set(&key_name, &default_value)?;
            } else {
                updated.custom.remove(&key_name);
            }
            println!("Reset key '{key_name}'");
        }
        None => {
            updated = Config::default();
            println!("Reset entire configuration to defaults");
        }
    }
    updated.save(None).context("failed to save config")?;
    Ok(())
}

fn edit(config: &Config) -> Result<()> {
    let editor = std::env::var("EDITOR").unwrap_or_else(|_| "vi".to_string());
    let config_path = dirs::config_dir()
        .ok_or_else(|| anyhow!("cannot resolve config directory"))?
        .join("aethelred")
        .join("config.toml");

    if !config_path.exists() {
        config.save(None)?;
    }

    let status = Command::new(&editor)
        .arg(&config_path)
        .status()
        .with_context(|| format!("failed to launch editor '{editor}'"))?;

    if !status.success() {
        return Err(anyhow!("editor exited with status {status}"));
    }
    Ok(())
}

fn export_config(config: &Config, output: &std::path::Path) -> Result<()> {
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    fs::write(output, toml::to_string_pretty(config)?)
        .with_context(|| format!("failed to write {}", output.display()))?;
    println!("Exported config to {}", output.display());
    Ok(())
}

fn import_config(input: &std::path::Path) -> Result<()> {
    let content =
        fs::read_to_string(input).with_context(|| format!("failed to read {}", input.display()))?;
    let parsed: Config =
        toml::from_str(&content).with_context(|| format!("failed to parse {}", input.display()))?;
    parsed
        .save(None)
        .context("failed to persist imported config")?;
    println!("Imported config from {}", input.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{display_value, is_sensitive_key};

    #[test]
    fn redacts_sensitive_custom_keys_with_separators() {
        assert_eq!(display_value("rpc.auth_token", "secret-value"), "[REDACTED]");
        assert_eq!(display_value("signing-key", "secret-value"), "[REDACTED]");
        assert_eq!(display_value("seed.phrase", "secret-value"), "[REDACTED]");
    }

    #[test]
    fn leaves_non_sensitive_keys_visible() {
        assert_eq!(
            display_value("rpc_endpoint", "https://rpc.aethelred.io"),
            "https://rpc.aethelred.io"
        );
        assert_eq!(display_value("network", "testnet"), "testnet");
    }

    #[test]
    fn recognizes_common_secret_key_patterns() {
        assert!(is_sensitive_key("api_key"));
        assert!(is_sensitive_key("RPC.AUTH-TOKEN"));
        assert!(is_sensitive_key("hardware.private.key"));
        assert!(!is_sensitive_key("chain_id"));
        assert!(!is_sensitive_key("gas.price"));
    }
}
