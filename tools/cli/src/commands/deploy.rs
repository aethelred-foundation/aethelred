//! Deploy commands.

use anyhow::{anyhow, Context, Result};
use serde_json::json;
use std::fs;
use std::path::Path;

use crate::commands::api::{file_sha256_hex, print_value, ApiClient};
use crate::config::Config;
use crate::DeployArgs;

pub async fn run(args: DeployArgs, config: &Config) -> Result<()> {
    if !args.artifact.exists() {
        return Err(anyhow!(
            "artifact does not exist: {}",
            args.artifact.display()
        ));
    }

    if !args.yes {
        println!(
            "Preparing deployment for {} (use --yes to skip this confirmation in automation)",
            args.artifact.display()
        );
    }

    let client = ApiClient::new(config)?;
    let artifact_hash = file_sha256_hex(&args.artifact)?;
    let artifact_size = fs::metadata(&args.artifact)
        .with_context(|| format!("failed to stat {}", args.artifact.display()))?
        .len();
    let artifact_kind = classify_artifact(&args.artifact);

    let payload = json!({
        "name": args.name,
        "artifact_path": args.artifact.display().to_string(),
        "artifact_kind": artifact_kind,
        "artifact_hash": artifact_hash,
        "artifact_size_bytes": artifact_size,
        "target_network": args.network.unwrap_or_else(|| config.network.clone()),
        "gas_limit": args.gas_limit
    });

    let endpoint = if artifact_kind == "model" {
        "/aethelred/pouw/v1/models/deploy"
    } else {
        "/v1/contracts/deploy"
    };
    let response = client
        .post_api(endpoint, &payload)
        .await
        .context("deployment request failed")?;

    print_value(&response, &config.output_format)
}

fn classify_artifact(path: &Path) -> &'static str {
    match path.extension().and_then(|ext| ext.to_str()) {
        Some("onnx" | "safetensors" | "pt" | "ckpt" | "tflite") => "model",
        Some("wasm" | "sol" | "json") => "contract",
        _ => "artifact",
    }
}
