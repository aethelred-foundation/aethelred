//! Model management commands.

use anyhow::{Context, Result};
use serde_json::json;
use std::fs;

use crate::commands::api::{file_sha256_hex, print_value, ApiClient};
use crate::config::Config;
use crate::ModelCommands;

pub async fn run(cmd: ModelCommands, config: &Config) -> Result<()> {
    let client = ApiClient::new(config)?;

    match cmd {
        ModelCommands::List(args) => {
            let mut query: Vec<(&str, String)> = vec![
                ("limit", args.limit.to_string()),
                ("offset", args.offset.to_string()),
            ];
            if let Some(owner) = args.owner {
                query.push(("owner", owner));
            }
            if let Some(status) = args.status {
                query.push(("status", status));
            }
            let response = client
                .get_api("/aethelred/pouw/v1/models", &query)
                .await
                .context("failed to list models")?;
            print_value(&response, &config.output_format)?;
        }
        ModelCommands::Register(args) => {
            let metadata = fs::metadata(&args.file)
                .with_context(|| format!("failed to inspect {}", args.file.display()))?;
            let hash = file_sha256_hex(&args.file)?;
            let payload = json!({
                "name": args.name,
                "version": args.version,
                "description": args.description,
                "tags": args.tags,
                "model_hash": hash,
                "file_size_bytes": metadata.len(),
                "require_tee": args.require_tee,
                "enable_zkml": args.enable_zkml
            });

            let response = client
                .post_api("/aethelred/pouw/v1/models", &payload)
                .await
                .context("failed to register model")?;
            print_value(&response, &config.output_format)?;
        }
        ModelCommands::Get { model } => {
            let response = client
                .get_api(&format!("/aethelred/pouw/v1/models/{model}"), &[])
                .await
                .with_context(|| format!("failed to fetch model '{model}'"))?;
            print_value(&response, &config.output_format)?;
        }
        ModelCommands::Deploy(args) => {
            let payload = json!({
                "validators": args.validators,
                "replicas": args.replicas,
                "wait": args.wait
            });
            let response = client
                .post_api(
                    &format!("/aethelred/pouw/v1/models/{}/deploy", args.model),
                    &payload,
                )
                .await
                .with_context(|| format!("failed to deploy model '{}'", args.model))?;
            print_value(&response, &config.output_format)?;
        }
        ModelCommands::Update(args) => {
            let payload = json!({
                "name": args.name,
                "description": args.description,
                "add_tags": args.add_tags,
                "remove_tags": args.remove_tags
            });
            let response = client
                .patch_api(
                    &format!("/aethelred/pouw/v1/models/{}", args.model),
                    &payload,
                )
                .await
                .with_context(|| format!("failed to update model '{}'", args.model))?;
            print_value(&response, &config.output_format)?;
        }
        ModelCommands::Export(args) => {
            let response = client
                .get_api(&format!("/aethelred/pouw/v1/models/{}", args.model), &[])
                .await
                .with_context(|| format!("failed to export model '{}'", args.model))?;
            let export = json!({
                "format": args.format,
                "include_weights": args.include_weights,
                "model": response
            });
            fs::write(&args.output, serde_json::to_vec_pretty(&export)?).with_context(|| {
                format!("failed to write model export to {}", args.output.display())
            })?;
            println!("Model exported to {}", args.output.display());
        }
        ModelCommands::Quantize(args) => {
            let payload = json!({
                "dtype": args.dtype,
                "calibration_dataset": args.calibration,
                "output": args.output,
                "method": args.method
            });
            let response = client
                .post_api(
                    &format!("/aethelred/pouw/v1/models/{}/quantize", args.model),
                    &payload,
                )
                .await
                .with_context(|| format!("failed to quantize model '{}'", args.model))?;
            print_value(&response, &config.output_format)?;
        }
        ModelCommands::Benchmark(args) => {
            let payload = json!({
                "batch_sizes": args.batch_sizes,
                "warmup": args.warmup,
                "iterations": args.iterations,
                "profile": args.profile
            });
            let response = client
                .post_api(
                    &format!("/aethelred/pouw/v1/models/{}/benchmark", args.model),
                    &payload,
                )
                .await
                .with_context(|| format!("failed to benchmark model '{}'", args.model))?;
            print_value(&response, &config.output_format)?;
        }
        ModelCommands::Verify { model } => {
            let response = client
                .post_api(
                    &format!("/aethelred/pouw/v1/models/{model}/verify"),
                    &json!({}),
                )
                .await
                .with_context(|| format!("failed to verify model '{model}'"))?;
            print_value(&response, &config.output_format)?;
        }
    }

    Ok(())
}
