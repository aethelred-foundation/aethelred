//! Digital seal commands.

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose, Engine as _};
use serde_json::json;
use std::fs;

use crate::commands::api::{print_value, ApiClient};
use crate::config::Config;
use crate::SealCommands;

pub async fn run(cmd: SealCommands, config: &Config) -> Result<()> {
    let client = ApiClient::new(config)?;

    match cmd {
        SealCommands::Create(args) => {
            let payload = json!({
                "model_hash": args.model,
                "input_hash": args.input,
                "output_hash": args.output,
                "with_attestation": args.with_attestation,
                "with_proof": args.with_proof
            });
            let response = client
                .post_api("/aethelred/seal/v1/seals", &payload)
                .await
                .context("failed to create seal")?;
            print_value(&response, &config.output_format)?;
        }
        SealCommands::Verify { seal_id } => {
            let response = client
                .get_api(&format!("/aethelred/seal/v1/seals/{seal_id}/verify"), &[])
                .await
                .with_context(|| format!("failed to verify seal '{seal_id}'"))?;
            print_value(&response, &config.output_format)?;
        }
        SealCommands::Get { seal_id } => {
            let response = client
                .get_api(&format!("/aethelred/seal/v1/seals/{seal_id}"), &[])
                .await
                .with_context(|| format!("failed to fetch seal '{seal_id}'"))?;
            print_value(&response, &config.output_format)?;
        }
        SealCommands::List(args) => {
            if args.from.is_some() || args.to.is_some() {
                bail!("date range filters are not supported by the seal query API");
            }
            if args.model.is_some() && args.creator.is_some() {
                bail!("model and creator filters must be queried separately");
            }

            let response = if let Some(model) = args.model {
                client
                    .get_api(
                        "/aethelred/seal/v1/seals/by_model",
                        &[("model_hash", hex_hash_to_base64(&model)?)],
                    )
                    .await
                    .context("failed to list seals by model")?
            } else if let Some(creator) = args.creator {
                client
                    .get_api(
                        "/aethelred/seal/v1/seals/by_requester",
                        &[("requester", creator)],
                    )
                    .await
                    .context("failed to list seals by creator")?
            } else {
                client
                    .get_api(
                        "/aethelred/seal/v1/seals",
                        &[("limit", args.limit.to_string())],
                    )
                    .await
                    .context("failed to list seals")?
            };
            print_value(&response, &config.output_format)?;
        }
        SealCommands::Export {
            seal_id,
            output,
            format,
        } => {
            let format = normalize_export_format(&format)?;
            let response = client
                .get_api(
                    &format!("/aethelred/seal/v1/seals/{seal_id}/export"),
                    &[("format", format)],
                )
                .await
                .with_context(|| format!("failed to export seal '{seal_id}'"))?;

            let export = response.get("export").unwrap_or(&response);
            fs::write(&output, serde_json::to_vec_pretty(export)?)
                .with_context(|| format!("failed to write export file {}", output.display()))?;
            println!("Seal export written to {}", output.display());
        }
    }

    Ok(())
}

fn normalize_export_format(format: &str) -> Result<String> {
    match format.trim().to_ascii_lowercase().as_str() {
        "" | "json" => Ok("json".to_string()),
        "compact" => Ok("compact".to_string()),
        "portable" => Ok("portable".to_string()),
        "audit" => Ok("audit".to_string()),
        other => bail!(
            "unsupported export format '{other}'; supported formats: json, compact, portable, audit"
        ),
    }
}

fn hex_hash_to_base64(hash: &str) -> Result<String> {
    let normalized = hash.strip_prefix("0x").unwrap_or(hash);
    let bytes = hex::decode(normalized)
        .with_context(|| "model hash must be a hex-encoded SHA-256 hash")?;
    if bytes.len() != 32 {
        bail!("model hash must decode to 32 bytes");
    }
    Ok(general_purpose::STANDARD.encode(bytes))
}
