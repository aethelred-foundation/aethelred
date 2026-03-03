//! Digital seal commands.

use anyhow::{Context, Result};
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
                .post_api(
                    &format!("/aethelred/seal/v1/seals/{seal_id}/verify"),
                    &json!({}),
                )
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
            let mut query: Vec<(&str, String)> = vec![("limit", args.limit.to_string())];
            if let Some(model) = args.model {
                query.push(("model_id", model));
            }
            if let Some(creator) = args.creator {
                query.push(("creator", creator));
            }
            if let Some(from) = args.from {
                query.push(("from", from));
            }
            if let Some(to) = args.to {
                query.push(("to", to));
            }

            let response = client
                .get_api("/aethelred/seal/v1/seals", &query)
                .await
                .context("failed to list seals")?;
            print_value(&response, &config.output_format)?;
        }
        SealCommands::Export {
            seal_id,
            output,
            format,
        } => {
            let response = client
                .get_api(
                    &format!("/aethelred/seal/v1/seals/{seal_id}/audit"),
                    &[("format", format)],
                )
                .await
                .with_context(|| format!("failed to export seal '{seal_id}'"))?;

            fs::write(&output, serde_json::to_vec_pretty(&response)?)
                .with_context(|| format!("failed to write export file {}", output.display()))?;
            println!("Seal export written to {}", output.display());
        }
    }

    Ok(())
}
