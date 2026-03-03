//! Validator commands.

use anyhow::{Context, Result};
use serde_json::json;

use crate::commands::api::{print_value, ApiClient};
use crate::config::Config;
use crate::ValidatorCommands;

pub async fn run(cmd: ValidatorCommands, config: &Config) -> Result<()> {
    let client = ApiClient::new(config)?;

    match cmd {
        ValidatorCommands::List(args) => {
            let mut query: Vec<(&str, String)> =
                vec![("limit", args.limit.to_string()), ("sort", args.sort)];
            if let Some(status) = args.status {
                query.push(("status", status));
            }

            let response = client
                .get_api("/aethelred/pouw/v1/validators", &query)
                .await
                .context("failed to list validators")?;
            print_value(&response, &config.output_format)?;
        }
        ValidatorCommands::Get { address } => {
            let stats = client
                .get_api(
                    &format!("/aethelred/pouw/v1/validators/{address}/stats"),
                    &[],
                )
                .await
                .with_context(|| format!("failed to fetch validator stats for '{address}'"))?;
            let capability = client
                .get_api(
                    &format!("/aethelred/pouw/v1/validators/{address}/capability"),
                    &[],
                )
                .await
                .unwrap_or_else(|err| json!({ "error": err.to_string() }));
            print_value(
                &json!({
                    "address": address,
                    "stats": stats,
                    "capability": capability
                }),
                &config.output_format,
            )?;
        }
        ValidatorCommands::Register(args) => {
            let payload = json!({
                "moniker": args.moniker,
                "commission": args.commission,
                "website": args.website,
                "description": args.description,
                "stake": args.stake
            });
            let response = client
                .post_api("/aethelred/pouw/v1/validators/register", &payload)
                .await
                .context("failed to register validator")?;
            print_value(&response, &config.output_format)?;
        }
        ValidatorCommands::Update(args) => {
            let payload = json!({
                "moniker": args.moniker,
                "commission": args.commission,
                "website": args.website,
                "description": args.description
            });
            let response = client
                .patch_api("/aethelred/pouw/v1/validators/me", &payload)
                .await
                .context("failed to update validator profile")?;
            print_value(&response, &config.output_format)?;
        }
        ValidatorCommands::Stake { amount } => {
            let response = client
                .post_api(
                    "/aethelred/pouw/v1/validators/me/stake",
                    &json!({ "amount": amount }),
                )
                .await
                .context("failed to stake tokens")?;
            print_value(&response, &config.output_format)?;
        }
        ValidatorCommands::Unstake { amount } => {
            let response = client
                .post_api(
                    "/aethelred/pouw/v1/validators/me/unstake",
                    &json!({ "amount": amount }),
                )
                .await
                .context("failed to unstake tokens")?;
            print_value(&response, &config.output_format)?;
        }
        ValidatorCommands::Status => {
            let response = client
                .get_api("/aethelred/pouw/v1/validators/me/status", &[])
                .await
                .context("failed to fetch validator status")?;
            print_value(&response, &config.output_format)?;
        }
    }

    Ok(())
}
