//! Transaction commands.

use anyhow::{anyhow, Context, Result};
use serde_json::json;
use std::time::{Duration, Instant};
use tokio::time::sleep;

use crate::commands::api::{parse_key_value_params, print_value, ApiClient};
use crate::config::Config;
use crate::TxArgs;

pub async fn run(args: TxArgs, config: &Config) -> Result<()> {
    let params = parse_key_value_params(&args.params)?;
    let payload = json!({
        "tx_type": args.tx_type,
        "params": params,
        "gas": args.gas,
        "fee": args.fee
    });

    if !args.yes {
        println!("Submitting transaction '{}'", payload["tx_type"]);
    }

    let client = ApiClient::new(config)?;
    let response = client
        .post_api("/v1/transactions", &payload)
        .await
        .or_else(|_| {
            client
                .post_api(
                    "/cosmos/tx/v1beta1/txs",
                    &json!({
                        "body": payload["params"],
                        "mode": "BROADCAST_MODE_SYNC"
                    }),
                )
                .await
        })
        .context("failed to submit transaction")?;

    print_value(&response, &config.output_format)?;

    if args.wait {
        let tx_hash = response
            .pointer("/tx_hash")
            .and_then(|value| value.as_str())
            .map(|value| value.to_string())
            .or_else(|| {
                response
                    .pointer("/tx_response/txhash")
                    .and_then(|value| value.as_str())
                    .map(|value| value.to_string())
            })
            .ok_or_else(|| anyhow!("could not derive transaction hash from response"))?;
        wait_for_tx_confirmation(&client, config, &tx_hash).await?;
    }

    Ok(())
}

async fn wait_for_tx_confirmation(
    client: &ApiClient,
    config: &Config,
    tx_hash: &str,
) -> Result<()> {
    let timeout = Duration::from_secs(120);
    let started = Instant::now();

    loop {
        let response = client
            .get_api(&format!("/v1/transactions/{tx_hash}"), &[])
            .await
            .or_else(|_| {
                client
                    .get_api("/cosmos/tx/v1beta1/txs", &[("hash", tx_hash.to_string())])
                    .await
            });

        match response {
            Ok(value) => {
                print_value(&value, &config.output_format)?;
                return Ok(());
            }
            Err(err) if started.elapsed() < timeout => {
                if err.to_string().contains("404") {
                    sleep(Duration::from_secs(2)).await;
                    continue;
                }
                return Err(err);
            }
            Err(err) => return Err(err).context("timed out waiting for transaction confirmation"),
        }
    }
}
